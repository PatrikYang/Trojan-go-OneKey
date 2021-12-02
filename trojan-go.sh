#!/bin/bash

if [[ $(id -u) != 0 ]]; then
    echo "请以超级用户身份运行此脚本。"
    exit 1
fi

if [[ $(uname -m 2> /dev/null) != x86_64 ]]; then
    echo "请在x86_64机器上运行此脚本。"
    exit 1
fi

_INSTALL(){
	install_dependency
	get_ip
	check_domain
	tls_generate_script_install
	tls_generate
	download_trojan
	trojan_conf
	download_ngnix
	ngnix_conf
	download_web
	echo "安装完成！"
}

install_dependency(){
	apt-get install wget
	apt-get update -y && apt-get install curl -y
	apt-get install xz-utils
	apt-get update
}

get_ip() {
  	local_ip=$(curl -s https://ipinfo.io/ip)
  	[[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://api.ip.sb/ip)
  	[[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://api.ipify.org)
  	[[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://ip.seeip.org)
  	[[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://ifconfig.co/ip)
  	[[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
  	[[ -z ${local_ip} ]] && ${local_ip}=$(curl -s icanhazip.com)
  	[[ -z ${local_ip} ]] && ${local_ip}=$(curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
  	[[ -z ${local_ip} ]] && echo "获取不到你vps的ip地址" && exit
}

check_domain() {
  	read -rp "请输入您的域名(如果用Cloudflare解析域名，请点击小云彩使其变灰):" domain
  	real_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
  	while [ "${real_ip}" != "${local_ip}" ]; do
    	read -rp "本机IP和域名绑定的IP不一致，请检查域名是否解析成功,并重新输入域名:" domain
    	real_ip=$(ping ${domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    	read -rp "我已人工确认，本机Ip和域名绑定的IP一致，继续安装（Y/n）？（默认:n）" continue_install
    	[[ -z ${continue_install} ]] && continue_install="n"
    	case ${continue_install} in
    		[yY][eE][sS] | [yY])
        	echo "继续安装"
        	break
        	;;
    	*)
        	echo "安装终止"
        	exit 2
        	;;
    	esac
  	done
}

tls_generate_script_install() {
    apt install socat netcat -y
    echo "安装 tls 证书生成脚本依赖"
    if [[ ${email} == "" ]]; then
      	read -p "请填写您的邮箱：" email
      	read -p "邮箱输入正确吗（Y/n）？（默认：n）" Yn
      	[[ -z ${Yn} ]] && Yn="n"
      	while [[ ${Yn} != "Y" ]] && [[ ${Yn} != "y" ]]; do
        	read -p "重新填写您的邮箱：" email
        	read -p "邮箱输入正确吗（Y/n）？（默认：n）" Yn
        	[[ -z ${Yn} ]] && Yn="n"
      	done
    fi
    curl https://get.acme.sh | sh -s email=${email}
	source ~/.bashrc
    echo "安装 tls 证书生成脚本"
}

tls_generate() {
  	if [[ -f "/data/${domain}/fullchain.cer" ]] && [[ -f "/data/${domain}/private.key" ]]; then
    	echo "证书已存在……不需要再重新签发了……"
  	else    
    	if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
        	echo "TLS 证书测试签发成功，开始正式签发"
        	rm -rf "$HOME/.acme.sh/${domain}_ecc"
        	sleep 2
    	else
        	echo "TLS 证书测试签发失败 "
        	rm -rf "$HOME/.acme.sh/${domain}_ecc"
        	exit 1
    	fi

    	if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        	echo "TLS 证书生成成功 "
        	sleep 2
        	mkdir /data
        	mkdir /data/${domain}
        	if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/${domain}/fullchain.cer --keypath /data/${domain}/private.key --ecc --force; then
            	echo "证书配置成功 "
            	sleep 2
        	fi
    	else
        	echo "TLS 证书生成失败"
        	rm -rf "$HOME/.acme.sh/${domain}_ecc"
        	exit 1
    	fi
  	fi
}

download_trojan(){
	if [ -f /etc/centos-release ]; then
		yum install -y wget curl zip
	else
		apt install -y wget curl zip
	fi
	mkdir /etc/trojan-go
	mkdir /usr/share/trojan-go
	wget -N --no-check-certificate https://github.com/p4gefau1t/trojan-go/releases/download/$(curl -fsSL https://api.github.com/repos/p4gefau1t/trojan-go/releases | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')/trojan-go-linux-amd64.zip && unzip -d /usr/share/trojan-go/ ./trojan-go-linux-amd64.zip && mv /usr/share/trojan-go/trojan-go /usr/bin/ && chmod +x /usr/bin/trojan-go && rm -rf ./trojan-go-linux-amd64.zip
	cp /usr/share/trojan-go/example/server.json /etc/trojan-go/config.json
	cp /usr/share/trojan-go/example/trojan-go.service /etc/systemd/system/trojan-go.service
}

trojan_conf(){
	read -rp "请输入您的Trojan-go密码:" password
	while [[ -z ${password} ]]; do
    	read -rp "密码不能为空,请重新输入您的Trojan-go密码:" password
	done
	touch /etc/trojan-go/config.json
	cat >/etc/trojan-go/config.json <<EOF
	{
    	"run_type": "server",
    	"local_addr": "0.0.0.0",
    	"local_port": 443,
    	"remote_addr": "127.0.0.1",
    	"remote_port": 80,
    	"password": [
        	"${password}"
    	],
    	"ssl": {
        	"cert": "/data/${domain}/fullchain.cer",
        	"key": "/data/${domain}/private.key",
        	"sni": "${domain}"
    	},
    	"router": {
        	"enabled": true,
        	"block": [
            	"geoip:private"
        	],
        	"geoip": "/usr/share/trojan-go/geoip.dat",
        	"geosite": "/usr/share/trojan-go/geosite.dat"
    	}
	}
EOF
	systemctl daemon-reload
	systemctl start trojan-go.service
	systemctl enable trojan-go.service
}

download_ngnix(){
	apt-get -y install  nginx wget unzip zip curl tar
	systemctl enable nginx.service
}

ngnix_conf(){
	touch /etc/nginx/nginx.conf
	cat >/etc/nginx/nginx.conf <<EOF
	user  root;
	worker_processes  1;
	error_log  /var/log/nginx/error.log warn;
	pid        /var/run/nginx.pid;
	events {
    worker_connections  1024;
	}
	http {
    	include       /etc/nginx/mime.types;
    	default_type  application/octet-stream;
    	log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    	access_log  /var/log/nginx/access.log  main;
    	sendfile        on;
    	#tcp_nopush     on;
    	keepalive_timeout  120;
    	client_max_body_size 20m;
    	#gzip  on;
    	server {
        	listen	80;
        	server_name  ${domain};
        	root /usr/share/nginx/html;
        	index index.php index.html index.htm;
    	}
	}
EOF
}

download_web(){
	rm -rf /usr/share/nginx/html/*
	cd /usr/share/nginx/html/
	wget https://github.com/PatrikYang/Trojan-go-OneKey/raw/main/web.zip
	unzip web.zip
	systemctl restart nginx.service
}

_UPDATE(){
	systemctl stop trojan-go
	rm -rf /usr/bin/trojan-go
	rm -rf /usr/share/trojan-go/*
	wget -N --no-check-certificate https://github.com/p4gefau1t/trojan-go/releases/download/$(curl -fsSL https://api.github.com/repos/p4gefau1t/trojan-go/releases | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')/trojan-go-linux-amd64.zip && unzip -d /usr/share/trojan-go/ ./trojan-go-linux-amd64.zip && mv /usr/share/trojan-go/trojan-go /usr/bin/ && chmod +x /usr/bin/trojan-go && rm -rf ./trojan-go-linux-amd64.zip
	systemctl restart trojan-go
	echo "升级完成！"
}

_UNINSTALL(){
	systemctl stop trojan-go
	systemctl disable trojan-go
	rm -rf /usr/bin/trojan-go /usr/share/trojan-go /etc/trojan-go
	rm -rf /etc/systemd/system/trojan-go.service
	systemctl daemon-reload
	echo "卸载完成！"
}

echo "1.安装trojan-go"
echo "2.升级trojan-go"
echo "3.卸载trojan-go"
echo
read -e -p "请输入数字：" num
case "$num" in
	1)
	_INSTALL
	;;
	2)
	_UPDATE
	;;
	3)
	_UNINSTALL
	;;
	*)
	echo "请输入正确的数字"
	;;
esac
