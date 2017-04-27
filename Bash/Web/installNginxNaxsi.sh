#!/bin/bash

#.  Description : Install Nginx with the Naxsi WAF from sources for debian 8, supposing that dependencies are already#.                installed
#.  Author : Aurélien DUBUS


##Install dependencies
apt-get install libpcre3-dev build-essential libssl-dev zlib1g-dev
##Download Nginx/Naxsi sources

cd /usr/local/src

wget http://nginx.org/download/nginx-1.6.2.tar.gz

tar -xvzf nginx-1.6.2.tar.gz > /dev/null 2>&1

wget https://github.com/nbs-system/naxsi/archive/master.zip
unzip master.zip > /dev/null 2>&1
cd nginx-1.6.2/

##Installation
echo "Compiling... "
./configure --conf-path=/etc/nginx/nginx.conf --add-module=../naxsi-master/naxsi_src/  --error-log-path=/var/log/nginx/error.log --http-client-body-temp-path=/var/lib/nginx/body  --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-log-path=/var/log/nginx/access.log  --http-proxy-temp-path=/var/lib/nginx/proxy --lock-path=/var/lock/nginx.lock  --pid-path=/var/run/nginx.pid --with-http_ssl_module  --without-mail_pop3_module --without-mail_smtp_module  --without-mail_imap_module --without-http_uwsgi_module  --without-http_scgi_module --with-ipv6 --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx

make 
make install

cp /usr/local/src/naxsi-master/naxsi_config/naxsi_core.rules /etc/nginx/ -fv

cat > /etc/nginx/nginx.conf << _EOF_
user www-data;
worker_processes 4;
pid /run/nginx.pid;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        # server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        include naxsi_core.rules;
        default_type application/octet-stream;
        client_max_body_size 20M;
        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;
        gzip_disable "msie6";

        # gzip_vary on;
        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}
_EOF_

mkdir /etc/nginx/sites-available /etc/nginx/sites-enabled

echo "Creating nginx.service file... "
cat > /lib/systemd/system/nginx.service << _FILE_
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
_FILE_

##Prise en compte des changements pour gérer Nginx avec systemctl
systemctl daemon-reload
systemctl restart nginx

echo "Installation finished. Think to include a naxsi.rules file into your vhost configuration."
