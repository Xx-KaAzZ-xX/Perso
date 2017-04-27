#!/bin/bash
#
# Filename : nginx_with_modsecurity.sh
# Version  : 1.0
# Author   : Aurélien DUBUS 
# Contrib  : 
# Description :
#  . Install Nginx with the Modsecurity module and add the OWASP rules on Debian Machines

function usage() {
  echo "
  Description :
    - Install Nginx with the Modsecurity module
    - Add the OWASP rules
      "
    }
usage

#Install dependancies
apt-get install git build-essential libpcre3 libpcre3-dev libssl-dev libtool autoconf apache2-prefork-dev libxml2-dev libcurl4-openssl-dev

#Download the Modsecurity Module
cd /root
git clone https://github.com/SpiderLabs/ModSecurity.git modsecurity

#Download the package
wget http://nginx.org/download/nginx-1.6.2.tar.gz
echo -e "\n Extracting Nginx files... \n"
tar -xvf nginx-1.6.2.tar.gz > /dev/null

#Installation
 cd /root/modsecurity
./autogen.sh > /dev/null

./configure --enable-standalone-module --disable-mlogc
make 
cd /root/nginx-1.6.2

#./configure --conf-path=/etc/nginx/conf/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --with-http_ssl_module --add-module=/root/modsecurity/nginx/modsecurity/
./configure --conf-path=/etc/nginx/nginx.conf --add-module=/root/modsecurity/nginx/modsecurity/  --error-log-path=/var/log/nginx/error.log --http-client-body-temp-path=/var/lib/nginx/body  --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-log-path=/var/log/nginx/access.log  --http-proxy-temp-path=/var/lib/nginx/proxy --lock-path=/var/lock/nginx.lock  --pid-path=/var/run/nginx.pid --with-http_ssl_module  --without-mail_pop3_module --without-mail_smtp_module  --without-mail_imap_module --without-http_uwsgi_module  --without-http_scgi_module --with-ipv6 --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx
echo -e "\n Compiling Nginx... \n"

make
make install

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

mkdir /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d

#Creating files to manage the nginx service
echo -e "\n Creating nginx.service file...\n"
touch /lib/systemd/system/nginx.service
cat > /lib/systemd/system/nginx.service << _EOF_
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
_EOF_
systemctl daemon-reload

#Configuration of modsecurity
cp /root/modsecurity/modsecurity.conf-recommended /etc/nginx/conf.d/modsecurity.conf
cp /root/modsecurity/unicode.mapping /etc/nginx/conf.d/ 

#Adding OWASP Rules
cd /usr/src/
git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git
cd owasp-modsecurity-crs
cp -R base_rules/ /etc/nginx/conf.d/

#Editing modsecurity.conf
cat >> /etc/nginx/conf.d/modsecurity.conf << _EOF_
#DefaultAction
SecDefaultAction "log,deny,phase:1"

#If you want to load single rule /usr/loca/nginx/conf
Include base_rules/modsecurity_crs_41_sql_injection_attacks.conf

#Load all Rule
#Include base_rules/*.conf
_EOF_

#Editing nginx.conf

if [ -f /etc/nginx/conf.d/modsecurity.conf ]; then
  sed -i 's#^SecRuleEngine\(.*\)$#SecRuleEngine On#g' /etc/nginx/conf.d/modsecurity.conf
  # Fix upload max file size at 32M
  sed -i 's#^SecRequestBodyLimit\(.*\)$#SecRequestBodyLimit 32768000#g' /etc/nginx/conf.d/modsecurity.conf
  sed -i 's#^SecRequestBodyInMemoryLimit\(.*\)$#SecRequestBodyInMemoryLimit 32768000#g' /etc/nginx/conf.d/modsecurity.conf
  sed -i 's#^SecResponseBodyAccess\(.*\)$#SecResponseBodyAccess Off#g' /etc/nginx/conf.d/modsecurity.conf
fi

echo -e "\n Start Nginx Server\n"
systemctl start nginx
exit 0
