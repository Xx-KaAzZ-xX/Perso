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

./configure --conf-path=/etc/nginx/conf/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --with-http_ssl_module --add-module=/root/modsecurity/nginx/modsecurity/
echo -e "\n Compiling Nginx... \n"

#echo "dire où les fichiers iront si on laisse par défaut , ou mettre des variables pour la compil"
make
make install
#Symbolic link to access the nginx command from anywhere
ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx

#Creating files to manage the nginx service
echo -e "\n Creating nginx.service file...\n"
touch /lib/systemd/system/nginx.service
cat >> /lib/systemd/system/nginx.service << _EOF_
[Service]
Type=forking
ExecStartPre=/usr/local/nginx/sbin/nginx -t -c /etc/nginx/conf/nginx.conf
ExecStart=/usr/local/nginx/sbin/nginx -c /etc/nginx/conf/nginx.conf
ExecReload=/usr/local/nginx/sbin/nginx -s reload
KillStop=/usr/local/nginx/sbin/nginx -s stop
 
KillMode=process
Restart=on-failure
RestartSec=42s
 
PrivateTmp=true
LimitNOFILE=200000
 
[Install]
WantedBy=multi-user.target
_EOF_
systemctl daemon-reload

echo -e "\n Creating /etc/init.d/nginx file...\n"
touch /etc/init.d/nginx
cat >> /etc/init.d/nginx << _EOF_
#!/bin/bash
 
### BEGIN INIT INFO
# Provides:          nginx
# Required-Start:    $all
# Required-Stop:     $all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: starts the nginx web server
# Description:       starts nginx using start-stop-daemon
### END INIT INFO
 
PATH=/opt/bin:/opt/sbin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/local/nginx/sbin/nginx
NAME=nginx
DESC=nginx
 
test -x $DAEMON || exit 0
 
# Include nginx defaults if available
if [ -f /etc/default/nginx ] ; then
        . /etc/default/nginx
fi
 
set -e
 
case "$1" in
  start)
        echo -n "Starting $DESC: "
        start-stop-daemon --start --quiet --pidfile /var/run/nginx.pid \
                --exec $DAEMON -- $DAEMON_OPTS
        echo "$NAME."
        ;;
  stop)
        echo -n "Stopping $DESC: "
        start-stop-daemon --stop --quiet --pidfile /var/run/nginx.pid \
                --exec $DAEMON
        echo "$NAME."
        ;;
  restart|force-reload)
        echo -n "Restarting $DESC: "
        start-stop-daemon --stop --quiet --pidfile \
                /var/run/nginx.pid --exec $DAEMON
        sleep 1
        start-stop-daemon --start --quiet --pidfile \
                /var/run/nginx.pid --exec $DAEMON -- $DAEMON_OPTS
        echo "$NAME."
        ;;
  reload)
      echo -n "Reloading $DESC configuration: "
      start-stop-daemon --stop --signal HUP --quiet --pidfile /var/run/nginx.pid \
          --exec $DAEMON
      echo "$NAME."
      ;;
  *)
        N=/etc/init.d/$NAME
        echo "Usage: $N {start|stop|restart|force-reload}" >&2
        exit 1
        ;;
esac
 
exit 0
_EOF_
chmod +x /etc/init.d/nginx

#Configuration of modsecurity
cp /root/modsecurity/modsecurity.conf-recommended /etc/nginx/conf/modsecurity.conf
cp /root/modsecurity/unicode.mapping /etc/nginx/conf/ 

#Adding OWASP Rules
cd /usr/src/
git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git
cd owasp-modsecurity-crs
cp -R base_rules/ /etc/nginx/conf/

#Editing modsecurity.conf
cat >> /etc/nginx/conf/modsecurity.conf << _EOF_
#DefaultAction
SecDefaultAction "log,deny,phase:1"

#If you want to load single rule /usr/loca/nginx/conf
Include base_rules/modsecurity_crs_41_sql_injection_attacks.conf

#Load all Rule
#Include base_rules/*.conf
_EOF_

#Editing nginx.conf

if [ -f /etc/nginx/conf/modsecurity.conf ]; then
  sed -i 's#^SecRuleEngine\(.*\)$#SecRuleEngine On#g' /etc/nginx/conf/modsecurity.conf
  # Fix upload max file size at 32M
  sed -i 's#^SecRequestBodyLimit\(.*\)$#SecRequestBodyLimit 32768000#g' /etc/nginx/conf/modsecurity.conf
  sed -i 's#^SecRequestBodyInMemoryLimit\(.*\)$#SecRequestBodyInMemoryLimit 32768000#g' /etc/nginx/conf/modsecurity.conf
  sed -i 's#^SecResponseBodyAccess\(.*\)$#SecResponseBodyAccess Off#g' /etc/nginx/conf/modsecurity.conf
fi

#Activation du module ModSecurity
sed -i '/gzip/a \#Enable ModSecurity\nModSecurityEnabled on;\nModSecurityConfig modsecurity.conf;\n' /etc/nginx/conf/nginx.conf

echo -e "\n Start Nginx Server\n"
systemctl start nginx
exit 0
