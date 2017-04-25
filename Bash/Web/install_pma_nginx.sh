#!/bin/bash
#
# Filename : install_pma_nginx.sh
# Version  : 1.0
# Author   : Mathieu Androz 
# Contrib  : Aurélien DUBUS
# Description :
#  . Install PhpMyAdmin on port 8888 with Nginx Web Server
#
Nginx_PATH="/etc/nginx"
apt-get install phpmyadmin
addgroup --system --gid 990 phpmyadmin
adduser --system --home /opt/phpmyadmin --uid 990 --gid 990 --shell /bin/sh phpmyadmin
cd /opt/phpmyadmin
mkdir tmp cgi-bin .socks sessions logs
echo "
Go to https://www.phpmyadmin.net/downloads/
"
read -p "Paste link to tar.gz of the PhpMyAdmin version you want to install : " PMALINK
cd /opt && wget "${PMALINK}"
tar xzf phpMyAdmin-4*
rm phpMyAdmin*tar.gz
mv phpMyAdmin* /opt/phpmyadmin/www
cp /opt/phpmyadmin/www/config.sample.inc.php /opt/phpmyadmin/www/config.inc.php
sed '$d' /opt/phpmyadmin/www/config.inc.php
echo "
/* Custom Configuration */
\$cfg['Servers'][\$i]['hide_db'] = '(information_schema|performance_schema|phpmyadmin|mysql)';
\$cfg['ShowServerInfo'] = false;
\$cfg['ShowPhpInfo'] = false;
\$cfg['ShowChgPassword'] = false;
\$cfg['ShowCreateDb'] = false;
\$cfg['SuggestDBName'] = false;
\$cfg['ThemeManager'] = false;
\$cfg['blowfish_secret'] = 'UFKGgyfKYFDflfDFyfOUG8D8Oteè-dubièdbkdè';
\$cfg['ThemeDefault'] = 'pmahomme';
\$cfg['SuhosinDisableWarning'] = true;
\$cfg['PmaNoRelation_DisableWarning'] = true;
?>
" >> /opt/phpmyadmin/www/config.inc.php
chown -R phpmyadmin:phpmyadmin /opt/phpmyadmin/


#Création du VHOST PhpMyAdmin pour Nginx
touch $Nginx_PATH/sites-available/phpmyadmin

#if [ -f "$Nginx_PATH/sites-available/phpmyadmin"]
#then
 
#Nginx VHOST
cat >> $Nginx_PATH/sites-available/phpmyadmin << _EOF_
  server {
  listen 8888 default_server;
  server_name _;
 
  root /opt/phpmyadmin/www/;
 
  index index.php;
  charset utf-8;
 
  location / {
    index  index.php;
  }
 
  error_log /opt/phpmyadmin/logs/error.log warn;
  access_log /opt/phpmyadmin/logs/access.log;
 
  location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    # With php5-cgi alone:
    # fastcgi_pass 127.0.0.1:9000;
    # # With php5-fpm:
    fastcgi_pass unix:/opt/phpmyadmin/.socks/phpmyadmin.sock;
    include fastcgi_params;
    # Custom conf
    fastcgi_split_path_info ^(.+\.php)(.*)$;
    #fastcgi_index  index.php;
    fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
    fastcgi_param  SCRIPT_NAME      $fastcgi_script_name;
    fastcgi_param  QUERY_STRING     $query_string;
    fastcgi_param  REQUEST_METHOD   $request_method;
    fastcgi_param  CONTENT_TYPE     $content_type;
    fastcgi_param  CONTENT_LENGTH   $content_length;
    fastcgi_intercept_errors        on;
    fastcgi_ignore_client_abort     off;
    fastcgi_connect_timeout 300;
    fastcgi_send_timeout 180;
    fastcgi_read_timeout 180;
    fastcgi_buffer_size 128k;
    fastcgi_buffers 4 256k;
    fastcgi_busy_buffers_size 256k;
    fastcgi_temp_file_write_size 256k;
  }
 
  # deny access to .htaccess files, if Apache's document root
  # concurs with nginx's one
  #
  location ~ /\.ht {
    deny all;
    return 404;
  }
 
  location ~ /\.git {
    deny all;
    return 404;
  }
 
  location /setup {
    deny all;
    return 404;
  }
 
  location /sql {
    deny all;
    return 404;
  }
 
  location /test {
    deny all;
    return 404;
  }
 
  location /libraries {
    deny all;
    return 404;
  }
 
  location ~ ^/(README|ChangeLog|RELEASE.*|LICENCE)$ {
    deny all;
    return 404;
  }
}
_EOF_
#fi

#if [ ! -f "/etc/php5/fpm/pool.d/phpmyadmin.conf" ]
#then
touch /etc/php5/fpm/pool.d/phpmyadmin.conf
cat >> /etc/php5/fpm/pool.d/phpmyadmin.conf << __EOF__
[phpmyadmin]

;prefix = /path/to/pools/\$pool

user = \$pool
group = \$pool

listen = /opt/\$pool/.socks/\$pool.sock
;listen.backlog = 128
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
listen.allowed_clients = 127.0.0.1

; priority = -19
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3

;pm.process_idle_timeout = 10s;
;pm.max_requests = 500

;ping.response = pong

;access.log = log/\$pool.access.log

; The access log format.
;access.format = "%R - %u %t \"%m %r%Q%q\" %s %f %{mili}d %{kilo}M %C%%"

;slowlog = log/\$pool.log.slow

;request_slowlog_timeout = 0
;request_terminate_timeout = 0
;rlimit_files = 1024
;rlimit_core = 0
;chroot =
chdir = /

; Pass environment variables like LD_LIBRARY_PATH. All \$VARIABLEs are taken from
; the current environment.
; Default Value: clean env
;env[HOSTNAME] = \$HOSTNAME
;env[PATH] = /usr/local/bin:/usr/bin:/bin
;env[TMP] = /tmp
;env[TMPDIR] = /tmp
;env[TEMP] = /tmp

; Default Value: nothing is defined by default except the values in php.ini and
;                specified at startup with the -d argument
;php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f www@my.domain.com

php_admin_value[open_basedir] = /opt/phpmyadmin/:/etc/phpmyadmin/
php_admin_value[session.save_path] = /opt/phpmyadmin/tmp
php_admin_value[upload_tmp_dir] = /opt/phpmyadmin/tmp
;php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f contact@ovm09.itserver.fr

;;; Gestion des erreurs
; Affichage des erreurs
php_flag[display_errors] = off
; Log des erreurs
php_admin_value[error_log] = /var/log/apache2/fpm-php-phpmyadmin.log
php_admin_flag[log_errors] = on

;;; Valeurs custom php.ini
php_admin_value[memory_limit] = 256M
php_admin_value[post_max_size] = 30M
php_admin_value[upload_max_filesize] = 30M
; SECURITY
php_admin_value[magic_quotes_gpc]=0
php_admin_value[register_globals]=0
php_admin_value[session.auto_start]=0
;php_admin_value[mbstring.http_input]="pass"
;php_admin_value[mbstring.http_output]="pass"
;php_admin_value[mbstring.encoding_translation]=0
php_admin_value[expose_php]=0
php_admin_value[allow_url_fopen]=1
php_admin_value[safe_mode]=0
;php_admin_value[cgi.fix_pathinfo]=1

; Liste des extensions autorisÃ©es avec php-fpm
security.limit_extensions = .php .php5 .html .htm
__EOF__
#fi

ln -s $Nginx_PATH/sites-available/phpmyadmin $Nginx_PATH/sites-enabled/
service nginx restart && service php5-fpm restart

#if [ ! -f "/etc/logrotate.d/phpmyadmin" ]; then
touch /etc/logrotate.d/phpmyadmin
cat >> /etc/logrotate.d/phpmyadmin << __EOF__
 /opt/phpmyadmin/logs/*.log {
 weekly
 missingok
 rotate 52
 compress
 delaycompress
 notifempty
 create 640 phpmyadmin adm
 sharedscripts
 postrotate
 /etc/init.d/apache2 reload > /dev/null
 endscript
 prerotate
 if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
 run-parts /etc/logrotate.d/httpd-prerotate; \
 fi; \
 endscript
 }
__EOF__
#fi

#log "Install of phpmyadmin : OK"
exit 0
