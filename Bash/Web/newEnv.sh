#!/bin/bash

# Filename : newEnv.sh
# Version  : 1.1
# Author   : Aurélien Dubus
# Contrib  :
# Description : Créer un nouvel utilisateur avec Vhost ( Nginx / Apache), pool fpm , espace FTP (si package installé),
#               génère une paire de clés SSH  et nouvel utilisateur SQL + nouvelle BDD


if [[ ! -d "/root/scripts" ]]; then
  log "Please execute firstinstall.sh script before this one. Aborted..."
  exit 1
fi

generate_password() {
  [[ -z ${1} ]] && PASS_LEN="15" || PASS_LEN=${1}
  echo $(cat /dev/urandom|tr -dc "a-zA-Z0-9\?"|fold -w ${PASS_LEN}|head -1)
}

unix_passwd=$(generate_password "15")
sql_passwd=$(generate_password "15")
machineName=$(cat /etc/hostname)

##Variables
read -p "Entrer le nom de l'utilisateur : " username
#Concaténation username + web
#userPool="${username}${username2}"
infoFile="/root/$username.info"
[[ -f ${infoFile} ]] && echo "A UNIX user should already exist with this name. Aborted." && echo exit 1

read -p "Renseigner URL: "  url

echo -e "Quel est le serveur Web :\n"

select choice in Apache Nginx
do
  case $choice in
    Apache)
      servWeb=1
      break
      ;;
    Nginx)
      servWeb=2
      break
      ;;
    *) echo "Choisir entre Apache et Nginx";;
  esac
done

echo "Choisir le format de DB"
select choiceDB in Utf8 Utf8mb4
do
  case $choiceDB in
    Utf8)
      DB=1
      break
      ;;
    Utf8mb4)
      DB=2
      break
      ;;
    *) echo "Choisir entre Utf8 et Utf8mb4";;
  esac
done


##Création de l'arborescence
useradd -m -s /bin/bash ${username}
echo "${username}:${unix_passwd}" | chpasswd

mkdir /home/$username/{www,tmp,logs,sessions,.socks,cgi-bin}
chown -R $username:$username /home/$username/{www,tmp,logs,sessions,.socks,cgi-bin}

case $servWeb in
  1*)
    echo -e "Création du nouveau Vhost pour Apache\n"

## Conf file to apply according to Apache version
version=$(apache2 -v | grep version | awk {'print $3'} | awk -F / {'print $2'} | awk -F . {'print $2'})
if [ "$version" -ne "4" ]
then
  cat >> /etc/apache2/sites-available/${url} << _END1_
<VirtualHost *:80>
    ServerAdmin ${machineName}@intuitiv.fr

    ServerName  ${url}

    RewriteEngine on
    #RewriteCond %{HTTPS} !on
    #RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}

    #RewriteCond %{HTTP_HOST} ^cc-genevois.fr [OR]
    #RewriteCond %{HTTP_HOST} ^(www\.)?${username}.org [OR]
    #RewriteCond %{HTTP_HOST} ^(www\.)?ville-${username}.(fr|com|org|eu) [OR]
    #RewriteCond %{HTTP_HOST} ^(www\.)?mairie-${username}.(com|org|fr)
    #RewriteRule ^(.*)$ http://${url}\$1 [L,R=301]

    DocumentRoot /home/${username}/www/
    <Directory /home/${username}/www/>
      #<IfModule security2_module>
      #   SecRuleEngine Off
      #</IfModule>
        Options -Indexes FollowSymLinks MultiViews
        AllowOverride All
        Order allow,deny
        Allow from all
        #AuthType Basic
        #AuthName "Restricted Area ${username} : please login"
        #AuthUserFile /home/${username}/.htpasswd
        #Require valid-user
        #Order deny,allow
        #Deny from env=Blacklist
        #Allow from env=Whitelist
    </Directory>

    Redirect 404 /favicon.ico
    <Location /favicon.ico>
        ErrorDocument 404 "No favicon"
    </Location>

  # Clear PHP settings of this website
  <FilesMatch ".+\.ph(p[345]?|t|tml)\$">
    SetHandler None
  </FilesMatch>
  <IfModule mod_fastcgi.c>
    <Directory /home/${username}/cgi-bin>
      Order allow,deny
      Allow from all
    </Directory>
    <FilesMatch "\.php[345]?\$">
      SetHandler php5-fcgi
    </FilesMatch>
    Action php5-fcgi /php5-fcgi
    Alias /php5-fcgi /home/${username}/cgi-bin/php5-fcgi-*-80
    FastCgiExternalServer /home/${username}/cgi-bin/php5-fcgi-*-80 -idle-timeout 300 -socket /home/${username}/.socks/${username}.sock -pass-header Authorization
  </IfModule>

    # Path of private php.ini
    #PHPINIDir /home/${username}/config

    ErrorLog /home/${username}/logs/error.log
    LogLevel warn
    CustomLog /home/${username}/logs/access.log combined
    ServerSignature Off
</VirtualHost>
_END1_

else
  cat >> /etc/apache2/sites-available/${url}.conf << _END2_
<VirtualHost *:80>

    ServerAdmin noreply@${machineName}.itserver.fr
    ServerName ${url}

    RewriteEngine on
    #RewriteCond %{HTTPS} !on
    #RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}

    #RewriteCond %{HTTP_HOST} ^${username}.fr [OR]
    #RewriteCond %{HTTP_HOST} ^(www\.)?${username}.org [OR]
    #RewriteCond %{HTTP_HOST} ^(www\.)?ville-${username}.(fr|com|org|eu) [OR]
    #RewriteCond %{HTTP_HOST} ^(www\.)?mairie-${username}.(com|org|fr)
    #RewriteRule ^(.*)$ http://www.${username}.fr\$1 [L,R=301]

    DocumentRoot /home/${username}/www/
    <Directory /home/${username}/www/>
      #<IfModule security2_module>
      #   SecRuleEngine Off
      #</IfModule>
        Options -Indexes +FollowSymLinks +MultiViews
        Require all granted
        #AuthType Basic
        #AuthName "Restricted Area ${username} : please login"
        #AuthUserFile /home/${username}/.htpasswd
        #Require valid-user
        #Order deny,allow
        #Deny from env=Blacklist
        #Allow from env=Whitelist
    </Directory>

    Redirect 404 /favicon.ico
    <Location /favicon.ico>
        ErrorDocument 404 "No favicon"
    </Location>

  # Clear PHP settings of this website
  <FilesMatch ".+\.ph(p[345]?|t|tml)\$">
    SetHandler None
  </FilesMatch>
  <IfModule mod_fastcgi.c>
    <Directory /home/${username}/cgi-bin>
      #Order allow,deny
      #Allow from all
      Require all granted
    </Directory>
    <FilesMatch "\.php[345]?\$">
      SetHandler php5-fcgi
    </FilesMatch>
    Action php5-fcgi /php5-fcgi
    Alias /php5-fcgi /home/${username}/cgi-bin/php5-fcgi-*-80
    FastCgiExternalServer /home/${username}/cgi-bin/php5-fcgi-*-80 -idle-timeout 300 -socket /home/${username}/.socks/${username}.sock -pass-header Authorization
  </IfModule>

    # Path of private php.ini
    #PHPINIDir /home/${username}/config

    ErrorLog /home/${username}/logs/error.log
    LogLevel warn
    CustomLog /home/${username}/logs/access.log combined
    ServerSignature Off
</VirtualHost>
_END2_
fi
;;

  2*)
    echo -e "Création du Vhost pour Nginx\n"
if [ ! -f /etc/nginx/sites-available/${url} ]
then
  cat >> /etc/nginx/sites-available/${url} << _END3_
# Redirection to principal domain name
# & www. management
#server {
#    listen 80;
#    server_name toto.com titi.com;
#    return 301 http://${url}\$request_uri;
#}

server {

    listen 80;
    server_name ${url};

    # SSL configuration
    #
    # listen 443 ssl default_server;
    # listen [::]:443 ssl default_server;
    #
    # Self signed certs generated by the ssl-cert package
    # Don't use them in a production server!
    #
    # include snippets/snakeoil.conf;


    ## DocumentRoot
    root /home/${username}/www;

    ## Htpasswd
    #auth_basic "Restricted";
    #auth_basic_user_file /home/${username}/.htpasswd;


    ## Access and error logs.
    access_log /home/${username}/logs/access.log;
    error_log /home/${username}/logs/error.log;


    # Add index.php to the list if you are using PHP
    index index.php index.html index.htm index.nginx-debian.html;


    ## serve imagecache files directly or redirect to drupal if they do not exist.
    location ~* files/styles {
        access_log off;
        expires 30d;
        try_files \$uri @drupal;
    }

    ## serve imagecache files directly or redirect to drupal if they do not exist.
    location ~* ^.+.(xsl|xml)$ {
        access_log off;
        expires 1d;
        try_files \$uri @drupal;
    }

    ## Default location
    location / {
        try_files \$uri \$uri/ @drupal;
        index  index.php;
    }

    # Don't allow direct access to PHP files in the vendor directory.
    location ~ /vendor/.*\.php$ {
        deny all;
        return 404;
    }

    location @drupal {
        rewrite ^/(.*)\$ /index.php?q=\$1 last;
    }

    ## Images and static content is treated different
    location ~* ^.+.(jpg|jpeg|gif|css|png|js|ico|xml)$ {
        access_log off;
        expires 30d;
        add_header Pragma public;
        add_header Cache-Control "public, must-revalidate, proxy-revalidate";
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        # With php5-cgi alone:
        # fastcgi_pass 127.0.0.1:9000;
        # # With php5-fpm:
        fastcgi_pass unix:/home/${username}/.socks/${username}.sock;
        include fastcgi_params;
        # Custom conf
        fastcgi_split_path_info ^(.+\.php)(.*)$;
        #fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
        fastcgi_param  SCRIPT_NAME      \$fastcgi_script_name;
        fastcgi_param  QUERY_STRING     \$query_string;
        fastcgi_param  REQUEST_METHOD   \$request_method;
        fastcgi_param  CONTENT_TYPE     \$content_type;
        fastcgi_param  CONTENT_LENGTH   \$content_length;
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
    }
    location ~ /\.git {
        deny all;
    }
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location ~ ^/sites/.*/private/ {
        return 403;
    }

    # Allow "Well-Known URIs" as per RFC 5785
    location ~* ^/.well-known/ {
        allow all;
    }

    # Block access to "hidden" files and directories whose names begin with a
    # period. This includes directories used by version control systems such
    # as Subversion or Git to store control files.
    location ~ (^|/)\. {
        return 403;
    }
}
_END3_
fi
;;
esac

echo -e "Création du logrotate\n"

if [ -f /etc/logrotate.d/nginx ]
then
cat >> /etc/logrotate.d/nginx << _EOF_
/home/${username}/logs/*.log {
        weekly
        missingok
        rotate 52
        compress
        delaycompress
        notifempty
        create 0640 root root
        sharedscripts
        prerotate
                if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
                        run-parts /etc/logrotate.d/httpd-prerotate; \
                fi \
        endscript
        postrotate
                invoke-rc.d nginx rotate >/dev/null 2>&1
        endscript
}
_EOF_
fi

echo -e "Création du pool FPM\n"
if [ ! -f /etc/php5/fpm/pool.d/${username}.conf ]
then
  cat >>  /etc/php5/fpm/pool.d/${username}.conf << _EOF_
[${username}]

; Per pool prefix
; It only applies on the following directives:
; - 'slowlog'
; - 'listen' (unixsocket)
; - 'chroot'
; - 'chdir'
; - 'php_values'
; - 'php_admin_values'
; When not set, the global prefix (or /usr) applies instead.
; Note: This directive can also be relative to the global prefix.
; Default Value: none
;prefix = /path/to/pools/\${username}

; Unix user/group of processes
; Note: The user is mandatory. If the group is not set, the default user's group
;       will be used.
user = \$pool
group = \$pool

listen = /home/${username}/.socks/${username}.sock

;listen.backlog = 128

listen.owner = www-data
listen.group = www-data
;listen.mode = 0660

listen.allowed_clients = 127.0.0.1

; Specify the nice(2) priority to apply to the pool processes (only if set)
; The value can vary from -19 (highest priority) to 20 (lower priority)
; Default Value: no set
; priority = -19

pm = dynamic

pm.max_children = 20
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 10
; Note: Used only when pm is set to 'ondemand'
;pm.process_idle_timeout = 10s;

; The number of requests each child process should execute before respawning.
; Default Value: 0
;pm.max_requests = 500

; This directive may be used to customize the response of a ping request. The
; Default Value: pong
;ping.response = pong

; The access log file
; Default: not set
;access.log = log/\${username}.access.log

; The access log format.
; Default: "%R - %u %t \"%m %r\" %s"
;access.format = "%R - %u %t \"%m %r%Q%q\" %s %f %{mili}d %{kilo}M %C%%"

; The log file for slow requests
; Default Value: not set
;slowlog = log/\${username}.log.slow
;request_slowlog_timeout = 0

;request_terminate_timeout = 0

; Set open file descriptor rlimit.
; Default Value: system defined value
;rlimit_files = 1024

; Set max core size rlimit.
; Possible Values: 'unlimited' or an integer greater or equal to 0
; Default Value: system defined value
;rlimit_core = 0

;chroot =

; Chdir to this directory at the start.
; Note: relative path can be used.
; Default Value: current directory or / when chroot
chdir = /

;catch_workers_output = yes

; Pass environment variables like LD_LIBRARY_PATH. All \$VARIABLEs are taken from
; the current environment.
; Default Value: clean env
;env[HOSTNAME] = \$HOSTNAME
;env[PATH] = /usr/local/bin:/usr/bin:/bin
;env[TMP] = /tmp
;env[TMPDIR] = /tmp
;env[TEMP] = /tmp

php_admin_value[open_basedir] = /home/${username}/www:/home/${username}/tmp:/home/${username}/sessions:/usr/share/php5:/usr/share/php:/tmp
php_admin_value[session.save_path] = /home/${username}/sessions
php_admin_value[upload_tmp_dir] = /home/${username}/tmp
;php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f contact@ovm08.itserver.fr

;;; Gestion des erreurs
; Affichage des erreurs
php_flag[display_errors] = off
; Log des erreurs
php_admin_value[error_log] = /home/${username}/logs/fpm-php.log
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

; Liste of authorized extensions with php-fpm
security.limit_extensions = .php .php5 .php3 .php4 .html .htm
_EOF_
fi

##test root SQL Password

read -s -p "Enter MYSQL root password: " mysqlRootPassword

while ! mysql -u root -p$mysqlRootPassword  -e ";" ; do
        read -s -p "Can't connect, please retry: " mysqlRootPassword
done


## Création BDD et USER

if [ $DB -eq 1 ]
then
  Q1="CREATE DATABASE IF NOT EXISTS ${username} CHARACTER SET utf8;"
  Q2="CREATE USER '${username}'@'localhost' IDENTIFIED BY '${sql_passwd}';"
  Q3="GRANT ALL PRIVILEGES ON ${username}.* TO '${username}'@'localhost';"
  Q4="FLUSH PRIVILEGES;"
  SQL="${Q1}${Q2}${Q3}${Q4}"
  mysql -u root -p$mysqlRootPassword -e "${SQL}"
elif [ $DB -eq 2 ]
then
  Q1="CREATE DATABASE IF NOT EXISTS ${username} CHARACTER SET utf8mb4;"
  Q2="CREATE USER '${username}'@'localhost' IDENTIFIED BY '${sql_passwd}';"
  Q3="GRANT ALL PRIVILEGES ON ${username}.* TO '${username}'@'localhost';"
  Q4="FLUSH PRIVILEGES;"
  SQL="${Q1}${Q2}${Q3}${Q4}"
  mysql -u root -p$mysqlRootPassword -e "${SQL}"
fi

##Création espace FTP
if [ ! -f /etc/pure-ftpd/db/mysql.conf ]
then
  echo "Le package pure-ftpd-mysql ne semble pas être installé"

else
  chmod 700 /root/scripts/Shell/web/ftp/createFtpUserWithQuota.sh && /root/scripts/Shell/web/ftp/createFtpUserWithQuota.sh
fi

if [ -d /home/${username}/www/sites/default/files ]
then
  echo "Changement de permission de /default/files"
  chown -R ${username}:${username} /home/${username}/www/sites/default/files
fi

##Création des ACL
:<<'COM'
if [ ! -f /root/aclFiles.lst ] || [ ! -f /root/aclLogs.lst ]
then
  cat >> /root/aclFiles.lst << _EOF_
  user::rwx
  user:${username}:rwx
  group::r-x
  other:r--
  default:user:${userPool}:rwx
  default:group::r-x
_EOF_


cat >> /root/aclLogs.lst << _EOF_

  user::rwx
  user:${userPool}:rwx
  group::r-x
  other:r--
  default:user:${username}:rwx
  default:group::r-x
_EOF_

echo "Activation des ACL sur les dossiers /logs /tmp /sessions"
setfacl -M /root/aclLogs.lst /home/${username}/{tmp,logs,sessions}
else
  echo "Les fichiers d'ACL ont déjà été créés"
fi
COM

##SSH-Keygen

runuser -l $username -c 'ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa'


/etc/init.d/php5-fpm restart

echo "----------------------------------------------------

  New informations about ${url} environnement :

      UNIX username     : ${username}
      UNIX password     : ${unix_passwd}
      USER FPM          : ${username}

      SQL username      : ${username}
      SQL Database      : ${username}
      SQL password      : ${sql_passwd}

----------------------------------------------------" | tee ${infoFile}
echo ""
echo "[INFO] Vhost will have to be activated"
#echo "[INFO] ACL will have to be set"

read -p "Press enter when you have saved all informations"

echo "Informations have been saved in ${infoFile}.
Do you want to delete it ?"

select delete in Yes No
do
  case $delete in
    Yes)
      rm ${infoFile} && break
    ;;
    No)
      break
    ;;
    *)
      echo "Do you want to delete it ? (Yyes/No)"
    ;;
  esac
done

exit 0
