#!/bin/sh
#
# Filename : installModSecurity_nginx.sh
# Version  : 1.0
# Author   : Mathieu Androz / Aurelien Dubus
# Description :
# . Script to launch after compiling Nginx With ModSecurity to activate ModSecurity and import OWASP rules
# . Update module's rules by the latest OWASP modsecurity rules
#   https://github.com/SpiderLabs/owasp-modsecurity-crs/tree/master/activated_rules

# VARIABLES
OWASPGIT='https://github.com/SpiderLabs/owasp-modsecurity-crs'
ModSecurityGIT='https://github.com/SpiderLabs/ModSecurity.git'
Nginx_PATH='/usr/local/nginx'

# Logs file (don't edit it)
LOGFILE="/var/log/backup/bkp.log"

createLogrotate() {
  LOGROTATEDIR="/etc/logrotate.d"
  LOGROTATEFILE="admin"
  if [[ -d ${LOGROTATEDIR} ]]; then
    if [[ ! -f ${LOGROTATEDIR}/${LOGROTATEFILE} ]]; then
      touch ${LOGROTATEDIR}/${LOGROTATEFILE}
      chmod 644 ${LOGROTATEDIR}/${LOGROTATEFILE}
      echo -e "${LOGFILE} {\n\tweekly \
           \n\tmissingok \
           \n\trotate 52 \
           \n\tcompress \
           \n\tdelaycompress \
           \n\tnotifempty \
           \n\tcreate 640 $(id -un) adm
           \n}" > ${LOGROTATEDIR}/${LOGROTATEFILE}
    fi
  fi
}

log() {
  [[ ! -d $(dirname ${LOGFILE}) ]] && mkdir -p $(dirname ${LOGFILE})
  echo "$(date +%Y%m%d-%H:%M:%S) :: " ${1} | tee -a ${LOGFILE}
}


test $(which git) || ( echo "git not found..." && exit 1 )

createLogrotate

##Téléchargement de modsecurity
cd /usr/src
git clone "${ModSecurityGIT}" modsecurity


cp /usr/src/modsecurity/modsecurity.conf-recommended $Nginx_PATH/conf/modsecurity.conf

if [ -f $Nginx_PATH/conf/modsecurity.conf ]; then
  sed -i 's#^SecRuleEngine\(.*\)$#SecRuleEngine On#g' $Nginx_PATH/conf/modsecurity.conf
  # Fix upload max file size at 32M
  sed -i 's#^SecRequestBodyLimit\(.*\)$#SecRequestBodyLimit 32768000#g' $Nginx_PATH/conf/modsecurity.conf
  sed -i 's#^SecRequestBodyInMemoryLimit\(.*\)$#SecRequestBodyInMemoryLimit 32768000#g' $Nginx_PATH/conf/modsecurity.conf
  sed -i 's#^SecResponseBodyAccess\(.*\)$#SecResponseBodyAccess Off#g' $Nginx_PATH/conf/modsecurity.conf
fi


# Get OWASP modsecurity's rules
:<<'com'  
cd /tmp
git clone "${OWASPGIT}"
[[ -d /usr/share/modsecurity-crs ]] && \
  ( mv /usr/share/modsecurity-crs /usr/share/modsecurity-crs.bak && mv /tmp/owasp-modsecurity-crs /usr/share/modsecurity-crs )
( [[ -f /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf.example ]] && [[ ! -f /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf ]] ) && \
  mv /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf.example /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf
ln -s /usr/share/modsecurity-crs/base_rules/*.conf /usr/share/modsecurity-crs/activated_rules/

a2enmod mod-security
service apache2 restart
com

##Importation des règles modsecurity d'OWASP
cd /usr/src/
git clone $OWASPGIT
cd owasp-modsecurity-crs
cp -R base_rules/ $Nginx_PATH/conf/

##Activation de mod_security avec Nginx

sed -i '/gzip/a \#Enable ModSecurity\nModSecurityEnabled on;\nModSecurityConfig modsecurity.conf;\n' $Nginx_PATH/conf/nginx.conf

exit 0
