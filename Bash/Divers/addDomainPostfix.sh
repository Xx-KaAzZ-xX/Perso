#!/bin/bash


usage(){
  filename=$(basename "$0")
  echo -e "Usage : ${filename} example.com "
      }

if [ -z ${1} ]
then
  usage
fi

##Définition des variables
opendkim_dir="/etc/opendkim/"
postfix_dir="/etc/postfix"

saslpasswd2 -u itserver.fr ${1}

mkdir ${dir}/keys/${1}
cd ${opendkim_dir}/keys/${1}
opendkim-genkey -s it -d ${1}
chown -R opendkim:opendkim ${opendkim_dir}/keys/${1}/
echo "it._domainkey.${1} itserver.fr:it:/etc/opendkim/keys/${1}/it.private" >> ${opendkim_dir}/key.table
echo "*@${1} it._domainkey.${1}" >> ${opendkim_dir}/signing.table
echo -e "${1} \t PERMIT" >> ${postfix_dir}/allowed_domains

##Application des modifications
postmap ${postfix_dir}/allowed_domains
/etc/init.d/postfix reload
/etc/init.d/opendkim reload

dkim_key=$(cat ${dir}/keys/${1}/it.txt | grep -oP '(?<=").*(?=")')

echo "Think to create the it_domainkey.${1} with this value :
      ${dkim_key}"


exit 0
