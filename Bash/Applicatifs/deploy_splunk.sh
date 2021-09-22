#!/bin/bash


if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

generate_password() {
  [[ -z ${1} ]] && PASS_LEN="14" || PASS_LEN=${1}
  echo $(cat /dev/urandom|tr -dc "a-zA-Z0-9\?"|fold -w ${PASS_LEN}|head -1)
}

DEPLOY_SERVER="splunk:8089"
FORWARD_SERVER="splunk:9998"
USERNAME="splunkforwarder"
PASSWORD=$(generate_password "14")


#si l'utilisateur de service splunkforwarder nexiste pas je lajoute en user de service (-r)

id -u ${USERNAME} &>/dev/null || useradd ${USERNAME} -m

#Decompression et modification du proprietaire
tar xvzf /home/ansible/splunkforwarder-8.1.3-63079c59e632-Linux-x86_64.tgz -C /opt

cat >> /opt/splunkforwarder/etc/system/local/user-seed.conf <<_CONF
[user_info]
USERNAME = admin
PASSWORD = ${PASSWORD}
_CONF

chown -R $USERNAME:$USERNAME /opt/splunkforwarder

#creation du service pour démarrer automatiquement splunkforwarder au boot via systemd
/opt/splunkforwarder/bin/splunk enable boot-start -user $USERNAME --accept-license --no-prompt


##Installation à partir de l'archive décompressée et génération de mdp automatique
/opt/splunkforwarder/bin/splunk start --accept-license --auto-ports --no-prompt
/opt/splunkforwarder/bin/splunk set deploy-poll $DEPLOY_SERVER --accept-license --auto-ports --no-prompt -auth admin:$PASSWORD
/opt/splunkforwarder/bin/splunk add forward-server $FORWARD_SERVER

##Changement du mdp par défaut par celui généré
#/opt/splunkforwarder/bin/splunk edit user admin -password $PASSWORD -auth admin:changeme
#/opt/splunkforwarder/bin/splunk restart

#configuration d'un forward-server pour auth.log
#Ajout de la data log
#index : Provide the destination index for events from the input source.
#sourcetype : Provide a sourcetype field value for events from the input source.
/opt/splunkforwarder/bin/splunk add monitor /var/log/ -index linux -sourcetype syslog

##création d'un fichier txt pour récupérer le mdp post-install
echo "${USERNAME} ${PASSWORD}" > pass.txt

exit 0
