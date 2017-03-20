#!/bin/sh

#Description. Script to deploy ocs inventory agent

test=$(whoami)
if [ "${test}" != "root" ]
then
  echo "This script must be run as root"
  exit 1
fi

mkdir /etc/ocsinventory
cat >> /etc/ocsinventory/ocsinventory-agent.cfg << _EOF_
logfile=/var/log/ocsinventory/ocsng.log
tag=tag
server=https://ocs.intuitiv.fr/ocsinventory
basevardir=/var/lib/ocsinventory-agent
debug=1
ssl=0
user=agent
password=ucMzQfNCaKMiR2ig2ZLT
realm=Realm
_EOF_

mkdir /var/log/ocsinventory
touch /var/log/ocsinventory/ocsng.log
##Installation des dépendances
apt-get update --fix-missing
apt-get install dmidecode
apt-get install libxml-simple-perl
apt-get install libcompress-zlib-perl
apt-get install libnet-ip-perl
apt-get install libwww-perl
apt-get install libdigest-md5-perl
apt-get install libnet-ssleay-perl
apt-get install gcc make
##Téléchargement de la bonne version de l'agent

cd /root/
wget https://launchpad.net/ocsinventory-unix-agent/stable-2.1/2.1/+download/Ocsinventory-Unix-Agent-2.1.tar.gz
tar xvf Ocsinventory-Unix-Agent-2.1.tar.gz
cd /root/Ocsinventory-Unix-Agent-2.1/
env PERL_AUTOINSTALL=1 perl Makefile.PL > /dev/null 2&>1
make
make install
ocsinventory-agent

exit 0
