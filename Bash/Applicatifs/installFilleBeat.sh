#!/bin/bash


echo "Filebeat installation..."

##Installation
#wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
#apt-get install apt-transport-https
#echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list
#apt-get update && apt-get install filebeat
#update-rc.d filebeat defaults 95 10
#
##Configuration

Nginx=$(netstat -paunt | grep 80 | grep nginx)
Apache=$(netstat -paunt | grep 80 | grep apache)

if [[ -n "$Nginx" ]]; then
    echo "Nginx listening"

elif [[ -n "$Apache" ]]; then
      echo "Apache listening"
fi

##Rajouter ce bloc dans /etc/init.d/firewall des servs en prod
:<<COM
logstash_connexion() {

        iptables -t filter -A INPUT -p tcp --dport 5044 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 5044 -j ACCEPT

        echo "Autorisation des connexions Logstash : [OK]"
}
COM


exit 0
