#!/bin/bash

##Check if necessary packages are installed
dpkg -s tor &>/dev/null || apt-get install tor &>/dev/null
dpkg -s apache2 &>/dev/null || apt-get install apache2 &>/dev/null

##Change config file for hidden service
sed -i 's/#HiddenServiceDir \/var\/lib\/tor\/hidden_service\//HiddenServiceDir \/var\/lib\/tor\/hidden_service\//g' /etc/tor/torrc  
sed -i 's/#HiddenServicePort 80 127.0.0.1:80/HiddenServicePort 80 127.0.0.1:8080/g' /etc/tor/torrc

systemctl restart tor

##Retrieve hostname
hostname=$(cat /var/lib/tor/hidden_service/hostname)
echo "This is your hidden hostname : $hostname"

exit 0
