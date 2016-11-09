#!/bin/bash


##Description : . Torify all the output trafic for a user

if [ -z "${1}" ]
then
 echo "Usage : ./torify_apps.sh username"
 else

echo 'nameserver 127.0.0.1' > /etc/resolv.conf

### set variables
_tor_uid=$(/etc/init.d/tor status | grep Main | awk '{print $3}')
_out_if="eth0"
_trans_port="9040"
_dns_port="5353"
_non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
ssh_port="6622"
#TorVirtualAddrNetworkIPv4
_virt_addr="10.192.0.0/10"
username="${1}"

if [ -z "${_tor_uid}" ]
then
  _tor_uid=$(ps -aux | grep /usr/bin/tor | sed -n 1p | awk '{printf $2}')
fi

iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner ${username} -m tcp --syn -j REDIRECT --to-ports 9040
iptables -t nat -A OUTPUT -p udp -m owner --uid-owner ${username} -m udp --dport 53 -j REDIRECT --to-ports 5353
iptables -t filter -A OUTPUT -p tcp -m owner --uid-owner ${username} -m tcp --dport 9040 -j ACCEPT
iptables -t filter -A OUTPUT -p udp -m owner --uid-owner ${username} -m udp --dport 5353 -j ACCEPT
iptables -t filter -A OUTPUT ! -o lo -m owner --uid-owner ${username} -j DROP
##Test
su - ${username} -c "nslookup google.fr" > /dev/null  2>&1
test=$(echo $?)

if [ $test -eq 0 ]
then
  echo "Connection to Tor Network: Done"
  echo "Think to run apps as user ${username}"
  echo "You could ./undo & ./torIptables.sh after this worked"
else
  echo "No Connection to Tor Network"
fi

fi

exit 0
