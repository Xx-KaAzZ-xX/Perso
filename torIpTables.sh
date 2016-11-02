#!/bin/bash

echo 'nameserver 127.0.0.1' > /etc/resolv.conf

### set variables
_tor_uid=$(/etc/init.d/tor status | grep Main | awk '{print $3}')
_out_if="eth0"
_trans_port="9040"
_dns_port="53"
_non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

if [ -z "${_tor_uid}" ]
then
  _tor_uid=$(ps -aux | grep /usr/bin/tor | sed -n 1p | awk '{printf $2}')
fi

iptables -F
iptables -t nat -F
### set iptables *nat
iptables -t nat -A OUTPUT -m owner --uid-owner $_tor_uid -j RETURN
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 22
#allow clearnet access for hosts in $_non_tor
for _clearnet in $_non_tor 127.0.0.0/9 127.128.0.0/10; do
  iptables -t nat -A OUTPUT -d $_clearnet -j RETURN
done

#redirect all other output to Tor’s TransPort
iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $_trans_port

### set iptables *filter
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#allow clearnet access for hosts in $_non_tor
for _clearnet in $_non_tor 127.0.0.0/8; do
  iptables -A OUTPUT -d $_clearnet -j ACCEPT
done

#allow only Tor output
iptables -A OUTPUT -m owner --uid-owner $_tor_uid -j ACCEPT
iptables -A OUTPUT -j REJECT

##Test
nslookup google.fr > /dev/null  2>&1
test=$(echo $?)

if [ $test -eq 0 ]
then
  echo "Connection to Tor Network: Done"
else
  echo "No Connection to Tor Network"
fi

exit 0
