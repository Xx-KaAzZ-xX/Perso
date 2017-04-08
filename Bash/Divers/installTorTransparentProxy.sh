#!/bin/bash

version=$(lsb_release -c | awk '{printf $2}')
echo "deb http://deb.torproject.org/torproject.org $version main " > /etc/apt/sources.list

gpg --keyserver keys.gnupg.net --recv 886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add --
apt-get update
apt-get install deb.torproject.org-keyring
apt-get install tor

echo 'nameserver 127.0.0.1' > /etc/resolv.conf

### set variables
#destinations you don’t want routed through Tor
_non_tor='192.168.1.0/24 192.168.0.0/24'
#the UID that Tor runs as (varies from system to system)
_tor_uid='136'

#Tor’s TransPort
_trans_port='9040'

### flush iptables
iptables -F
iptables -t nat -F
### set iptables *nat
iptables -t nat -A OUTPUT -m owner --uid-owner $_tor_uid -j RETURN
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53

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
