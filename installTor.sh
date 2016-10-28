#!/bin/bash

version=$(lsb_release -c | awk '{printf $2}')
echo "deb http://deb.torproject.org/torproject.org $version main " > /etc/apt/sources.list

gpg --keyserver keys.gnupg.net --recv 886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add --
apt-get update
apt-get install deb.torproject.org-keyring
apt-get install tor

echo 'nameserver 127.0.0.1' > /etc/resolv.conf

exit 0
