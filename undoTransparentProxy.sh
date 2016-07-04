#!/bin/bash

iptables -F
iptables -t nat -F

echo -e 'nameserver 208.67.222.222\nnameserver 208.67.220.220' > /etc/resolv.conf

/etc/init.d/tor restart

exit 0
