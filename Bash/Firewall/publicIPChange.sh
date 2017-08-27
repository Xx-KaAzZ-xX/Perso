#!/bin/bash

while true
do

  ip1="/tmp/ip1.txt"
  ip2="/tmp/ip2.txt"
  curl -s ifconfig.me  > $ip1
  before=$(cat $ip1)
  sleep -m 60
  curl -s ifconfig.me > $ip2
  after=$(cat $ip2)

  if [[ "${before}" != "${after}" ]]
  then
    echo "Nouvelle IP de connexion : ${after}" | mail -s "New Public IP"  al3rte5@gmail.com
  fi

done

exit 0
