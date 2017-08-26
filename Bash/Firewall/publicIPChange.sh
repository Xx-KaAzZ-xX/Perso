#!/bin/bash

ip1="/tmp/ip1.txt"
ip2="/tmp/ip2.txt"
curl ifconfig.me 2>/dev/null > $ip1

if [ -f $ip2 ]
then
  rm $ip2
fi

while true
do
  before=$(cat $ip1)
  sleep 5
  curl ifconfig.me 2>/dev/null > $ip2
  after=$(cat $ip2)

  if [[ "${before}" != "${after}" ]]
  then
    echo ${after}
    #echo "Nouvelle IP de connexion : ${after}" | mail -s "New Public IP"  al3rte5@gmail.com
  else
    echo "same"
  fi
done

exit 0
