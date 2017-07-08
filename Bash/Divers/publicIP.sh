#!/bin/bash


IP=$(curl ifconfig.me)
file1="/tmp/publicIP"
file2="/tmp/publicIP2"

echo $IP > $file1

if [ -f "${file1}" ]; then
  echo $IP > $file2
  diff $file1 $file2
  test=$(echo $?)
  if [ "${test}" -eq 0 ]; then
    :    
  else
    echo $IP > $file1 && rm $file2
    echo "La nouvelle IP de la boxe : ${IP}" | mail -s "Changement IP de la box" -a "From: al3rte5@gmail.com" al3rte5@gmail.com
  fi
fi


exit 0
