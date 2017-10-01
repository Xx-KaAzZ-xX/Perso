#!/bin/bash


before=$(dig +short myip.opendns.com @resolver1.opendns.com)
sleep 60m
after=$(dig +short myip.opendns.com @resolver1.opendns.com)
if [[ -z "${after}" ]];then
  exit 1
elif [[ "${before}" != "${after}" ]]
then
  echo "Nouvelle IP de connexion : ${after}" | mail -s "New Public IP"  al3rte5@gmail.com
fi

exit 0
