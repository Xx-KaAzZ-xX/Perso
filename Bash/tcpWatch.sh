#!/bin/bash

## Description : Watch a connection and modify a file if a connection is
## made an alert by email

script="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
port=$2
file="/tmp/connections.txt"
mailAddress=""
if [ -z "$1" ]
then
  echo "Usage : ${script} -p <port> or --port <port>"
fi

case "$1" in
  -h | --help)
    echo "Usage : ${script} -p <port> or --port <port>"
    ;;
  -p | --port)
  ##Surveille les co entrantes , si une ligne est ajoutée , alors modif du file2
    while true; do
      before=$(lsof -i :${port} | grep ESTABLISHED | wc -l)
      sleep 30
      after=$(lsof -i :${port} | grep ESTABLISHED | wc -l)

      #echo "before : $before"
      #echo "after : $after"
      if [[ "$after" -gt "$before" ]]
        then
          echo "Connexion sur le port ${port} le" `date` | mail -s "TCP Connection"  al3rte5@gmail.com
          wall New Connection
fi

done
    ;;
esac

exit 0

