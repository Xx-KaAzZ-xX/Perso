#!/bin/bash

## Description : Watch a connection and modify a file if a connection is
## made an alert by email

script="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
port=$2
echo "${port}"
file="/tmp/connections.txt"
file2="/tmp/test.txt"

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

      echo "before : $before"
      echo "after : $after"
      if [[ "$after" -gt "$before" ]]
        then
        "body of your email" | mail -s "This is a Subject" -a "From: you@example.com" recipient@elsewhere.com
fi

done
    ;;
esac

exit 0

