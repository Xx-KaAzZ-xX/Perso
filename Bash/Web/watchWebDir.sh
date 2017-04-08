#!/bin/bash

usage() {
 script_name=$(basename $0)
   echo -e "Usage : ./${script_name} /home/user/www"
}

if [ -z "${1}" ]
then
  usage
fi

while true; do

  inotifywait -e modify,create,delete -r $1 && \
    ##Put an alert command here
    <some command to execute when a file event is recorded>

done

exit 0
