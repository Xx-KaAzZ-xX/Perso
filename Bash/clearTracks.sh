#!/bin/bash

#.  Description : Script to clear all tracks on a Linux Machine
#.  mode bourrin -b qui clear tout et -s "subtil way"

usage() {

  script_name=$(basename $0)
  echo -e "This is the list of available options: "
  echo -e "\t  -b : The brutal way of clearing logs."
  echo -e "\t  -s : The subtil way of clearing logs."
}

brutal_way() {
echo "Clearing all logs..."
rm /root/.bash_history
}

subtil_way() {
echo "subtil way"
}

if [ -z ${1} ]
then
  usage
fi

while getopts "bs" opt; do
  case $opt in
    b) brutal_way
      ;;
    s) subtil_way
      ;;
  esac
done

exit 0
