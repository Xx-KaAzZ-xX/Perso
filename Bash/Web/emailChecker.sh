#!/bin/bash

#.  Description : Shell script to check in a list of emails if adresses exists without sending emails
#.  Author:   Aurélien DUBUS
#.  Version : 1.1

results="/tmp/results.txt"
exist="/tmp/exist.txt"
notExist="/tmp/notExist.txt"
others="/tmp/others.txt"
smtpOK="250"
smtpNotOK="550"

usage() {
  script_name=$(basename $0)
  echo -e "Exemple : ./${script_name} -f emails.txt"

}

if [ -f ${exist} ] || [ -f ${notExist} ] || [ -f ${others} ] || [ -f ${results} ]; then
  rm $exist $notExist $others $results
fi

if [ -z "$1" ];then
  usage
fi

while getopts ":f:" opt; do
  case $opt in
    f | file) file="$OPTARG"
    if [ -z "${file}" ];then
      usage
    fi

    cat ${file} | while read line
    do
      domainName=$(echo $line | awk -F "@" '{print $2}')
      mxServ=$(dig +short ${domainName} MX | awk '{print $2}' | head -n 1)
     (
      sleep 1
      echo "ehlo gmail.com"
      sleep 1
      echo "MAIL FROM:<al3rte5@gmail.com>"
      sleep 1
      echo "RCPT TO:<$line>"
      sleep 1
      echo "QUIT") | telnet $mxServ 25 >> $results

      servResponse=$(tac $results | head -n 1 | awk '{print $1}')
      mailExists=$(echo "${servResponse}" | grep "$smtpOK")
      mailNotExists=$(echo "${servResponse}" | grep "$smtpNotOK")
      if [ ! -z ${mailExists} ]; then
        echo "$line exists " >> ${exist}
      elif [ ! -z ${mailNotExists} ]; then
        echo "$line doesn't exists " >> ${notExist}
      else
        echo $line >> ${others}
      fi

    done
    exit 0
    ;;
  \? )
    usage
    ;;
  * ) 
    usage
    ;;
  esac
done

exit 0

