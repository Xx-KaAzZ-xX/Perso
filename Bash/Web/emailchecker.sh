#!/bin/bash

#.  Description : Shell script to check in a list of emails if adresses exists without sending emails
#.  Version : 1.0


#file="/root/mails.txt"
results="/tmp/results.txt"
finalResults="/tmp/finalResults"
smtpOK="250"
smtpNotOK="550"

usage() {
  script_name=$(basename $0)
  echo -e "Exemple : ./${script_name} -f emails.txt"

}

if [ -z "$1" ];then
  usage
fi

while getopts ":f:" opt; do
  case $opt in
    f | file) file="$OPTARG"

    cat ${file} | while read line
    do
      domainName=$(echo $line | awk -F "@" '{print $2}')
      mxServ=$(dig +short ${domainName} MX | awk '{print $2}' | head -n 1)
     (
      sleep 1
      echo "ehlo test"
      sleep 1
      echo "MAIL FROM:<al3rte5@gmail.com>"
      sleep 1
      echo "RCPT TO:<$line>"
      sleep 1
      echo "QUIT") | telnet $mxServ 25 > $results

      servResponse=$(tac $results | head -n 1 | awk '{print $1}')
      mailExists=$(echo "${servResponse}" | grep "$smtpOK")
      if [ ! -z ${mailExists} ]; then
        echo "$line exists " >> ${finalResults}
      else
        echo "$line doesn't exists " >> ${finalResults}
      fi

    done
  esac
done

exit 0
