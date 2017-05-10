#!/bin/bash

#.  Description : Shell script to check if  an email adress exists without sending emails
#.  Author:   Aurélien DUBUS
#.  Version : 1.0


file="/root/mails.txt"
telnetCommands="/tmp/telnetCommands.txt"
results="/tmp/results.txt"
finalResults="/tmp/finalResults"
smtpOK="250"
smtpNotOK="550"

cat ${file} | while read line
do
  domainName=$(echo $line | awk -F "@" '{print $2}')
  mxServ=$(dig +short ${domainName} MX | awk '{print $2}' | head -n 1)
  :<<COM
  telnet ${mxServ} 25 << _EOF_
  ehlo test
  mail from:<al3rte5@gmail.com>
  rcpt to:<$line>
  QUIT
_EOF_
COM
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

exit 0
