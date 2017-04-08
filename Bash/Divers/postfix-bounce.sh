#!/bin/bash

messages_id=$(cat /var/log/mail.log | grep status=bounced | awk '{print $6}' | sed 's/://')
nbBounced=$(cat /var/log/mail.log | grep status=bounced | wc -l)
file="/tmp/messages_id.txt"
senders="/tmp/senders.txt"
log_file="/tmp/bounces.log"
tmp1="/tmp/tmp1.txt"
tmp2="/tmp/tmp2.txt"
final_file="/root/bounces.log"

##Effacer les fichiers laissés par l'exécution précédente
[ -e ${file} ] && rm ${file}
[ -e ${senders} ] && rm ${senders}
[ -e ${log_file} ] && rm ${log_file}
[ -e ${tmp1} ] && rm ${tmp1}
[ -e ${tmp2} ] && rm ${tmp2}
[ -e ${final_file} ] && rm ${final_file}

##Error handling , on arrête le script si $messages_id est vide
if [ -z "${messages_id}" ]
then
  exit 1
fi

echo -e "${messages_id}\n" > ${file}

sed  '/^$/d' ${file} > /tmp/tmp.txt && mv /tmp/tmp.txt ${file}
##On récupère les NDD qui bounce
cat ${file} | while read line
do
  sender_address=$(cat /var/log/mail.log | grep $line | grep -oP '(?<=from=<).*?(?=>)' | tail -n 1)
  echo ${sender_address} >> ${senders}
done

sed  '/^$/d' ${senders} > /tmp/tmp.txt && mv /tmp/tmp.txt ${senders}

##Compteur de bounces par NDD
cat ${senders} | while read line
do

  occurences=$(grep -c "${line}" ${senders})
  stats=$(echo "scale=2; ${occurences}/${nbBounced} * 100" | bc)
  echo -e "${line}: ${occurences} bounces - ${stats}%" >> ${log_file}
done

nbBouncePerDomain=$(cat ${log_file} | sort -u > ${tmp1})

#Formatage du fichier comme syslog
cat ${tmp1} | logger -t BOUNCESTEST -i -s 2>&1 | tee -a ${tmp2}
id=$(cat ${tmp2} | cut -d "[" -f2 | cut -d "]" -f1 | head -n 1)
id="BOUNCESTEST\[${id}\]"
grep -w "${id}" /var/log/syslog > ${final_file}

exit 0
