#!/bin/bash

messages_id=$(cat /var/log/mail.log | grep status=bounced | awk '{print $6}' | sed 's/://')
nbBounced=$(cat /var/log/mail.log | grep status=bounced | wc -l)
file="/tmp/messages_id.txt"
senders="/tmp/senders.txt"
log_file="/tmp/bounces.log"
final_file="/root/bounces.log"
date=$(date | awk '{NF=4; print}') #On récup la date en format syslog
hostname=$(cat /etc/hostname)

##Effacer les fichiers laissés par l'exécution précédente
[ -e ${file} ] && rm ${file}
[ -e ${senders} ] && rm ${senders}
[ -e ${log_file} ] && rm ${log_file}
[ -e ${final_file} ] && rm ${final_file}

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
  echo -e "${line} \t ${occurences} \t \t ${stats}%" >> ${log_file}
done

:<<'COM'
echo "Rapport de bounce du ${date_debut} au ${date_fin}" > ${final_file}
echo -e "--------------------------------------------------------------|
        Adresses \t Nombre de Bounces \t Pourcentage  |" >> ${final_file}
echo -e "--------------------------------------------------------------|" >> ${final_file}
COM
nbBouncePerDomain=$(cat ${log_file} | sort -u > /tmp/nawak.txt)
cat /tmp/nawak.txt | while read line
do

#Formatage du fichier comme syslog
echo -e "${date} \t ${hostname} postfix/local [] ${line}" >> ${final_file}
done

exit 0
