#!/bin/bash
#
# Filename : deb8install.sh
# Version  : 1.0
# Author   : Aurélien DUBUS
# Description :
#  .    Script to manage some stuff on differents DB server
#  .
#


usage() {
  script_name=$0
  echo "Example: ${script_name} -u user"
} 
                                           

if [ -z "${0}" ]; then
  usage
fi

db_detect() {
mysql=$(pgrep mysql | wc -l)
mariadb=$(pgrep mariadb | wc -l)
postgres=$(pgrep postgres | wc -l)

if [ "${mysql}" -ge 1 ]; then
  echo "MySQL server detected"
  db_server="mysql"
elif [ "${mariadb}" -ge 1 ]; then
  echo "MariaDB server detected"
  db_server="mariadb"
elif [ "${postgres}" -ge 1 ]; then
  echo "Postgresql server detected"
  db_server="postgres"
fi

}
db_detect

case $db_server in
  mysql)
    echo "MySQL user:"
    read mysql_user
    echo "MySQL password:"
    read -s mysql_password   
    while ! mysql -u ${mysql_user} -p${mysql_password} -e ";" ; do
      read -s -p "Can't connect, please retry: " mysql_password
    done
    
    ;;
  mariadb)
    ;;
  postgres)
    [[ $(whoami) != "postgres" ]] && echo "You must run this script as postgres user" && exit 1
    ;;
  *)
    echo "Something went wrong"
    ;;
esac

exit 0
