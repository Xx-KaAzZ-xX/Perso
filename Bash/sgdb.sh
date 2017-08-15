#!/bin/bash
#
# Filename : deb8install.sh
# Version  : 1.0
# Author   : Aurélien DUBUS
# Description :
#  .    Script to manage some stuff on differents DB server
#  .
#


main_menu()
{
while true
do
  clear
  cat << _EOT_

  ########################################
  #                                      #
  #              MAIN MENU               #
  ########################################

  Select a SGDB Server :

  1.  MySQL
  2.  Postgresql
  3.  MariaDB

  Enter 'QUIT' to leave this program
_EOT_

  read choice
  clear
  case "${choice}" in
    1) mysql_menu ;;
    2) 
      echo ""
      ;;
    3)
      echo ""
      ;;
    QUIT)
      echo "Exiting..."
      exit 0 ;;
    *)
      echo "Please make a choice" ;;
  esac
done
}

mysql_menu()
{
UP=$(pgrep mysql | wc -l)
if [ ! "${UP}" -ge 1 ];
then
  echo "MySQL doesn't seem running."
  main_menu
fi

while true
do
  cat << SQLMENU

  ########################################
  #                                      #
  #              MySQL MENU              #
  #                                      #
  ########################################

  Select an option :

  1.  Create database
  2.  Drop database

  Enter 'return' to return to main menu
SQLMENU
  read choice
  clear
  case "${choice}" in
    1);;
    2);;
    return) main_menu ;;
    *) echo "Please make a choice";;
  esac
done
}


:<<COM case $db_server in
  mysql)
    echo "MySQL user:"
    read mysql_user
    echo "MySQL password:"
    read -s mysql_password   
    while ! mysql -u ${mysql_user} -p${mysql_password} -e ";" ; do
      read -s -p "Can't connect, please retry: " mysql_password
    done
    echo ""
    case $choice in
      1)
        echo "Create database"
        ;;
      2)
        echo "Drop database"
      #*)
      #exit 0
      #;;
    esac
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
COM
main_menu
exit 0
