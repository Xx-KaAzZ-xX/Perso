#!/bin/bash
#
# Filename : sgdb.sh
# Version  : 1.0
# Author   : Aurélien DUBUS
# Description :
#  .    Script to manage some stuff on differents DB server
#  .
#

my_exit()
{
  echo "Keyboard interrupt detected. Please type 'quit' to exit this program."
  return $?
  main_menu
}

main_menu()
{
while true
do
  clear
trap my_exit SIGINT SIGquit
  cat << _EOT_

  ########################################
  #                                      #
  #              MAIN MENU               #
  ########################################

  Select a SGDB Server :

  1.  MySQL
  2.  Postgresql
  3.  MariaDB

  Enter 'q' or 'quit' to leave this program
_EOT_

  read choice
  clear
  case "${choice}" in
    1) mysql_menu ;;
    2) postgresql_menu;;
    3)
      echo ""
      ;;
    q|quit)
      echo "Exiting..."
      exit 0 ;;
    *)
      echo "Please make a choice" ;;
  esac
  done
}

mysql_connect()
{
if [ -z "${mysql_password}" ]; then

  echo "MySQL root password:"
  read -s mysql_password
fi

while ! mysql -u root -p${mysql_password} -e ";" ; do
    read -s -p "Can't connect, please retry: " mysql_password
done
#is_connected=$(mysql -u root -p${mysql_password} -e ";") && echo "connected"

}

mysql_menu()
{
UP=$(pgrep mysql | wc -l)
if [ ! "${UP}" -ge 1 ];
then
  echo "MySQL doesn't seem running."
  main_menu
else
  mysql_connect
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
  3.  Database info

  Enter 'r' or 'return' to return to main menu
SQLMENU
  read choice
  clear
  case "${choice}" in
    1)read -p "Database name to create: " db_name
      read -p "Specify a user to manage this DB:" db_user
      read -s -p "Specify a password to this user:" db_user_password
      echo "Choisir le format de DB"
      select db_collation in Utf8 Utf8mb4
      do
        case $db_collation in
          Utf8)Q1="CREATE DATABASE $db_name CHARACTER SET ${db_collation} ;"
              break
              ;;
          Utf8mb4)Q1="CREATE DATABASE $db_name CHARACTER SET ${db_collation} ;"
              break
              ;;
          *) echo "Choisir entre Utf8 et Utf8mb4";;
        esac
      done
      Q2="CREATE USER '$db_user'@'localhost' IDENTIFIED BY '$db_user_password';"
      Q3="GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'localhost';"
      Q4="FLUSH PRIVILEGES;"
      SQL="${Q1}${Q2}${Q3}${Q4}"
      mysql -u root -p${mysql_password} -e "${SQL}"
      mysql_menu
      ;;
    2)read -p "Database name to drop: " db_name
      Q5="DROP DATABASE ${db_name};"
      echo "Would you like to delete the user associated with this DB ? [yes/no]"
      read answer
      case $answer in
        yes)Q7="DROP USER '${db_name}'@'locahost';"
            mysql -u root -p${mysql_password} -e "${Q7}"
            ;;
        no);;
        *) echo "Please make a choice";;
      esac
      mysql -u root -p${mysql_password} -e "${Q5}"
      ;;
    3)Q6="show databases;"
      mysql -u root -p${mysql_password} -e "${Q6}"
      read -p "On which database would you like info ?: " db_info
      Q8="SELECT * FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '${db_info}';"
      mysql -u root -p${mysql_password} -e "${Q8}"
      ;;
    r|return) main_menu ;;
    *) echo "Please make a choice";;
  esac
done
}

postgresql_menu()
{
UP=$(pgrep postgres | wc -l)
if [ ! "${UP}" -ge 1 ];
then
  echo "PostgreSQL doesn't seem running.Returning to main menu"
  sleep 2
  main_menu
fi

while true
do
  cat << POSTGREMENU

  ########################################
  #                                      #
  #            PostgreSQL MENU           #
  #                                      #
  ########################################

  Select an option :

  1.  Create database
  2.  Drop database
  3.  Database info

  Enter 'r' or 'return' to return to main menu
POSTGREMENU

  read choice
  clear
  case "${choice}" in
    1)read -p "Database name to create: " db_name
      read -p "Specify a user to manage this DB:" db_user
      read -s -p "Specify a password to this user:" db_user_password 
      runuser -l postgres -c "psql -c \"CREATE USER ${db_user};\""
      runuser -l postgres -c "psql -c \"ALTER ROLE  ${db_user} WITH CREATEDB;\""
      runuser -l postgres -c "psql -c \"ALTER ROLE  ${db_user} WITH SUPERUSER;\""
      runuser -l postgres -c "psql -c \"ALTER ROLE  ${db_user} WITH ENCRYPTED PASSWORD '${db_user_password}';\""
      runuser -l postgres -c "psql -c \"CREATE DATABASE ${db_name} WITH ENCODING 'UTF-8' TEMPLATE template0 OWNER ${db_user};\""
      ;;
    2)read -p "Database name to drop: " db_name
      runuser -l postgres -c "psql -c \"DROP DATABASE ${db_name};\""
      ;;
    3)#tmpfile="/tmp/pg_db"
      runuser -l postgres -c "psql -c \"\\\\l\""
      #cat $tmpfile && rm $tmpfile
      ;;
    r|return) main_menu;;
    *) echo "Please make a choice";;
  esac

done
}


###Main program##
main_menu
trap my_exit SIGINT SIGQUIT
exit 0

