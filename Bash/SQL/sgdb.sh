#!/bin/bash
#
# Filename : sgdb.sh
# Version  : 1.1
# Author   : Aurélien DUBUS
# Description :
#  .    Script to manage some stuff on differents DB server
#  .
#


# Pense-bête : Il reste à ajouter dans la partie Postgres : il faut passer les commandes à la db une fois qu'on est connecté dessus

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
  3.  Empty database
  4.  Database info
  5.  See how much data is stored in MyISAM and InnoDB
  6.  Size of each database
  7.  See slow queries
  8.  Personal query

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
    3)Q12="show databases;"
      mysql -u root -p${mysql_password} -e "${Q12}"
      ##To avoid foreign key constraint fails error##
      Q13="SET GLOBAL foreign_key_checks = 0;"
      mysql -u root -p${mysql_password} -e "${Q13}"
      read -p "Which database would you like to empty ?: " db_empty
      mysqldump -u root -p${mysql_password} --add-drop-table --no-data ${db_empty} | grep ^DROP | mysql -u root -p${mysql_password} ${db_empty}
      Q14="SET GLOBAL foreign_key_checks = 1;"
      mysql -u root -p${mysql_password} -e "${Q14}"
      ;;
    4)Q6="show databases;"
      mysql -u root -p${mysql_password} -e "${Q6}"
      read -p "On which database would you like info ?: " db_info
      Q8="SELECT * FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '${db_info}';"
      mysql -u root -p${mysql_password} -e "${Q8}"
      ;;
    5)Q9="SELECT IFNULL(B.engine,'Total') \"Storage Engine\",
      CONCAT(LPAD(REPLACE(FORMAT(B.DSize/POWER(1024,pw),3),',',''),17,' '),' ',
      SUBSTR(' KMGTP',pw+1,1),'B') \"Data Size\", CONCAT(LPAD(REPLACE(
      FORMAT(B.ISize/POWER(1024,pw),3),',',''),17,' '),' ',
      SUBSTR(' KMGTP',pw+1,1),'B') \"Index Size\", CONCAT(LPAD(REPLACE(
      FORMAT(B.TSize/POWER(1024,pw),3),',',''),17,' '),' ',
      SUBSTR(' KMGTP',pw+1,1),'B') \"Table Size\"
      FROM (SELECT engine,SUM(data_length) DSize,SUM(index_length) ISize,
      SUM(data_length+index_length) TSize FROM information_schema.tables
      WHERE table_schema NOT IN ('mysql','information_schema','performance_schema')
      AND engine IS NOT NULL GROUP BY engine WITH ROLLUP) B,
      (SELECT 3 pw) A ORDER BY TSize;"
      mysql -u root -p${mysql_password} -e "${Q9}"
      ;;
    6)Q10="SELECT table_schema AS \"Database\",
      ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS \"Size (MB)\"
      FROM information_schema.TABLES
      GROUP BY table_schema;"
      mysql -u root -p${mysql_password} -e "${Q10}"
      ;;
    7)Q11="SHOW PROCESSLIST;"
      mysql -u root -p${mysql_password} -e "${Q11}"
      ;;
    8)read  -p "Enter your personal query: " Q12
      mysql -u root -p${mysql_password} -e "${Q12}"
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
  3.  List databases
  4.  Get databases size
  5.  Select a database

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
    3)runuser -l postgres -c "psql -c \"\\\\l\""
      ;;
    4)runuser -l postgres -c "psql -c \"SELECT t1.datname AS db_name,pg_size_pretty(pg_database_size(t1.datname)) as db_size FROM pg_database t1
ORDER BY pg_database_size(t1.datname) DESC;\""
      ;;
    5)runuser -l postgres -c "psql -c \"\\\\l\""
      echo "Which database do you want to connect to ?"
      read db_choice
      runuser -l postgres -c "psql -c \"\connect ${db_choice}\""
      while true
      do
        cat << POSTGREDBMENU

   ########################################
   #                                      #
   #You are now connected to ${db_choice} #
   #                                      #
   ########################################

   Select an option :

   1.  List tables

   Enter 'r' or 'return' to return to main menu
POSTGREDBMENU
      read postgres_choice
      case "${postgres_choice}" in
        1)runuser -l postgres -c "psql -c \"\dt\""
        ;;
        r|return) postgresql_menu
        ;;
        *) echo "Please make a choice";;
      esac
      done
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

