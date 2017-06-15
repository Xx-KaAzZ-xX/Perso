#!/bin/bash

#.  Description : Script used to shrink the ibdata1 file size on disk
#.  Filename :
#.  Author : Aurélien  DUBUS
#.  Version : 1.0

FILE="/root/SQLData.sql"
DBLIST="/root/ListOfDatabases.txt"
DBHOST="localhost"
DBUSER="root"
DBPASS="root"
CustomSQL="/etc/mysql/conf.d/customIT.cnf"

##Step one : backup all DBs into a file

mysqldump -h ${DBHOST} -u ${DBUSER} -p""${DBPASS}"" --hex-blob --routines --triggers --all-databases | gzip > ${FILE}.gz

##Step two : Drop all databases except mysql, performance_schema, and information_schema

mysql -h ${DBHOST} -u ${DBUSER} -p""${DBPASS}"" -A --skip-column-names -e"SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema','mysql','performance_schema')" > ${DBLIST}

for DB in `cat ${DBLIST}`
do
SQL_QUERY="DROP DATABASE "${DB}";"
mysql -u root -p""${DBPASS}"" -e "${SQL}"
done

##Step three : Shutdown MySQL

systemctl stop mysql

##Step four : custom conf
if [ -f ${CustomSQL} ]; then
  echo "innodb_file_per_table" >> ${CustomSQL}
else
  cat >> ${CustomSQL} << _EOF_
[mysqld]
innodb_file_per_table
innodb_flush_method=O_DIRECT
_EOF_
fi

##Step 05 : Delete ibdata1, ib_logfile0 and ib_logfile1

rm /var/lib/mysql/ibdata1 /var/lib/mysql/ib_logfile0 /var/lib/mysql/ib_logfile1

##Step 06 : Restart MySQL

systemctl restart mysql

##Step 07 : Reload MySQL data into MySQL
gunzip ${FILE}.gz
mysql -h ${DBHOST} -u ${DBUSER} -p""${DBPASS}"" < ${FILE}

echo "With the innodb_file_per_table option, you can now run OPTIMIZE TABLE mydb.mytable on each DB to shrink the mytable.ibd file"

exit 0
