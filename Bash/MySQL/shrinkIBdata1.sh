#!/bin/bash

#.  Description : Script used to shrink the ibdata1 file size on disk
#.  Filename :
#.  Author : Aurélien  DUBUS
#.  Version : 1.0

FILE="/root/SQLData.sql"
DBLIST="ListOfDatabases.txt"
DBHOST="localhost"
DBUSER="root"
DBPASS="root"

##Step one : backup all DBs into a file

mysqldump -h ${DBHost} -u ${DBUSER} -p""${DBPASS}"" --hex-blob --routines --triggers --all-databases | gzip > ${FILE}.gz

##Step two : Drop all databases except mysql, performance_schema, and information_schema

mysql -h ${DBHOST} -u ${DBUSER} -p""${DBPASS}"" -A --skip-column-names -e"SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema','mysql','performance_schema')" > ${DBLIST}

for DB in `cat ${DBLIST}`
do

done


exit 0
