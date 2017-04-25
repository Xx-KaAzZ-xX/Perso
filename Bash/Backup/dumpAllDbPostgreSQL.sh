#!/bin/bash
#
# Filename : dumpAllDbPostgreSQL.sh
# Version  : 1.0
# Author   : Mathieu Androz 
# Contrib  : Aurélien DUBUS
# Description :
#  . Dump all databases
#  . Each db is stored in its own file and Gzip, user backupit has to be created
#  . As a Super user with read-only privileges.
#  . Think to give the right privileges to Backupit user on the Databases
#


function usage() {
  echo "
  Description :
    - Dump all databases
    - Each databae is stored in its own file and Gzip
      "
    }
usage
    # Security
    # Test if the script is executed by backupit !
    [[ $(whoami) != "backupit" ]] && exit 1

    # Where dumps are stored
    STORE_FOLDER="/home/backupit/DBs"
    # Databases list
    DBLIST='/home/backupit/db.txt'
    DBLIST2='/home/backupit/db2.txt'



    ( [[ "${STORE_FOLDER}" == "/" ]] || [[ -z "${STORE_FOLDER}" ]] || [[ "${DBLIST}" == "/" ]] || [[ -z "${DBLIST}" ]] ) && exit 1


    [[ ! -d "${STORE_FOLDER}" ]] && mkdir -p "${STORE_FOLDER}" && chmod 700 "${STORE_FOLDER}"

    # Keep all old backups (one day ago)
    if [[ "${STORE_FOLDER}" == "/home/backupit/DBs" ]] && [[ "${STORE_FOLDER}" != "/" ]]; then
        cd "${STORE_FOLDER}"
          for file in $(ls . | grep -E "sql.gz$")
              do
                    mv ${file} ${file}.old1day
                      done
                    fi

# Get databases list
 psql -U backupit postgres -c 'SELECT datname FROM pg_database;' > $DBLIST

#Remove undesired strings from $DBLIST
sed '/datname/d' $DBLIST > $DBLIST2 && mv $DBLIST2 $DBLIST
sed '/--/d'  $DBLIST > $DBLIST2 && mv $DBLIST2 $DBLIST
sed '/(/d'  $DBLIST > $DBLIST2 && mv $DBLIST2 $DBLIST
sed '/^$/d' $DBLIST > $DBLIST2 && mv $DBLIST2 $DBLIST
chmod 600 "${DBLIST}"

                    # Dump each db in a separate file
while read dbname
do
        pg_dump "${dbname}" | gzip > "${STORE_FOLDER}"/"${dbname}".sql.gz

done < "${DBLIST}"

exit 0
