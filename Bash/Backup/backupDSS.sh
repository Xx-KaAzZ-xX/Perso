#!/bin/bash

## Description. Script qui permet de sauvegarder des projets DSS

USER=$(whoami)
DATA_DIR="/home/anon/Documents/dataiku-dss-6.0.1/"
DSS_BIN="/home/anon/dataiku/bin"
BACKUP_DIR="/home/anon/Documents/backup"
date_of_day=$(date +%Y%m%d)
name="${date_of_day}-DSS-backup.tar.gz"
retention="7"

dss_test=$(ps -aux | grep dss | wc -l)

if [ ${USER} != "anon" ]
then
	echo "Script must run as DSS user !"
	exit 1
fi
if [ ${dss_test} > 1 ]
then
	${DSS_BIN}/dss stop
	tar -zcvf $name $DATA_DIR
	mv $name ${BACKUP_DIR}
	${DSS_BIN}/dss start
else
	tar -zcvf $name $DATA_DIR
        mv $name ${BACKUP_DIR}
        ${DSS_BIN}/dss start
fi

##Nettoyage : on supprime les backups plus vieux que le temps de rétention souhaité
find ${BACKUP_DIR} -type f -name *.tar.gz" -mtime +${retention} -exec rm -f {} \;


echo "Backup terminé ! "
