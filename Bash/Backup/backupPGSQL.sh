#!/bin/bash

##Author.       Aurélien DUBUS
## Description. Permet de faire la sauvegarde des BDD PostgreSQL et de les exporter

exec 1> >(logger -s -t $(basename $0)) 2>&1
##Définition des variables
database="forge_comint" #"bdd1" "bdd2" --> Variable liste à ajouter pour backup d'autres BDD
backup_user="postgres" #User de backup
date=$(date +"%Y%m%d")
backup_dir="${date}-BDD" #Dossier où va aller le backup du jour
backup_zip="${backup_dir}.zip"
backup_destination="/home/adm-cra/"
retention=7 #Variable de retention de fichiers zip en nombre de jours

if [ -d ${backup_dir} ]
then
        echo " Le dossier existe déjà. Le script va se terminer"
        exit 1
fi

cd /var/lib/pgsql #Chemin ou postgres créé les fichiers par défaut
##Backup des BDD choisies
su -c "mkdir ${backup_dir}" - ${backup_user}
for db in ${database}
do
                su -c "pg_dump ${db} > ${backup_dir}/${db}.sql" - ${backup_user}
done

##Compression du dossier et export
zip ${backup_zip} ${backup_dir}/*
rm -rf ${backup_dir}
mv ${backup_zip} ${backup_destination}

##Nettoyage : on supprime les backups plus vieux que le temps de rétention souhaité
find ${backup_destination} -type f -name *.zip" -mtime +${retention} -exec rm -f {} \;

exit 0
