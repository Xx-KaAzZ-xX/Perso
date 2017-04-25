#!/bin/bash

backup_dir="/root/Backup"
#dir1="/home/portfolio/www"
dir2="/home/wiki/www"
date=$(date +"%Y-%m-%d")
#portfolio="portfolio"
wiki="wiki"
#archive1=$portfolio$date
archive2=$wiki$date


if [ ! -d "${backup_dir}" ]
then
mkdir $backup_dir
fi

cd $backup_dir
#tar zcvf ./"${archive1}".tar.gz "${dir1}" > /dev/null 2>&1
tar zcvf ./"${archive2}".tar.gz "${dir2}" > /dev/null 2>&1

##Then backup DBs
bash $backup_dir/dumpalldb

exit 0
