#!/bin/bash

#
# Filename : backup_rsync
# Version  : 1.0
# Author   : Aurélien DUBUS
# Contrib  :
# Description :
#  . Simple script to backup on remote server via Rsync & SSH one directory. this script needs the id_rsa.
pub in the authorized_keys file of the remote server
#  .
#

source="/data/common/Compta"
destination="/home/compta/Backups"
remoteHost="bkp03.itserver.fr"
user="compta"
time=$(date +%d-%m-%y)
tarball="compta.${time}.tar.gz"
cd $source
tar zcf $tarball *
rsync -arz -e "ssh -p 6622" $tarball $user@$remoteHost:$destination && rm $tarball


exit 0
