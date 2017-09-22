#!/bin/bash

#
# Filename : dumpalldb
# Version  : 1.0
# Author   : mathieu androz
# Contrib  :
# Description :
#  . Make
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
rsync -arz -e "ssh -p 6622" $tarball $user@$remoteHost:$destination


exit 0
