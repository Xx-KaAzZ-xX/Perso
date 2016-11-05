#!/bin/bash

usage(){
echo -e " 
       -d : Specify the disk to format. It will be used to extend the LV
       -v : Specify the logical volume to extend
       -i : Display some infos about Volume Groups and Logical Volumes
       -h : Display this help"
}
info(){
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'
volume_info=$(lsblk | grep sd)
pv_info=$(pvdisplay | grep "PV Name" | awk {'print $3}')
lv_info=$(lvdisplay | grep "LV Name" | awk {'print $3}')
vg_info=$(vgdisplay | grep "VG Name" | awk {'print $3}')
echo -e "
------------- ${RED} Volume Informations ${NC}   -----------------------\n
${volume_info}

------------- ${GREEN}   Actual PV ${NC}         -----------------------\n
\n${pv_info}\n

------------- ${BLUE}   Actual LV ${NC}          -----------------------\n
${lv_info}

------------- ${YELLOW}   Actual VG ${NC}        -----------------------\n
${vg_info}
        "
}

lvmInstalled=$(dpkg -s lvm2 >/dev/null 2>&1)
test=$(echo $?)
if [[ ${test} = "1" ]]
then
  echo "lvm2 package seems to be not installed. Script will shutdown"
  exit 1

elif [[ $(whoami) != "root" ]]
then
  echo "You have to run this script as root"
  exit 1

else
volumeGroup=$(vgdisplay | grep Name | awk '{print $3}')

  while getopts ":d:v:hi" opt; do
    case $opt in
      d | disk) disk="$OPTARG"
        ##test si le disque est partitionné
        if [[ $(/sbin/sfdisk -d ${OPTARG} 2>&1) == "" ]]
          then
          echo "Device not partitioned"
                     
        else
         echo "${OPTARG} is still partitioned use a different disk."
         exit 1
        fi
        ;;
      v) volume="$OPTARG"
        ;;
      h) usage
        exit 1
        ;;
      i) info
         exit 1
        ;;
    esac
    ##Creating a partition
    (echo g; echo n; echo p; echo 1; echo; echo; echo w) | fdisk ${disk} > /dev/null 2>&1 && echo "One partition created successfuly on ${disk}"
    var="1"
    partition="${disk}""${var}"
    pvcreate ${partition}
    vgextend ${volumeGroup} ${partition}
    lvextend -l +100%FREE /dev/${volumeGroup}/${volume}
    resize2fs /dev/${volumeGroup}/${volume}
  done
fi



exit 0
