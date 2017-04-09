#!/bin/bash


#.  Description : Alerte lors d'un changement dans un répertoire au niveau des fichiers PHP ( Création/Modification/Suppression )
#.  Author : Aurélien DUBUS
#.  Version : 1.0


usage() {
 script_name=$(basename $0)
   echo -e "Usage : ./${script_name} /home/user/www"
}

if [ -z "${1}" ]
then
  usage
fi

while true; do

    command=$(inotifywait -e modify,create,delete -r $1)
    ##Put an alert command here
    message=$( echo "${command}" | head -n 1)
    php_file=$(echo "$message" | grep .php)

    if [ -z "${php_file}" ]
    then
      :
    else
    echo $php_file
    fi

done

exit 0
