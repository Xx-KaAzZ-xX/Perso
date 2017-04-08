#!/bin/bash

#.  Description : Script pour surveiller les signatures des fichiers PHP d'un hébergement web
#.                Alerte si jamais une des signatures a changé, un fichier a été enlevé ou modifier


usage() {
  script_name=$(basename $0)
  echo -e "This is the list of available options: "
  echo -e "\t  -d : Specify the directory to watch."
  echo -e "\t  -h : Displays this help."
  echo -e "\n"
  echo -e "Exemple : ./${script_name} -d /home/user/www"
}

if [ -z "${1}" ]; then
  usage
fi

while getopts ":d:h:" opt; do
    case "$opt" in
        d)  dir="$OPTARG"
            tmp1="/tmp/php_list_1.txt"
            tmp2="/tmp/php_list_2.txt"
            tmp3="/tmp/checksum_list1.txt"
            tmp4="/tmp/checksum_list2.txt"
            
            ##Before modifications

            php_files_before=$(find $dir -type f -name *.php)
            echo "$php_files_before" > $tmp1
            if [ -f "${tmp3}" ]; then
              rm $tmp3
            fi
            cat $tmp1 | while read line; do
                md5sum $line >> $tmp3
              done
            
            ##After modifications
            
            while true; do
              php_files_after=$(find $dir -type f -name *.php)
              echo "$php_files_after" > $tmp2
              
              
              if [ -f "${tmp4}" ]; then
                rm $tmp4
              fi

              cat $tmp2 | while read line; do
                md5sum $line >> $tmp4
              done
                
              modified_file=$(diff $tmp3 $tmp4 | awk '{print $3}' | sort -u)
              
              if [ -z "${modified_file}" ]
              then
                :
              else
                ##Alert
                echo "$modified_file was added, removed or modified !"
              fi
              sleep 15
            done
            ;;
        h)
            usage
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))


if [ -z "$" ] || [ -z "$" ]; then
    usage
fi




exit 0
