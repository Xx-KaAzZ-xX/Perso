#!/bin/bash

#.  Description : Script pour surveiller les signatures des fichiers PHP d'un hébergement web
#.                Alerte si jamais une des signatures a changé


usage() {
  script_name=$(basename $0)
  echo -e "This is the list of available options: "
  echo -e "\t  -d : Specify the directory to watch."
  echo -e "\t  -h : Displays this help."
  echo -e "\n"
  echo -e "\n"
  echo -e "Exemple : ./${script_name} -d /home/user/www"
}

if [ -z "$" ] || [ -z "$" ]; then
    usage
fi

while getopts ":d:h:" opt; do
    case "$opt" in
        d)  dir="$OPTARG"
            php_files=$(find $dir -type f -name *.php)
            echo "$php_files"
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





exit 0
