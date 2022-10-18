#!/bin/bash


#.  Description : Script that allows to download a package and all it's dependencies.

usage() {
 script_name=$(basename $0)
   echo -e "Usage : ./${script_name} <package name>"
   exit 1
}

if [ -z "${1}" ]
then
  usage
fi

dir="${1}_deb_files"
mkdir "${dir}"
echo "Downloading  the dependencies..."
cd "${dir}"
apt-get download ${1} && apt-cache depends -i ${1} | awk '/Dépend:/ {print $2}' | xargs apt-get download

echo "All deb files are in ${dir}"

exit 0


