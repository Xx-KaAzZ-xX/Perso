#!/bin/bash

generate_password() {
  [[ -z ${1} ]] && PASS_LEN="15" || PASS_LEN=${1}
  echo $(cat /dev/urandom|tr -dc "a-zA-Z0-9\?"|fold -w ${PASS_LEN}|head -1)
}

unix_passwd=$(generate_password "15")
username="dataiku"
##Voir pour générer ses variables depuis le script en powershell Windows
dataiku_archive="/mnt/c/Users/anon/Documents/DSS/dataiku-dss-8.0.4.tar.gz"
DSS_DEPENDENCIES="/mnt/c/Users/anon/Documents/DSS/DSS_DPKG_DEPENDENCIES/pkg"

# 1. Create dataiku user with random generated password
##Création de l'arborescence
useradd -m -s /bin/bash ${username}
echo "${username}:${unix_passwd}" | chpasswd

home_dir="/home/${username}/"
data_dir="/home/${username}/data_dir"
mkdir ${data_dir}
su - ${username} -c "tar xvzf ${dataiku_archive} -C ${home_dir}"
echo "Installing Dataiku Dependencies..."
dpkg -i ${DSS_DEPENDENCIES}/*


##Lancer l'installation
su - ${username} -c "${home_dir}/dataiku-dss-8.0.4/installer.sh -d ${data_dir} -p 11000"

echo "Done, dataiku password: "${unix_passwd}""
