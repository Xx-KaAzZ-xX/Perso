#!/bin/bash

generate_password() {
  [[ -z ${1} ]] && PASS_LEN="15" || PASS_LEN=${1}
  echo $(cat /dev/urandom|tr -dc "a-zA-Z0-9\?"|fold -w ${PASS_LEN}|head -1)
}

unix_passwd=$(generate_password "15")
username="dataiku"
##Voir pour générer ses variables depuis le script en powershell Windows
dataiku_archive="/mnt/c/Users/adm-cra/Documents/Script_DSS/dataiku-dss-8.0.4.tar.gz"
Script_DSS_DEPENDENCIES="/mnt/c/Users/adm-cra/Documents/Script_DSS/DSS_DPKG_DEPENDENCIES/pkg/"
license="/mnt/c/Users/adm-cra/Documents/Script_DSS/license.json"

# 1. Create dataiku user with random generated password
##Création de l'arborescence
useradd -m -s /bin/bash ${username}
echo "${username}:${unix_passwd}" | chpasswd

home_dir="/home/${username}/"
data_dir="/home/${username}/data_dir"
su - ${username} -c "mkdir ${data_dir}"
su - ${username} -c "tar xvzf ${dataiku_archive} -C ${home_dir}"
echo "Installing Dataiku Dependencies..."
dpkg -i ${Script_DSS_DEPENDENCIES}/*.deb


##Lancer l'installation et le lancement automatique au démarrage

su - ${username} -c "${home_dir}/dataiku-dss-8.0.4/installer.sh -d ${data_dir} -p 11000 -l ${license}"
su - ${username} -c "${data_dir}/bin/dss start"
/home/${username}/dataiku-dss-8.0.4/scripts/install/install-boot.sh "${data_dir}" ${username}
echo "Done, dataiku password: ${unix_passwd}"
echo "Dataiku is now accessible here : http://localhost:11000"
