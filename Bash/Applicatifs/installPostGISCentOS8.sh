#!/bin/bash

yum -y install https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
dnf config-manager --set-enabled PowerTools
dnf -y module disable postgresql

dnf -y install postgres96-server
dnf -y install postgis25_96


echo "Plus qu'à créer une DB et activer PostGis"

exit 0
