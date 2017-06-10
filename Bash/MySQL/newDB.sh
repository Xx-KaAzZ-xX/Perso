#!/bin/bash

## Création BDD et USER

if [[ -z "$1" ]] || ( [[ "$1" != "utf8" ]] || [[ "$1" != "utf8mb4" ]] )
then
  echo -e "Usage:
  ./newDB.sh {utf8|utf8mb4}
  "
  exit 1
fi

read -p  "Enter un nom d'utilisateur SQL : " username

read -s -p "Password for SQL user: ${username} : " password
read -s -p "Confirmer le mot de passe SQL pour ${username} : " password2
while [ "${password}" != "${password2}" ]
  do
    echo -e "Password don't match\n"
    read -s -p "Password for SQL user: ${username}" password
    read -s -p "Confirmer le mot de passe SQL pour ${username}" password2
  done

Q1="CREATE DATABASE IF NOT EXISTS ${username} CHARACTER SET ${1};"
Q2="CREATE USER '${username}'@'localhost' IDENTIFIED BY '${password}';"
Q3="GRANT ALL PRIVILEGES ON ${username}.* TO '${username}'@'localhost';"
Q4="FLUSH PRIVILEGES;"
SQL="${Q1}${Q2}${Q3}${Q4}"
mysql -u root -p -e "${SQL}"

exit 0
