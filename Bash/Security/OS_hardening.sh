#!/bin/bash

##Variables
DOMAIN_NAME="ad.lan"
SYSCTL_FILE="anssi_sysctl-conf"

#Check if machine is in Active Directory

realm list | grep active-directory > /dev/null 2>&1
#[ $? -eq 0 ]  || echo "Machine not in AD, the script will exit" && exit 1

##Si la machine est dans le domaine, on autorise les admins à se connecter
realm permit -g Administrateurs > /dev/null 2>&1

##On autorise ensuite les membres du groupe d'admin à lancer sudo
mv /etc/sudoers /etc/sudoers.bak
cat >> /etc/sudoers << _EOF_
## Sudoers allows particular users to run various commands as
## the root user, without needing the root password.
##
## Examples are provided at the bottom of the file for collections
## of related commands, which can then be delegated out to particular
## users or groups.
##
## This file must be edited with the 'visudo' command.


Defaults   !visiblepw
Defaults    always_set_home
Defaults    match_group_by_gid
Defaults    always_query_group_plugin

Defaults    env_reset
Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults    env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults    env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults    env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"


Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin

root    ALL=(ALL)   ALL

#Autorisation des admins à lancer la commande sudo
%Administrateurs@${DOMAIN_NAME}     ALL=(ALL)   ALL
_EOF_


##Durcissement de la sécurité avec le fichier sysctl de l'ANSSI

[ ! -f ./${SYSCTL_FILE} ] && echo "Le fichier ${SYSCTL_FILE} doit être dans le répertoire du script" && exit 1

mv /etc/sysctl.conf /etc/systcl.bak
mv ./${SYSCTL_FILE} /etc/sysctl.conf
