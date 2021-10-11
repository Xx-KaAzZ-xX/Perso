#!/bin/bash


##Variables à définir avant l'exécution du script
DOMAIN_NAME="ad.lan"
ADMIN_GROUP="Administrateurs"
SYSCTL_FILE="anssi_sysctl-conf"
USER_UMASK_VALUE="027"
##Liste des executables setuid à modifier
SETUID_EXEC="setuid_list.txt"
LOCAL_USER="anon" #sera adm-cra sur l'infra

#voir pour rajouter la système
#Check if machine is in Active Directory
realm list | grep active-directory > /dev/null 2>&1

if [[ $? -eq 0 ]] ; then
##Si la machine est dans le domaine, on autorise les admins à se connecter
realm permit -g ${ADMIN_GROUP} > /dev/null 2>&1

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
%${ADMIN_GROUP}@${DOMAIN_NAME}     ALL=(ALL)   ALL
_EOF_


##Durcissement de la sécurité avec le fichier sysctl des recommandations de l'ANSSI

[ ! -f ./${SYSCTL_FILE} ] && echo "Le fichier ${SYSCTL_FILE} doit être dans le répertoire du script" && exit 1

mv /etc/sysctl.conf /etc/systcl.bak
mv ./${SYSCTL_FILE} /etc/sysctl.conf

##Configuration de la longueur minimale de mots de passe, de pam_tally2 pour bloquer un compte lors des échecs, 
cp /etc/pam.d/passwd /etc/pam.d/passwd.bak
cp /etc/pam.d/login /etc/pam.d/login.bak
cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
cp /etc/login.defs /etc/login.defs.bak

echo -e "#Fichier/etc/pam.d/passwd
## Cette partie rentre en conflit avec les scripts de durcissement CIS DEBIAN OVH
#Au moins 12 caractères ,pas de répétition ni de séquence monotone,
#3 classes différentes (parmi majuscules,minuscules,chiffres,autres)
password	required	pam_cracklib.so minlen=12 minclass=3	\
				dcredit=0 ucredit=0 lcredit=0	\
				ocredit=0 maxrepeat=1		\
				maxsequence=1 gecoscheck	\
				reject_username enforce_for_root" | tee -a /etc/pam.d/passwd
echo "[-] Password minimal lenght : OK"
echo -e "# Blocage du compte pendant 5 min après 3 échecs
auth	required	pam_tally.so	deny=3	lock_time=300" | tee -a /etc/pam.d/login

echo "[-] Account locked after 3 fails : OK"

##Durcissement du stockage des mots de passe
echo -e "password	required	pam_unix.so	obscure sha512 rounds=65536" | tee -a /etc/pam.d/common-password
echo -e "ENCRYPT_METHOD	SHA512
SHA_CRYPT_MIN_ROUNDS	65536" | tee -a /etc/login.defs && echo "[-] Protection of saved passwords increased : OK"
cp /etc/profile /etc/profile.bak
echo "UMASK	${USER_UMASK_VALUE}" | tee -a /etc/profile && echo "[-] Umask value for users set to 027 : OK"

##Enlever le setuid et setgid pour les executables de la liste

echo "Voulez-vous supprimer les setuid et setgid ?"
select yn in "yes" "no"
do
    case ${yn} in
        yes)
        echo "Suppression des setuid..."
        if [[ -f ${SETUID_EXEC} ]];
        then
                cat ${SETUID_EXEC} | while read line
        do
                #echo $line
                find ${line} -type f -perm /600 -ls 2>/dev/null && chmod u-s ${line} && chmod g-s ${line}
        done
        else
                echo "${SETUID_EXEC} doit être dans le même répertoire que le script"
        fi
        echo "[-] Suppression des setuid : OK"
        break
        ;;
        no)
        break
        ;;
    esac
done

##Recherche des fichiers sans utilisateurs ni groupes
#Recherche des fichiers sans utilisateurs ni groupes
echo "Recherche des fichiers sans utilisateur ou groupe défini..."
find / -type f \( -nouser -o -nogroup \) -ls 2>/dev/null | awk '{print $11}' > file_without_user.txt
nb_line=$(cat file_without_user.txt | wc -l)
if [[ ${nb_line} -eq 0 ]];
then
        echo "[-] Pas de fichiers sans utilisateur indéfini"
else
        cat file_without_user.txt | while read line
        i=0
        do
                echo $line
                chown ${LOCAL_USER}:${LOCAL_USER} ${line}
                i= $i + 1
        done
echo "[-] Attribution de ${i} à l'utilisateur ${LOCAL_USER} : OK"
fi

rm file_without_user.txt

exit 0
