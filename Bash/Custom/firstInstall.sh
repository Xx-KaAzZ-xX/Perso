#!/bin/bash
#
# Filename : firstInstall.sh
# Version  : 1.1
# Author   : DUBUS Aurélien
# Contrib  :
# Description :
#  .
#  .
#


LOGFILE="/var/log/admin/admin.log"

# include
. /lib/lsb/init-functions


usage() {
    ::
}

createLogrotate() {
    LOGROTATEDIR="/etc/logrotate.d"
    LOGROTATEFILE="admin"
    if [[ -d ${LOGROTATEDIR} ]]; then
        if [[ ! -f ${LOGROTATEDIR}/${LOGROTATEFILE} ]]; then
            touch ${LOGROTATEDIR}/${LOGROTATEFILE}
            chmod 644 ${LOGROTATEDIR}/${LOGROTATEFILE}
            echo -e "${LOGFILE} {\n\tweekly \
                \n\tmissingok \
                \n\trotate 52 \
                \n\tcompress \
                \n\tdelaycompress \
                \n\tnotifempty \
                \n\tcreate 640 root root
                \n}" > ${LOGROTATEDIR}/${LOGROTATEFILE}
        fi
    fi
}

log() {
    [[ ! -d $(dirname ${LOGFILE}) ]] && mkdir -p $(dirname ${LOGFILE})
    echo "$(date +%Y%m%d-%H:%M:%S) :: " ${1} | tee -a ${LOGFILE}
}

installPackage() {
    if [[ $(dpkg -l | awk '{print $1" "$2}' | grep " ${1}"$) != "ii ${1}" ]]; then
        log "Installation du package ${1}..."
        apt-get -y -q install "${1}" &> /dev/null
    else
        log "Package ${1} already installed on your system."
    fi
}


recoverGIT() {
    if [[ ! -d /root/scripts ]]; then
        SFSVN="/root/scripts"
        mkdir -p ${SFSVN} && git clone https://github.com/Xx-KaAzZ-xX/admin.git ${SFSVN}
        chown -R root:root ${SFSVN} && chmod -R 700 ${SFSVN}
        log "SourceForge scripts in ${SFSVN}"
    elif [[ ! -d /root/scriptsSF ]]; then
        SFSVN="/root/scriptsSF"
        mkdir -p ${SFSVN} && git clone https://github.com/Xx-KaAzZ-xX/admin.git ${SFSVN}
        chown -R root:root ${SFSVN} && chmod -R 700 ${SFSVN}
        log "SourceForge scripts in ${SFSVN}"
    else
       echo "/root/scripts already exists !"
    fi
}

vimConfig() {
    installPackage vim && log "Installation of Vim"
    if [[ ! -f /etc/vim/vimrc.local ]]; then
        echo -e "syntax on \
            \nset smarttab \
            \nset noet ci pi sts=0 sw=4 ts=4 \
            \nset cursorline \
            \nfiletype plugin indent on \
            \nset t_Co=256 \
            \nset background=dark \
            \nset titlestring=%f title \
            \nset nobk nowb noswf \
            \nset tabstop=2 \
            \nset shiftwidth=2 \
            \nset expandtab \
            " > /etc/vim/vimrc.local
        log "Configuration of Vim in /etc/vim/vimrc.local"
    fi
}

installFirewall() {
    if [[ ! -f /etc/init.d/firewall ]]; then
        cp /root/scripts/Banned/firewall.sh /etc/init.d/firewall
        chmod 755 /etc/init.d/firewall
        vi /etc/init.d/firewall && log "Installation of Firewall script"
        cp /etc/crontab /etc/crontab.orig
        echo -e " \
            \n# Restart Firewall \
            \n0  5    * * *   root    /etc/init.d/firewall restart 2>&1 /dev/null \
            \n" >> /etc/crontab && log "Firewall setup in /etc/crontab" || logfailure "Firewall not setup in /etc/crontab"
    fi
}

installNTP() {
    installPackage ntpdate && log "Install of Ntpdate"
    cp /etc/crontab /etc/crontab.orig.2
    echo -e " \
        \n#Synchronisation NTP \
        \n00 01 * * * root ntpdate 0.fr.pool.ntp.org &> /dev/null \
        \n" >> /etc/crontab && log "Ntpdate setup in /etc/crontab" || logfailure "Ntpdate not setup in /etc/crontab"
}




#################################
#
#           MAIN
#
#################################

# Install packages
installPackage htop
installPackage iotop
installPackage iostat
installPackage zip
installPackage rsync
installPackage git
installPackage sysstat
installPackage chkconfig

recoverGIT
vimConfig
#installFirewall
installNTP


# Custom bashrc
cp /root/.bashrc /root/.bashrc.orig
sed -i 's/^# export LS_OPTIONS=/export LS_OPTIONS=/g' /root/.bashrc
sed -i 's/^# eval "`dircolors`"/eval "`dircolors`"/g' /root/.bashrc
sed -i 's/^# alias ls=/alias ls=/g' /root/.bashrc
sed -i 's/^# alias ll=/alias ll=/g' /root/.bashrc
sed -i 's/^# alias l=/alias l=/g' /root/.bashrc

echo "
alias al=\"ls \$LS_OPTIONS -alh\"
alias showconnections=\"netstat -ntu | awk '{print \$5}' | cut -d: -f1 | grep -E [0-9.]+ | sort | uniq -c | sort -n\"
alias sfupdate=\"cd ${SFSVN} && git pull && chmod -R 700 ${SFSVN} && chown -R root:root ${SFSVN}\"
alias createftp=\"/root/scripts/Shell/web/ftp/createFtpUserWithQuota.sh\"
alias newDB=\"/root/scripts/Shell/mysql/newDB.sh\"
alias newenv=\"/root/scripts/Shell/newEnv.sh\"
function n2ensite {
  NGINXDIR=\"/etc/nginx/\"
  [[ \${1} = \"\" ]] && echo \"You don't have specified a virtualhost\" && return 1
  ln -s \${NGINXDIR}/sites-available/\"\${1}\" \${NGINXDIR}/sites-enabled/\"\${1}\"
  echo \"Virtualhost \${1} enabled.\"
  echo \"Reload Nginx to apply changes : service nginx reload\"
}
function n2dissite {
  NGINXDIR=\"/etc/nginx/\"
  [[ \${1} = \"\" ]] && echo \"You don't have specified a virtualhost\" && return 1
  rm \${NGINXDIR}/sites-enabled/\"\${1}\"
  echo \"Virtualhost \${1} disabled.\"
  echo \"Reload Nginx to apply changes : service nginx reload\"
}" >> /root/.bashrc

# Custom sources.list
cp /etc/apt/sources.list /root/sources.list
sed -i 's/^deb cdrom/#deb cdrom/g' /etc/apt/sources.list
sed -i 's/^deb\(.*\)main$/deb\1main contrib non-free/g' /etc/apt/sources.list


exit 0
