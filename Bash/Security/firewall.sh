#!/bin/bash
### BEGIN INIT INFO
# Provides:          firewall
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# X-Interactive:     true
# Short-Description: Start/Stop/Status Iptables Firewall script
### END INIT INFO

#############################################################################
# Script de configuration iptables pour Debian
# Modif : 24/04/2014
#   . Ajout de la prevention contre les DDoS
#---------------------------------------------------------------------------
# Utilisation du script :
# cp firewall.sh /etc/init.d/firewall
# Activation au demarrage : update-rc.d firewall defaults
# Desactivation au démarrage : update-rc.d --force firewall remove
#
# Ajouter cette ligne dans /etc/crontab
# 0  5    * * *   root    /etc/init.d/firewall restart &> /dev/null
#############################################################################


SSH_PORT="22"
TMP="/tmp/_iptables.txt"
## ! IP des serveurs de monitoring !
MONITORING_IP_LIST=("192.168.1.5")

systemctl disable firewalld
systemctl stop firewalld
###############
#  Fonctions  #
###############

fail2ban_present() {
    echo -e "Fail2ban est-il installe ? : ${FAIL2BAN_OK}"
    if [[ ${FAIL2BAN_OK} != "ii" ]] ; then
    	echo -e "\nFail2ban n'est pas installé. Démarrage de l'installation..."
    	echo -e "yum install fail2ban"
    	yum -y install fail2ban 2>&1 /dev/null
    	echo -e "Installation de Fail2ban : [OK]"
    fi
}

reset_iptables() {
        #-------------------------------------------------------------------
        # Reset des tables et regles iptables
        #-------------------------------------------------------------------
        fail2ban_present
        # Vider les tables actuelles
        iptables -t filter -F
        # Vider les regles personnelles
        iptables -t filter -X
        # On autorise toutes les connexions
        iptables -t filter -P INPUT ACCEPT
        iptables -t filter -P FORWARD ACCEPT
        iptables -t filter -P OUTPUT ACCEPT

        echo "Remise a zero des regles et tables iptables : [OK]"
}

init_iptables() {
        #-------------------------------------------------------------------
        # Initialisation des tables et regles iptables
        #-------------------------------------------------------------------
        reset_iptables
        # Interdire toute connexion entrante et sortante
        iptables -t filter -P INPUT DROP
        iptables -t filter -P FORWARD DROP
        iptables -t filter -P OUTPUT DROP
        # On log pour psad
        #iptables -A INPUT -j LOG
        #iptables -A FORWARD -j LOG
        # Ne pas casser les connexions etablies
        iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

        echo "Initialisation d'iptables : [OK]"
}

loopback() {
        #--------------------------------------------------------------------
        # Connexion lo : localhost loopback
        #--------------------------------------------------------------------
        # Autoriser loopback
        iptables -t filter -A INPUT -i lo -j ACCEPT
        iptables -t filter -A OUTPUT -o lo -j ACCEPT

        echo "Autorisation de la connexion loopback lo : [OK]"
}

ping_icmp() {
        #--------------------------------------------------------------------
        # ICMP (Ping)
        #--------------------------------------------------------------------
        for monitor_ip  in "${MONITORING_IP_LIST[@]}"
        do
          iptables -t filter -A INPUT -p icmp -s ${monitor_ip} -j ACCEPT
          iptables -t filter -A OUTPUT -p icmp -s ${monitor_ip} -j ACCEPT
        done
        iptables -t filter -A OUTPUT -p icmp -s ${SERVER_IP} -j ACCEPT
        
        echo "Autorisation ICMP (Ping) : [OK]"
}

ssh_connexion() {
        #--------------------------------------------------------------------
        # Connexion SSH
        # Attention a utiliser le bon port !
        #--------------------------------------------------------------------
        # SSH In
        iptables -t filter -A INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT
        # SSH Out
        iptables -t filter -A OUTPUT -p tcp --dport ${SSH_PORT} -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport ${SSH_PORT} -j ACCEPT

        echo "Autorisation de la connexion SSH (port ${SSH_PORT}) : [OK]"
}

dns_connexion() {
        #--------------------------------------------------------------------
        # DNS
        #--------------------------------------------------------------------
        # DNS In/Out
        #iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
        iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT
        #iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
        iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT

        echo "Autorisation DNS : [OK]"
}

ntp_connexion() {
        #---------------------------------------------------------------------
        # Synchronisation de l'heure
        #---------------------------------------------------------------------
        # NTP Out
        iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT
        # NTP In
        iptables -t filter -A INPUT -p udp --dport 123 -j ACCEPT

        echo "Autorisation synchronisation du temps (NTP) : [OK]"
}

apache_connexion() {
        #---------------------------------------------------------------------
        # APACHE2 : Serveur Web
        #---------------------------------------------------------------------
        # HTTP + HTTPS Out
        iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT
        # HTTP + HTTPS In
        iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT
        #iptables -t filter -A INPUT -p tcp --dport 8443 -j ACCEPT

        echo "Autorisation des connexions web (HTTP/HTTPS) : [OK]"
}

ftp_connexion() {
        #---------------------------------------------------------------------
        # PURE-FTPD : Serveur FTP
        #---------------------------------------------------------------------
        # FTP Out
        iptables -t filter -A OUTPUT -p tcp --dport 20:21 -j ACCEPT
        # FTP In
        #iptables -t filter -A INPUT -p tcp --dport 20:21 -j ACCEPT
        #iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

        echo "Autorisation des connexions FTP : [OK]"
}

smtp_connexion() {
        #---------------------------------------------------------------------
        # MAIL : Envoi des mails
        #---------------------------------------------------------------------
        # Mail SMTP:25
        #iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
        #iptables -t filter -A INPUT -p tcp --dport 587 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 587 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 465 -j ACCEPT

        echo "Autorisation de l'envoi des mails (SMTP) : [OK]"
}

postgresql_connexion() {
        #---------------------------------------------------------------------
        # MYSQL
        #---------------------------------------------------------------------
        # Mysql In/Out
        iptables -t filter -A INPUT -p tcp --dport 5432 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 5432 -j ACCEPT

        echo "Autorisation des connexions POSTGRESQL : [OK]"
}

nagios_connexion() {
        #---------------------------------------------------------------------
        # Nagios NRPE
        #---------------------------------------------------------------------
        # Autorissation de connexion à Nagios NRPE
        for monitor_ip  in "${MONITORING_IP_LIST[@]}"
        do
          iptables -t filter -A INPUT -p tcp --dport 5666 -s ${monitor_ip} -j ACCEPT
          iptables -t filter -A OUTPUT -p tcp --dport 5666 -s ${monitor_ip} -j ACCEPT
        done

        echo "Autorisation des connexions Nagios NRPE : [OK]"
}


block_port_scan() {
		#-----------------------------------------------------------------------
		# Rules to block port scanner
		#-----------------------------------------------------------------------
		iptables -N PORT-SCAN
		iptables -A PORT-SCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j RETURN
		iptables -A PORT-SCAN -j DROP
}


block_https_for() {
        #-----------------------------------------------------------------------
        # Block HTTPS access for specific domains patterns given in parameters
        #-----------------------------------------------------------------------
        for n in "$@"
        do
            iptables -I INPUT 2 -p tcp --dport 443 -m string --string ${n} --algo kmp -j DROP
        done
}

ddos_prevention() {
        #-----------------------------------------------------------------------
        # DDoS prevention :
        # Les règles suivantes permettent de limiter le nombre de connexion
        # depuis une source à 50 hits pendant 10 secondes sur le port 80
        #-----------------------------------------------------------------------
        DDOSTIME="10"
        DDOSHITS="50"
        iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW -m recent --set --name WEB
        iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW -m recent \
            --update --seconds ${DDOSTIME} --hitcount ${DDOSHITS} --rttl --name WEB -j DROP

        echo "DDoS prevention status for ${DDOSHITS} hits for ${DDOSTIME} sec : [OK]"
}


#############
#    Main   #
#############

if ! [ -x /sbin/iptables ]; then
        exit 0
fi

iptables_start() {
        # Initialisation iptables
        init_iptables
        loopback
        # Quelle(s) connexion(s) ouvrir ?
        ping_icmp
        ssh_connexion
        dns_connexion
        ntp_connexion
        #apache_connexion
        #ddos_prevention
        #ftp_connexion
        #smtp_connexion
        postgresql_connexion
        block_port_scan
        return 0
}

iptables_stop() {
        # Reinitialisation iptables
        reset_iptables
        return 0
}

case ${1} in
        start)
            echo "Starting firewall..."
            iptables_start
            sleep 1
            [[ ${FAIL2BAN_OK} == "ii" ]] && /etc/init.d/fail2ban restart
            echo "done."
        ;;
        restart)
            echo "Stopping firewall..."
            iptables_stop
            sleep 1
            echo "Starting firewall..."
            iptables_start
            sleep 1
            [[ ${FAIL2BAN_OK} == "ii" ]] && /etc/init.d/fail2ban restart
            echo "done."
        ;;
        stop)
            echo "Stopping firewall..."
            iptables_stop
            sleep 1
            [[ ${FAIL2BAN_OK} == "ii" ]] && /etc/init.d/fail2ban restart
            echo "done."
        ;;
        status)
            iptables -L --line-numbers -n > ${TMP}
            less ${TMP}
            if [ -f ${TMP} ] ; then
                rm ${TMP}
            fi
            exit 0
        ;;
        *)
            echo "Usage : $0 {start|stop|restart|status}"
            exit 1
        ;;
esac

exit 0

