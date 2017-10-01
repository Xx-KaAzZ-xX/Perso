#!/bin/bash


echo "Filebeat installation..."

##Installation
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list
apt-get update && apt-get install filebeat
update-rc.d filebeat defaults 95 10

##Configuration

##Get logs file to send to logstash server
log_file=("access.log" "error.log" "fpm-php.log" "ssl_access.log" "ssl_error.log")
tmp1="/tmp/tmp1.txt"
logstash_server="logs02.xprogress.net"
log_file_to_send="/tmp/tmp2.txt"
filebeat_file="/etc/filebeat/filebeat.yml"

if [ -f $log_file_to_send ];then
  rm $log_file_to_send
fi

ls /home > $tmp1


##Get the log files to send

cat $tmp1 | while read line
do
  log_dir=$(find /home/$line/ -type d -name "logs")
  #find /home/$line/ -type d -name "logs"
  echo $log_dir
  for i in "${log_file[@]}"
  do
    if [ -f $log_dir/$i ];then
      echo "$log_dir/$i" >> $log_file_to_send
    fi
  done
done

mv $filebeat_file $filebeat_file.bak

mkdir -p /etc/pki/tls/certs/

cat >>/etc/pki/tls/certs/logstash.crt << _cert_
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIJAP3LRs2g89h4MA0GCSqGSIb3DQEBCwUAMB8xHTAbBgNV
BAMMFGxvZ3MwMi54cHJvZ3Jlc3MubmV0MB4XDTE3MDgzMDEyNTc1MVoXDTI3MDgy
ODEyNTc1MVowHzEdMBsGA1UEAwwUbG9nczAyLnhwcm9ncmVzcy5uZXQwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCijECLYMujkeB+a0/gFtKvzhFU6Qh5
G9l9pgFR2D7wYFwawWSmkKD/pK90Z+OiMP5cDZt9yDntIis4GAsz1IPv/0d3pwtQ
Gd5PB6WLZB2tfynjVnHxJPldVFJ3ME/adgK0vfmXROw7Sc+rU88BO2udebjeiZrt
geNTvrmCeRsbbQgMucEtFHvgooG1l/o+deSLfsXSngCJfvmxr5CpgQiAknW0lQw6
YWAPPqnfrq1vbx+kkmBmj6lSocW1Fm/c2h2z6asqEkty0r4MpMBipAcgawRby5cz
uf+S7amE1SwXPTs6p/F3q4mqzVUEPtm9QvR2eJButF/y2j4nHuW2io+tAgMBAAGj
UDBOMB0GA1UdDgQWBBTqptZhJ7KP7Wwd2/nOMHMa405uVjAfBgNVHSMEGDAWgBTq
ptZhJ7KP7Wwd2/nOMHMa405uVjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQB3q78vIBVkyZae2Jzvfuei6qgMzT2O/6BhjvRE6OAyseYvxkDFML22mrfh
VHK7tbrLuyG7yOOgFEafOz2oF2pw1co1YQ5F1ci6836KGlIst+FcvEJ1+hjLW9cB
dWWv/U8q9t0wKsWcA6OoNTKIHRxKiCTeL85ZxmaEjRQeMmN16o3stZFy1RQN6VPa
kl93u6iAVuRA/aTKljfhmFTbPnLDcFr0XDqEQ0Feq2Jvopg4gUa4+zO+DxVue9Mo
VXCQ1eOGh5/tMP2+YK62jb9otjoCeermrJj4kY40Wb/rKhqYF1pjeoGyrKlOR9tv
QN7Rd2lw/dgVbEkPIDqiwSaQPsmJ
-----END CERTIFICATE-----
_cert_

#Format log_file_to_send for filebeat conf file
sed -i -e 's/^/-\ /' $log_file_to_send
final=$(cat $log_file_to_send)
cat >> $filebeat_file << _EOF_

############################# Filebeat ######################################
filebeat:
  prospectors:
    -
      paths:
        ${final}

      input_type: log

      document_type: syslog


  registry_file: /var/lib/filebeat/registry

output:
  ### Logstash as output
  logstash:
    # The Logstash hosts
    hosts: ["${logstash_server}:5044"]
    #hosts: ["logs02.xprogress.net:5044"]

    # Number of workers per Logstash host.
    #worker: 1

    # The maximum number of events to bulk into a single batch window. The
    # default is 2048.
    bulk_max_size: 1024

    # Set gzip compression level.
    #compression_level: 3

    # Optional load balance the events between the Logstash hosts
    #loadbalance: true

    # Optional index name. The default index name depends on the each beat.
    # For Packetbeat, the default is set to packetbeat, for Topbeat
    # top topbeat and for Filebeat to filebeat.
    #index: filebeat

    # Optional TLS. By default is off.
    tls:
      # List of root certificates for HTTPS server verifications
      certificate_authorities: ["/etc/pki/tls/certs/logstash.crt"]

      # Certificate for TLS client authentication
      #certificate: "/etc/pki/client/cert.pem"

      # Client Certificate Key
      #certificate_key: "/etc/pki/client/cert.key"

      # Controls whether the client verifies server certificates and host name.
      # If insecure is set to true, all server host names and certificates will be
      # accepted. In this mode TLS based connections are susceptible to
      # man-in-the-middle attacks. Use only for testing.
      #insecure: true

      # Configure cipher suites to be used for TLS connections
      #cipher_suites: []

      # Configure curve types for ECDHE based cipher suites
      #curve_types: []

############################# Logging #########################################

# There are three options for the log ouput: syslog, file, stderr.
# Under Windos systems, the log files are per default sent to the file output,
# under all other system per default to syslog.
logging:

  # Send all logging output to syslog. On Windows default is false, otherwise
  # default is true.
  #to_syslog: true

  # Write all logging output to files. Beats automatically rotate files if rotateeverybytes
  # limit is reached.
  #to_files: false

  # To enable logging to files, to_files option has to be set to true
  files:
    # The directory where the log files will written to.
    #path: /var/log/mybeat

    # The name of the files where the logs are written to.
    #name: mybeat

    # Configure log file size limit. If limit is reached, log file will be
    # automatically rotated
    rotateeverybytes: 10485760 # = 10MB

    # Number of rotated log files to keep. Oldest files will be deleted first.
    #keepfiles: 7

  # Enable debug output for selected components. To enable all selectors use ["*"]
  # Other available selectors are beat, publish, service
  # Multiple selectors can be chained.
  #selectors: [ ]

  # Sets log level. The default log level is error.
  # Available log levels are: critical, error, warning, info, debug
  #level: error

_EOF_

##Rajouter ce bloc dans /etc/init.d/firewall des servs en prod

if [ -f /etc/init.d/firewall ];then
	mv /etc/init.d/firewall /etc/init.d/firewall.bak
	cat >> /etc/init.d/firewall << _EOF2_
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




FAIL2BAN_OK=$(dpkg --list | grep fail2ban | awk '{print $1}')
#DOS2UNIX_OK=$(dpkg --list | grep dos2unix | awk '{print $1}')
SSH_PORT=$(egrep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
TMP="/tmp/_iptables.txt"
## ! IP des serveurs de monitoring !
MONITORING_IP_LIST=("80.12.83.108" "37.59.3.119")
## IP publique du serveur
SERVER_IP=$(ifconfig eth0 | egrep "inet " | cut -d: -f2 | cut -d" " -f1)

###############
#  Fonctions  #
###############

#On verifie si fail2ban est installe
fail2ban_present() {
    echo -e "Fail2ban est-il installe ? : ${FAIL2BAN_OK}"
    if [[ ${FAIL2BAN_OK} != "ii" ]] ; then
        echo -e "\nFail2ban n'est pas installé. Démarrage de l'installation..."
        echo -e "aptitude install fail2ban"
        aptitude -y install fail2ban 2>&1 /dev/null
        echo -e "Installation de Fail2ban : [OK]"
    fi
}

dos2unix_present() {
        echo -e "dos2unix est-il installe ? : ${DOS2UNIX_OK}"
    if [[ ${DOS2UNIX_OK} != "ii" ]] ; then
            echo -e "\ndos2unix n'est pas installé. Démarrage de l'installation..."
        echo -e "aptitude install dos2unix"
        aptitude -y install dos2unix 2>&1 /dev/null
        echo -e "Installation de dos2unix : [OK]"
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
        #dos2unix_present
        # Vider les tables actuelles
        iptables -t filter -F
        # Vider les regles personnelles
        iptables -t filter -X
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
        iptables -t filter -A OUTPUT -p tcp --dport 22 -j ACCEPT

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
        #iptables -t filter -A INPUT -p udp --dport 123 -j ACCEPT

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
        modprobe nf_conntrack_ftp # ligne facultative avec les serveurs OVH
        iptables -t filter -A INPUT -p tcp --dport 20:21 -j ACCEPT
        iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

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

logstash_connexion() {

        iptables -t filter -A INPUT -p tcp --dport 5044 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 5044 -j ACCEPT

        echo "Autorisation des connexions Logstash : [OK]"
}

mysql_connexion() {
        #---------------------------------------------------------------------
        # MYSQL
        #---------------------------------------------------------------------
        # Mysql In/Out
        iptables -t filter -A INPUT -p tcp --dport 3306 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 3306 -j ACCEPT

        echo "Autorisation des connexions MYSQL : [OK]"
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

munin_connexion() {
        #---------------------------------------------------------------------
        # Munin-node
        #---------------------------------------------------------------------
        # Autorissation de connexion à Munin-node
        for monitor_ip  in "${MONITORING_IP_LIST[@]}"
        do
          iptables -t filter -A INPUT -p tcp --dport 4949 -s ${monitor_ip} -j ACCEPT
          iptables -t filter -A OUTPUT -p tcp --dport 4949 -s ${monitor_ip} -j ACCEPT
        done

        echo "Autorisation des connexions Munin-node : [OK]"
}

zend_connexion() {
        #---------------------------------------------------------------------
        # Zend Server
        #---------------------------------------------------------------------
        for monitor_ip  in "${MONITORING_IP_LIST[@]}"
        do
          iptables -t filter -A INPUT -p tcp --dport 10081 -s ${monitor_ip} -j ACCEPT
          iptables -t filter -A OUTPUT -p tcp --dport 10081 -s ${monitor_ip} -j ACCEPT
        done

        echo "Autorisation des connexions Zend Server : [OK]"
}

phpmyadmin_connexion() {
        #---------------------------------------------------------------------
        # PHPMYADMIN
        #---------------------------------------------------------------------
        iptables -t filter -A INPUT -p tcp --dport 8888 -j ACCEPT
        iptables -t filter -A OUTPUT -p tcp --dport 8888 -j ACCEPT

        echo "Autorisation des connexions Phpmyadmin : [OK]"
}

blocked_ip() {
        #----------------------------------------------------------------------
        # List of Banned IP providing from Hackers
        #----------------------------------------------------------------------
        TMP_IP_BAN="/tmp/ip_to_ban.txt"
        TMP_IP_BAN2="/tmp/ip_to_ban2.txt"
        cd /tmp/
        if [[ -f ${TMP_IP_BAN} || -f ${TMP_IP_BAN2} ]]; then
                rm ${TMP_IP_BAN} 2> /dev/null ; rm ${TMP_IP_BAN2} 2> /dev/null
        fi
        wget -q --no-check-certificate https://svn.code.sf.net/p/admin-scripts/code/trunk/Banned/ip_to_ban.txt
        #dos2unix ${TMP_IP_BAN}
        cat ${TMP_IP_BAN} | tr -d '\r' > ${TMP_IP_BAN2}
        iptables -N BANNED-IP
        iptables -I FORWARD 1 -j BANNED-IP
        iptables -I INPUT 1 -j BANNED-IP
        while read line
        do
        iptables -A BANNED-IP --src ${line} -j DROP
        done < ${TMP_IP_BAN2}
        if [[ -f ${TMP_IP_BAN} || -f ${TMP_IP_BAN2} ]]; then
                rm ${TMP_IP_BAN} 2> /dev/null ; rm ${TMP_IP_BAN2} 2> /dev/null
        fi
        echo "Blocage des IPs bannies : [OK]"
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
        apache_connexion
        ddos_prevention
        ftp_connexion
        smtp_connexion
        #mysql_connexion
        nagios_connexion
        logstash_connexion
        #munin_connexion
        #zend_connexion
        phpmyadmin_connexion
        blocked_ip
        block_port_scan
        #block_https_for "toto.com" "titi.com" "blop.com"
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

_EOF2_

/etc/init.d/firewall restart

exit 0
