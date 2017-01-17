#!/bin/bash

##Postfix configuration##

dpkg -s postfix &>/dev/null || apt-get install postfix -y
cat >> /etc/postfix/main.cf << _EOF_ 
# See /usr/share/postfix/main.cf.dist for a commented, more complete version


# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc package for
# information on enabling SSL in the smtp client.

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_una                                     uth_destination
myhostname = debian
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = localhost.localdomain, debian, localhost.localdomain, localhost
relayhost = [smtp.gmail.com]:587
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_command = procmail -a "$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

##custom conf ##

# enable SASL authentication
smtp_sasl_auth_enable = yes
# disallow methods that allow anonymous authentication.
smtp_sasl_security_options = noanonymous
# where to find sasl_passwd
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
# Enable STARTTLS encryption
smtp_use_tls = yes
# where to find CA certificates
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
_EOF_

if [[ ! -f /etc/postfix/sasl_passwd ]] 
then
  echo "[smtp.gmail.com]:587 al3rte5@gmail.com:password" > /etc/postfix/sasl_passwd
fi

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
force_color_prompt=\"yes\"
PS1='${debian_chroot:+($debian_chroot)}\[\033[01;95m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '" >> /root/.bashrc
echo "
date=$(date)
who=$(who | tail -n1 | awk \'{print $5}\')
echo "Accès Shell root le ${date}" | mail -s "From ${who}" al3rte5@gmail.com" >> /root/.bashrc

echo "Think to do 
-source /root/.bashrc
-Change /etc/postfix/sasl_passwd and postmap it
"

exit 0
