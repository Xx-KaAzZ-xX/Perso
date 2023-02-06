#!/bin/bash

##Installation de python
ansible 192.168.56.11 -i inventaire -m apt -a "name=python" --become
ansible 192.168.56.12 -i inventaire -m dnf -a "name=python3" --become

##Changement du MOTD
ansible all -i inventaire -m copy -a "content=BONJOUR dest=/etc/motd" --become

##Installation apache
ansible 192.168.56.11 -i inventaire -m apt -a "name=apache2" --become
ansible 192.168.56.12 -i inventaire -m dnf -a "name=httpd" --become

##Upload du fichier index

ansible all -i inventaire -m copy -a "src=/home/vagrant/index.html dest=/var/www/html/index.html" --become

##redémarrage du service apache
ansible 192.168.56.11 -i inventaire -m service -a "name=apache2 state=started"
ansible 192.168.56.12 -i inventaire -m service -a "name=httpd state=started"

#ansible all -i inventaire -m reboot --become

exit 0
vagrant@deb
