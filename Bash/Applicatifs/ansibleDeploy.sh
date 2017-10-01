#!/bin/bash

#.  Script name : ansibleDeploy.sh
#.  Author: Aurélien DUBUS
#.  Description:  Deploy ansible user on a server
#.  Version : 1.0


sshPubKey="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGCsNSjzzrOnqNAhcV4GiTMn4Ld0wFCvhr4EG8osrr/8n/QyJub0ExPN8jN/dO5nzcYOG4sITXEeyjGD9NmUC6X1x59w8LMT8Ry9unvfK/ah1MgECP0EzUo6mF+TQIBDHQw0kKb68KKK6FDpKp3YEG06qVir3vzy1xqjKPV4rLLQUNBYHBGnBRlBaHdjTAd/Y4mkU20T7LeqUCpzxrJU6XhLHOtjqX9gbFfeBU9FoXQt+nQprv/acn4Zmok0K3M/ADVgynOmqrcQw2BBt59keo8D+UWs9na/Xel/MBOTPIyFQnaiOlEa3UuNycMdEUVoGaszMZMWHtp2COEt2flvIF ansible@ocs"
installPackage() {
    if [[ $(dpkg -l | awk '{print $1" "$2}' | grep " ${1}"$) != "ii ${1}" ]]; then
        log "Installation du package ${1}..."
        apt-get -y -q install "${1}" &> /dev/null
    else
        echo "Package ${1} already installed on your system."
    fi
}

installPackage sudo

if [ ! -d /home/ansible ]; then
  useradd -m -s /bin/bash ansible
  runuser -l ansible -c 'ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa'
  echo "ansible ALL=NOPASSWD: /bin/sh" >> /etc/sudoers
  cd /home/ansible/.ssh
  echo "${sshPubKey}" > authorized_keys

  echo -e "\nThink to add this host in the hosts list on the Ansible server."
else
  echo "User Ansible still exists."
  exit 1
fi

exit 0
