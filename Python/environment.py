#!/usr/bin/python


#. Description: Script d'analyse d'environnement à partir d'un point de montage
#. Requirements : 
#- hayabusa in the folder of the script
#- regripper in the folder of the script
#- python-regristry

import platform
import pandas as pd
import struct
import os
import ipaddress
import re
import time
import yaml
import gzip
import locale
import subprocess
from collections import OrderedDict
#from tabulate import tabulate
from datetime import datetime, timedelta
import sys
from pathlib import Path
from Registry import Registry
from Evtx.Evtx import Evtx
from lxml import etree
import csv
import shutil
import glob
import sqlite3

# Chemin vers le système de fichiers monté
script_name = sys.argv[0]

def usage():
    print("Exemple : python " + script_name + " /mnt/root")

# Déclarer la variable globale pour le répertoire courant original
original_cwd_fd = None

def chroot_and_run_command(mount_path, command):
    """Exécute une commande dans un environnement chrooté."""
    result = subprocess.run(
        ['chroot', mount_path, 'bash', '-c', command],
        capture_output=True, text=True
    )
    return result.stdout, result.stderr

def get_windows_timestamp(win_timestamp):
    # Date de référence pour les timestamps Windows : 1er janvier 1601
    windows_epoch = datetime(1601, 1, 1)

    # Le timestamp de Windows est en 100 nanosecondes, on le convertit en secondes
    seconds = win_timestamp / 10**7

    # On ajoute ces secondes à la date de référence
    final_date = windows_epoch + timedelta(seconds=seconds)

    return final_date


# Fonction pour récupérer les informations système
def get_system_info(mount_path):
    output_file = script_path + "/" + result_folder + "/linux_system_info.csv"
    print("[+] Retrieving System information ...")
    try:
        # Get computer name from /etc/hostname
        installation_date = ''
        last_event = ''
        hostname_file = os.path.join(mount_path, "etc/hostname")
        if os.path.exists(hostname_file):
            with open(hostname_file) as f:
                computer_name = f.read().strip()
                #return computer_name

        # Get distribution from /etc/os-release
        distro_file = os.path.join(mount_path, "etc/os-release")
        if os.path.exists(distro_file):
            with open(distro_file) as f:
                for line in f:
                    if line.startswith("ID="):
                        distro = line.strip().split("=")[1].strip('"')
                        #break
         # Extraction des DNS à partir de resolv.conf
        resolv_file = os.path.join(mount_path, "etc/resolv.conf")
        ntp_file = os.path.join(mount_path, "etc/ntp.conf")
        dns_servers = []
        if os.path.exists(resolv_file):
            with open(resolv_file) as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])  # Ajoute le serveur DNS à la liste
         # Si vous voulez stocker tous les serveurs DNS dans une seule chaîne pour 'system_info'
            if dns_servers:
                dns_server = ', '.join(dns_servers)  # Joindre les serveurs par des virgules
        # Extraction du serveur NTP à partir de ntp.conf
        ntp_server = None
        if os.path.exists(ntp_file):
            with open(ntp_file) as f:
                for line in f:
                    if line.startswith('server'):
                        ntp_server = line.split()[1]


        # Get last update
        log_installation_file = os.path.join(mount_path, "var/log/installer/syslog")
        if os.path.exists(log_installation_file):
            log_installation_file_infos = os.stat(log_installation_file)
            timestamp = log_installation_file_infos.st_ctime
            last_update = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        # Get installation_date
        passwd_file = os.path.join(mount_path, "etc/passwd")
        if os.path.exists(passwd_file):
            passwd_file_infos = os.stat(passwd_file)
            timestamp = passwd_file_infos.st_ctime
            installation_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

        # Get last event (this could be tailored depending on the log type)
        last_event_log = os.path.join(mount_path, "var/log/syslog")  # Example for Ubuntu/Debian
        if os.path.exists(last_event_log):
            last_log_infos = os.stat(last_event_log)
            timestamp = last_log_infos.st_mtime
            last_event = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

        last_update_file = ""
        if distro in ["debian", "ubuntu", "kali"]:
            log_path = os.path.join(mount_path, "var/log/apt/history.log")

            if not os.path.exists(log_path):
                print(f"Log file for updates not found for {distro}.")
                return None

            last_update = None

            with open(log_path, "r") as log_file:
                for line in log_file:
                    if "Start-Date" in line:
                        # Extract the date
                        date_str = line.split("Start-Date: ")[-1].strip()
                        # Parse the date to datetime object
                        last_update = datetime.strptime(date_str, "%Y-%m-%d  %H:%M:%S")

        elif distro in ["rhel", "centos", "fedora", "almalinux"]:
              log_path = os.path.join(mount_path, "var/log/yum.log")

              if not os.path.exists(log_path):
                  print(f"Log file for updates not found for {distro}.")
                  return None

              last_update = None

              with open(log_path, "r") as log_file:
                  for line in log_file:
                      if "Updated" in line:
                          # Extract the date (example format: 'Jan 01 12:34:56')
                          date_str = line[:15].strip()
                          # Parse the date to datetime object
                          last_update = datetime.strptime(date_str, "%b %d %H:%M:%S")

       # Output results to CSV
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['computer_name', 'distro', 'installation_date', 'ntp_server', 'dns_server', 'last_update', 'last_event']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            #writer.writerow(system_info)
            writer.writerow({'computer_name': computer_name, 'distro': distro, 'installation_date': installation_date, 'ntp_server': ntp_server, 'dns_server': dns_server, 'last_update': last_update, 'last_event': last_event})

        print(f"System information have been written to {output_file}")

        return computer_name

    except Exception as e:
        print("An error occurred while gathering system information:", e)

def get_network_info(mount_path, computer_name):

    output_file = script_path + "/" + result_folder + "/linux_network_info.csv"
    print("[+] Retrieving Network information...")
    # Chemins potentiels pour les fichiers de configuration réseau
    interfaces_file = os.path.join(mount_path, "etc/network/interfaces")
    netplan_dir = os.path.join(mount_path, "etc/netplan/")
    redhat_ifcfg_dir = os.path.join(mount_path, "etc/sysconfig/network-scripts/")

        # Préparation pour l'écriture dans le fichier CSV
    csv_columns = ['computer_name', 'interface', 'ip_address', 'netmask', 'gateway']
    iface, ip, netmask, gateway = None, None, None, None
    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        try:
            # Extraction des informations des interfaces
            if os.path.exists(interfaces_file):
                print(f"Trying with {interfaces_file}") 
                with open(interfaces_file) as f:
                    #iface, ip, netmask, gateway = None, None, None, None
                    for line in f:
                        line = line.strip()
                        if line.startswith('iface'):
                            iface = line.split()[1]
                        if 'address' in line:
                            ip = line.split()[1]
                        if 'netmask' in line:
                            netmask = line.split()[1]
                        if 'gateway' in line:
                            gateway = line.split()[1]
                    if iface:
                        writer.writerow({'computer_name': computer_name, 'interface' : iface, 'ip_address': ip, 'netmask': netmask, 'gateway' : gateway})

        # Extraction des informations pour RedHat (ifcfg)
            elif os.path.exists(redhat_ifcfg_dir):
                for filename in os.listdir(redhat_ifcfg_dir):
                    #print(f"Trying with {filename}")
                    if filename.startswith('ifcfg-'):
                        with open(os.path.join(redhat_ifcfg_dir, filename)) as f:
                            iface, ip, netmask, gateway = None, None, None, None
                            for line in f:
                                if line.startswith('DEVICE'):
                                    iface = line.split('=')[1].strip()
                                if line.startswith('IPADDR'):
                                    ip = line.split('=')[1].strip()
                                if line.startswith('NETMASK'):
                                    netmask = line.split('=')[1].strip()
                                if line.startswith('GATEWAY'):
                                    gateway = line.split('=')[1].strip()
                            if iface:
                                writer.writerow({'computer_name': computer_name, 'interface' : iface, 'ip_address': ip, 'netmask': netmask, 'gateway' : gateway})

            elif os.path.exists(netplan_dir):
                for filename in os.listdir(netplan_dir):
                    if filename.endswith('.yaml') or filename.endswith('.yml'):  # Vérifier que c'est un fichier YAML
                        print(f"Trying with {filename}")
                        with open(os.path.join(netplan_dir, filename), 'r') as f:
                            netplan_config = yaml.safe_load(f)  # Charger le contenu YAML
                            # Accéder à la configuration des réseaux
                            if 'network' in netplan_config and 'ethernets' in netplan_config['network']:
                                for iface, iface_config in netplan_config['network']['ethernets'].items():
                                    # Récupérer l'adresse IP et le masque
                                    ip_info = iface_config.get('addresses', [])
                                    if ip_info:
                                        # Supposons qu'il y ait une seule adresse IP configurée
                                        ip_mask = ip_info[0]  # Prendre la première adresse
                                        ip, netmask = ip_mask.split('/')  # Séparer l'adresse IP du masque
                                        # Récupérer la passerelle
                                        gateway = None
                                    if 'routes' in iface_config:
                                        for route in iface_config['routes']:
                                            if 'to' in route and route['to'] == 'default':
                                                gateway = route['via']

                            writer.writerow({'computer_name': computer_name, 'interface': iface, 'ip_address': ip, 'netmask': netmask, 'gateway': gateway})
            print(f"Network information has been written to {output_file}")
        except Exception as e:
            print(f"Error retrieving Linux network information : {e}")


# Fonction pour récupérer les informations de stockage
def get_storage_info(mount_path):
    try:
        # à voir si ça marche vraiment avec un filesystem monté sur le système
        disk_usage = os.popen("df -h " + mount_path).read()
    except Exception as e:
        print("Une erreur s'est produite lors de la récupération des informations de stockage :", e)
        return
    chaine = "Informations de stockage "
    print(bandeau(chaine))
    print(disk_usage)

def get_users_and_groups(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "linux_users_and_groups.csv"
    users = []
    groups = []
    print("[+] Retrieving users & groups informations")
    # Command to get users from /etc/passwd
    passwd_file = os.path.join(mount_path, "etc/passwd")
    group_file = os.path.join(mount_path, "etc/group")

    # Parse /etc/passwd to get users and their IDs
    with open(passwd_file, 'r') as passwd:
        for line in passwd:
            parts = line.strip().split(':')
            if len(parts) > 6:
                username = parts[0]
                uid = parts[2]
                gid = parts[3]
                user_info = {
                    'username': username,
                    'uid': uid,
                    'gid': gid,
                    'groups': []
                }
                users.append(user_info)

    # Parse /etc/group to get groups, group IDs, and members
    with open(group_file, 'r') as group:
        for line in group:
            parts = line.strip().split(':')
            if len(parts) > 3:
                groupname = parts[0]
                gid = parts[2]
                members = parts[3].split(',') if parts[3] else []
                groups.append({
                    'groupname': groupname,
                    'gid': gid,
                    'members': members
                })
                # Assign groups to users
                for user in users:
                    if user['username'] in members or user['gid'] == gid:
                        user['groups'].append(groupname)

    # Write to CSV
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['computer_name', 'username', 'uid', 'gid', 'groups']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for user in users:
            writer.writerow({
                'computer_name': computer_name,
                'username': user['username'],
                'uid': user['uid'],
                'gid': user['gid'],
                'groups': ','.join(user['groups'])
            })

    print(f"Users and groups information written to {output_file}")

def list_connections(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "linux_connections.csv"
    print("[+] Retrieving connection information...")

    csv_columns = ['computer_name', 'connection_date', 'user', 'scr_ip']
    # Ouvrir le fichier CSV pour écrire les informations
    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        counter = 0
        # Chemin vers les fichiers de log de connexion
        log_files_path = os.path.join(mount_path, "var/log")

        if not os.path.isdir(log_files_path):
            print("Log folder doesn't exist.")
            return

        log_files = os.listdir(log_files_path)

        # Parcourir les fichiers de log pour récupérer les adresses IP
        for log_file in log_files:
            log_file_path = os.path.join(log_files_path, log_file)

            # Traitement des fichiers auth.log ou secure.log
            if "auth.log" in log_file or "secure" in log_file:
                file_stat = os.stat(log_file_path)
                file_creation_year = time.localtime(file_stat.st_ctime).tm_year
                with open(log_file_path, encoding='ISO-8859-1') as file:
                    log_content = file.read()
                    for line in log_content.split("\n"):
                        if "sshd" in line and "Accepted" in line:
                            parts = line.split()
                            connection_date = " ".join(parts[0:3])  # Date de connexion
                            connection_date_with_year = f"{connection_date} {file_creation_year}"
                            user = parts[8]  # Utilisateur
                            scr_ip = parts[10]  # IP source
                            counter += 1
                            writer.writerow({'computer_name': computer_name, 'connection_date': connection_date_with_year, 'user': user, 'scr_ip': scr_ip})
                                       # Traitement des fichiers wtmp (via la commande last)
            if "wtmp" in log_file:
                last_cmd = f"last -F -f {log_file_path}"
                result_last = subprocess.run(last_cmd, shell=True, capture_output=True, text=True)

                for line in result_last.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 10:
                        connection_date = " ".join(parts[4:8])  # Date de connexion
                        user = parts[0]  # Utilisateur
                        if user == "reboot":
                            #print("belek")
                            continue
                        src_ip = parts[2]
                        #scr_ip = parts[-1] if parts[-1] != "::" else "local"  # IP source ou local
                        counter += 1
                        writer.writerow({'computer_name': computer_name, 'connection_date': connection_date, 'user': user, 'scr_ip': src_ip})
            # Vérification de l'existence du dossier audit et recherche des fichiers audit.log
            audit_dir = os.path.join(log_files_path, "audit")
            if os.path.isdir(audit_dir):
                audit_files = os.listdir(audit_dir)

                for audit_file in audit_files:
                    if "audit.log" in audit_file:
                        audit_file_path = os.path.join(audit_dir, audit_file)
                        zgrep_cmd = f"zgrep 'USER_LOGIN' {audit_file_path} | grep 'success'"
                        result_zgrep = subprocess.run(zgrep_cmd, shell=True, capture_output=True, text=True)

                        for line in result_zgrep.stdout.splitlines():
                            parts = line.split()
                            if "success" in parts:
                                connection_date = parts[0] + " " + parts[1]  # Date de connexion
                                user = parts[-4]  # Utilisateur
                                scr_ip = parts[-1]  # IP source
                                counter += 1
                                writer.writerow({'computer_name': computer_name, 'connection_date': connection_date, 'user': user, 'scr_ip': scr_ip})
    if counter >= 1:
        print(f"Connections informations have been written into {output_file}")
    else:
        print(f"No connections has been found, {output_file} is empty")


def list_installed_apps(mount_path, computer_name):
    distro_file = mount_path + "/etc/os-release"
    output_file = script_path + "/" + result_folder + "/linux_installed_apps.csv"
    print("[+] Retrieving installed apps...")

    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['computer_name', 'package_name', 'install_date']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        if os.path.exists(distro_file):
            with open(distro_file) as f:
                for line in f:
                    if line.startswith("ID="):
                        distro = line.strip().split("=")[1].strip('"')
                        break

            # Pour Debian/Ubuntu
            if distro in ["debian", "ubuntu", "kali"]:
                chroot_command = "zgrep 'install ' /var/log/dpkg.log* | sort | cut -f1,2,4 -d' '"
                result, _ = chroot_and_run_command(mount_path, chroot_command)

                if result:
                    for line in result.splitlines():
                        parts = line.split()
                        if len(parts) == 3:
                            install_date = parts[0] + " " + parts[1]
                            package_name = parts[2]
                            writer.writerow({'computer_name' : computer_name, 'package_name': package_name, 'install_date': install_date})

            # Pour RHEL/CentOS/Fedora/AlmaLinux
            elif distro in ["rhel", "centos", "fedora", "almalinux"]:
                chroot_command = "rpm -qa --queryformat '%{installtime:date} %{name}-%{version}-%{release}\n' | sort"
                result, _ = chroot_and_run_command(mount_path, chroot_command)

                if result:
                    for line in result.splitlines():
                        parts = line.split()
                        if len(parts) > 1:
                            install_date = " ".join(parts[:3])
                            package_name = parts[3]
                            writer.writerow({'computer_name' : computer_name, 'package_name': package_name, 'install_date': install_date})
                else:
                    print("No RPM packages found, checking yum logs.")

                    # Lister les logs yum pour récupérer les infos d'installation
                    yum_log_path = os.path.join(mount_path, "var/log/yum.log*")
                    yum_log_files = glob.glob(yum_log_path)

                    if yum_log_files:
                        for log_file in yum_log_files:
                            if log_file.endswith(".gz"):
                                with gzip.open(log_file, 'rt', encoding='utf-8') as f:
                                    result_logs = f.read()
                                    for line in result_logs.splitlines():
                                        if "Updated" in line or "Installed" in line:
                                            parts = line.split()
                                            install_date = " ".join(parts[:3])
                                            package_name = parts[-1]
                                            writer.writerow({'computer_name' : computer_name, 'package_name': package_name, 'install_date': install_date})
                            else:
                                with open(log_file, 'r', encoding='utf-8') as f:
                                    result_logs = f.read()
                                    for line in result_logs.splitlines():
                                        if "Updated" in line or "Installed" in line:
                                            parts = line.split()
                                            install_date = " ".join(parts[:3])
                                            package_name = parts[-1]
                                            writer.writerow({'computer_name' : computer_name, 'package_name': package_name, 'install_date': install_date})
                    else:
                        print("No yum logs found.")
            print(f"Linux installed apps informations have been written into {output_file}")
        else:
            print("Unknown distribution")


def list_services(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "linux_services.csv")
    init_path = os.path.join(mount_path, "usr/sbin/init")
    print("[+] Retrieving Services informations...")

    if os.path.exists(init_path):
        init_sys = os.path.basename(os.readlink(init_path))

        if init_sys == "systemd":
            chroot_command = "systemctl list-unit-files --type=service"
            stdout, stderr = chroot_and_run_command(mount_path, chroot_command)

            if stderr:
                print(f"Erreur: {stderr}")
                return

            # Traitement de la sortie
            services = []
            for line in stdout.splitlines()[1:]:  # Ignorer l'en-tête
                parts = line.split()
                if len(parts) == 3:  # service_name, 8tatus, status_at_boot
                    service_name = parts[0]
                    status = parts[1]
                    # Le statut au démarrage est généralement indiqué par la troisième colonne,
                    # si présente, sinon mettre une valeur par défaut ou gérer les erreurs.
                    status_at_boot = parts[2] if len(parts) > 2 else "unknown"
                    services.append((computer_name, service_name, status, status_at_boot))

            # Écrire dans le fichier CSV
            with open(output_file, mode='w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(['computer_name', 'service_name', 'status', 'status_at_boot'])  # En-tête
                csv_writer.writerows(services)

            print(f"Services informations has been written into {output_file}.")
        else:
            print("Not managed by Systemd")
    else:
        print("System is not managed by Systemd")


def get_firewall_rules(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "linux_firewall_rules.csv")
    csv_columns = ['computer_name', 'chain', 'target', 'prot', 'source', 'destination', 'port']
    print("[+] Retrieving Firewall Rules...")

    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()

            # Exécuter la commande iptables dans l'environnement chrooté
            iptables_command = "iptables -L -n"
            stdout, stderr = chroot_and_run_command(mount_path, iptables_command)

            if stderr:
                print(f"Error running iptables command: {stderr}")
                return

            rules = []
            current_chain = ""
            lines = stdout.splitlines()

            # Regex pour extraire les ports tcp ou udp
            port_regex = re.compile(r'(tcp|udp).*dpt:(\d+)')

            for line in lines:
                line = line.strip()
                if not line:
                    continue  # Ignorer les lignes vides

                parts = line.split()

                # Si la ligne commence par "Chain", c'est une nouvelle chaîne
                if line.startswith("Chain"):
                    current_chain = parts[1]  # On récupère le nom de la chaîne (INPUT, OUTPUT, etc.)
                    continue
                if line.startswith("target"):
                    continue

                # Si la ligne ne contient pas assez de colonnes, on l'ignore
                if len(parts) < 5:
                    continue

                # Extraire les informations de la ligne
                target = parts[0]
                protocol = parts[1]
                opt = parts[2]
                source = parts[3]
                destination = parts[4]

                # Chercher un port si applicable
                port = ""
                port_match = port_regex.search(line)
                if port_match:
                    protocol = port_match.group(1)
                    port = port_match.group(2)

                # Ajouter la règle à la liste
                rules.append({
                    'computer_name': computer_name,
                    'chain': current_chain,
                    'target': target,
                    'prot': protocol,
                    'source': source,
                    'destination': destination,
                    'port': port  # À adapter si nécessaire
                })

            # Écrire les règles dans le fichier CSV
            writer.writerows(rules)
            print(f"Firewall rules have been written into {output_file}")

    except Exception as e:
        print(f"An error occurred: {e}")


def get_linux_browsing_history(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "linux_browsing_history.csv"
    csv_columns = ['computer_name', 'source', 'user', 'link', 'search_date']
    print("[+] Retrieving browsing history")

    find_firefox_cmd = 'find . -type f -name "places.sqlite" '
    stdout, stderr = chroot_and_run_command(mount_path, find_firefox_cmd)
    firefox_file = stdout.strip()

    # Chemin du fichier temporaire
    temp_file = "/tmp/places_temp.sqlite"

    if not firefox_file:
        print("[-] No Firefox profile found.")
        return

    # Chemin complet du fichier 'places.sqlite' à partir de l'image montée
    firefox_profile_file = os.path.join(mount_path, firefox_file)
    firefox_profile_file = os.path.normpath(firefox_profile_file)

    try:
        # Copier le fichier places.sqlite dans /tmp
        shutil.copyfile(firefox_profile_file, temp_file)
        print(f"[+] Copied Firefox history to temporary file: {temp_file}")

        # Ouvrir le fichier CSV pour écrire les résultats
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()

            # Connexion à la copie temporaire de la base de données Firefox
            conn = sqlite3.connect(temp_file)
            cursor = conn.cursor()

            # Requête pour récupérer l'historique de navigation
            cursor.execute("""
                SELECT moz_places.url, moz_historyvisits.visit_date
                FROM moz_places, moz_historyvisits
                WHERE moz_places.id = moz_historyvisits.place_id
            """)
            firefox_rows = cursor.fetchall()

            # Traiter les résultats et les écrire dans le fichier CSV
            for row in firefox_rows:
                url, visit_time = row
                visit_date = convert_firefox_time(visit_time)
                writer.writerow({
                    'computer_name': computer_name,
                    'source': 'Firefox',
                    'user': 'kasper',  # Ajuste le nom de l'utilisateur si nécessaire
                    'link': url,
                    'search_date': visit_date
                })

            # Fermer la connexion à la base de données
            conn.close()
            print(f"Browsing history has been written into {output_file}")

    except Exception as e:
        print(f"Error processing Firefox history: {e}")

    finally:
        # Supprimer le fichier temporaire après utilisation
        if os.path.exists(temp_file):
            os.remove(temp_file)
            print(f"[+] Temporary file {temp_file} has been deleted.")

def get_windows_machine_name(mount_path):
    #chaine = "Informations du système Windows"
    #print (bandeau(chaine))
    user_input = input("Do you want to set computer name ? (y/N) ").strip().lower()
    if user_input == 'y':
        computer_name = input("Veuillez entrer le nom de la machine: ").strip()
        return computer_name
    else:
        path_to_reg_hive = (mount_path+ 'Windows/System32/config/SYSTEM')
        reg = Registry.Registry(path_to_reg_hive)
        try:
            key = reg.open("ControlSet001\\Control\\ComputerName\\ComputerName")
        except Registry.RegistryKeyNotFoundException:
            print("Couldn't find Computer Name. Script terminated.")
            sys.exit(1)

        for value in [v for v in key.values() \
                       if v.value_type() == Registry.RegSZ or \
                          v.value_type() == Registry.RegExpandSZ]:
    #result = print("%s: %s" % (value.name(), value.value()))
            if value.name() == "ComputerName":
                computer_name = value.value()
                return computer_name

def get_windows_storage_info(mount_path):
    try:
        # à voir si ça marche vraiment avec un filesystem monté sur le système
        disk_usage = os.popen("df -h " + mount_path).read()
    except Exception as e:
        print("Une erreur s'est produite lors de la récupération des informations de stockage :", e)
        return
    chaine = "Informations de stockage "
    print(bandeau(chaine))
    print(disk_usage)

def get_windows_mounted_devices(mount_path):
    path_to_reg_hive = mount_path + 'Windows/System32/config/SYSTEM'
    reg = Registry.Registry(path_to_reg_hive)

    try:
        key = reg.open("MountedDevices")
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the key. Exiting...")
        sys.exit(-1)

    for value in key.values():
        print(f"{value.name()}")


def get_windows_disk_volumes(mount_path):
    chaine = "Volumes de disque"
    print(bandeau(chaine))
    path_to_reg_hive = mount_path + 'Windows/System32/config/SYSTEM'
    reg = Registry.Registry(path_to_reg_hive)

    possible_disk_enum_path = [
        "CurrentControlSet\\Services\\Disk\\Enum",
        "ControlSet001\\Services\\Disk\\Enum",
        "CurrentControlSet\\MountedDevices",
        "ControlSet001\\MountedDevices",
        "CurrentControlSet\\Enum\\STORAGE\\Volume",
        "ControlSet001\\Enum\\STORAGE\\Volume"
    ]


    # Flag to check if any information is found
    found_any = False

    # Iterate over the possible paths
    for path in possible_disk_enum_path:
        try:
            key = reg.open(path)
            print(f"\nFound disk information in: {path}")
            found_any = True

            # Check if the key has subkeys (as in STORAGE\Volume or Disk\Enum)
            if len(key.subkeys()) > 0:
                for subkey in key.subkeys():
                    print(f"Subkey: {subkey.name()}")
                    for value in subkey.values():
                        print(f"{value.name()}: {value.value()}")
                    print("-" * 40)
            else:
                # If no subkeys, print values directly
                for value in key.values():
                    print(f"{value.name()}: {value.value()}")
                print("-" * 40)

        except Registry.RegistryKeyNotFoundException:
            print(f"Couldn't find the key at {path}. Continuing...")

    if not found_any:
        print("No disk information found in any path.")




def get_windows_info(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "windows_system_info.csv"  # Assurez-vous que result_folder est défini si nécessaire
    csv_columns = ['computer_name', 'windows_version', 'installation_date', 'ntp_server', 'last_update', 'last_event', 'keyboard_layout']

    # Initialisation des variables
    system_info = {
        'computer_name': computer_name,
        'windows_version': '',
        'installation_date': '',
        'ntp_server': '',
        'last_update': '',
        'last_event': '',
        'keyboard_layout': ''
    }
    print("[+] Retrieving system information...")
    # Récupération des informations NTP (dans le registre SYSTEM)
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SYSTEM')
    try:
        reg = Registry.Registry(path_to_reg_hive)
        ntp_key = reg.open("ControlSet001\\Services\\W32Time\\Parameters")
        for value in ntp_key.values():
            if value.name() == "NtpServer":
                system_info['ntp_server'] = value.value()
    except Exception as e:
        print(f"Erreur lors de la récupération des informations NTP: {e}")
    try:
        path_to_ntdat = os.path.join(mount_path, 'Users/Default/NTUSER.DAT')
        reg = Registry.Registry(path_to_ntdat)
        keyboard_key = reg.open("Keyboard Layout\\Preload")
        for value in keyboard_key.values():
            layout_hex = value.value()
            layout_int = int(layout_hex, 16)
            lang_code = locale.windows_locale.get(layout_int)
            if lang_code:
                system_info['keyboard_layout'] = lang_code
            else:
                lang_code = ""
                system_info['keyboard_layout'] = lang_code
    except Exception as e:
        print(f"Error retrieving keyboard layout : {e}")



    # Récupération des informations de produit et d'installation (dans le registre SOFTWARE)
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SOFTWARE')
    try:
        reg = Registry.Registry(path_to_reg_hive)
        key = reg.open("Microsoft\\Windows NT\\CurrentVersion")

        # Récupérer la version de Windows
        for value in key.values():
            if value.name() == "ProductName":
                system_info['windows_version'] = value.value()

        # Récupérer la date d'installation
        for value in key.values():
            if value.name() == "InstallDate":
                install_date_timestamp = value.value()
                date_time = datetime.fromtimestamp(install_date_timestamp)
                system_info['installation_date'] = date_time.strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        print(f"Erreur lors de la récupération des informations du produit ou de la date d'installation: {e}")

    # Récupération du dernier événement (last_event)
    try:
        last_event_log = os.path.join(mount_path, 'Windows/System32/winevt/Logs/System.evtx')
        if os.path.exists(last_event_log):
            last_log_infos = os.stat(last_event_log)
            timestamp = last_log_infos.st_mtime
            system_info['last_event'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
    except Exception as e:
        print(f"Erreur lors de la récupération du dernier événement: {e}")

        # Récupération de la dernière MAJ
    try:
        reg = Registry.Registry(os.path.join(mount_path, 'Windows/System32/config/SOFTWARE'))
        update_key = reg.open("Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install")
        for value in update_key.values():
            if value.name() == "LastSuccessTime":
                system_info['last_update'] = value.value()
    except Exception as e:
        print(f"Erreur lors de la récupération des informations de dernière mise à jour: {e}")



# Écriture des informations dans un fichier CSV
    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerow(system_info)
        print(f"System information has been written into {output_file}")
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier CSV: {e}")

def get_windows_network_info(mount_path, computer_name):
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SYSTEM')
    reg = Registry.Registry(path_to_reg_hive)
    output_file = script_path + "/" + result_folder + "/" + "windows_network_info.csv"
    print("[+] Retrieving network information")
    # Initialisation des données
    network_info = []

    try:
        key = reg.open("ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces")
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the network informations. Exiting...")
        return

    for subkey in key.subkeys():
        interface_name = subkey.name()
        ip_address = None
        netmask = None
        gateway = None
        dns_server = None

        for value in subkey.values():
            if value.name() == "DhcpIPAddress" or value.name() == "IPAddress":
                ip_address = value.value()
            elif value.name() == "SubnetMask":
                netmask = value.value()
            elif value.name() == "DefaultGateway":
                gateway = value.value()
            elif value.name() == "NameServer":
                dns_server = value.value()

        # Ajouter les informations de l'interface au tableau
        network_info.append({
            'computer_name': computer_name,
            'interface': interface_name,
            'ip_address': ip_address,
            'netmask': netmask,
            'gateway': gateway,
            'dns_server': dns_server
        })

    # Écriture dans le fichier CSV
    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['computer_name', 'interface', 'ip_address', 'netmask', 'gateway', 'dns_server'])
            writer.writeheader()
            writer.writerows(network_info)
        print(f"Network information has been written into {output_file}")
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier CSV: {e}")

def get_startup_services(mount_path, computer_name):
    # Registry path for services
    services_path = "ControlSet001\\Services"
    output_file = os.path.join(script_path, result_folder, "windows_services.csv")
    print("[+] Retrieving Windows Services information...")

    # Load the SYSTEM hive
    try:
        reg = Registry.Registry(os.path.join(mount_path, 'Windows/System32/config/SYSTEM'))
    except Exception as e:
        print(f"Error loading SYSTEM hive: {e}")
        return

    try:
        key = reg.open(services_path)
    except Registry.RegistryKeyNotFoundException:
        print(f"Couldn't find the services key at {services_path}. Exiting...")
        return

    # Open the output file to store the list of startup services
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['computer_name', 'service_name', 'start_type'])
        writer.writeheader()

        # Iterate through the service subkeys
        for subkey in key.subkeys():
            try:
                service_name = subkey.name()
                # Check for the "Start" value
                start_value = subkey.value("Start").value()

                # Determine the start type
                if start_value in [0, 1, 2]:  # Boot Start, System Start, Automatic
                    start_type = ""
                    if start_value == 0:
                        start_type = "Boot Start"
                    elif start_value == 1:
                        start_type = "System Start"
                    elif start_value == 2:
                        start_type = "Automatic Start"

                    # Write the service information to the CSV
                    writer.writerow({'computer_name': computer_name, 'service_name': service_name, 'start_type': start_type})
            except Registry.RegistryValueNotFoundException:
                # If "Start" value is not found, skip the service
                continue

    print(f"Windows services information has been written to {output_file}")


def get_windows_users(mount_path, computer_name):
    print("[+] Retrieving Windows Users informations...")
    try:
        sam_file = os.path.join(mount_path, 'Windows/System32/config/SAM')
        regripper_path = "/usr/bin/regripper"
        output_file = os.path.join(script_path, result_folder, "windows_users.csv")

        if os.path.exists(regripper_path):
            regripper_cmd = f"{regripper_path} -a -r {sam_file}"
            result_regripper = subprocess.run(regripper_cmd, shell=True, capture_output=True, text=True)
            output = result_regripper.stdout

            # Vérifiez si l'output est vide
            if not output.strip():
                print("[-] No output from regripper.")
                return

            lines = output.splitlines()
            users = []
            with open(output_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['computer_name', 'username', 'full_name', 'account_type', 'creation_date', 'last_login_date', 'login_count', 'rid'])
                writer.writeheader()
                user_info = {}  # Dictionnaire pour stocker les infos utilisateur
                for line in lines:
                    if "Username" in line:
                        if user_info:  # Si des données utilisateur sont déjà présentes, les ajouter avant de commencer un nouveau bloc
                            user_info["computer_name"] = computer_name  # Ajout du nom de l'ordinateur
                            users.append(user_info)
                            writer.writerow(user_info)
                            user_info = {}  # Réinitialiser pour le prochain utilisateur
                        username = line.split(":")[1].strip()
                        user_info["username"] = username
                    elif "Full Name" in line:
                        user_info["full_name"] = line.split(":")[1].strip()
                    elif "Account Type" in line:
                        user_info["account_type"] = line.split(":")[1].strip()
                    elif "Account Created" in line:
                        user_info["creation_date"] = line.split(":")[1].strip()
                    elif "Last Login Date" in line:
                        user_info["last_login_date"] = line.split(":")[1].strip()
                    elif "Login Count" in line:
                        user_info["login_count"] = line.split(":")[1].strip()
                    elif "Embedded RID" in line:
                        user_info["rid"] = line.split(":")[1].strip()

                if user_info:  # Ajouter les dernières données utilisateur
                    user_info["computer_name"] = computer_name
                    users.append(user_info)
                    writer.writerow(user_info)

        print(f"Users informations have been written into {output_file}")
    except Exception as e:
        print(f"Error : {e}")


def get_windows_groups(mount_path, computer_name):
    print("[+] Retrieving Windows Groups informations...")
    try:
        sam_file = os.path.join(mount_path, 'Windows/System32/config/SAM')
        regripper_path = "/usr/bin/regripper"
        output_file = os.path.join(script_path, result_folder, "windows_groups.csv")

        if os.path.exists(regripper_path):
            regripper_cmd = f"{regripper_path} -a -r {sam_file}"
            result_regripper = subprocess.run(regripper_cmd, shell=True, capture_output=True, text=True)
            output = result_regripper.stdout

            # Vérifiez si l'output est vide
            if not output.strip():
                print("[-] No output from regripper.")
                return

            lines = output.splitlines()
            groups = []
            with open(output_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['computer_name', 'groupname', 'last_write', 'users'])
                writer.writeheader()
                group_info = {}  # Dictionnaire pour stocker les infos groupes
                in_users_section = False  # Flag pour indiquer si on est dans la section "Users"
                users_list = []  # Liste des utilisateurs membres d'un groupe

                for line in lines:
                    line = line.strip()  # Nettoyer la ligne des espaces inutiles
                    # Vérifiez que la ligne contient bien un ":"
                    if ":" in line:
                        in_users_section = False  # Dès qu'on trouve un ":", on sort de la section "Users"
                        if "Group Name" in line:
                            if group_info:  # Ajouter les infos du groupe précédent
                                group_info["computer_name"] = computer_name  # Ajouter le nom de l'ordinateur
                                group_info["users"] = ";".join(users_list) if users_list else "None"  # Ajouter les membres
                                groups.append(group_info)
                                writer.writerow(group_info)
                                group_info = {}  # Réinitialiser pour le prochain groupe
                                users_list = []  # Réinitialiser la liste des utilisateurs
                            group_info["groupname"] = line.split(":")[1].strip()
                        elif "LastWrite" in line:
                            group_info["last_write"] = line.split(":")[1].strip()
                        elif "Users" in line:
                            users_value = line.split(":")[1].strip()
                            if users_value != "None":  # Si ce n'est pas "None", on commence à chercher les SIDs
                                in_users_section = True
                    elif in_users_section:  # On est dans la section "Users", on doit récupérer les SIDs
                        if line.startswith("S-1-"):  # Si la ligne commence par un SID
                            users_list.append(line)  # Ajouter le SID à la liste des utilisateurs

                # Ajouter le dernier groupe si nécessaire
                if group_info:
                    group_info["computer_name"] = computer_name
                    group_info["users"] = ";".join(users_list) if users_list else "None"
                    groups.append(group_info)
                    writer.writerow(group_info)

        print(f"Groups informations have been written into {output_file}")
    except Exception as e:
        print(f"Error: {e}")

def get_windows_firewall_rules(mount_path, computer_name):
    firewall_paths = [
        "ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
        "CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    ]
    print("[+] Retrieving Firewall rules...")
    output_file = os.path.join(script_path, result_folder, "windows_firewall_rules.csv")

    csv_columns = ['computer_name', 'action', 'active', 'direction', 'protocol', 'profile', 'srcport', 'dstport', 'app', 'svc', 'rule_name', 'desc', 'embedctxt']

    try:
        reg = Registry.Registry(os.path.join(mount_path, 'Windows/System32/config/SYSTEM'))
    except Exception as e:
        print(f"Error loading SYSTEM hive: {e}")
        return

    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()

        for path in firewall_paths:
            try:
                key = reg.open(path)
            except Registry.RegistryKeyNotFoundException:
                print(f"Couldn't find the key {path}. Continuing...\n")
                continue

            for value in key.values():
                rule_data = value.value().split('|')
                rule_dict = {}

                # Mapping fields to appropriate columns
                for item in rule_data:
                    if '=' in item:
                        k, v = item.split('=', 1)
                        # Mapping the keys to the corresponding CSV columns
                        if k == 'Action':
                            rule_dict['action'] = v
                        elif k == 'Active':
                            rule_dict['active'] = v
                        elif k == 'Dir':
                            rule_dict['direction'] = v
                        elif k == 'Protocol':
                            rule_dict['protocol'] = v
                        elif k == 'Profile':
                            rule_dict['profile'] = v
                        elif k == 'LPort':
                            rule_dict['srcport'] = v
                        elif k == 'RPort':
                            rule_dict['dstport'] = v
                        elif k == 'App':
                            rule_dict['app'] = v
                        elif k == 'Svc':
                            rule_dict['svc'] = v
                        elif k == 'Name':
                            rule_dict['rule_name'] = v
                        elif k == 'Desc':
                            rule_dict['desc'] = v
                        elif k == 'EmbedCtxt':
                            rule_dict['embedctxt'] = v

                # Add the computer name to the row
                rule_dict['computer_name'] = computer_name

                # Write the row to CSV, filling missing fields with empty strings
                writer.writerow({col: rule_dict.get(col, '') for col in csv_columns})

    print(f"Firewall rules written to {output_file}")

def get_windows_installed_roles(mount_path, computer_name):
    #chaine = "Windows Installed Roles"
    #print(bandeau(chaine))
    # Définir le chemin du registre
    output_file = script_path + "/" + result_folder + "/" + "windows_roles.csv"
    #print(f"Role/Feature: {subkey.name()}")
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SOFTWARE')
    reg = Registry.Registry(path_to_reg_hive)
    print("[+] Retrieving Windows Roles informations...")

    # Définir le chemin de la clé de registre pour les rôles et fonctionnalités installés
    key_path = 'Microsoft\\ServerManager\\ServicingStorage\\ServerComponentCache'
    csv_columns = ['computer_name','role_name', 'install_state']
    try:
        key = reg.open(key_path)
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the key. Exiting...")
        return

    try:
        # Parcourir les sous-clés
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for subkey in key.subkeys():
                install_state = None
                role_name = subkey.name()
                try:
                    if subkey.values():
                    #print(f"there is value in {role_name}")
                    # Parcourir les valeurs de chaque sous-clé pour trouver 'InstallState'
                        for value in subkey.values():
                            if value.name() == "InstallState":
                                install_state = value.value()
                            continue
                        writer.writerow({'computer_name': computer_name, 'role_name': role_name, 'install_state': install_state})
                    else:
                        continue
                        writer.writerow({'computer_name': computer_name, 'role_name': role_name, 'install_state': 'No value'})
                except Exception as e_bis:
                    writer.writerow({'computer_name': computer_name, 'role_name': role_name, 'install_state': 'No value'})
            print(f"Roles information have been written into {output_file}")
    except Exception as e:
        print(f"Error retrieving roles information : {e}")

'''
def get_windows_installed_programs(mount_path, computer_name):
    installed_programs_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    ]

    output_file = script_path + "/" + result_folder + "/" + "windows_installed_programs.csv"
    csv_columns = ['computer_name', 'DisplayName', 'DisplayVersion', 'InstallDate', 'Publisher']
    print("[+] Retrieving installed programs")

    try:
        reg = Registry.Registry(os.path.join(mount_path, 'Windows/System32/config/SOFTWARE'))
    except Exception as e:
        print(f"Error loading SOFTWARE hive: {e}")
        return

    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()

        for path in installed_programs_paths:
            try:
                key = reg.open(path)
            except Registry.RegistryKeyNotFoundException:
                print(f"Couldn't find the key {path}. Continuing...\n")
                continue

            try:
                # Capturer l'erreur lors de la tentative d'accès aux sous-clés
                subkeys = key.subkeys()
            except Exception as e:
                print(f"Error retrieving subkeys from {path}: {e}")
                continue

            for subkey in subkeys:
                try:
                    program_info = {
                        'computer_name': computer_name,
                        'DisplayName': '',
                        'DisplayVersion': '',
                        'InstallDate': '',
                        'Publisher': ''
                    }

                    for value in subkey.values():
                        if value.name() == 'DisplayName':
                            program_info['DisplayName'] = value.value()
                        elif value.name() == 'DisplayVersion':
                            program_info['DisplayVersion'] = value.value()
                        elif value.name() == 'InstallDate':
                            program_info['InstallDate'] = value.value()
                        elif value.name() == 'Publisher':
                            program_info['Publisher'] = value.value()

                    if program_info['DisplayName']:  # Only write if there is a program name
                        writer.writerow(program_info)

                except Exception as subkey_error:
                    print(f"Error processing subkey {subkey.name()}: {subkey_error}")
                    continue  # Skip this subkey if there's an issue

    print(f"Installed programs have been written into {output_file}")
'''

def get_windows_installed_programs(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "windows_installed_programs.csv"
    software_file = os.path.join(mount_path, 'Windows/System32/config/SOFTWARE')
    csv_columns = ['computer_name', 'program_name', 'program_version', 'install_date']
    print("[+] Retrieving installed programs")

    regripper_path = "/usr/bin/regripper"  # Chemin vers regripper
    try:
        regripper_cmd = f"{regripper_path} -p uninstall -r {software_file}"
        result_regripper = subprocess.run(regripper_cmd, shell=True, capture_output=True, text=True)
        output = result_regripper.stdout

        # Vérifiez si l'output est vide
        if not output.strip():
            print("[-] No output from regripper.")
            return

        # Décomposition de l'output en lignes
        lines = output.splitlines()
        programs = []
        install_date = None

        # Parcourir les lignes pour extraire les informations
        for line in lines:
            line = line.strip()

            # Identifier les lignes contenant les dates d'installation
            if "Z" in line and line.endswith("Z"):
                install_date = line.strip()
            elif "v." in line:
                # Extraction du nom et de la version du programme
                try:
                    program_name, program_version = line.rsplit(" v.", 1)
                    program_name = program_name.strip()
                    program_version = program_version.strip()

                    # Ajout des informations à la liste des programmes
                    programs.append({
                        'computer_name': computer_name,
                        'program_name': program_name,
                        'program_version': program_version,
                        'install_date': install_date
                    })
                except ValueError:
                    continue  # Ignore toute ligne qui ne correspond pas au format attendu

        # Écriture des informations dans le fichier CSV
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerows(programs)

        print(f"[+] Installed programs have been written into {output_file}")

    except Exception as e:
        print(f"Error running regripper or writing output: {e}")
        return



def get_windows_executed_programs(amcache_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "windows_executed_programs.csv"
    csv_columns = ['computer_name', 'filepath', 'executed_date']
    print("[+] Retrieving executed programs")

    # Ouvrir le fichier de registre Amcache.hve
    try:
        reg = Registry.Registry(amcache_path)
    except Exception as e:
        print(f"Error opening Amcache.hve: {e}")
        return

    # Ouvrir la clé Root\File qui contient les informations sur les exécutables
    try:
        key = reg.open("Root\\File")
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the Amcache key. Exiting...")
        return

    with open(output_file, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()

        # Parcourir et lister les sous-clés de Root\File
        for subkey in key.subkeys():
            program_info = {
                'computer_name': computer_name,
                'filepath': '',
                'executed_date': ''
            }
            try:
                # Parcourir et lister les sous-clés de cette sous-clé
                for sub_subkey in subkey.subkeys():
                    for value in sub_subkey.values():
                        # print(f"{value.name()}")
                        # print(f"{value.value()}")
                        if value.name() == "17":
                            win_timestamp = (value.value())
                            #print("Executed date: " + str(get_windows_timestamp(win_timestamp)))
                            program_info['executed_date'] = str(get_windows_timestamp(win_timestamp))
                        if value.name() == "15":
                            #print(f"Filepath : {value.value()}")
                            program_info['filepath'] = (value.value())
                    if program_info['filepath']:
                        writer.writerow(program_info)
            except Registry.RegistryKeyNotFoundException as e:
                print(f"Error accessing subkeys of {subkey.name()}: {e}")
                continue
    print(f"Executed programs have been written into {output_file}")


def convert_chrome_time(chrome_timestamp):
    """ Convert Webkit timestamp (microseconds since 1601) to human-readable date. """
    epoch_start = datetime(1601, 1, 1)
    return epoch_start + timedelta(microseconds=chrome_timestamp)

def convert_firefox_time(firefox_timestamp):
    """ Convert Unix timestamp in microseconds to human-readable date. """
    return datetime.utcfromtimestamp(firefox_timestamp / 1000000)

def get_windows_browsing_history(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "windows_browsing_history.csv"
    csv_columns = ['computer_name', 'source', 'user', 'link', 'search_date']
    print("[+] Retrieving browsing history")
    temp_file = "/tmp/places_temp.sqlite"

    # Ouvrir le fichier CSV pour écrire les résultats
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()

        # Parcourir les utilisateurs dans le répertoire Users
        users_dir = os.path.join(mount_path, 'Users')
        for user in os.listdir(users_dir):
            user_dir = os.path.join(users_dir, user)

            # 1. Google Chrome
            chrome_history_path = os.path.join(user_dir, 'AppData/Local/Google/Chrome/User Data/Default/History')
            if os.path.exists(chrome_history_path):

                try:
                    # Open the Chrome History SQLite file
                    conn = sqlite3.connect(chrome_history_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT urls.url, visits.visit_time FROM urls, visits WHERE urls.id = visits.url")
                    chrome_rows = cursor.fetchall()

                    for row in chrome_rows:
                        url, visit_time = row
                        visit_date = convert_chrome_time(visit_time)
                        writer.writerow({
                            'computer_name': computer_name,
                            'source': 'Chrome',
                            'user': user,
                            'link': url,
                            'search_date': visit_date
                        })

                    conn.close()
                except Exception as e:
                    print(f"Error processing Chrome history: {e}")

            # 2. Firefox
            firefox_profile_dir = os.path.join(user_dir, 'AppData/Roaming/Mozilla/Firefox/Profiles')
            if os.path.exists(firefox_profile_dir):
                for profile in os.listdir(firefox_profile_dir):
                    places_db = os.path.join(firefox_profile_dir, profile, 'places.sqlite')
                    if os.path.exists(places_db):
                        print(places_db)
                        try:
                            shutil.copyfile(places_db, temp_file)
                            # Open the Firefox History SQLite file
                            conn = sqlite3.connect(places_db)
                            cursor = conn.cursor()
                            cursor.execute("SELECT moz_places.url, moz_historyvisits.visit_date FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id")
                            firefox_rows = cursor.fetchall()

                            for row in firefox_rows:
                                url, visit_time = row
                                visit_date = convert_firefox_time(visit_time)
                                writer.writerow({
                                    'computer_name': computer_name,
                                    'source': 'Firefox',
                                    'user': user,
                                    'link': url,
                                    'search_date': visit_date
                                })

                            conn.close()

                        except Exception as e:
                            print(f"Error processing Firefox history: {e}")
                        finally:
                            if os.path.exists(temp_file):
                                os.remove(temp_file)

    print(f"Browsing history has been written into {output_file}")

def hayabusa_evtx(mount_path, computer_name):
    hayabusa_path = script_path + "/hayabusa/hayabusa"
    run_hayabusa = input("Do you want to launch Hayabusa? (yes/no): ").strip().lower()

    if run_hayabusa == "yes":
        # Demander le nom du fichier de sortie
        if os.path.exists(hayabusa_path):
            output_file = script_path + "/" + result_folder + "/" + "hayabusa_output.csv"
            print("[+] Launching Hayabusa...")
            command = f"{hayabusa_path} csv-timeline -C -d {mount_path}/Windows/System32/winevt/Logs/ -T -o {output_file}"
            os.system(command)
            df = pd.read_csv(output_file)
            df['Computer'] = computer_name
            df.to_csv(output_file, index=False)

        else:
            print(f"[-] Hayabusa executable has to be in {script_path} folder.")
            

def determine_platform(mount_path):
    linux_indicators = ['etc', 'var', 'usr']
    windows_indicators = ['Windows', 'Program Files', 'Users']

    # List directories in the mount point
    try:
        dirs = os.listdir(mount_path)
    except FileNotFoundError:
        return "Mount point not found"

    linux_count = sum(1 for d in dirs if d in linux_indicators)
    windows_count = sum(1 for d in dirs if d in windows_indicators)

    if linux_count > windows_count:
        return "Linux"
    elif windows_count > linux_count:
        return "Windows"
    else:
        return "Unknown"
# Appeler les fonctions pour afficher les informations
if len(sys.argv) > 1:
    mount_path = sys.argv[1]
    if not mount_path.endswith('/'):
        mount_path += '/'
    amcache_path = mount_path + "Windows/AppCompat/Programs/Amcache.hve"
    script_path = os.path.dirname(os.path.realpath(__file__))
    normalized_mount_path = os.path.normpath(mount_path)
    platform = determine_platform(mount_path)
    # Ne pas créer de dossier si le chemin est vide ou '/' mais continuer le script
    if os.path.isdir(mount_path):
        result_folder = os.path.basename(normalized_mount_path)
        # Si le chemin est non vide et non la racine '/'
        if result_folder and result_folder != '/':
            try:
                os.makedirs(result_folder, exist_ok=True)  # Créer le dossier si possible
                print(f"Result folder {script_path}/{result_folder} created")
            except OSError as e:
                print(f"Error creating folder {result_folder}: {e}")
        if platform == "Linux":
            computer_name = get_system_info(mount_path)
            #get_storage_info(mount_path)
            get_network_info(mount_path, computer_name)
            get_users_and_groups(mount_path, computer_name)
            list_installed_apps(mount_path, computer_name)
            list_connections(mount_path, computer_name)
            list_services(mount_path, computer_name)
            get_firewall_rules(mount_path, computer_name)
            get_linux_browsing_history(mount_path, computer_name)
            #create_volatility_profile(mount_path)
        elif platform == "Windows":
            computer_name = get_windows_machine_name(mount_path)
            get_windows_info(mount_path, computer_name)
            #get_windows_storage_info(mount_path)
            #get_windows_mounted_devices(mount_path)
            #get_windows_disk_volumes(mount_path)
            get_windows_network_info(mount_path, computer_name)
            get_windows_users(mount_path, computer_name)
            get_windows_groups(mount_path, computer_name)
            get_startup_services(mount_path, computer_name)
            get_windows_firewall_rules(mount_path, computer_name)
            get_windows_installed_roles(mount_path, computer_name)
            get_windows_installed_programs(mount_path, computer_name)
            get_windows_executed_programs(amcache_path, computer_name)
            get_windows_browsing_history(mount_path, computer_name)
            hayabusa_evtx(mount_path, computer_name)
            #extract_windows_evtx
        else:
            print("Unknown OS")
    else:
        print("Le répertoire " + mount_path + " n'existe pas")
else:
    usage()

# Fermer le descripteur de fichier global après utilisation
if original_cwd_fd is not None:
    os.close(original_cwd_fd)

