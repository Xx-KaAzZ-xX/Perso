#!/usr/bin/python


#. Description: Script d'analyse d'environnement à partir d'un point de montage
#. Requirements : 
#- hayabusa in the folder of the script
#- regripper in the folder of the script
#- python-regristry : https://github.com/williballenthin/python-registry

import platform
import pandas as pd
import struct
import os
import ipaddress
import re
import time
import yaml
import gzip
import json
import magic
import math
from collections import Counter
import locale
import subprocess
from collections import OrderedDict
#from tabulate import tabulate
from datetime import datetime, timedelta
import sys
from pathlib import Path
try:
    from Registry import Registry
except ImportError:
    print("You must install python-registry here : https://github.com/williballenthin/python-registry")
#from Evtx.Evtx import Evtx
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

def red(text):
    return f"\033[91m{text}\033[0m"

def green(text):
    return f"\033[92m{text}\033[0m"

def yellow(text):
    return f"\033[93m{text}\033[0m"



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

def get_system_info(mount_path):
    output_file = os.path.join(script_path, result_folder, "linux_system_info.csv")
    print(yellow(f"[+] Retrieving System information ..."))
    try:
        # Initialisation des valeurs par défaut
        last_update = ''
        installation_date = ''
        last_event = ''
        distro_version = ''
        
        # Get computer name from /etc/hostname
        hostname_file = os.path.join(mount_path, "etc/hostname")
        if os.path.exists(hostname_file):
            with open(hostname_file) as f:
                computer_name = f.read().strip()

        # Get distribution and version from /etc/os-release
        distro_file = os.path.join(mount_path, "etc/os-release")
        if os.path.exists(distro_file):
            with open(distro_file) as f:
                for line in f:
                    if line.startswith("ID="):
                        distro = line.strip().split("=")[1].strip('"')
                    elif line.startswith("VERSION_ID="):
                        distro_version = line.strip().split("=")[1].strip('"')

        # Extraction des DNS
        resolv_file = os.path.join(mount_path, "etc/resolv.conf")
        ntp_file = os.path.join(mount_path, "etc/ntp.conf")
        dns_servers = []
        if os.path.exists(resolv_file):
            with open(resolv_file) as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
            dns_server = ', '.join(dns_servers) if dns_servers else "Unknown"

        # Extraction du serveur NTP
        ntp_server = None
        if os.path.exists(ntp_file):
            with open(ntp_file) as f:
                for line in f:
                    if line.startswith('server'):
                        ntp_server = line.split()[1]

        # Get installation_date
        passwd_file = os.path.join(mount_path, "etc/passwd")
        if os.path.exists(passwd_file):
            passwd_file_infos = os.stat(passwd_file)
            timestamp = passwd_file_infos.st_ctime
            installation_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

        # Get last event
        last_event_log = os.path.join(mount_path, "var/log/syslog")
        if os.path.exists(last_event_log):
            last_log_infos = os.stat(last_event_log)
            timestamp = last_log_infos.st_mtime
            last_event = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

        # Get last update based on distro
        if distro in ["debian", "ubuntu", "kali"]:
            log_path = os.path.join(mount_path, "var/log/apt/history.log")
            if os.path.exists(log_path):
                with open(log_path, "r") as log_file:
                    for line in log_file:
                        if "Start-Date" in line:
                            date_str = line.split("Start-Date: ")[-1].strip()
                            last_update = datetime.strptime(date_str, "%Y-%m-%d  %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")

        elif distro in ["rhel", "centos", "fedora", "almalinux"]:
            log_path = os.path.join(mount_path, "var/log/yum.log")
            if os.path.exists(log_path):
                with open(log_path, "r") as log_file:
                    for line in log_file:
                        if "Updated" in line:
                            date_str = line[:15].strip()
                            last_update = datetime.strptime(date_str, "%b %d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        
        # Output results to CSV
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['computer_name', 'distro', 'distro_version', 'installation_date', 'ntp_server', 'dns_server', 'last_update', 'last_event']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow({
                'computer_name': computer_name,
                'distro': distro,
                'distro_version': distro_version,
                'installation_date': installation_date,
                'ntp_server': ntp_server,
                'dns_server': dns_server,
                'last_update': last_update,
                'last_event': last_event
            })

        print(green(f"[92m System information has been written to {output_file}"))
        return computer_name

    except Exception as e:
        print(red(f"[-] An error occurred while gathering system information: {e}"))

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
            print(green(f"Network information has been written to {output_file}"))
        except Exception as e:
            print(red(f"Error retrieving Linux network information : {e}"))


def get_users_and_groups(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "linux_users_and_groups.csv"
    users = []
    groups = []
    print(yellow("[+] Retrieving users & groups informations"))
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

    print(green(f"Users and groups information written to {output_file}"))

def list_connections(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "linux_connections.csv"
    print(yellow("[+] Retrieving connection information..."))

    csv_columns = ['computer_name', 'connection_date', 'user', 'src_ip']
    # Ouvrir le fichier CSV pour écrire les informations
    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        counter = 0
        # Chemin vers les fichiers de log de connexion
        log_files_path = os.path.join(mount_path, "var/log")

        if not os.path.isdir(log_files_path):
            print(red(f"[-] Folder {log_files_path} doesn't exist."))
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
                            src_ip = parts[10]  # IP source
                            counter += 1
                            writer.writerow({'computer_name': computer_name, 'connection_date': connection_date_with_year, 'user': user, 'src_ip': src_ip})
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
                        counter += 1
                        writer.writerow({'computer_name': computer_name, 'connection_date': connection_date, 'user': user, 'src_ip': src_ip})
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
                                src_ip = parts[-1]  # IP source
                                counter += 1
                                writer.writerow({'computer_name': computer_name, 'connection_date': connection_date, 'user': user, 'src_ip': src_ip})
    if counter >= 1:
        print(green(f"Connections informations have been written into {output_file}"))
    else:
        print(yellow(f" No connections has been found, {output_file} is empty"))


def list_installed_apps(mount_path, computer_name):
    distro_file = mount_path + "/etc/os-release"
    output_file = script_path + "/" + result_folder + "/linux_installed_apps.csv"
    print(yellow("[+] Retrieving installed apps..."))

    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['computer_name', 'package_name', 'install_date']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        counter = 0

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
                            counter += 1

            # Pour RHEL/CentOS/Fedora/AlmaLinux
            elif distro in ["rhel", "centos", "fedora", "almalinux"]:
                chroot_command = "rpm -qa --queryformat '%{installtime:date} %{name}-%{version}-%{release}\n' | sort"
                result, _ = chroot_and_run_command(mount_path, chroot_command)

                if result:
                    for line in result.splitlines():
                        #print(line)
                        parts = line.split()
                        if len(parts) > 4:
                            install_date = " ".join(parts[1:6])
                            package_name = parts[7]
                            writer.writerow({'computer_name' : computer_name, 'package_name': package_name, 'install_date': install_date})
                            counter += 1
                else:
                    print(yellow("No RPM packages found, checking yum logs."))

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
                                            counter += 1
                            else:
                                with open(log_file, 'r', encoding='utf-8') as f:
                                    result_logs = f.read()
                                    for line in result_logs.splitlines():
                                        if "Updated" in line or "Installed" in line:
                                            parts = line.split()
                                            install_date = " ".join(parts[:3])
                                            package_name = parts[-1]
                                            writer.writerow({'computer_name' : computer_name, 'package_name': package_name, 'install_date': install_date})
                                            counter += 1
                    else:
                        print("No yum logs found.")
            if counter >= 1:
                print(green(f"Linux installed apps informations have been written into {output_file}"))
            else:
                print(yellow(f"{output_file} should be empty"))
        else:
            print(red("[-] Unknown distribution"))


def list_services(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "linux_services.csv")
    init_path = os.path.join(mount_path, "usr/sbin/init")
    print(yellow("[+] Retrieving Services informations..."))

    if os.path.exists(init_path):
        init_sys = os.path.basename(os.readlink(init_path))

        if init_sys == "systemd":
            chroot_command = "systemctl list-unit-files --type=service"
            stdout, stderr = chroot_and_run_command(mount_path, chroot_command)

            if stderr:
                print(red(f"[-] Erreur: {stderr}"))
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

            print(green(f"Services informations has been written into {output_file}."))
        else:
            print(yellow("Not managed by Systemd"))
    else:
        print(yellow("System is not managed by Systemd"))


def get_command_history(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "linux_command_history.csv")
    print(yellow("[+] Retrieving command history ..."))
    csv_columns = ['computer_name', 'user', 'shell', 'command']
    
    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            
            # Rechercher tous les dossiers "home" pour les utilisateurs
            home_dirs = glob.glob(os.path.join(mount_path, "home", "*"))
            home_dirs.append(os.path.join(mount_path, "root"))

            
            for home_dir in home_dirs:
                user = os.path.basename(home_dir)
                # Vérifier les fichiers d'historique de commandes
                for shell_history_file in ['.bash_history', '.zsh_history', '.sh_history']:
                    history_file_path = os.path.join(home_dir, shell_history_file)
                    shell = shell_history_file.replace("_history", "").replace(".", "")
                    
                    if os.path.exists(history_file_path):
                        try:
                            with open(history_file_path, 'r', encoding='utf-8', errors='ignore') as hist_file:
                                for command in hist_file:
                                    command = command.strip()
                                    if command:
                                        writer.writerow({
                                            'computer_name': computer_name,
                                            'user': user,
                                            'shell': shell,
                                            'command': command
                                        })
                        except Exception as file_error:
                            print(red(f"[-] Error reading {history_file_path}: {file_error}"))
    
    except Exception as e:
        print(red(f"[-] Error retrieving command history: {e}"))
    
    print(green(f"Command history has been written into {output_file}"))

def get_firewall_rules(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "linux_firewall_rules.csv")
    csv_columns = ['computer_name', 'chain', 'target', 'prot', 'source', 'destination', 'port']
    print(yellow("[+] Retrieving Firewall Rules..."))
    counter = 0

    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()

            # Exécuter la commande iptables dans l'environnement chrooté
            iptables_command = "iptables -L -n"
            stdout, stderr = chroot_and_run_command(mount_path, iptables_command)

            if stderr:
                print(red(f"[-] Error running iptables command: {stderr}"))
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
                counter += 1

            # Écrire les règles dans le fichier CSV
            writer.writerows(rules)
            if counter >= 1:
                print(green(f"Firewall rules have been written into {output_file}"))
            else:
                print(yellow(f"No rules have been found, {output_file} should be empty"))

    except Exception as e:
        print(red(f"[-] An error occurred: {e}"))


def get_linux_browsing_history(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "linux_browsing_history.csv"
    csv_columns = ['computer_name', 'source', 'user', 'link', 'search_date']
    print(yellow("[+] Retrieving browsing history"))
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        users_dir = os.path.join(mount_path, 'home')
        for user in os.listdir(users_dir):
            user_dir = os.path.join(users_dir, user)
            find_firefox_cmd = f"find {user_dir} -type f -name 'places.sqlite' "
            stdout, stderr = chroot_and_run_command(mount_path, find_firefox_cmd)
            firefox_files = stdout.splitlines()
            print(firefox_files)
       
            for firefox_file in firefox_files:
                if not firefox_file:
                    print(red("[-] No Firefox profile found."))
                    return
                # Chemin du fichier temporaire
                temp_file = "/tmp/places_temp.sqlite"

                # Chemin complet du fichier 'places.sqlite' à partir de l'image montée
                firefox_profile_file = os.path.join(mount_path, firefox_file)
                firefox_profile_file = os.path.normpath(firefox_profile_file)

                try:
                    # Copier le fichier places.sqlite dans /tmp
                    shutil.copyfile(firefox_profile_file, temp_file)
                    print(yellow(f"[+] Copied Firefox history to temporary file: {temp_file}"))

                    # Ouvrir le fichier CSV pour écrire les résultats
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
                            'user': user,  # Ajuste le nom de l'utilisateur si nécessaire
                            'link': url,
                            'search_date': visit_date
                        })

                        # Fermer la connexion à la base de données
                    conn.close()
                    print(green(f"Browsing history has been written into {output_file}"))

                except Exception as e:
                    print(red(f"[-] Error processing Firefox history: {e}"))

                finally:
                    # Supprimer le fichier temporaire après utilisation
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                        print(yellow(f"[+] Temporary file {temp_file} has been deleted."))

def get_linux_browsing_data(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "linux_browsing_data.csv"
    csv_columns = ['computer_name', 'source', 'user', 'ident', 'creds', 'platform', 'saved_date']
    print(yellow("[+] Retrieving browsing data (saved logins)"))

    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()

        users_dir = os.path.join(mount_path, 'home')
        for user in os.listdir(users_dir):
            user_dir = os.path.join(users_dir, user)

            # 1. Google Chrome logins
            chrome_login_path = os.path.join(user_dir, '.config/google-chrome/Default/Login Data')
            if os.path.exists(chrome_login_path):
                try:
                    conn = sqlite3.connect(chrome_login_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
                    chrome_rows = cursor.fetchall()

                    for row in chrome_rows:
                        url, username, password, date_created = row
                        saved_date = convert_chrome_time(date_created)
                        writer.writerow({
                            'computer_name': computer_name,
                            'source': 'Chrome',
                            'user': user,
                            'ident': username,
                            'creds': password,  # The password is encrypted; decryption may require OS-specific methods
                            'platform': url,
                            'saved_date': saved_date
                        })

                    conn.close()
                except Exception as e:
                    print(red(f"[-] Error processing Chrome logins for user {user}: {e}"))

            # 2. Mozilla Firefox logins
            firefox_profile_dir = os.path.join(user_dir, '.mozilla/firefox')
            if os.path.exists(firefox_profile_dir):
                try:
                    for profile in os.listdir(firefox_profile_dir):
                        profile_dir = os.path.join(firefox_profile_dir, profile)
                        if os.path.isdir(profile_dir) and profile.endswith('.default-release'):
                            login_db_path = os.path.join(profile_dir, 'logins.json')
                            if os.path.exists(login_db_path):
                                with open(login_db_path, 'r', encoding='utf-8') as login_file:
                                    logins = json.load(login_file).get('logins', [])
                                    for login in logins:
                                        writer.writerow({
                                            'computer_name': computer_name,
                                            'source': 'Firefox',
                                            'user': user,
                                            'ident': login.get('usernameField', ''),
                                            'creds': login.get('passwordField', ''),  # Encrypted; requires further processing to decrypt
                                            'platform': login.get('hostname', ''),
                                            'saved_date': datetime.fromtimestamp(login['timeCreated'] / 1000).isoformat()
                                        })

                except Exception as e:
                    print(red(f"[-] Error processing Firefox logins for user {user}: {e}"))

    print(green(f"Browsing data has been written into {output_file}"))

def get_linux_used_space(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "linux_disk_usage.csv")
    csv_columns = ['computer_name', 'directory', 'percent_used']
    print("[+] Retrieving disk usage ...")
    
    try:
        # Taille totale de la partition racine (en octets)
        total_size = shutil.disk_usage(mount_path).total

        # Ouvrir le fichier CSV pour écrire les résultats
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            chroot_command = "du -sb /*"
            result, _ = chroot_and_run_command(mount_path, chroot_command)
            excluded_dirs = {'dev', 'proc', 'sys', 'run'}
            lines = result.splitlines()
            for line in lines:
                bytes_size = line.split()[0]
                directory = line.split('/')[1]
                if directory in excluded_dirs:
                    continue
                percentage = (int(bytes_size) / total_size) * 100
                percentage_truncated = f"{percentage:.2f}"
                writer.writerow({
                    'computer_name': computer_name,
                    'directory': directory,
                    'percent_used' : percentage_truncated
                    })
        print(green(f"Disk usage information has been written to {output_file}"))
        
    except Exception as e:
        print(red(f"[-] An error occurred while gathering disk usage information: {e}"))

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
    print(yellow(f"[+] Retrieving system information..."))
    # Récupération des informations NTP (dans le registre SYSTEM)
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SYSTEM')
    try:
        reg = Registry.Registry(path_to_reg_hive)
        ntp_key = reg.open("ControlSet001\\Services\\W32Time\\Parameters")
        for value in ntp_key.values():
            if value.name() == "NtpServer":
                system_info['ntp_server'] = value.value()
    except Exception as e:
        print(red(f"Erreur lors de la récupération des informations NTP: {e}"))
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
        print(red(f"[-] Error retrieving keyboard layout : {e}"))



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
        print(red(f"[-]Error retrieving system installation information: {e}"))

    # Récupération du dernier événement (last_event)
    try:
        last_event_log = os.path.join(mount_path, 'Windows/System32/winevt/Logs/System.evtx')
        if os.path.exists(last_event_log):
            last_log_infos = os.stat(last_event_log)
            timestamp = last_log_infos.st_mtime
            system_info['last_event'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
    except Exception as e:
        print(red(f"Error retrieving last event: {e}"))

        # Récupération de la dernière MAJ
    try:
        reg = Registry.Registry(os.path.join(mount_path, 'Windows/System32/config/SOFTWARE'))
        update_key = reg.open("Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install")
        for value in update_key.values():
            if value.name() == "LastSuccessTime":
                system_info['last_update'] = value.value()
    except Exception as e:
        print(red(f"[-] Error retrieving last update information: {e}"))



# Écriture des informations dans un fichier CSV
    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerow(system_info)
        print(green(f"System information has been written into {output_file}"))
    except Exception as e:
        print(red(f"[-] Error writting into the CSV: {e}"))

def get_windows_network_info(mount_path, computer_name):
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SYSTEM')
    reg = Registry.Registry(path_to_reg_hive)
    output_file = script_path + "/" + result_folder + "/" + "windows_network_info.csv"
    print(yellow("[+] Retrieving network information"))
    # Initialisation des données
    network_info = []

    try:
        key = reg.open("ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces")
    except Registry.RegistryKeyNotFoundException:
        print(red("[-] Couldn't find the network informations. Exiting..."))
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
        print(green(f"Network information has been written into {output_file}"))
    except Exception as e:
        print(red(f"Erreur lors de l'écriture dans le fichier CSV: {e}"))

def get_startup_services(mount_path, computer_name):
    # Registry path for services
    services_path = "ControlSet001\\Services"
    output_file = os.path.join(script_path, result_folder, "windows_services.csv")
    print(yellow("[+] Retrieving Windows Services information..."))

    # Load the SYSTEM hive
    try:
        reg = Registry.Registry(os.path.join(mount_path, 'Windows/System32/config/SYSTEM'))
    except Exception as e:
        print(red(f"[-] Error loading SYSTEM hive: {e}"))
        return

    try:
        key = reg.open(services_path)
    except Registry.RegistryKeyNotFoundException:
        print(red(f"[-] Couldn't find the services key at {services_path}. Exiting..."))
        return

    # Open the output file to store the list of startup services
    counter = 0
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
                    counter += 1
            except Registry.RegistryValueNotFoundException:
                # If "Start" value is not found, skip the service
                continue
    if counter >= 1:
        print(green(f"Windows services information has been written to {output_file}"))


def get_windows_users(mount_path, computer_name):
    print(yellow("[+] Retrieving Windows Users informations..."))
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
                print(red("[-] No output from regripper."))
                return

            lines = output.splitlines()
            users = []
            counter = 0
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
                    counter += 1
        if counter >= 1:
            print(green(f"Users informations have been written into {output_file}"))
    except Exception as e:
        print(red(f"[-] Error : {e}"))


def get_windows_groups(mount_path, computer_name):
    print(yellow("[+] Retrieving Windows Groups informations..."))
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
                print(red("[-] No output from regripper."))
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

        print(green(f"Groups informations have been written into {output_file}"))
    except Exception as e:
        print(red(f"Error: {e}"))

def get_windows_firewall_rules(mount_path, computer_name):
    firewall_paths = [
        "ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
        "CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    ]
    print(yellow("[+] Retrieving Firewall rules..."))
    output_file = os.path.join(script_path, result_folder, "windows_firewall_rules.csv")

    csv_columns = ['computer_name', 'action', 'active', 'direction', 'protocol', 'profile', 'srcport', 'dstport', 'app', 'svc', 'rule_name', 'desc', 'embedctxt']

    try:
        reg = Registry.Registry(os.path.join(mount_path, 'Windows/System32/config/SYSTEM'))
    except Exception as e:
        print(red(f"Error loading SYSTEM hive: {e}"))
        return

    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        counter = 0
        for path in firewall_paths:
            try:
                key = reg.open(path)
            except Registry.RegistryKeyNotFoundException:
                print(yellow(f"Couldn't find the key {path}. Continuing...\n"))
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
                counter += 1

    if counter >= 1:
        print(green(f"Firewall rules written to {output_file}"))
    else:
        print(yellow(f"{output_file} should be empty"))

def get_windows_installed_roles(mount_path, computer_name):
    # Définir le chemin du registre
    output_file = script_path + "/" + result_folder + "/" + "windows_roles.csv"
    #print(f"Role/Feature: {subkey.name()}")
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SOFTWARE')
    reg = Registry.Registry(path_to_reg_hive)
    print(yellow("[+] Retrieving Windows Roles informations..."))

    # Définir le chemin de la clé de registre pour les rôles et fonctionnalités installés
    key_path = 'Microsoft\\ServerManager\\ServicingStorage\\ServerComponentCache'
    csv_columns = ['computer_name','role_name', 'install_state']
    try:
        key = reg.open(key_path)
    except Registry.RegistryKeyNotFoundException:
        print(red("[-] Couldn't find the key. Exiting..."))
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
            print(green(f"Roles information have been written into {output_file}"))
    except Exception as e:
        print(red(f"[-] Error retrieving roles information : {e}"))

def get_windows_installed_programs(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "windows_installed_programs.csv"
    software_file = os.path.join(mount_path, 'Windows/System32/config/SOFTWARE')
    csv_columns = ['computer_name', 'program_name', 'program_version', 'install_date']
    print(yellow("[+] Retrieving installed programs"))

    regripper_path = "/usr/bin/regripper"  # Chemin vers regripper
    try:
        regripper_cmd = f"{regripper_path} -p uninstall -r {software_file}"
        result_regripper = subprocess.run(regripper_cmd, shell=True, capture_output=True, text=True)
        output = result_regripper.stdout

        # Vérifiez si l'output est vide
        if not output.strip():
            print(red("[-] No output from regripper."))
            return

        # Décomposition de l'output en lignes
        lines = output.splitlines()
        programs = []
        install_date = None
        counter = 0

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
                    counter += 1
                except ValueError:
                    continue  # Ignore toute ligne qui ne correspond pas au format attendu

        # Écriture des informations dans le fichier CSV
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerows(programs)

        if counter >= 1:
            print(green(f"[+] Installed programs have been written into {output_file}"))
        else:
            print(yellow(f"{output_file} should be empty"))

    except Exception as e:
        print(red(f"[-] Error running regripper or writing output: {e}"))
        return
'''
def get_windows_executed_programs(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "windows_executed_programs.csv")
    csv_columns = ['computer_name', 'filepath', 'executed_date']
    print(yellow("[+] Retrieving executed programs"))

    possible_amcache_path = [
        "Windows/AppCompat/Programs/Amcache.hve",
        "Windows/appcompat/Programs/Amcache.hve"
    ]
    counter = 0
    # Parcourt tous les chemins possibles pour Amcache
    for amcache in possible_amcache_path:
        amcache_path = os.path.join(mount_path, amcache)
        if os.path.exists(amcache_path):
            try:
                reg = Registry.Registry(amcache_path)
            except Exception as e:
                print(red(f"Error opening Amcache.hve at {amcache_path}: {e}"))
                continue  # Passe au prochain chemin si erreur lors de l'ouverture

            try:
                key = reg.open("Root\\File")
            except Registry.RegistryKeyNotFoundException:
                print(yellow(f"Couldn't find the Amcache key in {amcache_path} "))
                continue  # Passe au prochain chemin si la clé n'est pas trouvée

            # Écriture dans le fichier CSV pour chaque clé trouvée
            with open(output_file, mode='a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=csv_columns)
                writer.writeheader()
                
                try:
                    for subkey in key.subkeys():
                        program_info = {
                            'computer_name': computer_name,
                            'filepath': '',
                            'executed_date': ''
                        }
                        try:
                            for sub_subkey in subkey.subkeys():
                                for value in sub_subkey.values():
                                    if value.name() == "17":
                                        win_timestamp = value.value()
                                        program_info['executed_date'] = str(get_windows_timestamp(win_timestamp))
                                    elif value.name() == "15":
                                        program_info['filepath'] = value.value()
                                if program_info['filepath']:
                                    writer.writerow(program_info)
                                    counter += 1
                        except Registry.RegistryKeyNotFoundException as e:
                            print(red(f"[-]Error accessing subkeys of {subkey.name()}: {e}"))
                            continue
                except Exception as e:
                    print(red(f"[-] Problem retrieving executed program elements: {e}"))
        else:
            print(yellow(f"{amcache_path} not found, moving to the next path."))

    if counter >= 1:
        print(green(f"Executed programs have been written into {output_file}"))
    else:
        print(yellow(f"{output_file} should be empty"))

'''

def get_windows_executed_programs(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "windows_executed_programs.csv")
    csv_columns = ['computer_name', 'filepath', 'executed_date']
    print(yellow("[+] Retrieving executed programs"))

    possible_amcache_path = [
        "Windows/AppCompat/Programs/Amcache.hve",
        "Windows/appcompat/Programs/Amcache.hve"
    ]
    counter = 0

    for amcache in possible_amcache_path:
        amcache_path = os.path.join(mount_path, amcache)
        if os.path.exists(amcache_path):
            try:
                regripper_path = "/usr/bin/regripper"
                if os.path.exists(regripper_path):
                    regripper_cmd = f"{regripper_path} -p amcache -r {amcache_path}"
                    result_regripper = subprocess.run(regripper_cmd, shell=True, capture_output=True, text=True)
                    output = result_regripper.stdout

                    if not output.strip():
                        print(red("[-] No output from regripper."))
                        return

                    lines = output.splitlines()
                    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=csv_columns)
                        writer.writeheader()
                        filepath = ""
                        executed_date = ""
                        for line in lines:
                            line = line.strip()

                            # Format 1: ".exe" and "LastWrite" on the same line
                            if ".exe" in line and "LastWrite" in line:
                                parts = line.split("  ")
                                filepath = parts[0].strip()
                                executed_date = parts[1].replace("LastWrite: ", "").strip()
                                writer.writerow({
                                    'computer_name': computer_name,
                                    'filepath': filepath,
                                    'executed_date': executed_date
                                })
                                counter += 1

                            # Format 2: Detected by "File Reference" line
                            elif line.startswith("File Reference:"):
                                filepath = ""
                                executed_date = ""

                            if "LastWrite" in line:
                                executed_date = line.split(":", 1)[1].strip()
                            elif "Path" in line:
                                filepath = line.split(":", 1)[1].strip()

                            # Write entry if both fields are populated
                            if filepath and executed_date:
                                writer.writerow({
                                    'computer_name': computer_name,
                                    'filepath': filepath,
                                    'executed_date': executed_date
                                })
                                counter += 1
                                filepath = None
                                executed_date = None

                if counter >= 1:
                    print(green(f"[+] Executed programs information have been written into {output_file}"))
                else:
                    print(yellow(f"[!] {output_file} should be empty"))

            except Exception as e:
                print(red(f"Error opening Amcache.hve at {amcache_path}: {e}"))
                continue


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
    print(yellow("[+] Retrieving browsing history"))
    temp_file = "/tmp/places_temp.sqlite"

    # Ouvrir le fichier CSV pour écrire les résultats
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        counter = 0
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
                        counter += 1

                    conn.close()
                except Exception as e:
                    print(red(f"Error processing Chrome history: {e}"))

            #2. Firefox
            firefox_profile_dir = os.path.join(user_dir, 'AppData/Roaming/Mozilla/Firefox/Profiles')
            if os.path.exists(firefox_profile_dir):
                for profile in os.listdir(firefox_profile_dir):
                    places_db = os.path.join(firefox_profile_dir, profile, 'places.sqlite')
                    if os.path.exists(places_db):
                        #print(f"[+] Firefox file found: {places_db}")
                        try:
                            # Copier le fichier places.sqlite dans /tmp
                            shutil.copyfile(places_db, temp_file)
                            #print(f"[+] Copied Firefox history to temporary file: {temp_file}")

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
                                    'user': user,  # Ajuste le nom de l'utilisateur si nécessaire
                                    'link': url,
                                    'search_date': visit_date
                                })
                                counter += 1

                            # Fermer la connexion à la base de données
                            conn.close()

                        except Exception as e:
                            print(red(f"Error processing Firefox history: {e}"))

                        finally:
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                                #print(f"[+] Temporary file {temp_file} has been deleted.")
    if counter >= 1:
        print(green(f"Browsing history has been written into {output_file}"))
    else:
        print(yellow(f"Browsing history {output_file} should be empty"))


def get_windows_browsing_data(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "windows_browsing_data.csv"
    csv_columns = ['computer_name', 'source', 'user', 'ident', 'creds', 'platform', 'saved_date']
    print(yellow("[+] Retrieving browsing data (saved logins)"))
    
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        counter = 0

        users_dir = os.path.join(mount_path, 'Users')
        for user in os.listdir(users_dir):
            user_dir = os.path.join(users_dir, user)

            # 1. Google Chrome logins
            chrome_login_path = os.path.join(user_dir, 'AppData/Local/Google/Chrome/User Data/Default/Login Data')
            if os.path.exists(chrome_login_path):
                try:
                    conn = sqlite3.connect(chrome_login_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
                    chrome_rows = cursor.fetchall()

                    for row in chrome_rows:
                        url, username, password, date_created = row
                        saved_date = convert_chrome_time(date_created)
                        writer.writerow({
                            'computer_name': computer_name,
                            'source': 'Chrome',
                            'user': user,
                            'ident': username,
                            'creds': password,  # The password is encrypted; decryption may require OS-specific methods
                            'platform': url,
                            'saved_date': saved_date
                        })
                        counter += 1

                    conn.close()
                except Exception as e:
                    print(red(f"[-] Error processing Chrome logins for user {user}: {e}"))

            # 2. Mozilla Firefox logins
            firefox_login_path = os.path.join(user_dir, 'AppData/Roaming/Mozilla/Firefox/Profiles')
            if os.path.exists(firefox_login_path):
                try:
                    for profile in os.listdir(firefox_login_path):
                        login_db_path = os.path.join(firefox_login_path, profile, 'logins.json')
                        if os.path.exists(login_db_path):
                            with open(login_db_path, 'r', encoding='utf-8') as login_file:
                                logins = json.load(login_file).get('logins', [])
                                for login in logins:
                                    writer.writerow({
                                        'computer_name': computer_name,
                                        'source': 'Firefox',
                                        'user': user,
                                        'ident': login['usernameField'],
                                        'creds': login['passwordField'],  # Encrypted; requires further processing to decrypt
                                        'platform': login['hostname'],
                                        'saved_date': datetime.fromtimestamp(login['timeCreated'] / 1000).isoformat()
                                    })
                                    counter += 1

                except Exception as e:
                    print(red(f"[-] Error processing Firefox logins for user {user}: {e}"))

    if counter >= 1:
        print(green(f"Browsing data has been written into {output_file}"))
    else:
        print(yellow(f"Browsing data {output_file} should be empty"))


def hayabusa_evtx(mount_path, computer_name):
    hayabusa_path = script_path + "/hayabusa/hayabusa"
    run_hayabusa = input("Do you want to launch Hayabusa? (yes/no): ").strip().lower()

    if run_hayabusa == "yes":
        # Demander le nom du fichier de sortie
        if os.path.exists(hayabusa_path):
            output_file = script_path + "/" + result_folder + "/" + "hayabusa_output.csv"
            print("[+] Launching Hayabusa...")
            command = f"{hayabusa_path} csv-timeline -C -d {mount_path}/Windows/System32/winevt/Logs/ -T -o {output_file}"
            #command = f"{hayabusa_path} csv-timeline -C -N -A -a -w -d {mount_path}/Windows/System32/winevt/Logs/ -T -o {output_file}"
            os.system(command)
            df = pd.read_csv(output_file)
            df['Computer'] = computer_name
            df.to_csv(output_file, index=False)

        else:
            print(f"[-] Hayabusa executable has to be in {script_path} folder.")


## This 3 functions are meant to detect VeraCrypt Container


def has_no_signature(file_path):
    # Utilise la bibliothèque `magic` pour récupérer le type MIME du fichier
    f = magic.Magic(mime=True)
    file_type = f.from_file(file_path)

    # Vérifie si le type MIME est générique, indiquant potentiellement un fichier sans signature
    if file_type == "application/octet-stream":
        return True  # Pas de signature identifiable
    else:
        return False

def is_size_divisible_by_512(file_path):
    file_size = os.path.getsize(file_path)
    return file_size % 512 == 0

def calculate_entropy(data):
    if not data:
        return 0
    frequency = Counter(data)
    data_length = len(data)
    entropy_value = -sum((count / data_length) * math.log2(count / data_length) for count in frequency.values())
    return entropy_value

def get_files_of_interest(mount_path, computer_name):
    run_find_crypto = input("Do you want to launch some files of interest research? It will be quite long? (yes/no): ").strip().lower()

    if run_find_crypto == "yes":
        output_file = f"{script_path}/{result_folder}/files_of_interest.csv"

        folder_to_search = ['bitcoin', 'monero']
        files_to_search = ['wallet.dat', 'wallet.keys', 'default_wallet', "*.kdbx"]
        if os.path.exists('/usr/bin/yara'):
            print(yellow("[+] Launching Crypto research. It may take several minutes..."))
            yara_rule = script_path + '/' + 'files_of_interest.yar'
            if os.path.exists(yara_rule):
                yara_cmd = f"yara -w -s -r {yara_rule}"
            else:
                print(red(f"Yara rule {yara_rule} doesn't exist, you have to create it before launching the research. Script will exit."))
                sys.exit(1)

            # Search for folders
            for folder in folder_to_search:
                print(f"Looking for {folder} folder in all the filesystem")
                find_dir_cmd = f"find {mount_path} -type d -name {folder}"
                result_find_dir = subprocess.run(find_dir_cmd, shell=True, capture_output=True, text=True)
                output = result_find_dir.stdout
                if output:
                    print(green(f"[+] Result found for {folder} !"))
                    print(output)

            print(yellow("No crypto folders found... Looking for known files"))

            # Search for specific files
            for file in files_to_search:
                find_file_cmd = f"find {mount_path} -type f -name {file}"
                result_find_file = subprocess.run(find_file_cmd, shell=True, capture_output=True, text=True)
                output = result_find_file.stdout
                if output:
                    print(green(f"[+] Result found for {file} !"))
                    print(output)

            
            # Search for wallet addresses in text and database files
            file_types_to_search = ["*.txt", "*.exe", "*.exe_"]
            csv_columns = ['computer_name', 'type', 'match', 'source_file']

            with open(output_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=csv_columns)
                writer.writeheader()
                source_file = ""
                counter = 0
                unique_entries = set()
                for file_type in file_types_to_search:
                    print(f"Looking for files of interest into {file_type} with YARA.")
                    find_file_type_cmd = f"find {mount_path} -type f -name '{file_type}' -exec {yara_cmd} {{}} \\;"
                    # print(f"Launching cmd : {find_file_type_cmd}")
                    result_find_type = subprocess.run(find_file_type_cmd, shell=True, capture_output=True, text=True)
                                        #print(result_find_type)
                    clean_output = result_find_type.stdout.replace(r'\n', '\n')
                    lines = clean_output.splitlines()

                    for line in lines:
                        if line.startswith("Detect_Files_Of_Interest"):
                            source_file = line.split(" ", 1)[1]
                        elif source_file:
                            match_info = re.match(r"0x[\da-f]+:\$(\w+): (.+)", line)
                            if match_info:
                                tag_type = match_info.group(1)
                                matched_string = match_info.group(2)
                                entry = (computer_name, tag_type, matched_string, source_file)
                                if entry not in unique_entries:
                                    unique_entries.add(entry)
                                    writer.writerow({
                                        "computer_name": computer_name,
                                        "type": tag_type,
                                        "match": matched_string,
                                        "source_file": source_file
                                    })
                                    counter += 1
                find_file_without_extension_cmd = f"find {mount_path} -type f ! -name \"*.*\"-type f ! -name \"*.*\" -exec {yara_cmd} {{}} \\;"
                print(f"Looking for files of interest without extension with YARA")
                result_find_without_extension = subprocess.run(find_file_without_extension_cmd, shell=True, capture_output=True, text=True)
                clean_output2 = result_find_without_extension.stdout.replace(r'\n', '\n')
                lines2 = clean_output2.splitlines()
                for line2 in lines2:
                    if line2.startswith("Detect_Files_Of_Interest"):
                        source_file = line2.split(" ", 1)[1]
                    elif source_file:
                        match_info = re.match(r"0x[\da-f]+:\$(\w+): (.+)", line2)
                        if match_info:
                            tag_type = match_info.group(1)
                            matched_string = match_info.group(2)
                            entry = (computer_name, tag_type, matched_string, source_file)
                            if entry not in unique_entries:
                                unique_entries.add(entry)
                                writer.writerow({
                                    "computer_name": computer_name,
                                    "type": tag_type,
                                    "match": matched_string,
                                    "source_file": source_file
                                })
                                counter += 1
                ## Detect VeraCrypt container; File has to be larger than 1GB, without signature and a large entropy
                print("Looking now for Veracrypt container on the FileSystem...")
                min_size = 1 * 1024**3 #1Go min
                find_vc_cmd = f"find {mount_path} -type f -size +{min_size // 1024}k"
                result = subprocess.run(find_vc_cmd, shell=True, capture_output=True, text=True)
                large_files = result.stdout.splitlines()
                print(large_files)
                if large_files != "":
                    for file_path in large_files:
                        print(f"Testing signature of {file_path}")
                        if has_no_signature(file_path) and is_size_divisible_by_512(file_path):
                            print(f"Calculing entropy for {file_path}")
                            file_entropy = calculate_entropy(file_path)
                            print(f"entropy of {file_path} is : {file_entropy}")
                            if file_entropy > 3.1:
                                writer.writerow({"computer_name": computer_name, "type": "potential_veracrypt_container", "match": "", "source_file": file_path})
                                counter += 1
                else:
                    print(yellow("No VeraCrypt container found"))

            if counter >= 1:
                print(green(f"[+] Files of interest have been written into {output_file}"))
            else:
                print(yellow(f"{output_file} should be empty."))



        else:
            print(red("[-] Yara has to be installed on your system."))

        
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
            get_network_info(mount_path, computer_name)
            get_users_and_groups(mount_path, computer_name)
            list_installed_apps(mount_path, computer_name)
            list_connections(mount_path, computer_name)
            list_services(mount_path, computer_name)
            get_command_history(mount_path, computer_name)
            get_firewall_rules(mount_path, computer_name)
            get_linux_used_space(mount_path, computer_name)
            get_linux_browsing_history(mount_path, computer_name)
            get_linux_browsing_data(mount_path, computer_name)
            #create_volatility_profile(mount_path)
            get_files_of_interest(mount_path, computer_name)
        elif platform == "Windows":
            computer_name = get_windows_machine_name(mount_path)
            get_windows_info(mount_path, computer_name)
            get_windows_network_info(mount_path, computer_name)
            get_windows_users(mount_path, computer_name)
            get_windows_groups(mount_path, computer_name)
            get_startup_services(mount_path, computer_name)
            get_windows_firewall_rules(mount_path, computer_name)
            get_windows_installed_roles(mount_path, computer_name)
            get_windows_installed_programs(mount_path, computer_name)
            get_windows_executed_programs(mount_path, computer_name)
            get_windows_browsing_history(mount_path, computer_name)
            get_windows_browsing_data(mount_path, computer_name)
            hayabusa_evtx(mount_path, computer_name)
            get_files_of_interest(mount_path, computer_name)
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


