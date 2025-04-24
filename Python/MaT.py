#!/usr/bin/python


#. Description: Script to mount and make a triage (MaT). The artifacts are exported into CSV files.


#. Requirements : 
#- hayabusa in the folder of the script
#- regripper in the folder of the script
#- python-regristry : https://github.com/williballenthin/python-registry
#- and all libraries that are imported 
#- tabulate pour regipy


import platform
import pandas as pd
import argparse
import struct
import os
import requests
import logging
import ipaddress
import pytsk3
import re
import time
import xml.etree.ElementTree as ET
import yaml
import gzip
import base58
from bech32 import bech32_decode, convertbits
import json
import magic
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Lock
import threading
import hashlib,base58,binascii
import sha3 #for eth address verification
from tqdm import tqdm
import math
from collections import Counter
from bitcoinaddress import Address
import locale
import subprocess
import string
from mnemonic import Mnemonic
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
from crontab import CronSlices
# for full dump of registry key
from regipy.registry import RegistryHive

# Chemin vers le système de fichiers monté
script_name = sys.argv[0]


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
        dns_server = []
        if os.path.exists(resolv_file):
            with open(resolv_file) as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_server.append(line.split()[1])
        else:
            dns_server= "Unknown"

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
        else:
             #find the oldest write on /var/log
            last_event = 0
            latest_file = ""
            log_dir = os.path.join(mount_path, "var/log/")
            for root, dirs, files in os.walk(log_dir):
                for file in files:
                    path = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(path)
                        if mtime > last_event:
                            last_event = mtime
                            latest_file = path
                    except:
                        continue
            last_event = (f"{datetime.fromtimestamp(last_event)}")

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

        print(green(f"System information has been written to {output_file}"))
        return computer_name

    except Exception as e:
        print(red(f"[-] An error occurred while gathering system information: {e}"))

def get_network_info(mount_path, computer_name):

    output_file = script_path + "/" + result_folder + "/linux_network_info.csv"
    print(yellow("[+] Retrieving Network information..."))
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
                #print(f"Trying with {interfaces_file}") 
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
                ## if IP address is empty, we'll check into interfaces.d directory
                if not ip:
                    interfaces_d_dir = os.path.join(mount_path, "etc/network/interfaces.d")
                    if os.path.isdir(interfaces_d_dir):
                        for filename in os.listdir(interfaces_d_dir):
                            filepath = os.path.join(interfaces_d_dir, filename)
                            if os.path.isfile(filepath):
                                with open(filepath) as subf:
                                    for line in subf:
                                        line = line.strip()
                                        if line.startswith('iface'):
                                            iface = line.split()[1]
                                        if 'address' in line:
                                            ip = line.split()[1]
                                        if 'netmask' in line:
                                            netmask = line.split()[1]
                                        if 'gateway' in line:
                                            gateway = line.split()[1]
                                if iface and ip:
                                    writer.writerow({'computer_name': computer_name, 'interface': iface, 'ip_address': ip, 'netmask': netmask, 'gateway': gateway})

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
        fieldnames = ['computer_name', 'package_name', 'install_date', 'version']
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
                chroot_command = "zgrep 'install\\|upgrade' /var/log/dpkg.log* | sort"
                #chroot_command = "zgrep 'install' /var/log/dpkg.log* | sort | cut -f1,2,4 -d' '"
                result, _ = chroot_and_run_command(mount_path, chroot_command)
                #print(f"{result}")
                # Regex pour capturer le nom du paquet et la version
                date_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
                package_pattern = r"([a-zA-Z0-9\.\-]+):([a-zA-Z0-9\-\.]+) ([^\s]+)"

                if result:
                    for line in result.splitlines():
                        date_match = re.search(date_pattern, line)
                        if date_match:
                            install_date = date_match.group(1)
                        else:
                            install_date = None
                        after_date = line.split(" ", 2)[-1]  # Après la date et le statut
                        package_match = re.search(package_pattern, after_date)
                        if package_match:
                            package_name = package_match.group(1)
                            version = package_match.group(3)
                        else:
                            package_name = None
                            version = None

                        writer.writerow({
                            'computer_name': computer_name,
                            'package_name': package_name,
                            'install_date': install_date,
                            'version': version
                        })
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
    counter = 0
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
                if len(parts) == 2:  # service_name, status
                    service_name = parts[0]
                    status = parts[1]
                    # Le statut au démarrage est généralement indiqué par la troisième colonne,
                    # si présente, sinon mettre une valeur par défaut ou gérer les erreurs.
                    services.append((computer_name, service_name, status))
                    counter += 1

                elif len(parts) == 3:  # service_name, 8tatus, status_at_boot
                    service_name = parts[0]
                    status = parts[1]
                    # Le statut au démarrage est généralement indiqué par la troisième colonne,
                    # si présente, sinon mettre une valeur par défaut ou gérer les erreurs.
                    status_at_boot = parts[2] if len(parts) > 2 else "unknown"
                    services.append((computer_name, service_name, status, status_at_boot))
                    counter += 1

            # Écrire dans le fichier CSV
            with open(output_file, mode='w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(['computer_name', 'service_name', 'status', 'status_at_boot'])  # En-tête
                csv_writer.writerows(services)
            if counter >= 1:
                print(green(f"Services informations has been written into {output_file}."))
            else:
                print(yellow(f"{output_file} must be empty."))
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
    csv_columns = ['computer_name', 'source', 'user', 'url_title', 'link', 'search_date']
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
                        SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date
                        FROM moz_places, moz_historyvisits
                        WHERE moz_places.id = moz_historyvisits.place_id
                    """)
                    firefox_rows = cursor.fetchall()

                    # Traiter les résultats et les écrire dans le fichier CSV
                    for row in firefox_rows:
                        url, url_title, visit_time = row
                        visit_date = convert_firefox_time(visit_time)
                        writer.writerow({
                            'computer_name': computer_name,
                            'source': 'Firefox',
                            'user': user,  # Ajuste le nom de l'utilisateur si nécessaire
                            'url_title': url_title,
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
        counter = 0

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
                        counter += 1
                    cursor.execute("SELECT origin_domain, username_value, update_time FROM stats")
                    chrome_rows = cursor.fetchall()
                    for row in chrome_rows:
                        url, username, update_time = row
                        saved_date = convert_chrome_time(update_time)
                        writer.writerow({
                            'computer_name': computer_name,
                            'source': 'Chrome (stats table)',
                            'user': "",
                            'ident': username,
                            'creds': "",  # The password is encrypted; decryption may require OS-specific methods
                            'platform': url,
                            'saved_date': update_time
                        })
                        counter += 1
 

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
                                        counter += 1

                except Exception as e:
                    print(red(f"[-] Error processing Firefox logins for user {user}: {e}"))
    if counter >= 1:
        print(green(f"Browsing data has been written into {output_file}"))
    else:
        print(yellow(f"No browsing data found, {output_file} should be empty"))


def parse_crontab_line(line, is_user_crontab=False):
    parts = line.split()
    if len(parts) < (6 if not is_user_crontab else 5):
        return None

    if is_user_crontab:
        # Crontab utilisateur : pas de champ pour l'utilisateur
        minute, hour, day, month, weekday = parts[:5]
        task = ' '.join(parts[5:])
        user_crontab = None  # Utilisateur déterminé hors de cette fonction
        schedule = " ".join(parts[:5])
    else:
        # /etc/crontab ou /etc/cron.d/ : champ utilisateur inclus
        minute, hour, day, month, weekday, user_crontab = parts[:6]
        task = ' '.join(parts[6:])
        schedule = " ".join(parts[:5])
        user_crontab = (parts[5])
    return schedule, task, user_crontab



def get_linux_crontab(mount_path, computer_name):
    #output_file = os.path.join(script_path, result_folder, "linux_crontab.csv")
    script_path = os.path.dirname(os.path.realpath(__file__))
    output_file = script_path + "/" + result_folder + "/" + "linux_crontab.csv"
    csv_columns = ['computer_name', 'user', 'scheduled', 'task', 'source_file']
    print(yellow("[+] Retrieving crontab ..."))
    tasks = []
    
    try:
         
        users = [
        entry.split(':')[0] 
        for entry in open(mount_path + '/etc/passwd').readlines() 
        if int(entry.split(':')[2]) >= 1000 or entry.split(':')[0] == "root"
        ]
 

 # Parse /etc/crontab
        etc_crontab = os.path.join(mount_path, "etc/crontab")
        if os.path.exists(etc_crontab):
            with open(etc_crontab, "r") as file:
                for line in file:
                    if line.strip() and not line.startswith("#"):
                        parsed_schedule = parse_crontab_line(line)
                        if parsed_schedule:
                            schedule, task, user_crontab = parsed_schedule
                            tasks.append({
                                "computer_name": computer_name,
                                "user": user_crontab,  # Default user for /etc/crontab
                                "scheduled": schedule,
                                "task": task,
                                "source_file": "/etc/crontab"
                            })
    
    # Parse /etc/cron.d/
        cron_d_dir = os.path.join(mount_path, "etc/cron.d")
        if os.path.isdir(cron_d_dir):
            for file_name in os.listdir(cron_d_dir):
                cron_file = os.path.join(cron_d_dir, file_name)
                if os.path.isfile(cron_file):
                    with open(cron_file, "r") as file:
                        for line in file:
                            if line.strip() and not line.startswith("#"):
                                parsed_schedule = parse_crontab_line(line)
                                if parsed_schedule:
                                    schedule, task, user_crontab = parsed_schedule
                                    tasks.append({
                                        "computer_name": computer_name,
                                        "user": user_crontab,
                                        "scheduled": schedule,
                                        "task": task,
                                        "source_file": f"/etc/cron.d/{file_name}"
                                    })
    
    # Parse /etc/cron.{daily,weekly,monthly}
        cron_periodic_dirs = ["daily", "weekly", "monthly"]
        for period in cron_periodic_dirs:
            cron_dir = os.path.join(mount_path, f"etc/cron.{period}")
            if os.path.isdir(cron_dir):
                for script in os.listdir(cron_dir):
                    script_path = os.path.join(cron_dir, script)
                    if os.path.isfile(script_path):
                        tasks.append({
                            "computer_name": computer_name,
                            "user": user_crontab,
                            "scheduled": f"every {period}",
                            "task": script,
                            "source_file": f"/etc/cron.{period}/{script}"
                        })
    
    # Parse crontab for each user
        for user in users:
            user_crontab = os.path.join(mount_path, f"var/spool/cron/crontabs/{user}")
            if os.path.exists(user_crontab):
                with open(user_crontab, "r") as file:
                    for line in file:
                        if line.strip() and not line.startswith("#"):
                            parsed_schedule = parse_crontab_line(line)
                            #print(f"foobar {schedule}")
                            if parsed_schedule:
                                schedule, task, user_crontab = parsed_schedule
                                tasks.append({
                                    "computer_name" : computer_name,
                                    "user": user,
                                    "scheduled": schedule,
                                    "task": task,
                                    "source_file": user_crontab
                                })

    # Write tasks to CSV
        with open(output_file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerows(tasks)
    except Exception as e:
        print(red(f"Error : {e}"))

    print(green(f"Crontab entries saved to {output_file}"))

     

def get_linux_used_space(mount_path, computer_name):
    output_file = os.path.join(script_path, result_folder, "linux_disk_usage.csv")
    csv_columns = ['computer_name', 'directory', 'percent_used']
    print(yellow("[+] Retrieving disk usage ..."))
    
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


def decode_product_key(digital_product_id):
    key_offset = 52  # Position du début de la clé dans DigitalProductId
    chars = "BCDFGHJKMPQRTVWXY2346789"  # Alphabet de 24 caractères
    key = []
    
    for i in range(25):
        current = 0
        for j in range(14, -1, -1):
            current = current * 256 + digital_product_id[key_offset + j]
            digital_product_id[key_offset + j] = current // 24
            current = current % 24
        key.insert(0, chars[current])
    
    for i in range(4, 25, 5):
        key.insert(i, "-")

    return "".join(key)

def get_windows_info(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "windows_system_info.csv"  # Assurez-vous que result_folder est défini si nécessaire
    csv_columns = ['computer_name', 'windows_version', 'installation_date', 'ntp_server', 'last_update', 'last_event', 'keyboard_layout', 'license_key']

    # Initialisation des variables
    system_info = {
        'computer_name': computer_name,
        'windows_version': '',
        'installation_date': '',
        'ntp_server': '',
        'last_update': '',
        'last_event': '',
        'keyboard_layout': '',
        'license_key': ''
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
            elif value.name() == "DigitalProductId":
                digital_product_id = value.value()
                #print(digital_product_id)
                if len(digital_product_id) == 15:  # Windows 7 et antérieurs
                    deciphered_digital_product_id = digital_product_id.decode(errors='ignore')  # En clair
                    #print(deciphered_digital_product_id)
                    system_info['license_key'] = deciphered_digital_product_id
                else:  # Windows 8+
                    deciphered_digital_product_id = decode_product_key(bytearray(digital_product_id))
                    #print(deciphered_digital_product_id)
                    system_info['license_key'] = deciphered_digital_product_id
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


def get_windows_scheduled_tasks(mount_path, computer_name):
    tasks_dir = os.path.join(mount_path, "Windows/System32/Tasks")
    output_file = os.path.join(script_path, result_folder, "windows_scheduled_tasks.csv")
    csv_columns = ['computer_name', 'task_name', 'date', 'action', 'user', 'schedule', 'command']

    print(yellow("[+] Retrieving scheduled tasks from Tasks directory"))
    tasks = []
    target_tags = ["Date", "Author", "Triggers", "Enabled", "UserId", "Actions", "Exec", "Command"]
    counter = 0
    task_counter = 0

    try:
        # Parcourir les fichiers XML dans le répertoire des tâches
        for root_dir, _, files in os.walk(tasks_dir):
            for file in files:
                file_path = os.path.join(root_dir, file)
                task_counter += 1
                try:
                    tree = ET.parse(file_path)
                    root = tree.getroot()

                    task_data = {
                        'computer_name': computer_name,
                        'task_name': file,
                        'date' : None,
                        'action': None,
                        'user': None,
                        'schedule': None,
                        'command' : None
                    }

                    # Extraction des informations pertinentes
                    for elem in root.iter():
                        tag_name = elem.tag.split('}')[-1]
                        if tag_name in target_tags:
                            value = elem.text.strip() if elem.text else None
                            if tag_name == "UserId":
                                task_data['user'] = value
                            elif tag_name == "Actions":
                                task_data['action'] = value
                            elif tag_name == "Date":
                                task_data['date'] = value
                            elif tag_name == "Triggers":
                                task_data['schedule'] = value  # Vous pouvez affiner la gestion des déclencheurs ici
                            elif tag_name == "Command":
                                task_data['command'] = value

                    tasks.append(task_data)
                    counter += 1

                except Exception as e:
                    print(red(f"[-] Error parsing task file {file_path}: {e}"))

        # Écriture des informations dans le fichier CSV
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerows(tasks)

        if counter >= 1:
            print(green(f"[+] Scheduled tasks have been written into {output_file}"))
            #print(f"there is {task_counter} scheduled task")
        else:
            print(yellow(f"{output_file} should be empty."))

    except Exception as e:
        print(f"[-] Error retrieving scheduled tasks: {e}")

def serialize_entry(entry, computer_name, hive_name):
    # Sérialiser chaque entrée dans un format de dictionnaire adapté pour CSV
    return {
        'computer_name': computer_name,
        'hive': hive_name,
        'subkey_name': entry.subkey_name,
        'path': entry.path,
        #'timestamp': entry.timestamp.isoformat() if isinstance(entry.timestamp, datetime.datetime) else None,
        'timestamp': entry.timestamp,
        'values_count': entry.values_count,
        'values': [
            {
                'name': v.name,
                'value': v.value,
                'value_type': v.value_type,
                'is_corrupted': v.is_corrupted
            } for v in entry.values
        ],
        'actual_path': entry.actual_path
    }

def get_windows_full_registry(mount_path, computer_name):
    user_input = input("Do you want to dump the full registry KEYS ? It could be very long. (y/N) ").strip().lower()
    if user_input == 'y':
        output_dir = script_path + "/" + result_folder + "/"
        try:
            # Liste des hives standards
            hive_names = ['SYSTEM', 'SOFTWARE', 'SECURITY', 'SAM']
            ntuser_dirs = []

            # Recherche des NTUSER.DAT
            user_dir = mount_path + "/Users/"
            if not os.path.exists(user_dir):
                print(yellow(f"{user_dir} doesn't exist"))
            else:
                for root, _, files in os.walk(user_dir):
                    for file in files:
                        if file.upper() == 'NTUSER.DAT':
                            ntuser_dirs.append(os.path.join(root, file))

            # Ajout des hives standards
            hive_paths = [os.path.join(mount_path, 'Windows', 'System32', 'config', h) for h in hive_names]
            hive_paths.extend(ntuser_dirs)

            os.makedirs(output_dir, exist_ok=True)

            for hive_path in hive_paths:
                if not os.path.exists(hive_path):
                    print(yellow(f"{hive_path} doesn't exist"))
                    continue

                hive_name = os.path.basename(hive_path)
                csv_output = os.path.join(output_dir, f"{hive_name}.csv")
                print(yellow(f"[+] Dumping {hive_path} hive ..."))
                hive = RegistryHive(hive_path)
                if hive_name == "NTUSER.DAT":
                    username = os.path.basename(os.path.dirname(hive_path))
                    # Construire le nouveau nom de fichier
                    csv_output = f"{output_dir}{username}_{hive_name}.csv"# Construire le nouveau nom de fichier

                with open(csv_output, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = [
                        'computer_name', 'hive', 'subkey_name', 'path', 'timestamp', 'values_count', 'values', 'actual_path'
                    ]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()

                    # Redirige tous les logs de regipy vers un handler qui ignore tout
                    logging.getLogger('regipy').addHandler(logging.NullHandler())

                    # Parcourir les sous-clés et sérialiser les entrées
                    try:
                        for entry in hive.recurse_subkeys():
                            #print(entry)
                            serialized_entry = serialize_entry(entry, computer_name, hive_name)
                            writer.writerow(serialized_entry)
                    except Exception as e:
                        pass

                print(green(f"[+] {hive_name} written in {csv_output}"))
        except Exception as e:
            print(red(f"[-] Error when dumping hive file : {e}"))  


def convert_chrome_time(chrome_timestamp):
    """ Convert Webkit timestamp (microseconds since 1601) to human-readable date. """
    epoch_start = datetime(1601, 1, 1)
    return epoch_start + timedelta(microseconds=chrome_timestamp)

def convert_firefox_time(firefox_timestamp):
    """ Convert Unix timestamp in microseconds to human-readable date. """
    return datetime.utcfromtimestamp(firefox_timestamp / 1000000)

def get_windows_browsing_history(mount_path, computer_name):
    output_file = script_path + "/" + result_folder + "/" + "windows_browsing_history.csv"
    csv_columns = ['computer_name', 'source', 'user', 'url_title', 'link', 'search_date']
    print(yellow("[+] Retrieving browsing history"))
    temp_file = "/tmp/temp_history.sqlite"

    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        counter = 0

        users_dir = os.path.join(mount_path, 'Users')
        for user in os.listdir(users_dir):
            user_dir = os.path.join(users_dir, user)

            # 1. Google Chrome
            chrome_history_path = os.path.join(user_dir, 'AppData/Local/Google/Chrome/User Data/Default/History')
            if os.path.exists(chrome_history_path):
                try:
                    conn = sqlite3.connect(chrome_history_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT urls.url, urls.title, visits.visit_time FROM urls, visits WHERE urls.id = visits.url")
                    for url, url_title, visit_time in cursor.fetchall():
                        visit_date = convert_chrome_time(visit_time)
                        writer.writerow({
                            'computer_name': computer_name, 'source': 'Chrome', 'user': user,
                            'link': url, 'url_title': url_title, 'search_date': visit_date
                        })
                        counter += 1
                    conn.close()
                except Exception as e:
                    print(red(f"Error processing Chrome history: {e}"))

            # 2. Firefox
            firefox_profile_dir = os.path.join(user_dir, 'AppData/Roaming/Mozilla/Firefox/Profiles')
            if os.path.exists(firefox_profile_dir):
                for profile in os.listdir(firefox_profile_dir):
                    places_db = os.path.join(firefox_profile_dir, profile, 'places.sqlite')
                    if os.path.exists(places_db):
                        try:
                            shutil.copyfile(places_db, temp_file)
                            conn = sqlite3.connect(temp_file)
                            cursor = conn.cursor()
                            cursor.execute("""
                                SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date
                                FROM moz_places, moz_historyvisits
                                WHERE moz_places.id = moz_historyvisits.place_id
                            """)
                            for url, url_title, visit_time in cursor.fetchall():
                                visit_date = convert_firefox_time(visit_time)
                                writer.writerow({
                                    'computer_name': computer_name, 'source': 'Firefox', 'user': user,
                                    'link': url, 'url_title': url_title, 'search_date': visit_date
                                })
                                counter += 1
                            conn.close()
                        except Exception as e:
                            print(red(f"Error processing Firefox history: {e}"))
                        finally:
                            if os.path.exists(temp_file):
                                os.remove(temp_file)

            # 3. Microsoft Edge
            edge_history_path = os.path.join(user_dir, 'AppData/Local/Microsoft/Edge/User Data/Default/History')
            if os.path.exists(edge_history_path):
                try:
                    conn = sqlite3.connect(edge_history_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT urls.url, urls.title, visits.visit_time FROM urls, visits WHERE urls.id = visits.url")
                    for url, url_title, visit_time in cursor.fetchall():
                        visit_date = convert_chrome_time(visit_time)
                        writer.writerow({
                            'computer_name': computer_name, 'source': 'Edge', 'user': user,
                            'link': url, 'url_title': url_title, 'search_date': visit_date
                        })
                        counter += 1
                    conn.close()
                except Exception as e:
                    print(red(f"Error processing Edge history: {e}"))

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
                            'source': 'Chrome (logins table)',
                            'user': user,
                            'ident': username,
                            'creds': password,  # The password is encrypted; decryption may require OS-specific methods
                            'platform': url,
                            'saved_date': saved_date
                        })
                        counter += 1
                    cursor.execute("SELECT origin_domain, username_value, update_time FROM stats")
                    chrome_rows = cursor.fetchall()
                    for row in chrome_rows:
                        url, username, update_time = row
                        saved_date = convert_chrome_time(update_time)
                        writer.writerow({
                            'computer_name': computer_name,
                            'source': 'Chrome (stats table)',
                            'user': "",
                            'ident': username,
                            'creds': "",  # The password is encrypted; decryption may require OS-specific methods
                            'platform': url,
                            'saved_date': update_time
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
    try:
        f = magic.Magic()
        file_type = f.from_file(file_path)
        return file_type in ["data", "binary data", "application/octet-stream"]
    except Exception as e:
        print(f"Erreur lors de la détection de la signature : {e}")
        return False  # Par défaut, on considère qu'il a une signature en cas d'erreur


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

def extract_printable_strings(file_path):
    words_list = []  # Liste pour garder l'ordre des mots
    try:
        with open(file_path, 'rb') as f:
            byte_data = f.read()

            current_string = []
            for byte in byte_data:
                char = chr(byte)
                if char in string.printable and char not in string.whitespace:
                    current_string.append(char)
                else:
                    if current_string:
                        words_list.append(''.join(current_string))
                    current_string = []
            if current_string:
                words_list.append(''.join(current_string))

        # Découper les chaînes en mots et les retourner dans l'ordre d'apparition
        return [word for word in ' '.join(words_list).split()]

    except Exception as e:
        print(f"Erreur lors de l'extraction des chaînes du fichier {file_path}: {e}")
        return []

def find_btc_mnemo_in_files(file_path, bip39_words, min_matches=10):
    try:
        # Extraire les mots imprimables dans l'ordre
        printable_words = extract_printable_strings(file_path)

        # Nettoyer les mots pour ne garder que des caractères alphabétiques
        cleaned_printable_words = set()
        for word in printable_words:
            cleaned_word = re.sub(r"[^a-z]", "", word.lower())  # Nettoyage de chaque mot
            if len(cleaned_word) > 2:
                cleaned_printable_words.add(cleaned_word)

        # Intersection avec le dictionnaire BIP39
        matches = cleaned_printable_words.intersection(bip39_words)
        #print(f"{matches} dans {file_path}")

        # Vérifier si le nombre de correspondances atteint le seuil
        if len(matches) >= min_matches:
            #print(f"{file_path} sera analysé pour la seed")
            return True
        return False
    except Exception as e:
        print(f"[-] Error processing {file_path}: {e}")
        return False


def find_btc_seed_in_file(file_path, bip39_words):
    try:
        printable_words = extract_printable_strings(file_path)

        # Liste pour stocker les mots trouvés dans la seed
        found_words = []
        jokers = 0  # Compteur de joker (mots non BIP39)
        max_jokers = 0

        # Parcours des mots imprimables extraits, respectant l'ordre
        for word in printable_words:
            word = word.lower()
            if len(word) > 2 and re.fullmatch(r"[a-z]+", word):
                #print(f"Traitement du mot : {word}")
                if word in bip39_words:
                    found_words.append(word)
                    #jokers = 0  # Réinitialiser le compteur de joker
                #elif jokers < max_jokers:
                    #jokers += 1  # Ignorer les mots non valides mais dans la limite de jokers
                else:
                    found_words = []  # Réinitialiser si trop de jokers
                    break
                    #jokers = 0

                # Vérifier si la longueur de found_words atteint le nombre minimal
                if len(found_words) in {12, 15, 18, 24}:
                #if 11 <= len(found_words) <= 24:
                    #print(f"Seed potentielle trouvée : {found_words}")
                    return " ".join(found_words)

        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def analyze_yara(computer_name, file_path, rule):
    if os.path.exists('/usr/bin/yara'):
        yara_rule = os.path.join(script_path, rule)
        if not os.path.exists(yara_rule):
            print(f"Yara rule {yara_rule} doesn't exist. Script will exit.")
            sys.exit(1)

    yara_cmd = f"yara -w -s -r {yara_rule}"
    launch_yara_cmd = f"{yara_cmd} {file_path}"
    results = []
    result_yara_cmd = subprocess.run(launch_yara_cmd, shell=True, capture_output=True, text=True)
    clean_output = result_yara_cmd.stdout.replace(r'\n', '\n')
    lines = clean_output.splitlines()
    match_count = 0

    ## Limit match to 10, more is not necessary and csv file become too huge for nothing
    for line in lines:
        match_info = re.match(r"0x[\da-f]+:\$(\w+): (.+)", line)
        if match_info:
            match_count += 1
            if match_count == 40:
                return results
                break
            if rule == "yara/script_rule.yar":
                tag_type = "potential_malicious_script"
                matched_string = ""
            else:
                tag_type = match_info.group(1)
                matched_string = match_info.group(2)
            entry = {
                "computer_name": computer_name,
                "type": tag_type,
                "match": matched_string,
                "source_file": file_path
            }
            results.append(entry)
    return results

def process_chunk(chunk, computer_name, csv_queue, thread_id):
    local_pbar = tqdm(
        total=len(chunk), desc=f"Thread {thread_id}", position=thread_id, unit="file"
    )
    min_sql_size = 1 * 1024**3 #1Go min
    min_sql_lite_size = 1 * 1024**2 #1Mo min
    try:
        #file_to_analyze_per_chunk = f"thread_{thread_id}_files.txt"
        for file_path in chunk:
            result = {"computer_name": computer_name, "match": "", "source_file": file_path}
            yara_result = []
            rule = "yara/files_rule.yar"
            extension = Path(file_path).suffix
            #with open(file_to_analyze_per_chunk, "a") as file:
                #output = f"{file_path}\n"
                #file.write(output)

            # Exclude Linux documentation files
            if "/doc/" in file_path or "/usr/share/" in file_path or "/usr/lib" in file_path:
                local_pbar.update(1)
                continue

            if "kdb" in extension:
                result.update({"type": "keepass_file"})
                csv_queue.put(result)
            elif "tox" in extension:
                result.update({"type": "qTox_file"})
                csv_queue.put(result)
            elif "ps1" in extension or "py" in extension or "pl" in extension or "sh" in extension:
                rule = "yara/script_rule.yar"
                yara_result = analyze_yara(computer_name, file_path, rule)
                if yara_result:
                    for item in yara_result:
                        csv_queue.put(item)
            ## il faut modifier ce bloc qui actuellement est pas fou pour les BDD SQLServer
            elif "ibd" in extension or "frm" in extension:
                db_name = Path(file_path).parent.name  # Récupère le dossier parent comme nom de la DB
                if not result["match"]:
                    result["match"] = []  # Initialise une liste si vide
                elif not isinstance(result["match"], list):
                    result["match"] = [result["match"]]  # Convertit en liste si c'est une seule valeur
                if db_name not in result["match"]:
                    result["match"].append(db_name)
                #print(db_name)
                result.update({"type": "database_mysql"})
                csv_queue.put(result)
            elif "fsm" in extension or "tbl" in extension:
                db_name = Path(file_path).parent.name  # Récupère le dossier parent comme nom de la DB
                if not result["match"]:
                    result["match"] = []  # Initialise une liste si vide
                elif not isinstance(result["match"], list):
                    result["match"] = [result["match"]]  # Convertit en liste si c'est une seule valeur
                if db_name not in result["match"]:
                    result["match"].append(db_name)
                result.update({"type": "database_postgresql"})
                csv_queue.put(result)
            elif extension in {"mdf", "ndf", "ldf"}:
                parent_dir = Path(file_path).parent
                mdf_files = list(parent_dir.glob("*.mdf"))
                ldf_files = list(parent_dir.glob("*.ldf"))
                if mdf_files:  # Vérifie qu'il y a bien un .mdf, qui est le cœur de la DB
                    for mdf in mdf_files:
                        db_name = mdf.stem  # Récupère le nom de fichier sans extension (nom de la DB)
                        if not result["match"]:
                            result["match"] = []
                        elif not isinstance(result["match"], list):
                            result["match"] = [result["match"]]
                        if db_name not in result["match"]:
                            result["match"].append(db_name)
                    result.update({"type": "database_sqlserver"})
                    csv_queue.put(result)
            elif extension in {"mdf", "ndf", "ldf"}:
                parent_dir = Path(file_path).parent
                mdf_files = list(parent_dir.glob("*.mdf"))
                ldf_files = list(parent_dir.glob("*.ldf"))
            
                if mdf_files:  # Vérifie qu'il y a bien un .mdf, qui est le cœur de la DB
                    for mdf in mdf_files:
                        db_name = mdf.stem  # Récupère le nom de fichier sans extension (nom de la DB)
                        if not result["match"]:
                            result["match"] = []
                        elif not isinstance(result["match"], list):
                            result["match"] = [result["match"]]
                        if db_name not in result["match"]:
                            result["match"].append(db_name)
            
                    result.update({"type": "database_sqlserver"})
                    csv_queue.put(result)
            elif "sqlite" in extension:
                if "AppData/Local/Packages" in file_path or "AppData/Roaming/Mozilla/Firefox/Profiles" in file_path:
                    continue
                sql_lite_file_size = os.path.getsize(f"{file_path}")
                if sql_lite_file_size > min_sql_lite_size:
                    result.update({"type": "sqlite_file"})
                    csv_queue.put(result)
            elif "sql" in extension or "psql" in extension:
                sql_file_size = os.path.getsize(f"{file_path}")
                if sql_file_size > min_sql_size:
                    result.update({"type": "database_file"})
                    csv_queue.put(result)
            elif "dmp" in extension:
                result.update({"type": "minidump_file"})
                csv_queue.put(result)
            else:
                yara_result = analyze_yara(computer_name, file_path, rule)
                if yara_result:
                    for item in yara_result:
                        csv_queue.put(item)

            local_pbar.update(1)

    except Exception as e:
        print(f"[-] Error in thread {thread_id}: {e}")
    finally:
        local_pbar.close()

def find_files_chunk(mount_path, file_pattern):
    ##Exécute une commande find pour un pattern donné et retourne les fichiers trouvés.
    find_cmd = f"find {mount_path} -type f -name '{file_pattern}'"
    result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
    return result.stdout.splitlines()

def get_files_of_interest(mount_path, computer_name, platform):
    run_find_crypto = input("Do you want to launch some files of interest & crypto stuff research? It will be quite long? (yes/no): ").strip().lower()
    if run_find_crypto != "yes":
        return
    if platform == "Linux":
        output_file = f"{script_path}/{result_folder}/linux_files_of_interest.csv"
    elif platform == "Windows":
        output_file = f"{script_path}/{result_folder}/windows_files_of_interest.csv"
    elif platform == "Unknown":
        output_file = f"{script_path}/{result_folder}/files_of_interest.csv"


    files_to_search = ['wallet.*', '*.wallet', "*.kdbx", '*.tox']
    file_types_to_search = ["*.txt", "*.exe", "*.exe_", "*.sql", "*.ibd", "*.mdb", "*.psql", "*.pgsql", "*.frm",
                            "*.tbl", "*.mdf", "*.ndf", "*.ldf", "*.bson", "*.json", "*.dat", "*.db", "*.sqlite",
                            "*.dmp", "pagefile.sys", "*.sh", "*.ps1", "*.py", "*.pl"]

    num_threads = 6
    files_found = []

    # Lancer la recherche en parallèle
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(find_files_chunk, mount_path, pattern): pattern for pattern in files_to_search + file_types_to_search}

        for future in as_completed(futures):
            files_found.extend(future.result())

    # Ajouter les fichiers sans extension en parallèle
    find_cmd_no_extension = f"find {mount_path} -type f ! -name '*.*'"
    result_no_extension = subprocess.run(find_cmd_no_extension, shell=True, capture_output=True, text=True)
    files_found.extend(result_no_extension.stdout.splitlines())


    # Split files into chunks for multithreading
    chunk_size = len(files_found) // num_threads + 1
    print(f"There are {len(files_found)} to analyze")
    file_chunks = [files_found[i:i + chunk_size] for i in range(0, len(files_found), chunk_size)]

    csv_queue = Queue()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(process_chunk, chunk, computer_name, csv_queue, thread_id)
            for thread_id, chunk in enumerate(file_chunks)
        ]
        for future in futures:
            future.result()
    print("[+] Writing results to CSV...")
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['computer_name', 'type', 'match', 'source_file'])
        writer.writeheader()
        while not csv_queue.empty():
            entry = csv_queue.get()
            writer.writerow(entry)
        # Detect VeraCrypt container; File has to be larger than 1GB, without signature and a large entropy
        print("Looking now for Veracrypt container on the FileSystem...")
        min_size = 1 * 1024**3 #1Go min
        find_vc_cmd = f"find {mount_path} -type f -size +{min_size // 1024}k"
        result = subprocess.run(find_vc_cmd, shell=True, capture_output=True, text=True)
        large_files = result.stdout.splitlines()
        if large_files != "":
            for file_path in large_files:
                #print(f"Testing signature of {file_path}")
                #To avoid the pagefile false positive
                if ".sys" in file_path:
                    continue
                if has_no_signature(file_path) and is_size_divisible_by_512(file_path):
                    #print(f"Calculing entropy for {file_path}")
                    file_entropy = calculate_entropy(file_path)
                    #print(f"entropy of {file_path} is : {file_entropy}")
                    if file_entropy > 4.1:
                        writer.writerow({"computer_name": computer_name, "type": "potential_veracrypt_container", "match": "", "source_file": file_path})
    # Optional: Remove duplicates
    print("[+] Removing duplicates in CSV...")
    try:
        df = pd.read_csv(output_file)

        # Supprimer les doublons basés uniquement sur la colonne "match" (pour les valeurs non vides)
        df_non_empty_match = df[~df['match'].isna() & (df['match'] != "")].drop_duplicates(subset=['match'])

        # Conserver les entrées où "match" est vide
        df_empty_match = df[df['match'].isna() | (df['match'] == "")]

        # Fusionner les résultats
        df_unique = pd.concat([df_empty_match, df_non_empty_match])

        # Supprimer les doublons globaux en prenant en compte toutes les colonnes
        df_unique = df_unique.drop_duplicates()



        # export to csv
        df_unique.to_csv(output_file, index=False)
        print(green(f"{df_unique.shape[0]} unique rows written to {output_file}"))
    except Exception as e:
        print(f"Error deduplicating CSV: {e}")
    ##Finally, launch crypto research
    crypto_search(computer_name, mount_path)

def validate_litecoin_legacy(address):
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25:
            return False

        # Préfixes P2PKH Litecoin legacy : 0x30 (48 decimal), souvent représenté par 'L' ou 'M'
        prefix = decoded[0]
        if prefix != 0x30:
            return False

        data = decoded[:-4]
        given_checksum = decoded[-4:]
        recalculated_checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]

        if given_checksum == recalculated_checksum:
            return True

    except Exception:
        return False

def validate_btc_address(address):
    try:
        # Décoder l'adresse Bitcoin en Base58Check
        decoded = base58.b58decode(address)

        # Vérifier que la longueur est correcte (25 octets)
        if len(decoded) != 25:
            #print(f"Address {address} has incorrect length")
            return False

        # Extraire les 4 derniers octets comme checksum
        given_checksum = decoded[-4:]

        # Extraire les 21 premiers octets (préfixe + hachage public)
        data = decoded[:-4]

        # Recalculer le checksum : double SHA-256
        recalculated_checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]

        # Comparer les checksums
        if given_checksum == recalculated_checksum:
            return True
        else:
            return False

    except Exception as e:
        print(f"Error: {e}")
        return False

def validate_bitcoin_p2sh(address):
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25:
            return False

        prefix = decoded[0]
        if prefix != 0x05:
            return False

        given_checksum = decoded[-4:]
        data = decoded[:-4]
        recalculated_checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]

        if given_checksum == recalculated_checksum:
            return True

    except Exception:
        return False

def validate_bech32_address(address):
    try:
        # Decode the Bech32 address
        hrp, data = bech32_decode(address)
        if not data:
            return False

        # Check if the Human-Readable Part is valid (mainnet: "bc", testnet: "tb")
        if hrp not in ["bc", "tb"]:
            return False

        # Convert the data to 5-bit groups for SegWit validation
        decoded = convertbits(data[1:], 5, 8, False)
        if decoded is None or len(decoded) < 2 or len(decoded) > 40:
            return False

        # If everything is valid, return True
        return True
    except Exception as e:
        print(f"Validation error: {e}")
        return False

def validate_ethereum_address(eth_address):
    # Retire le préfixe '0x'
    eth_address = eth_address.lower().replace("0x", "")

    # Hash Keccak-256 de l'adresse en minuscules
    keccak_hash = sha3.keccak_256()
    keccak_hash.update(eth_address.encode('utf-8'))
    hash_keccak = keccak_hash.hexdigest()

    # Applique la règle de la checksum EIP-55
    checksum_address = "0x"
    for i, char in enumerate(eth_address):
        if char.isdigit():
            checksum_address += char
        else:
            checksum_address += char.upper() if int(hash_keccak[i], 16) >= 8 else char.lower()
    
    return checksum_address    



def process_crypto_chunk(chunk, computer_name, files_to_search, bip39_words, csv_queue, thread_id):
    local_pbar = tqdm(
        total=len(chunk), desc=f"Thread {thread_id}", position=thread_id, unit="file"
    )
    try:
        rule = "yara/crypto_rule.yar"
        max_file_size = 5 * 1024 * 1024 * 1024  # Limit analysis to 5Go

        for file_path in chunk:
            results = []
            file_name = file_path.split("/")[-1]
            
            # Exclude certain paths
            if "/usr/" in file_path or "/doc/" in file_path or "/snap/" in file_path or "/proc" in file_path or "/sys/" in file_path:
                local_pbar.update(1)
                continue
            if os.path.getsize(file_path) > max_file_size:
                local_pbar.update(1)
                continue
            with open("process_crypto_log.txt", "a") as log_file:
                log_file.write(f"Starting analysis of {file_path}\n")

            # Check if the file matches one of the wallet names
            if file_name in files_to_search:
                result = {"computer_name": computer_name, "type": "potential_wallet", "match": "", "source_file": file_path}
                results.append(result)

            # Check for BTC mnemonic in the file
            '''
            if find_btc_mnemo_in_files(file_path, bip39_words, min_matches=10):
                found_words = find_btc_seed_in_file(file_path, bip39_words)
                if found_words:
                    result = {"computer_name": computer_name, "type": "potential_btc_seed", "match": found_words, "source_file": file_path}
                    results.append(result)
            '''
            # Analyze Yara rule for the file
            entries = analyze_yara(computer_name, file_path, rule)
            if entries:
                for entry in entries:
                    result = {
                        "computer_name": entry["computer_name"],
                        "type": entry["type"],
                        "match": entry["match"],
                        "source_file": entry["source_file"]
                    }
                    results.append(result)

            # Write results to the queue
            for res in results:
                csv_queue.put(res)

            # Update progress bar
            local_pbar.update(1)

    except Exception as e:
        print(f"[-] Error in thread {thread_id}: {e}")
    finally:
        local_pbar.close()



def crypto_search(computer_name, mount_path):
    print(f"Looking now for crypto elements")
    output_file = f"{script_path}/{result_folder}/crypto.csv"
    files_to_search = [
        "wallet.dat", "electrum.dat", "default_wallet", "keystore", "wallet.json",
        "UTC--", "blockchain_wallet", "keyfile", "bitcoincash.dat", "monero-wallet.dat"
    ]
    ## ici, ça passe au scan yara "crypto"
    file_types_to_search = ["*.txt", "*.exe", "*.exe_", "*.sql", "*.ibd", "*.mdb", "*.psql", "*.pgsql" "*.bson", "*.json", "*.dat", "*.db", "*.sqlite", "*.dmp", "pagefile.sys"]
    csv_columns = ['computer_name', 'type', 'match', 'source_file']
    mnemo = Mnemonic("english")
    bip39_words = set(mnemo.wordlist)  # Set des 2048 mots BIP39
    num_threads = 6

    # Collect all files
    files_found = []
    for file_type in files_to_search + file_types_to_search:
        find_cmd = f"find {mount_path} -type f -name '{file_type}'"
        result_find = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
        files_found.extend(result_find.stdout.splitlines())

    find_cmd_no_extension = f"find {mount_path} -type f ! -name '*.*'"
    result_no_extension = subprocess.run(find_cmd_no_extension, shell=True, capture_output=True, text=True)
    files_found.extend(result_no_extension.stdout.splitlines())

    # Split files into chunks for multithreading
    chunk_size = len(files_found) // num_threads + 1
    file_chunks = [files_found[i:i + chunk_size] for i in range(0, len(files_found), chunk_size)]

    # Thread-safe queue to collect CSV results
    csv_queue = Queue()

    # Progress bars for each thread
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(process_crypto_chunk, chunk, computer_name, files_to_search, bip39_words, csv_queue, thread_id)
            for thread_id, chunk in enumerate(file_chunks)
        ]
        for future in futures:
            try:
                future.result()  # Wait for all threads to finish
            except Exception as e:
                print(red(f"Thread encoutered an error: {e}"))

    # Écrire les résultats dans le fichier CSV
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        while not csv_queue.empty():
            writer.writerow(csv_queue.get())

    print(f"[+] Cleaning {output_file}...")
    try:
        df = pd.read_csv(output_file)
        df_unique = df.drop_duplicates()
        #df_unique.to_csv(output_file, index=False)
        if df_unique.shape[0] > 0:
            print(f"Verifying crypto address...")
            df_unique['verified'] = 'unknown'
            for index, row in df_unique.iterrows():
                if row['type'] == 'litecoin_legacy':
                    is_valid = validate_litecoin_legacy(row['match'])
                    df_unique.at[index, 'verified'] = 'true' if is_valid else 'false'
                if row['type'] == 'bitcoin_legacy':
                    is_valid = validate_btc_address(row['match'])
                    df_unique.at[index, 'verified'] = 'true' if is_valid else 'false'
                if row['type'] == 'bitcoin_bech32':
                    is_valid = validate_bech32_address(row['match'])
                    df_unique.at[index, 'verified'] = 'true' if is_valid else 'false'
                if row['type'] == 'bitcoin_p2sh':
                    is_valid = validate_bitcoin_p2sh(row['match'])
                    df_unique.at[index, 'verified'] = 'true' if is_valid else 'false'
                if row['type'] == 'ethereum_address':
                    is_valid = validate_ethereum_address(row['match'])
                    df_unique.at[index, 'verified'] = 'true' if is_valid else 'false'
            # Filtrer les lignes où 'verified' est 'false'
            df_unique = df_unique[df_unique['verified'] != 'false']
            print(green(f"{df_unique.shape[0]} unique rows written to {output_file}"))
            df_unique.to_csv(output_file, index=False)
        else:
            print(yellow(f"{output_file} should be empty"))
    except Exception as e:
        print(f"Error deduplicating CSV: {e}")

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

def get_inode_table(computer_name, real_image, sub_part, byte_offset, image_format):
    print(yellow(f"[+] Extracting Inode Table from {real_image} (offset {byte_offset})..."))

    # Init SleuthKit
    try:
        img = pytsk3.Img_Info(real_image)
        fs = pytsk3.FS_Info(img, offset=byte_offset)
    except Exception as e:
        print(red(f"[-] pytsk3 FS_Info failed: {e}"))
        return

    output_csv = os.path.join(script_path, result_folder, "linux_inode_table.csv")
    inode_list = []
    threads = 8

    # Équivalent switch-case pour fls
    if image_format == "qcow2":
        fls_cmd = ["fls", "-r", "-p", "-o", "0", sub_part]
    elif image_format == "raw" or image_format == "img":
        fls_cmd = ["fls", "-r", "-p", "-o", str(byte_offset // 512), real_image]
    elif image_format == "e01":
        fls_cmd = ["fls", "-r", "-p", "-o", str(byte_offset // 512), real_image]
    else:
        print(red("[-] Unsupported image format for fls"))
        return

    try:
        fls_output = subprocess.check_output(fls_cmd, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
    except Exception as e:
        print(red(f"[-] Failed to run fls: {e}"))
        return

    for line in fls_output.strip().splitlines():
        match = re.search(r'([0-9]+):\s+(.*)$', line)
        if match:
            inode = match.group(1)
            source_path = match.group(2)
            inode_list.append((inode, source_path))

    # Écriture CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["computer_name", "inode", "deleted", "source_path", "ctime", "mtime", "atime"])
        for inode, source_path in inode_list:
            try:
                entry = fs.open_meta(inode=int(inode))
                deleted = not bool(entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                ctime = entry.info.meta.crtime
                mtime = entry.info.meta.mtime
                atime = entry.info.meta.atime
                writer.writerow([computer_name, inode, deleted, source_path, ctime, mtime, atime])
            except:
                continue
    df = pd.read_csv(output_csv)
    for col in ["ctime", "mtime", "atime"]:
        df[col] = pd.to_datetime(df[col], unit='s', errors='coerce')
    df.to_csv(output_csv, index=False)

    print(green(f"[+] Inode Table written to {output_csv}"))




def get_mft(computer_name, image_path, byte_offset):
    print(yellow("[+] Extracting Master File Table (MFT)..."))
    mft_raw_path = f"{script_path}/{result_folder}/mft.raw"
    mft_csv_path = f"{script_path}/{result_folder}/mft_parsed.csv"

    try:
        # Extraction brute avec icat
        os.system(f"icat -o {byte_offset // 512} {image_path} 0 > {mft_raw_path}")
        print(green(f"[+] MFT raw extracted to {mft_raw_path}"))

        # Analyse avec analyzeMFT.py
        os.system(f"analyzeMFT.py -f {mft_raw_path} -o {mft_csv_path} -p")
        if os.path.exists(mft_csv_path):
            df = pd.read_csv(mft_csv_path)
            df['computer_name'] = computer_name
            df.to_csv(mft_csv_path, index=False)
            print(green(f"[+] MFT parsed to {mft_csv_path}"))
            os.remove(mft_raw_path)

    except Exception as e:
        print(red(f"[-] Error extracting or parsing MFT: {e}"))

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--image", required=False, help="Path to disk image (.raw, .img, .qcow2, .E01)")
parser.add_argument("-d", "--mount", required=True, help="Mount directory")
args = parser.parse_args()

image_path = args.image
mount_path = args.mount

if image_path:
    if not os.path.isfile(image_path):
        print(red(f"[-] Image file does not exist: {image_path}"))
        sys.exit(1)

    # Détection du format
    ext = image_path.lower().split('.')[-1]
    is_img = ext == "img"
    is_raw = ext == "raw"
    is_001 = ext == "001"
    is_e01 = ext == "e01"
    is_qcow = ext == "qcow2"
    real_image = image_path


    # --- E01 ---
    if is_e01:
        print("[+] Detected E01 image, mounting with ewfmount...")
        image_format = "e01"
        try:
            for i in range(10):
                ewf_mountpoint = "/mnt/ewf" if i == 0 else f"/mnt_ewf_{i}"
                if not os.path.ismount(ewf_mountpoint):
                    os.makedirs(ewf_mountpoint, exist_ok=True)
                    break
            else:
                print(red("[-] No free ewf mount point found"))
                sys.exit(1)

            subprocess.run(["ewfmount", image_path, ewf_mountpoint], check=True)
            real_image = os.path.join(ewf_mountpoint, "ewf1")
        except Exception as e:
            print(red(f"[-] Failed to mount E01 image: {e}"))
            sys.exit(1)

    # --- QCOW2 ---
    elif is_qcow:
        print("[+] Detected QCOW2 image, attaching with qemu-nbd...")
        image_format = "qcow2"
        try:
            subprocess.run(["modprobe", "nbd"], check=True)
            nbd_device = None
            for i in range(16):
                candidate = f"/dev/nbd{i}"
                result = subprocess.run(["fdisk", "-l", candidate],
                                        capture_output=True, text=True)
                if result.returncode != 0:
                    nbd_device = candidate
                    break
            if not nbd_device:
                print(red("[-] No free /dev/nbdX device found"))
                sys.exit(1)

            subprocess.run(["qemu-nbd", "--connect", nbd_device, image_path], check=True)
            real_image = nbd_device
            time.sleep(2)
        except Exception as e:
            print(red(f"[-] Failed to attach QCOW2 image: {e}"))
            sys.exit(1)
    elif is_001 or is_raw or is_img:
        print("[+] Detected RAW image")
        image_format = "raw"



    # --- Partitions ---
    try:
        output = subprocess.check_output(["fdisk", "-l", real_image], text=True)
    except Exception as e:
        print(red(f"[-] Failed to run fdisk: {e}"))
        sys.exit(1)

    lines = output.strip().splitlines()
    partitions = []
    found = False
    for line in lines:
        if line.startswith("Device"):
            found = True
            continue
        if found and line.strip():
            partitions.append(line)

    if not partitions:
        print(red("[-] No valid partitions found."))
        sys.exit(1)

    print(yellow("\n[+] Partitions found:"))
    for i, part in enumerate(partitions, 1):
        print(f"{i}: {part}")

    try:
        part_num = int(input("\n[?] Enter the number of the partition to mount: "))
        if not (1 <= part_num <= len(partitions)):
            raise ValueError
    except:
        print(red("[-] Invalid input"))
        sys.exit(1)

    chosen_line = partitions[part_num - 1].split()
    if "*" in chosen_line:
        offset_sector = int(chosen_line[2])
    else:
        offset_sector = int(chosen_line[1])
    byte_offset = offset_sector * 512
    sub_part = chosen_line[0]

    # --- Montage ---
    if not os.path.exists(mount_path):
        os.makedirs(mount_path)

    try:
        subprocess.run(["mount", "-o", f"ro,norecovery,offset={byte_offset}", real_image, mount_path], check=True)
        print(green(f"[+] Mounted partition {part_num} at {mount_path} (offset {byte_offset})"))
    except Exception as e:
        print(red(f"[-] Failed to mount: {e}"))
        sys.exit(1)


if not os.path.exists(mount_path):
    os.makedirs(mount_path)
    print(green(f"[+] Created mount point: {mount_path}"))


if len(sys.argv) > 1:
    #mount_path = sys.argv[1]
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
            if image_path:
                get_inode_table(computer_name, real_image, sub_part, byte_offset, image_format)
                #get_inode_table(computer_name, sub_part)
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
            get_linux_crontab(mount_path, computer_name)
            #create_volatility_profile(mount_path)
            get_files_of_interest(mount_path, computer_name, platform)
        elif platform == "Windows":
            computer_name = get_windows_machine_name(mount_path)
            if image_path:
                get_mft(computer_name, image_path, byte_offset)
            get_windows_info(mount_path, computer_name)
            get_windows_network_info(mount_path, computer_name)
            get_windows_users(mount_path, computer_name)
            get_windows_groups(mount_path, computer_name)
            get_startup_services(mount_path, computer_name)
            get_windows_firewall_rules(mount_path, computer_name)
            get_windows_installed_roles(mount_path, computer_name)
            get_windows_installed_programs(mount_path, computer_name)
            get_windows_executed_programs(mount_path, computer_name)
            get_windows_scheduled_tasks(mount_path, computer_name)
            get_windows_full_registry(mount_path, computer_name)
            get_windows_browsing_history(mount_path, computer_name)
            get_windows_browsing_data(mount_path, computer_name)
            hayabusa_evtx(mount_path, computer_name)
            get_files_of_interest(mount_path, computer_name, platform)
            #extract_windows_evtx
        else:
            print("Unknown OS")
            run_search = input("The mouting point isn't a filesystem, but do you can launch some files of interest research? It will be quite long? (yes/no): ").strip().lower()
            if run_search == "yes":
                computer_name = "Unknown"
                get_files_of_interest(mount_path, computer_name, platform="Unknown")
            else:
                print("Script is going to exit.")
                sys.exit(0)




    else:
        print("Le répertoire " + mount_path + " n'existe pas")
else:
    usage()

# Fermer le descripteur de fichier global après utilisation
if original_cwd_fd is not None:
    os.close(original_cwd_fd)
