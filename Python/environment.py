#!/usr/bin/python


#. Description: Script d'analyse d'environnement à partir d'un point de montage
#  - rajouter la liste des utilisateurs et groupes : OK
#  - rajouter la liste d'installation des paquets et les dates : OK
#  - apparemment, on pourrait se chrooter dans le répertoire monté pour avoir les commandes dans le contexte du système monté : OK
#  - version du kernel => à revoir
#  - infos réseaux => à revoir

import platform
import os
import ipaddress
import re
import time
import yaml
import subprocess
#from tabulate import tabulate
from datetime import datetime, timedelta
import sys
from pathlib import Path
from Registry import Registry
from Evtx.Evtx import Evtx
from lxml import etree
import csv
import glob

# Chemin vers le système de fichiers monté
script_name = sys.argv[0]

def usage():
    print("Exemple : python " + script_name + " /mnt/root")

def bandeau(chaine):
    lignes = chaine.split('\n')
    largeur_max = max(len(ligne) for ligne in lignes)
    cadre_haut_bas = '+' + '-' * (largeur_max + 2) + '+'

    lignes_encadrees = [cadre_haut_bas]
    for ligne in lignes:
        lignes_encadrees.append('| ' + ligne.ljust(largeur_max) + ' |')
    lignes_encadrees.append(cadre_haut_bas)

    return '\n'.join(lignes_encadrees)

# Déclarer la variable globale pour le répertoire courant original
original_cwd_fd = None

# Fonction pour lancer des commandes chrootées sur un système Linux
def chroot_and_run_command(mount_path, chroot_command):
    global original_cwd_fd
    if original_cwd_fd is None:
        original_cwd_fd = os.open('/', os.O_RDONLY)

    # Changer la racine du système de fichiers
    try:
        os.chroot(mount_path)
        os.chdir("/")
    except PermissionError:
        print("Permission denied: You need to run this script as root.")
        sys.exit(-1)

    # Exécuter la commande dans l'environnement chrooté
    try:
        result = subprocess.run(chroot_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        print(f"Command '{chroot_command}' failed with error: {e.stderr.decode()}")

    # Restaurer le répertoire courant et la racine d'origine
    finally:
        os.fchdir(original_cwd_fd)
        os.chroot(".")
        # Ne pas fermer original_cwd_fd ici pour qu'il soit réutilisé
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
    output_csv = result_folder + "machine_info.csv"
    print(f"le fichier d'output est : {output_csv}")
    system_info = {
        'computer_name': '',
                'distro': '',
                'installation_date': '',
        'ntp_server': '',
        'dns_server': '',
        'last_update': '',
        'last_event': ''
    }

    try:
        # Get computer name from /etc/hostname
        hostname_file = os.path.join(mount_path, "etc/hostname")
        if os.path.exists(hostname_file):
            with open(hostname_file) as f:
                computer_name = f.read().strip()
                system_info['computer_name'] = computer_name
                return computer_name

        # Get distribution from /etc/os-release
        distro_file = os.path.join(mount_path, "etc/os-release")
        if os.path.exists(distro_file):
            with open(distro_file) as f:
                for line in f:
                    if line.startswith("ID="):
                        distro = line.strip().split("=")[1].strip('"')
                        system_info['distro'] = distro
                        break
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
                system_info['dns_server'] = dns_server  # Ajoute à system_info
        # Extraction du serveur NTP à partir de ntp.conf
        ntp_server = None
        if os.path.exists(ntp_file):
            with open(ntp_file) as f:
                for line in f:
                    if line.startswith('server'):
                        ntp_server = line.split()[1]
                        system_info['ntp_server'] = ntp_server
                        break


        # Get installation date
        log_installation_file = os.path.join(mount_path, "var/log/installer/syslog")
        if os.path.exists(log_installation_file):
            log_installation_file_infos = os.stat(log_installation_file)
            timestamp = log_installation_file_infos.st_ctime
            system_info['last_update'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        else:
            passwd_file = os.path.join(mount_path, "etc/passwd")
            if os.path.exists(passwd_file):
                passwd_file_infos = os.stat(passwd_file)
                timestamp = passwd_file_infos.st_ctime
                system_info['installation_date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

        # Get last event (this could be tailored depending on the log type)
        last_event_log = os.path.join(mount_path, "var/log/syslog")  # Example for Ubuntu/Debian
        if os.path.exists(last_event_log):
            last_log_infos = os.stat(last_event_log)
            timestamp = last_log_infos.st_mtime
            system_info['last_event'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        # Output results to CSV
        with open(output_csv, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['computer_name', 'distro', 'installation_date', 'ntp_server', 'dns_server', 'last_update', 'last_event']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(system_info)

        print(f"System information written to {output_csv}")

    except Exception as e:
        print("An error occurred while gathering system information:", e)

def get_network_info(mount_path, computer_name):
    output_csv = "network_info.csv"

    # Chemins potentiels pour les fichiers de configuration réseau
    interfaces_file = os.path.join(mount_path, "etc/network/interfaces")
    netplan_dir = os.path.join(mount_path, "etc/netplan/")
    redhat_ifcfg_dir = os.path.join(mount_path, "etc/sysconfig/network-scripts/")

        # Préparation pour l'écriture dans le fichier CSV
    csv_columns = ['computer_name', 'interface', 'ip_address', 'netmask', 'gateway']
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()

        # Extraction des informations des interfaces
        if os.path.exists(interfaces_file):
            with open(interfaces_file) as f:
                iface, ip, netmask, gateway = None, None, None, None
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
                    #writer.writerow({'computer_name': computer_name, 'interface': iface, 'ip_address': ip, 'netmask': netmask, 'gateway': gateway})
                    writer.writerow(network_info)

        # Extraction des informations pour RedHat (ifcfg)
        if os.path.exists(redhat_ifcfg_dir):
            for filename in os.listdir(redhat_ifcfg_dir):
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
                            writer.writerow({'Interface': iface, 'IP Address': ip, 'Netmask': netmask, 'Gateway': gateway})
                           #writer.writerow({'Interface': 'netplan', 'IP Address': ip, 'Netmask': 'N/A', 'Gateway': gateway})

        if os.path.exists(netplan_dir):
            for filename in os.listdir(netplan_dir):
                 if filename.endswith('.yaml') or filename.endswith('.yml'):  # Vérifier que c'est un fichier YAML
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
        print(f"Network information extracted and written to {output_csv}")


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
'''
def get_network_info(mount_path):
    chaine = "Informations réseau "
    print(bandeau(chaine))
'''

def get_users(mount_path):
    chroot_command = "cat /etc/passwd"
    chaine = "Utilisateurs sur le système"
    print(bandeau(chaine))
    chroot_and_run_command(mount_path, chroot_command)

def get_groups(mount_path):
    chroot_command = "cat /etc/group"
    chaine = "Groupes sur le système"
    print(bandeau(chaine))
    chroot_and_run_command(mount_path, chroot_command)


def list_connections(mount_path):
    chaine = "Liste des connexions"
    print(bandeau(chaine))

    # Chemin vers les fichiers de log de connexion
    log_files_path = os.path.join(mount_path, "var/log")

    # Vérifier que le répertoire des fichiers de log existe
    if not os.path.isdir(log_files_path):
        print("Le répertoire des fichiers de log n'existe pas.")
        return

    # Récupérer les fichiers de log de connexion
    log_files = os.listdir(log_files_path)

    # Parcourir les fichiers de log pour récupérer les adresses IP
    for log_file in log_files:
        log_file_path = os.path.join(log_files_path, log_file)


        # Traitement des fichiers auth.log
        if "auth.log" in log_file:
            with open(log_file_path, encoding='ISO-8859-1') as file:
                log_content = file.read()
                for line in log_content.split("\n"):
                    if "sshd" in line and "Accepted" in line:
                        chaine = "Liste des connexions réussies depuis le auth.log"
                        print(bandeau(chaine))
                        print(line)
        if "secure*" in log_file:
            with open(log_file_path, encoding='ISO-8859-1') as file:
                log_content = file.read()
                for line in log_content.split("\n"):
                    if "sshd" in line and "Accepted" in line:
                        chaine = "Liste des connexions réussies depuis le auth.log"
                        print(bandeau(chaine))
                        print(line)
        # Traitement des fichiers wtmp
        if "wtmp" in log_file:
            chaine = "Liste des connexions réussies depuis le wtmp:"
            print(bandeau(chaine))
            last_cmd = f"last -f {log_file_path} -F"
            result_last = subprocess.run(last_cmd, shell=True, capture_output=True, text=True)
            print(result_last.stdout)

        # Vérification de l'existence du dossier audit
        if "audit" in log_file and os.path.isdir(os.path.join(log_files_path, "audit")):
            audit_dir = os.path.join(log_files_path, "audit")
            audit_files = os.listdir(audit_dir)

            print(bandeau("Recherche des connexions réussies dans les fichiers audit.log"))

            for audit_file in audit_files:
                if "audit.log" in audit_file:
                    audit_file_path = os.path.join(audit_dir, audit_file)

                    # Exécuter zgrep pour trouver les occurrences de "success" dans les fichiers audit.log
                    zgrep_cmd = f"zgrep 'USER_LOGIN' {audit_file_path} | grep 'success'"
                    result_zgrep = subprocess.run(zgrep_cmd, shell=True, capture_output=True, text=True)

                    # Afficher les lignes qui correspondent
                    if result_zgrep.stdout:
                        print(f"Lignes trouvées dans {audit_file_path} :\n{result_zgrep.stdout}")
                    else:
                        print(f"Aucune correspondance trouvée dans {audit_file_path}")

def list_installed_apps(mount_path):
    distro_file = mount_path + "/etc/os-release"
    chaine = "Liste des applications installées"
    print(bandeau(chaine))

    if os.path.exists(distro_file):
        with open(distro_file) as f:
            for line in f:
                if line.startswith("ID="):
                    distro = line.strip().split("=")[1].strip('"')
                    #print(distro)
                    break
        if distro in ["debian", "ubuntu"]:
            chroot_command = "zgrep 'install ' /var/log/dpkg.log* | sort | cut -f1,2,4 -d' '"
            chroot_command2 = "apt list --installed"
            chroot_and_run_command(mount_path, chroot_command)
            chroot_and_run_command(mount_path, chroot_command2)
        elif distro in ["rhel", "centos", "fedora", "almalinux"]:
            # Exécutez la première commande
            chroot_command = "rpm -qa --queryformat '%{installtime:date} %{name}-%{version}-%{release}\n' | sort"
            result = chroot_and_run_command(mount_path, chroot_command)

            # Vérifiez si la sortie est vide
            if result:
                print(result)
            else:
                print("Aucun paquet trouvé, tentative de récupération des logs yum ou dnf.")

                # Lister tous les fichiers yum.log* dans /var/log
                yum_log_path = os.path.join(mount_path, "var/log/yum.log*")
                yum_log_files = glob.glob(yum_log_path)  # Récupère tous les fichiers correspondants

                if yum_log_files:
                    for log_file in yum_log_files:
                        # Déterminer si le fichier est compressé
                        if log_file.endswith(".gz"):
                            with gzip.open(log_file, 'rt', encoding='utf-8') as f:
                                result_logs = f.read()
                                if result_logs:
                                    print(f"Contenu du fichier {log_file}:")
                                    print(result_logs)
                                else:
                                    print(f"Aucun contenu trouvé dans le fichier {log_file}.")

                        else:
                            with open(log_file, 'r', encoding='utf-8') as f:
                                result_logs = f.read()
                                if result_logs:
                                    print(f"Contenu du fichier {log_file}:")
                                    print(result_logs)
                                else:
                                    print(f"Aucun contenu trouvé dans le fichier {log_file}.")
                else:
                    print("Aucun fichier yum.log n'a été trouvé.")
        else:
            print("Distribution inconnue")

def list_services(mount_path):
    chaine = "Liste des services sur la machine"
    print(bandeau(chaine))
    init_path = mount_path + "/usr/sbin/init"
    if os.path.exists(init_path):
        init_sys = os.path.basename(os.readlink(init_path))
        if init_sys == "systemd":
            chroot_command = "systemctl list-unit-files --type=service"
            chroot_and_run_command(mount_path, chroot_command)
        else:
            # Afficher la sortie d'erreur de la commande
            #print(f"Erreur: {result.stderr}")
                print("Not managed by Systemd")
    else:
        print("System is not managed by Systemd")
def get_firewall_rules(mount_path):
    print(bandeau("Firewall Rules Linux"))
    chroot_command = "iptables -L"
    chroot_and_run_command(mount_path, chroot_command)

def create_volatility_profile(mount_path):
    create_profile = input("Voulez-vous créer un profil Volatility ? (oui/non) ").strip().lower()
    if create_profile == 'non':
        print("Opération annulée.")
    elif create_profile == 'oui':
        volatility_dir = input("Veuillez entrer le répertoire de Volatility: ").strip()
        # Trouver la version du noyau
        lib_modules_path = os.path.join(mount_path, 'lib/modules')
        versions = os.listdir(lib_modules_path)
        if len(versions) == 0:
            print(f"Aucune version de noyau trouvée dans {mount_path}lib/modules.")
            sys.exit(1)

        # Utiliser la première version trouvée (ou ajouter une logique pour choisir la bonne version)
        kernel_version = versions[0]
        print(f"Version de noyau trouvée: {kernel_version}")

        # Mettre à jour les variables d'environnement pour le Makefile
        os.environ['KDIR'] = mount_path
        os.environ['KVER'] = kernel_version
        os.environ['PWD'] = os.path.join(volatility_dir, 'tools/linux')

        # Chemin vers le répertoire contenant le Makefile de Volatility
        makefile_dir = os.path.join(volatility_dir, 'tools/linux')
        build_path = mount_path + "lib/modules"
        # Exécuter le make dans le répertoire contenant le Makefile
        try:
            subprocess.run(['make', '-C', makefile_dir, 'dwarf'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors de la création du profil : {e}")
            sys.exit(1)

        print("Fichier dwarf généré avec succès.")

        # Générer le fichier zip contenant le module dwarf et System.map
        dwarf_file = os.path.join(makefile_dir, 'module.dwarf')
        system_map_file = os.path.join(mount_path, 'boot', f'System.map-{kernel_version}')
        output_zip = os.path.join(volatility_dir, f'{kernel_version}_profile.zip')

        if not os.path.exists(dwarf_file):
            print(f"Le fichier {dwarf_file} n'existe pas.")
            sys.exit(1)

        if not os.path.exists(system_map_file):
            print(f"Le fichier {system_map_file} n'existe pas.")
            sys.exit(1)

        with zipfile.ZipFile(output_zip, 'w') as zipf:
            zipf.write(dwarf_file, 'module.dwarf')
            zipf.write(system_map_file, f'System.map-{kernel_version}')

        print(f"Profil Volatility créé avec succès: {output_zip}")

def get_windows_machine_name(mount_path):
    #chaine = "Informations du système Windows"
    #print (bandeau(chaine))
    path_to_reg_hive = (mount_path+ 'Windows/System32/config/SYSTEM')
    reg = Registry.Registry(path_to_reg_hive)
    try:
        key = reg.open("ControlSet001\\Control\\ComputerName\\ComputerName")
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find Run key. Exiting...")
        sys.exit(-1)

    for value in [v for v in key.values() \
                       if v.value_type() == Registry.RegSZ or \
                          v.value_type() == Registry.RegExpandSZ]:
    #result = print("%s: %s" % (value.name(), value.value()))
        if value.name() == "ComputerName":
            computer_name = value.value()
            #print(f"Nom de la machine: {computer_name}")
            #print("Nom de la machine: "+value.value())
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
    csv_columns = ['computer_name', 'windows_version', 'installation_date', 'ntp_server', 'last_update', 'last_event']

    # Initialisation des variables
    system_info = {
        'computer_name': computer_name,
        'windows_version': '',
        'installation_date': '',
        'ntp_server': '',
        'last_update': '',
        'last_event': ''
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
'''
def get_windows_users(mount_path):
    chaine = "Liste des utilisateurs Windows"
    print(bandeau(chaine))

    path_to_reg_hive = mount_path + 'Windows/System32/config/SAM'

    try:
        # Ouvrir la ruche SAM
        reg = Registry.Registry(path_to_reg_hive)
    except Registry.RegistryParseException as e:
        print(f"Error opening SAM hive: {e}")
        sys.exit(-1)

    try:
        # Ouvrir la clé contenant les informations des utilisateurs
        key = reg.open("SAM\\Domains\\Account\\Users\\Names")
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the key. Exiting...")
        sys.exit(-1)

    # Parcourir les sous-clés pour obtenir les noms des utilisateurs
    for subkey in key.subkeys():
        print(f"User: {subkey.name()}")
'''
def get_windows_users(mount_path, computer_name):

    output_file = script_path + "/" + result_folder + "/" + "windows_users.csv"
    print("[+] Retrieving users informations")
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SAM')

    try:
        # Ouvrir la ruche SAM
        reg = Registry.Registry(path_to_reg_hive)
    except Registry.RegistryParseException as e:
        print(f"Erreur lors de l'ouverture de la ruche SAM : {e}")

    try:
        # Ouvrir la clé contenant les informations des utilisateurs
        user_key = reg.open("SAM\\Domains\\Account\\Users\\Names")
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the key for users. Exiting...")

    # Récupérer les utilisateurs
    users = {}
    for subkey in user_key.subkeys():
        username = subkey.name()
        # Récupérer la valeur par défaut pour obtenir le SID
        for value in subkey.values():
            if value.name() == "(default)":
                users[username] = value.value()

    # Récupérer les groupes et les SID correspondants
    group_sids = {}
    try:
        group_key = reg.open("SAM\\Domains\\Account\\Groups")
        for subkey in group_key.subkeys():
            group_name = subkey.name()
            for value in subkey.values():
                if value.name() == "(default)":
                    group_sids[group_name] = value.value()  # Récupérer le SID du groupe
                    break
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the key for groups. Exiting...")

    # Établir l'appartenance des utilisateurs aux groupes
    user_group_membership = {user: [] for user in users.keys()}

    for group, sid in group_sids.items():
        try:
            # Vérifier les utilisateurs dans chaque groupe
            group_membership_key = reg.open(f"SAM\\Domains\\Account\\Groups\\{group}\\Members")
            for value in group_membership_key.values():
                if value.value() in users.values():
                    # Trouver le nom d'utilisateur correspondant au SID
                    for username, user_sid in users.items():
                        if user_sid == value.value():
                            user_group_membership[username].append(group)
        except Registry.RegistryKeyNotFoundException:
            continue

    # Écriture dans un fichier CSV
    csv_columns = ['computer_name', 'username', 'sid', 'groups']

    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            for user, sid in users.items():
                writer.writerow({'computer_name': computer_name, 'username': user, 'sid': sid, 'groups': ', '.join(user_group_membership[user])})
        print(f"Les informations sur les utilisateurs et leurs groupes ont été écrites dans {output_file}")
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier CSV: {e}")


def get_windows_groups(mount_path):
    chaine = "Liste des groupes Windows"
    print(bandeau(chaine))
    path_to_reg_hive = mount_path + 'Windows/System32/config/SAM'
    reg = Registry.Registry(path_to_reg_hive)

    try:
        key = reg.open("SAM\\Domains\\Builtin\\Aliases\\Names")
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the key. Exiting...")
        sys.exit(-1)
    print
    for subkey in key.subkeys():
        print(f"Group: {subkey.name()}")

def get_powershell_history(mount_path):
    chaine = "Historique des commandes PowerShell"
    print(bandeau(chaine))

    users_path = os.path.join(mount_path, 'Users')
    if not os.path.isdir(users_path):
        print(f"Le chemin {users_path} n'existe pas ou n'est pas un répertoire.")
        return

    for user_dir in os.listdir(users_path):
        user_path = os.path.join(users_path, user_dir)
        history_path = os.path.join(user_path, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt')
        if os.path.isfile(history_path):
            print(f"\nHistorique des commandes PowerShell pour l'utilisateur : {user_dir}")
            try:
                with open(history_path, 'r', encoding='utf-8') as file:
                    history = file.readlines()
                    for command in history:
                        print(command.strip())
            except Exception as e:
                print(f"Une erreur s'est produite lors de la lecture de {history_path} : {e}")
        else:
                print(f"Le fichier {history_path} n'existe pas pour l'utilisateur {user_dir}.")


def get_startup_services(mount_path):
    chaine = "Services au démarrage"
    print(bandeau(chaine))

    # Registry path for services
    services_path = "ControlSet001\\Services"

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
    #with open("startup_services.txt", "w") as f:
    for subkey in key.subkeys():
        try:
            service_name = subkey.name()
            # Check for the "Start" value
            start_value = subkey.value("Start").value()
            if start_value in [0, 1, 2]:  # Boot Start, System Start, Automatic
                start_type = ""
                if start_value == 0:
                    start_type = "Boot Start"
                elif start_value == 1:
                    start_type = "System Start"
                elif start_value == 2:
                    start_type = "Automatic Start"
                print(f"Service: {service_name}, Start Type: {start_type}")
        except Registry.RegistryValueNotFoundException:
            # If "Start" value is not found, skip the service
            continue

def get_windows_firewall_rules(mount_path, computer_name):
    firewall_paths = [
        "ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
        "CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    ]
    print(computer_name)
    output_file = "firewall_rules.csv"
    # Add 'ComputerName' to the CSV columns
    csv_columns = ['ComputerName', 'Action', 'Active', 'Dir', 'Protocol', 'Profile', 'LPort', 'RPort', 'App', 'Svc', 'Name', 'Desc', 'EmbedCtxt']

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

                # Parse each part of the rule data, dynamically
                for item in rule_data:
                    if '=' in item:
                        key, val = item.split('=', 1)
                        rule_dict[key] = val

                # Add the computer name to the row
                rule_dict['ComputerName'] = computer_name

                # Write the row to CSV, filling missing fields with empty strings
                writer.writerow({col: rule_dict.get(col, '') for col in csv_columns})

    print(f"Firewall rules written to {output_file}")

def get_windows_installed_roles(mount_path):
    chaine = "Windows Installed Roles"
    print(bandeau(chaine))
    # Définir le chemin du registre
    path_to_reg_hive = os.path.join(mount_path, 'Windows/System32/config/SOFTWARE')
    reg = Registry.Registry(path_to_reg_hive)

    # Définir le chemin de la clé de registre pour les rôles et fonctionnalités installés
    key_path = 'Microsoft\\ServerManager\\ServicingStorage\\ServerComponentCache'

    try:
        key = reg.open(key_path)
    except Registry.RegistryKeyNotFoundException:
        print("Couldn't find the key. Exiting...")
        return

    # Parcourir les sous-clés
    for subkey in key.subkeys():
        install_state = None

        # Parcourir les valeurs de chaque sous-clé pour trouver 'InstallState'
        for value in subkey.values():
            if value.name() == "InstallState":
                install_state = value.value()
                break

        # Afficher les sous-clés dont la valeur 'InstallState' est 1
        if install_state == 1:
            print(f"Role/Feature: {subkey.name()}")

def get_windows_installed_programs(mount_path, computer_name):
    installed_programs_paths = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",  # Ajout de ce chemin au cas où
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    ]

    output_file = "installed_programs.csv"
    csv_columns = ['ComputerName','DisplayName', 'DisplayVersion', 'InstallDate', 'Publisher']

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

            for subkey in key.subkeys():
                program_info = {
                    'ComputerName': computer_name,
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

    print(f"Installed programs written to {output_file}")

def get_windows_executed_programs(amcache_path):
    chaine = "Windows Executed Programs from Amcache"
    print(bandeau(chaine))
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

    # Parcourir et lister les sous-clés de Root\File
    print("Listing subkeys under Root\\File:")
    for subkey in key.subkeys():

        # Parcourir et lister les sous-clés de cette sous-clé
        for sub_subkey in subkey.subkeys():
            for value in sub_subkey.values():
                #print(f"{value.name()}")
                #print(f"{value.value()}")
                if value.name() == "17":
                    win_timestamp = (value.value())
                    print("Executed date: " + str(get_windows_timestamp(win_timestamp)))
                if value.name() == "15":
                    print(f"Filepath : {value.value()}")

def hayabusa_evtx(mount_path):
    hayabusa_path = script_path + "/hayabusa/hayabusa"
    print(hayabusa_path)
    run_hayabusa = input("Do you want to launch Hayabusa? (yes/no): ").strip().lower()

    if run_hayabusa == "yes":
        # Demander le nom du fichier de sortie
        output_filename = input("Enter the filename for the output CSV: ").strip()

    # Construire la commande à exécuter
    command = f"{hayabusa_path} csv-timeline -d {mount_path}/Windows/System32/winevt/Logs/ -T -o {output_filename}"

    # Exécuter la commande
    os.system(command)

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
            #get_users(mount_path)
            #get_groups(mount_path)
            #list_installed_apps(mount_path)
            #list_connections(mount_path)
            #list_services(mount_path)
            #get_firewall_rules(mount_path)
            #create_volatility_profile(mount_path)
        elif platform == "Windows":
            computer_name = get_windows_machine_name(mount_path)
            get_windows_info(mount_path, computer_name)
            #get_windows_storage_info(mount_path)
            #get_windows_mounted_devices(mount_path)
            #get_windows_disk_volumes(mount_path)
            get_windows_network_info(mount_path, computer_name)
            get_windows_users(mount_path, computer_name)
            #get_windows_groups(mount_path)
            #get_windows_rdp_connections(mount_path)
            #get_powershell_history(mount_path)
            #get_windows_services(mount_path)
            #get_startup_services(mount_path)
            #get_windows_firewall_rules(mount_path, computer_name)
            #get_windows_installed_roles(mount_path)
            get_windows_installed_programs(mount_path, computer_name)
            #get_windows_executed_programs(amcache_path)
            #hayabusa_evtx(mount_path)
        else:
            print("Unknown OS")
    else:
        print("Le répertoire " + mount_path + " n'existe pas")
else:
    usage()

# Fermer le descripteur de fichier global après utilisation
if original_cwd_fd is not None:
    os.close(original_cwd_fd)
