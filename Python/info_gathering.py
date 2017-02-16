#!/bin/python
# -*- coding: ISO-8859-1 -*- 

#. Description:     Tool to automatize information gathering step

import os, sys, os.path, apt, socket

##Définitions des variables
scriptname = sys.argv[0]
cache = apt.Cache()
prerequisites = "/tmp/prerequisites.txt"
yes = set(['yes','y', 'ye', ''])
no = set(['no','n'])


##Usage function
def usage ():
    print ("This is the list of available options:")
    print ("\t -h : Set the host or domain name")
    print ("\t -p : Set a person name \n")
    print ("\t Example : python "+scriptname+" -h example.com")

##Check if necessary packages are installed
def check_package():
    ##On définit une liste des paquets requis pour le script
    file = open(prerequisites, 'wb')
    file.write("nikto\ntor\nproxychains\nnmap")
    file.close()
    
    ##On check si chacun d'eux est installé
    with open(prerequisites, 'r') as f:
        for line in f:
            line = line.rstrip('\n')
            if cache[line].is_installed: 
                print (line+" :[OK]")
            else:
                os.system('which'+line)
                test_dpkg = os.system('echo $?')
                if test_dpkg == "1":
                    print (line+" is not installed. Do you want the script to install it for you ? [Y/n]")
                    choice = raw_input().lower()
                    if choice in yes:
                        os.system('apt-get install -y '+line)
                    else:
                        print ("The script won't work without the "+line+"package")
                else:
                    print (line+" :[OK]")
def scan_target():
    target = sys.argv[2]
    ##Error handling for NX domains##
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print ("The target does not exist")
        sys.exit()
        
    path = os.getenv("HOME")
    os.chdir(path)
    try:
        os.mkdir(target)
    except OSError:
        print ("The directory"+target+"exists. Try again")
        sys.exit()
    
    #Target results in a specific directory

    scan_directory = (path+'/'+target+'/')
    print (scan_directory)
    
    nmap_scan = os.system('proxychains nmap -A -T4 -sV '+target_ip+' -oA '+scan_directory+'nmap_scan')
    #result = subprocess.check_output(nmap_scan, shell=True)

def exploits_search():
    #Must grep nmap output and search for possible exploits through the web
    
def main_prog():
    for arg in sys.argv:
        if arg == "-h":
            scan_target()
        if len(sys.argv) == 1:
            usage()

print ("===== Prerequisites =====\n")
check_package()
print ("==========================\n")
main_prog()


