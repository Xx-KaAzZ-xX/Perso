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
                print (line+" is not installed. Do you want the script to install it for you ? [Y/n]")
                choice = raw_input().lower()
                if choice in yes:
                    os.system('apt-get install -y '+line)
                else:
                    print ("The script won't work without the "+line+"package")
def scan_target():
    target = sys.argv[2]
    target_ip = socket.gethostbyname(target)


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


