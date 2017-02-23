#!/usr/bin/python
# -*- coding: ISO-8859-1 -*-
#. Description: Outil qui fait de la recherche dans plusieurs BDD CVE en fonction du -s search_term

#. Pense-bête: 
#. Où en étais-je: Améliorer l'output pour les CVE

import os, sys, requests, re, subprocess

##Une fois que ça marche avec un site , il faut mettre la liste d'url avec params à modifier dans cette boucle
## WARNING : Les sites ne vont pas tous retournés les datas sous le même genre !

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'

def usage ():
        print ("This is the list of available options:")
        print ("\t -s : Set the search term")
        sys.exit()

for arg in sys.argv:
    if arg == "-s":
        search_term = sys.argv[2]

    ##NVD DATABASE PART##
        
        print (bcolors.OKGREEN+"\t \tNVD DATABASE\t \t \n")
        cve1 = "cve1.html"
        cve2 = open(cve1, 'wb')
        base_url1 = "https://web.nvd.nist.gov/view/vuln/"
        page = requests.get(base_url1+"search-results?query="+search_term)
        content = page.content
        cve2.write(content)
        with open(cve1, 'r') as f:
            for line in f:
                cve = re.search('CVE', line)
                if cve:
                    ##C'est ici qu'il faut faire la regex en python pour faire ressortir la liste des URL
                    #print((line.split(start))[0].split(end)[0])
                    url1 = re.findall('detail(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
                    for i in range(len(url1)):
                        print (base_url1+url1[i])
        cve2.close
        ##PacketStorm Security DATABASE PART##
        
        print (bcolors.OKBLUE+"\n \t \tPacketStormSecurity DATABASE \t \t \n")
	cve3 = "cve2.html"
        cve4 = open(cve3, 'wb')
        base_url2 = "https://packetstormsecurity.com"
        page = requests.get(base_url2+"/search/?q="+search_term)
        content = page.content
        cve4.write(content)
        sys.stdout = open("cve_packet.txt", 'w')
        with open(cve3, 'r') as f:
            for line in f:

                cve = re.search('CVE', line)
                if cve:
                    ##C'est ici qu'il faut faire la regex en python pour faire ressortir la liste des URL
                    url2 = re.findall('/files(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)

                    for i in range(len(url2)):
                        print (base_url2+url2[i])
                        #cve_packet.write(test)
                        #cve_packet.close
                        #test2 = re.findall('/files/cve/CVE-(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)


        sys.stdout.close
        cve4.close

        sys.stdout = open("/dev/stdout", "w")
        os.system('cat cve_packet.txt | sort -u > cve_packet2.txt')
        with open("cve_packet2.txt", "r") as f:
            for line in f:
                print (line)
        #os.system('rm cve_packet.txt')                

        ##Exploit-DB Part##

        os.system('/root/Pentest/exploit-db/searchsploit '+search_term)

if len(sys.argv) == 1:
        usage()


