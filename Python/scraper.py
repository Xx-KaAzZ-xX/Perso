#!/usr/bin/python
# -*- coding: ISO-8859-1 -*-
#. Description: Outil qui fait de la recherche dans plusieurs BDD CVE en fonction du -s search_term

#. Pense-bête: 
#. Où en étais-je: Améliorer l'output pour les CVE

import os, sys, requests, re, subprocess

##Une fois que ça marche avec un site , il faut mettre la liste d'url avec params à modifier dans cette boucle
## WARNING : Les sites ne vont pas tous retournés les datas sous le même genre !
'''
with open('sites.txt', 'r')as f:
    for line in f:
        page = requests.get(line+'apache2.4')
        content = page.content
'''

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
        '''
        print (bcolors.OKGREEN+"\t \t \t ====== NVD DATABASE ======")
        cve1 = "cve1.html"
        cve2 = open(cve1, 'wb')
        base_url = "https://web.nvd.nist.gov/view/vuln/"
        page = requests.get(base_url+"search-results?query="+search_term)
        content = page.content
        cve2.write(content)
        with open(cve1, 'r') as f:
            for line in f:
                cve = re.search('CVE', line)
                if cve:
                    ##C'est ici qu'il faut faire la regex en python pour faire ressortir la liste des URL
                    #print((line.split(start))[0].split(end)[0])
                    url = re.findall('detail(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
                    for i in range(len(url)):
                        print (base_url+url[i])
        cve2.close
        '''
        ##0DAY DATABASE PART##
        
        print (bcolors.OKBLUE+"\t \t \t ====== ODAY DATABASE ======")
        cve1 = "cve1.html"
        cve2 = open(cve1, 'wb')
        #base_url = "https://web.nvd.nist.gov/view/vuln/"
        page = requests.get("http://0day.today/search?search_request="+search_term)
        content = page.content
        
        cve2.write(content)
        with open(cve1, 'r') as f:
            for line in f:
                cve = re.search('CVE', line)
                #start = "v2 - "
                #end = ">CVE-"
                if cve:
                    ##C'est ici qu'il faut faire la regex en python pour faire ressortir la liste des URL
                    #print((line.split(start))[0].split(end)[0])
                    url = re.findall('detail(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
                    for i in range(len(url)):
                        print (url[i])
        cve2.close
        

if len(sys.argv) == 1:
        usage()


