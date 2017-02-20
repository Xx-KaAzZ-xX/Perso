#/usr/bin/python

#. Description: Outil qui fait de la recherche dans plusieurs BDD CVE en fonction du -s search_term

#.Pense-bête: 
#. Où en étais-je: Améliorer l'output pour les CVE

import sys, getopt, requests, re

##Une fois que ça marche avec un site , il faut mettre la liste d'url avec params à modifier dans cette boucle
## WARNING : Les sites ne vont pas tous retournés les datas sous le même genre !
'''
with open('sites.txt', 'r')as f:
    for line in f:
        page = requests.get(line+'apache2.4')
        content = page.content
'''

def usage ():
        print ("This is the list of available options:")
        print ("\t -s : Set the search term")
        sys.exit()

for arg in sys.argv:
    if arg == "-s":
        search_term = sys.argv[2]
        #print (search_term)
        cve1 = "cve1.html"
        cve2 = open(cve1, 'wb')
        page = requests.get("https://web.nvd.nist.gov/view/vuln/search-results?query="+search_term)
        content = page.content
        cve2.write(content)

        with open(cve1, 'r') as f:
            for line in f:
                if re.search('CVE',line):
                    print (line)

        cve2.close
    if len(sys.argv) == 1:
        usage()

