#!/usr/bin/python

## Il me reste à rediregirer l'output vers la sortie standard

import re, requests, sys, os, subprocess

for arg in sys.argv:
        if arg == "-s":
            search_term = sys.argv[2]
            sys.stdout = open("cve_packet.txt", 'w')
            cve3 = "cve2.html"
            cve4 = open(cve3, 'wb')
            base_url = "https://packetstormsecurity.com"
            page = requests.get(base_url+"/search/?q="+search_term)
            content = page.content
            cve4.write(content)
            with open(cve3, 'r') as f:
                for line in f:
                    
                    cve = re.search('CVE', line)
                    if cve:
                        #print(line)
                        
                        ##C'est ici qu'il faut faire la regex en python pour faire ressortir la liste des URL
                        url = re.findall('/files(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)                   
                        
                        for i in range(len(url)):
                            
                            print (base_url+url[i])
                            
                            #cve_packet.write(test)
                            #cve_packet.close
                            #test2 = re.findall('/files/cve/CVE-(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
                        
            sys.stdout.close
            cve4.close
            sort = "cat cve_packet.txt | sort -u"
            links = subprocess.check_output([sort], stdout=subprocess.PIPE)
            out = links.stdout.red()
            print out
            #os.system('cat cve_packet.txt | sort -u')
            #os.system('rm cve_packet.txt')
            
