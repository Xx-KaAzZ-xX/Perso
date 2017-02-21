#!/usr/bin/python


import requests, sys, re

for arg in sys.argv:
        if arg == "-s":
            search_term = sys.argv[2]
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
                        print(line)
                        
                        ##C'est ici qu'il faut faire la regex en python pour faire ressortir la liste des URL
                        url = re.findall('/files(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
                        for i in range(len(url)):
                            test = print (base_url+url[i])
                            test2 = re.findall('https://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', test)
                            print (test2)
            cve4.close