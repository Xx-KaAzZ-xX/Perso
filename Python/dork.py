#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import sys
import optparse
import re
import random
from bs4 import BeautifulSoup

def duckDuckGoSimple(dork):
	user_agent_file = "user_agent.txt"
        num_lines = sum(1 for line in open(user_agent_file))
        #print (num_lines)
        rand_num = random.randint(1,num_lines)
        with open(user_agent_file) as f:
            user_agent = f.read().split('\n')[rand_num]
        ##problem with the random user_agent, search is broken when changing
        headers_Get = {
            #'User-Agent': user_agent,
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/50.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
    	}
    	s = requests.Session()
    	##replace space by +
    	dork = '+'.join(dork.split())
    	url = 'https://duckduckgo.com/lite?q=' + dork + '&sc=25'
    	request = s.get(url, headers=headers_Get)
	content = request.text
    	soup = BeautifulSoup(request.text, "html.parser")
	for link in soup.findAll('a', attrs={'href': re.compile("^http|^https://")}):
                print link.get('href')

def duckDuckGoList(dorkList):
    with open(dorkList) as f:
        for dork in f:
            print ()
            print ("[+] Searcing results for:" + dork)
            duckDuckGoSimple(dork)
def main():
	scriptname = sys.argv[0]
    	parser = optparse.OptionParser('Example: '+scriptname+' -d "inurl:php?id="')
    	parser.add_option('-d', dest='dork', type='string', help='specify dork')
    	parser.add_option('-l', dest='dorkList', type='string', help='specify dork list')
    	(options, args) = parser.parse_args()
    	dork = options.dork
    	dorkList=options.dorkList

    	if (dork == None) & (dorkList == None):
        	print '[-] You must specify a dork or dorkList'
        	exit (0)

        elif (dork != None):
            duckDuckGoSimple(dork)
        elif (dorkList != None):
            duckDuckGoList(dorkList)

if __name__ == '__main__':
     	main()
