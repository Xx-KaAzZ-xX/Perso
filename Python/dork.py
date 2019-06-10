#!/usr/bin/python

import requests
import sys
import optparse
from bs4 import BeautifulSoup

def duckDuckGo(dork):
	headers_Get = {
        	'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
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
	#print (url)
    	request = s.get(url, headers=headers_Get, verify=False)
	content = request.text
    	soup = BeautifulSoup(request.text, "html.parser")
	print (content)
	output = []
	for link in soup.findAll('a', href=True):
                print link.string


def main():
	scriptname = sys.argv[0]
    	parser = optparse.OptionParser('Example: '+scriptname+' -d "inurl:php?id="')
    	parser.add_option('-d', dest='dork', type='string', help='specify dork')
    	parser.add_option('-l', dest='dorkList', type='string', help='specify dork list')
    	(options, args) = parser.parse_args()
    	dork = options.dork
    	dorkList=options.dorkList

    	if (dork == None):
        	print '[-] You must specify a dork or dorkList'
        	exit (0)

    	duckDuckGo(dork)

if __name__ == '__main__':
     	main()
