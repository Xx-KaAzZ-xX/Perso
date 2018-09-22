#!/usr/bin/python
# coding: utf-8

# Description :	Script to get CVE Exploit from Nmap Scan file
# Author	: Aurélien DUBUS
# Version : 1.0

import optparse
import sys
import string
from lxml import etree


def main():
	scriptname = sys.argv[0]
	parser = optparse.OptionParser('Example:'+scriptname+'-f <file>')
	parser.add_option('-f', dest='file', type='string', help='specify input Nmap file')
	(options, args) = parser.parse_args()
	file = options.file

	if file == None:
		print parser.usage
		exit(0)
	elif file.endswith('.xml'):
		#start searching
		cve_search(file)
	else:
		print ('specify a Nmap Scan xml file')


def cve_search(file):
	tree = etree.parse(file)
	for ports in list(tree):
		port = ports.find('portid').text
		print (port)


if __name__ == '__main__':
	main()

