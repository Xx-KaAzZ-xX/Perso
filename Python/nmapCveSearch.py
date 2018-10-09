#!/usr/bin/python
# coding: utf-8

# Description :	Script to get CVE Exploit from Nmap Scan file
# Author	: Aurélien DUBUS
# Version : 1.0

import optparse
import sys
import string
from lxml import etree
import xml.etree.ElementTree as ET
from xml.dom import minidom

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
	tree = ET.parse(file)
	root = tree.getroot()
	#print (root.tag)
	xmldoc = minidom.parse(file)
	hosts = xmldoc.getElementsByTagName("host")
	for host in hosts:
		address = host.getElementsByTagName("address")
		if address:
			ip = address[0].attributes["addr"]
			IP = ip.value
			print("IP:%s"%(IP))
	ports = xmldoc.getElementsByTagName("port")
	i = 0
	for port in ports:
		service = host.getElementsByTagName("service")
		if service:
			##Il faut faire un test sur chaque variable si elle est vide ou non et l'afficher ensuite
			try:
				product = service[i].attributes["product"]
				PRODUCT = product.value
				name = service[i].attributes["name"]
				NAME = name.value
				version = service[i].attributes["version"]
				VERSION = version.value
				print ("Service name: "+NAME+" Product: "+PRODUCT+" Version: "+VERSION)
			except:
				print ("no error")
		i += 1
		
if __name__ == '__main__':
	main()

