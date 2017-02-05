#!/bin/python

#. Description:     Tool to automatize information gathering step

import sys, os.path, apt
scriptname = sys.argv[0]
cache = apt.Cache()

##Usage function
def usage ():
    print ("This is the list of available options:")
    print ("\t -h : Set the host or domain name")
    print ("\t -p : Set a person name \n")
    print ("\t Example : python "+scriptname+" -h example.com")

##Check if necessary packages are installed
def check_package():
    if cache['nikto'].is_installed:
        print "it works"

check_package()

'''
for arg in sys.argv:
    if arg == "-h":
        print "It works"
    if len(sys.argv) == 1:
        usage()
'''
