#!/usr/bin/python

#. Description : Little python script to scan for vulnerable banners contended in "vuln_banners.txt" for main services

import socket
import sys
import os

def usage():
    filename = sys.argv[0]
    print ("Example: python"+filename+" 175.67.138.69")
    sys.exit()

def grab_banner(ip_address,port):
      try:
           s=socket.socket()
           s.connect((ip_address,port))
           banner = s.recv(1024)
           print (ip_address + ' : ' + banner)
           check_vuln(banner)
      except:
           return

def check_vuln(banner):
    f = open ("vuln_banners.txt", 'r')
    for line in f.readlines():
        if line.strip('\n') in banner:
            print "[+] Server is vulnerable: "+banner.strip('\n')

    print "[-] No vulnerable banners found"

def main():
    #Common ports for banner Grabbing
    portList = [21,22,25,80,110,443,993,995,8080]
    if len(sys.argv) > 1:
        ip_address = sys.argv[1]
        for port in portList:
            grab_banner(ip_address,port)
    else:
        usage()


main()
