#!/usr/bin/python

#. Description : Python script to grab the banner on opened ports and does a cve-search on the banner
#.               The script requires https://github.com/cve-search/cve-search

import optparse
import os
import sys
from socket import *


def conn(targetHost, targetPort):
    try:
        conn = socket(AF_INET, SOCK_STREAM)
        conn.connect((targetHost, targetPort))
        print '[+] Connection to ' + targetHost + ' port ' + str(targetPort) + ' succeeded!'
        grab(conn)
    except Exception, e:
        print '[-] Connection to ' + targetHost + ' port ' + str(targetPort) + ' failed: ' + str(e)
    finally:
        conn.close()

def grab(conn):
    try:
        conn.send('foobar\r\n')
        ret = conn.recv(1024)
        print '[+]' + str(ret)
        return
    except Exception, e:
        print '[-] Unable to grab any information: ' + str(e)
        return

def main():
    scriptname = sys.argv[0]
    cve_search = "/root/Pentest/Cve-search"
    parser = optparse.OptionParser("Example: "+scriptname+" -t <target host(s)> -p <target port(s)>")
    parser.add_option('-t', dest='targetHosts', type='string', help='Specify the target host(s); Separate them by commas')
    parser.add_option('-p', dest='targetPorts', type='string', help='Specify the target port(s); Separate them by commas')
    (options, args) = parser.parse_args()
    if (options.targetHosts == None) | (options.targetPorts == None):
        print parser.usage
        exit(0)
    targetHosts = str(options.targetHosts).split(',')
    targetPorts = str(options.targetPorts).split(',')
    setdefaulttimeout(5)
    if not os.path.exists(cve_search):
        print (""+cve_search+" doesn't exist. Script will exit.")
        exit(0)
    for targetHost in targetHosts:
        for targetPort in targetPorts:
            conn(targetHost, int(targetPort))

if __name__ == '__main__':
    main()
