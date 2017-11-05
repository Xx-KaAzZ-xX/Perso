#/usr/bin/python

import optparse
import sys
import socket
from socket import *
from threading import Thread

screenLock = Semaphore(value=1)
def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('foobar\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print '[+]%d/tcp open'% tgtPort
        print '[+]'+str(results)
        connSkt.close()
    except:
        screenLock.acquire()
        print '[-]%d/tcp closed'% tgtPort
    finally:
        screenLock.release()
        connSkt.close()

def portScan(tgtHost,tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print "[-] Cannot resolve '%s': Unknown host"%tgtHost
        return
    try:
        tgtName = gesthostbyaddr(tgtIP)
        print '\n[+] Scan Results for: ' + tgtName[0]
    except:
        print '\n[+] Scan Results for: ' + tgtIP
        setdefaulttimeout(1)
        for tgtPort in tgtPorts:
            thread = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
            thread.start()
            print 'Scanning port ' +tgtPort
            connScan(tgtHost, int(tgtPort))

def main():
    scriptname = sys.argv[0]
    parser = optparse.OptionParser('Example: '+scriptname+' -t <target host> -p <target port>')
    parser.add_option('-t', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port(s)')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    #tgtPort = options.tgtPort
    tgtPorts = str(options.tgtPort).split(', ')

    if (tgtHost == None) | (tgtPorts[0] == None):
        print '[-] You must specify a target host and port[s].'
        exit (0)
    portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
    main()
