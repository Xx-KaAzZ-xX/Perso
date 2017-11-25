#!/usr/bin/python
import optparse
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
    parser = optparse.OptionParser("%prog -t <target host(s)> -p <target port(s)>")
    parser.add_option('-t', dest='targetHosts', type='string', help='Specify the target host(s); Separate them by commas')
    parser.add_option('-p', dest='targetPorts', type='string', help='Specify the target port(s); Separate them by commas')
    (options, args) = parser.parse_args()
    if (options.targetHosts == None) | (options.targetPorts == None):
        print parser.usage
        exit(0)
    targetHosts = str(options.targetHosts).split(',')
    targetPorts = str(options.targetPorts).split(',')
    setdefaulttimeout(5)
    for targetHost in targetHosts:
        for targetPort in targetPorts:
            conn(targetHost, int(targetPort))

if __name__ == '__main__':
    main()
