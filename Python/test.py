#!/usr/bin/python

#.  Description : Little python script to locate a Wifi Network with the BSSID
import requests
import json
import optparse
import sys

def search(bssid):
    '''s = requests.Session()
    web_search = s.get('https://api.wigle.net/api/v2/network/search?onlymine=false&freenet=false&paynet=false&netid='+ bssid, auth=('AIDab32be676685227dce097b267c241523', '1ce370bdccd6742ff59b58c9bf72c717'))
    json_file = open('file.json', 'wb') 
    json_file.write (web_search.text)
    json_file.close'''
    json_file = "file.json"
    with open (json_file) as json_data:
        data = json.load(json_data)
        #data = json.load(json_data)["trilat"]["trilong"]
        print data

def main():
    scriptname = sys.argv[0]
    parser = optparse.OptionParser(scriptname +' -b <BSSID>')
    parser.add_option('-b', dest='bssid', type='string', help='specify a MAC Address')
    (options, args) = parser.parse_args()
    bssid = options.bssid
    if bssid == None:
        print parser.usage
        exit(0)
    else:
        search(bssid)
 
if __name__ == '__main__':
    main()
