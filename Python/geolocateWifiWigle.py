#!/usr/bin/python
# coding: utf-8

#.  Description : Little python script to locate a Wifi Network with the BSSID on Wigle Database
import requests
import json
import optparse
import sys

def search(bssid):
    s = requests.Session()
    web_search = s.get('https://api.wigle.net/api/v2/network/search?onlymine=false&freenet=false&paynet=false&netid='+ bssid, auth=('AIDab32be676685227dce097b267c241523', '1ce370bdccd6742ff59b58c9bf72c717'))
    json_file = open('file.json', 'wb') 
    json_file.write (web_search.text)
    json_file.close
    json_file = "search.json"
    with open (json_file, 'r') as json_data:
        data = json.load(json_data)
        ssid =  data["results"][0]["ssid"]
        country =  data["results"][0]["country"]
        city =  data["results"][0]["city"]
        region =  data["results"][0]["region"]
        trilat =  data["results"][0]["trilat"]
        trilong =  data["results"][0]["trilong"]
    print ("SSID: "+ssid)
    print ("Country: "+country)
    print ("City: "+city)
    print ("Region: "+region)
    print ("Latitude: ")
    print (trilat)
    print ("Longitude")
    print (trilong)
       

def main():
    scriptname = sys.argv[0]
    parser = optparse.OptionParser(scriptname +' -b <BSSID>')
    parser.add_option('-b', dest='bssid', type='string', help='specify a MAC Address')
    parser.add_option('-e', dest='extract', type='string', help='extract mode for windows laptop machines')
    (options, args) = parser.parse_args()
    bssid = options.bssid
    extract = options.extract
    if bssid == None:
        print parser.usage
        exit(0)
    else:
        search(bssid)
 
if __name__ == '__main__':
    main()
