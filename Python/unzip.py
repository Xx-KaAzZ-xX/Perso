#!/user/bin/python

#.  Description : Script to bruteforce zip file with a list of passwords

import zipfile
import optparse
# This allows to use threads execution for trying simultaneous passwords
from threading import Thread


def extractFile(file, password):
    try:
        file.extractall(pwd=password)
        return password
    except:
        return
def main():
    parser = optparse.OptionParser("Example: -f <zipfile> -d <dictionary>")
    parser.add_option('-f', dest='zname', type='string',\
            help='specify zip file')
    parser.add_option('-d', dest='dname', type='string',\
            help='specify dictionary file')
    (options, args) = parser.parse_args()
    if (options.zname == None) | (options.dname == None):
        print parser.usage
        exit(0)
    else:
        zname = options.zname
        dname = options.dname
        file = zipfile.ZipFile(zname)
        dictionary = open(dname)
    for line in dictionary.readlines():
        password = line.strip('\n')
        test = Thread(target=extractFile, args=(file, password))
        test.start()
        if test:
            print '[+] Password = ' + password + '\n'
            exit(0)
if __name__ == '__main__':
    main()
