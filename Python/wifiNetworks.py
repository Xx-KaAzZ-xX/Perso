#!/usr/bin/python
# -*- coding: utf-8 -*

from _winreg import *

## Petite fonction pour convertir la valeur en hexa contenue
## dans la clé de registre pour obtenir une MAC Address
def val2addr(val):
    addr = ""
    for ch in val:
		addr += ("%02x "% ord(ch))
		addr = addr.strip(" ").replace(" ",":")[0:17]
		return addr

def printNetworks():
    net = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
    key = OpenKey(HKEY_LOCAL_MACHINE, net)
    print "\n [*] Networks you have joined."
    for i in range(100):
        try:
            guid = EnumKey(key, i)
            netKey = OpenKey(key, str(guid))
            (n, addr, t) = EnumValue(netKey, 5)
            (n, addr, t) = EnumValue(netKey, 4)
            macAddr = val2addr(addr)
            netName = str(name)
            print "[+] "+ netName + " " + macAddr
            CloseKey(netKey)
        except:
            break

def main():
    printNetworks()
if __name__ == "__main__":
    main()