#/usr/bin/python

import requests

page = requests.get("https://www.exploit-db.com/")
content = page.content
print (content)
