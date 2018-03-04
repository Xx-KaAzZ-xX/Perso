#!/usr/bin/python

import socket
import string
import time
import math
from decimal import Decimal

server = "irc.root-me.org"       #settings
channel = "#root-me_challenge"
botnick = "PythonBot"
irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #defines the socket
print ("connecting to:"+ server)
irc.connect((server, 6667))                                                         #connects to the    server
irc.send("USER "+ botnick +" "+ botnick +" "+ botnick +" :This is a fun bot!\n") #user authentication
irc.send("NICK "+ botnick +"\n")                            #sets nick
time.sleep(4)
#irc.send("PRIVMSG nickserv :iNOOPE\r\n")    #auth
irc.send("JOIN "+ channel +"\n")        #join the chan
irc.send("PRIVMSG Candy :!ep1 "'\r\n')

while True:    #puts it in a loop
    text=irc.recv(2048)  #receive the text
    #print (text)   #print text to console

    if text.find('PING') != -1:                          #check if 'PING' is found
        irc.send('PONG ' + text.split() [1] + '\r\n') #returnes 'PONG' back to the server (prevents     pinging out!)

    if text.find('PRIVMSG') and text.find('PythonBot') and text.find('Candy') !=-1:
        #Partie qui fonctionne pas
    #if text.find("/")>-1: # Just to make sure if we're receiving the challenge message
        text=text[(text[1:].find(":"))+2:] # strip the message to look
        text=text[:text.find(".")]         # like number1/number2
        #print(text)
        #verifier la taille du tableau avant
        table = text.split(" ")
        if (len(table)) == 3:
            nb1 = int(table[0])
            nb2 = float(table[2])
            print (nb1)
            print (nb2)
            #carre=round(math.sqrt(nb1),2)  # calculate the answer
            carre=math.sqrt(nb1)
            print (carre)
            result = carre*nb2
            result = "{0:.2f}".format(result)
            print ("The answer is: " +result)



            #answer=bytes(Decimal(division).encode("ASCII")) # convert answer to bytes to send it
            irc.send("PRIVMSG Candy :!ep1 -rep "+result+"\r\n") # send answer
            print(irc.recv(2048)) # Get validation password
            irc.send("QUIT :By3 By3!") # End up client session
            break

irc.close()
