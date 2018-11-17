#!/usr/bin/python
# encoding: utf8

## Script qui permet de changer chaque caractere du fichier en code ASCII, de bruteforce
## le codage cesar donc de 0 à 128 mais avec + et - et de retransformer le code
## ASCII du caractère chiffré en caractère lisible
file = "ch7.bin"
array = []
with open(file, 'r') as content_file:
    content = content_file.read()
    #print (content)
    for rank in range(len(content)):
    	char = content[rank]
    	array += [ord(char)]
    #print (array)

    for i in range(128):
    	string = "KEY #"
    	string += str(i)
    	print string
    	decipher_array = []
    	decipher_array2 = []
    	for x in array:
    		#print (x)
    		new_ascii_code = x + i	
    		decipher_array += [new_ascii_code]
    		new_ascii_code2 = x - i
    		decipher_array2 += [new_ascii_code2]
    	#print(decipher_array)
    	for y in decipher_array:
    		try:
    			test = chr(y)
    			print (test),
    			#break
    		except ValueError:
    			print "Pas de code correspondant au caractère"
    	print ("ANOTHER POSSIBLE KEY ")
    	for y in decipher_array2:
    		try:
    			test2 = chr(y)
    			print (test2),
    			#break
    		except ValueError:
    			print "Pas de code correspondant au caractère"
    	#print (test)
    	del decipher_array[:]
    	del decipher_array2[:]
    		