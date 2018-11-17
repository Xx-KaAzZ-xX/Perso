#!/usr/bin/python
#encoding: utf8

file = "ch7.bin"
LETTERS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
with open(file, 'r') as content_file:
    content = content_file.read()
    print (content)
    # loop through every possible key
for key in range(len(LETTERS)):
	translated = ''
	for symbol in content:
		if symbol in LETTERS:
			num = LETTERS.find(symbol) # get the number of the symbol
			num = num - key
		if num < 0:
			num = num + len(LETTERS)
			translated = translated + LETTERS[num]
		else:
			translated = translated + symbol
	print('Key #%s: %s' % (key, translated))
