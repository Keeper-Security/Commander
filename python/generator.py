#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2015 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import random
import string

def randomSample(sampleLength=0, sampleString=''):
	sample = ''

	for i in range(sampleLength):
		sample += sampleString[random.randint(0,len(sampleString)-1)]

	return sample;

def rules(uppercase=0, lowercase=0, digits=0, special_characters=0):
	""" Generate a password of specified length with specified number of uppercase, lowercase, digits and special characters """
    
	password = ''
	
	if uppercase:
		password += randomSample(uppercase, string.ascii_uppercase)
	if lowercase:
		password += randomSample(lowercase, string.ascii_lowercase)
	if digits:
		password += randomSample(digits, string.digits)
	if special_characters:
		password += randomSample(special_characters, string.punctuation)
	
	newpass = ''.join(random.sample(password,len(password)))
	return newpass

def generate(length=64):
    """ Generate password of specified len """
    increment = length // 4
    lastincrement = increment + (length % 4)
    return rules(increment, increment, increment, lastincrement)
