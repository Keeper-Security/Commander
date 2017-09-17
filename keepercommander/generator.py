#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#

import random
import string

def randomSample(sampleLength=0, sampleString=''):
    sample = ''

    for i in range(sampleLength):
        sample += sampleString[random.randint(0,len(sampleString)-1)]

    return sample

def rules(uppercase=0, lowercase=0, digits=0, special_characters=0):
    """ Generate a password of specified length with specified number of """
    """ uppercase, lowercase, digits and special characters """
    
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

def generateFromRules(rulestring):
    """ Generate based on rules from a string similar to "4,5,2,5" """
    uppercase, lowercase, digits, special = 0,0,0,0

    ruleparams = filter(str.isdigit, rulestring)

    rulecount = 0
    for rule in ruleparams:
        if rulecount == 0:
            uppercase = int(rule)
        elif rulecount == 1:
            lowercase = int(rule)
        elif rulecount == 2:
            digits = int(rule)
        elif rulecount == 3:
            special = int(rule)
        rulecount += 1

    return rules(uppercase, lowercase, digits, special)

def generate(length=64):
    """ Generate password of specified len """
    increment = length // 4
    lastincrement = increment + (length % 4)
    return rules(increment, increment, increment, lastincrement)
