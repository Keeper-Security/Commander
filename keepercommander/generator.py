#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#
import logging
import os
import random
import string
from typing import Optional
from secrets import choice

from Cryptodome.Random.random import shuffle


DEFAULT_PASSWORD_LENGTH = 32
PW_SPECIAL_CHARACTERS = '!@#$%()+;<>=?[]{}^.,'


def randomSample(sampleLength=0, sampleString=''):
    sample = ''

    use_secrets = False

    try:
        # Older version of Python (before 3.6) don't have this module.
        # If not installed, fall back to the original version of the code
        import secrets
        logging.debug("module 'secrets' is installed")
        use_secrets = True
    except ModuleNotFoundError:
        logging.warning("module 'secrets' is not installed")

    for i in range(sampleLength):
        if use_secrets:
            sample += secrets.choice(sampleString)
        else:
            pos = int.from_bytes(os.urandom(2), 'big') % len(sampleString)
            sample += sampleString[pos]

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


class KeeperPasswordGenerator:
    def __init__(self, length: int = DEFAULT_PASSWORD_LENGTH, symbols: Optional[int] = None,
                 digits: Optional[int] = None, caps: Optional[int] = None, lower: Optional[int] = None,
                 special_characters: str = PW_SPECIAL_CHARACTERS):
        none_count = (symbols, digits, caps, lower).count(None)
        sum_categories = sum(0 if i is None or i <= 0 else i for i in (symbols, digits, caps, lower))
        if none_count > 0:
            # remaining length of password will be divided among unspecified categories
            extra_count = length - sum_categories if length > sum_categories else 0
            new_none_value = extra_count // none_count
            symbols, digits, caps, lower = (new_none_value if i is None else i for i in (symbols, digits, caps, lower))
            sum_categories += new_none_value * none_count
        elif sum_categories == 0:
            symbols, digits, caps, lower, sum_categories = 1, 1, 1, 1, 4
        extra_count = length - sum_categories if length > sum_categories else 0
        self.category_map = [
            (symbols, special_characters),
            (digits, string.digits),
            (caps, string.ascii_uppercase),
            (lower, string.ascii_lowercase),
        ]
        extra_chars = ''.join(c[1] for c in self.category_map if c[0] > 0)
        self.category_map.append((extra_count, extra_chars))

    def generate(self) -> str:
        password_list = []
        for count, chars in self.category_map:
            password_list.extend(choice(chars) for i in range(count))
        shuffle(password_list)
        return ''.join(password_list)

    @classmethod
    def create_from_rules(cls, rule_string: str, length: Optional[int] = None,
                          special_characters: str = PW_SPECIAL_CHARACTERS):
        """Create instance of class from rules string

        rule_string: comma separated integer character counts of uppercase, lowercase, numbers, symbols
        length: length of password
        special_characters: set of characters used to generate password symbols
        """
        rule_list = [s.strip() for s in rule_string.split(',')]
        if len(rule_list) != 4 or not all(n.isnumeric() for n in rule_list):
            logging.warning(
                'Invalid rules to generate password. Format is "upper, lower, digits, symbols"'
            )
            return None
        else:
            rule_list = [int(n) for n in rule_list]
            upper, lower, digits, symbols = rule_list
            length = sum(rule_list) if length is None else length
            return cls(
                length=length, caps=upper, lower=lower, digits=digits, symbols=symbols,
                special_characters=special_characters
            )
