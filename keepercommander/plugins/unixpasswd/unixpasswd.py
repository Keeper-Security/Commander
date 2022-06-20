# -*- coding: utf-8 -*-
#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


import pexpect
import logging

from ...commands.base import RecordMixin

"""Commander Plugin for Unix Passwd Command
   Dependencies: 
       pip3 install pexpect
"""

PasswordOld = ['[Oo]ld', '[Cc]urrent']
PasswordNew = ['[Nn]ew']
PasswordAgain = ['[Rr]etype']


def rotate(record, newpassword):
    user = RecordMixin.get_record_field(record, 'login')
    oldpassword = RecordMixin.get_record_field(record, 'password')

    prompt = r'.*\$ '

    p = pexpect.spawn('bash', timeout=5)
    p.expect(prompt)
    logging.info('Connecting to super user %s', user)
    p.sendline(f'su - {user}')
    p.expect('[Pp]assword')
    p.sendline(oldpassword)
    p.expect(prompt)
    logging.info('Changing password for %s', user)
    p.sendline('passwd')
    i = p.expect(PasswordOld + PasswordNew)
    if i < len(PasswordOld):
        p.sendline(oldpassword)
        p.expect(PasswordNew)
    p.sendline(newpassword)
    p.expect(PasswordAgain)
    p.sendline(newpassword)

    i = p.expect(['.try again', '.authentication', '.failure', prompt])

    if i == 0:
        logging.info('Password change failed')
    elif i == 1:
        logging.info('Current password is incorrect')
    elif i == 2:
        logging.info('General failure in password update')
    elif i == 3:
        logging.info('Password changed successfully')
        return True

    return False
