# -*- coding: utf-8 -*-
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


import pexpect
import logging


"""Commander Plugin for Unix Passwd Command
   Dependencies: 
       pip3 install pexpect
"""

def rotate(record, newpassword):
    user = record.login
    oldpassword = record.password
    prompt = '.*\$ '

    p = pexpect.spawn('bash', timeout=300)
    i = p.expect(prompt)
    logging.info('Connecting to super user %s', user)
    p.sendline('su - %s' % (user))
    i = p.expect('[Pp]assword')
    p.sendline(oldpassword)
    i = p.expect(prompt)
    logging.info('Changing password for %s', user)
    p.sendline('passwd')
    i = p.expect(['[Oo]ld [Pp]assword', '.current.*password', '[Nn]ew [Pp]assword'])
    l = p.before
    if i == 0 or i == 1:
        p.sendline(oldpassword)
        i = p.expect('[Nn]ew [Pp]assword')
    p.sendline(newpassword)
    i = p.expect("[Rr]etype [Nn]ew [Pp]assword:")
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
        record.password = newpassword
        return True

    return False
