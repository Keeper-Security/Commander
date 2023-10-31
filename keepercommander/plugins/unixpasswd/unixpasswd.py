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

import logging
import pexpect
import shutil

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

    logging.info('Connecting to super user %s', user)
    user = user.replace("\\", "\\\\").replace("\"", "\\\"").replace(";", "\\;")
    p = pexpect.spawn(f'su - "{user}"', timeout=5)
    p.expect('[Pp]assword')
    if not p.waitnoecho(1):
        raise Exception('Password prompt is expected')
    p.sendline(oldpassword)
    attempt = 0
    while attempt < 5:
        attempt += 1
        no = p.expect(['(.+)\n', pexpect.TIMEOUT], timeout=0.1)
        if no == 1:
            break
    logging.info('Changing password for %s', user)
    p.sendline(shutil.which('passwd'))
    i = p.expect(PasswordOld + PasswordNew)
    if not p.waitnoecho(1):
        raise Exception('Password prompt is expected')
    if i < len(PasswordOld):
        p.sendline(oldpassword)
        p.expect(PasswordNew)
    p.sendline(newpassword)
    p.expect(PasswordAgain)
    p.sendline(newpassword)

    i = p.expect(['.try again', '.authentication', '.failure', '.has not been changed', '.successfully', pexpect.TIMEOUT])

    if i == 0:
        logging.info('Password change failed')
    elif i == 1:
        logging.info('Current password is incorrect')
    elif i == 2:
        logging.info('General failure in password update')
    elif i == 3:
        logging.info('Password password has not been changed')
    elif i == 4:
        logging.info('Password changed successfully')
        return True

    return False
