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

"""Commander Plugin for Unix Passwd Command
   Dependencies: 
       pip3 install pexpect
"""

def rotate(record, newpassword):
    """ Grab any required fields from the record """
    user = record.login
    oldpassword = record.password

    result = False

    child = pexpect.spawn("/usr/bin/passwd %s"%(user))

    i = child.expect(['[Oo]ld [Pp]assword', '.current.*password', '[Nn]ew [Pp]assword'])

    if i == 0 or i == 1:
        child.sendline(oldpassword)
        child.expect('[Nn]ew [Pp]assword')
    child.sendline(newpassword)
    child.expect("Retype New Password:")
    child.sendline(newpassword)

    i = child.expect(['.try again', '.authentication', '.failure', pexpect.EOF])

    if i == 0:
        print('Password change failed')
    elif i == 1:
        print('Current password is incorrect')
    elif i == 2:
        print('General failure in password update')
        result = True
    elif i == 3:
        print('Password changed succesfully')
        result = True

    return result
