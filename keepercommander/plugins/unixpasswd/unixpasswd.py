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
    user = record.login
    oldpassword = record.password
    prompt = '.*\$ '

    p = pexpect.spawn('bash', timeout=300)
    i = p.expect(prompt) 
    print('Connecting to super user %s'%(user))
    p.sendline('su - %s' % (user))
    i = p.expect('[Pp]assword')
    p.sendline(oldpassword)
    i = p.expect(prompt)
    print('Changing password for %s'%(user))
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
        print('Password change failed')
        return False
    elif i == 1:
        print('Current password is incorrect')
        return False
    elif i == 2:
        print('General failure in password update')
        return False
    elif i == 3:
        print('Password changed successfully')
        record.password = newpassword
        return True

    return False
