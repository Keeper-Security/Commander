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

"""Commander Plugin for Windows net Command
   Dependencies: 
       pip3 install pexpect
"""

def rotate(record, newpassword):
    """ Grab any required fields from the record """
    user = record.login

    result = False

    child = pexpect.spawn('net user ', [user, newpassword])

    i = child.expect(['The command completed succesfully.', pexpect.EOF])

    if i == 0:
        print('Password changed succesfully')
        result = True
    elif i == 1:
        print('Password change failed')

    return result
