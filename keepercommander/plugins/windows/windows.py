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

import subprocess, re

def rotate(record, newpassword):
    """ Grab any required fields from the record """
    user = record.login

    result = False

    # the characters below mess with windows command line
    np = re.sub('[<>&|]', '', newpassword)
    i = subprocess.call("net user {0} {1}".format(user, np), shell = True)

    if i == 0:
        print('Password changed succesfully')
        if np != newpassword:
            record.password = np
        result = True
    else:
        print('Password change failed')

    return result
