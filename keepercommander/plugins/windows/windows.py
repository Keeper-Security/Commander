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

    i = subprocess.call(["net", "user", user, newpassword], shell = True)

    if i == 0:
        print('Password changed successfully')
        record.password = newpassword
        result = True
    else:
        print('Password change failed')

    return result


def adjust(newpassword):
    # the characters below mess with windows command line
    return re.sub('[<>&|]', '', newpassword)
