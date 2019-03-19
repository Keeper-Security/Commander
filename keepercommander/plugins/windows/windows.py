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

import logging
import subprocess
import re


def rotate(record, newpassword):
    """ Grab any required fields from the record """

    i = subprocess.call(["net", "user", record.login, newpassword], shell=True)

    if i == 0:
        logging.info('Password changed successfully')
        record.password = newpassword
        return True

    logging.error('Password change failed')
    return True


def adjust(newpassword):
    # the characters below mess with windows command line
    return re.sub('[<>&|]', '', newpassword)
