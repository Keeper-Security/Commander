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
import subprocess


# These characters don't work for Windows password rotation
DISALLOW_WINDOWS_SPECIAL_CHARACTERS = '<>^&|'


class Rotator:
    def __init__(self, login, **kwargs):
        self.login = login
        self.disallow_special_characters = DISALLOW_WINDOWS_SPECIAL_CHARACTERS

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        logging.info(f'Rotating password for Windows account "{self.login}"...')

    def rotate(self, record, new_password):
        """Rotate Windows account password"""
        domain, sep, username = self.login.rpartition('\\')
        cmd_line = ["net", "user", username, new_password]
        if domain:
            cmd_line.append('/domain')
        error_code = subprocess.call(cmd_line)
        if error_code == 0:
            logging.info(f'Password changed successfully for user "{self.login}"')
            return True
        else:
            logging.error(f'Password change failed for user "{self.login}"')
            return False
