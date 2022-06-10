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

from ..windows.windows import DISALLOW_WINDOWS_SPECIAL_CHARACTERS


class Rotator:
    def __init__(self, login, host=None, **kwargs):
        self.login = login
        self.host = host
        host_msg = f' on host "{self.host}"' if self.host else ''
        self.user_host_msg = f'user "{self.login}"{host_msg}'
        self.disallow_special_characters = DISALLOW_WINDOWS_SPECIAL_CHARACTERS

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        logging.info(f'Rotating password for {self.user_host_msg}...')

    def rotate(self, record, new_password):
        """Rotate Windows account password"""
        host_arg = f'\\\\{self.host} ' if self.host else ''
        # the characters below mess with windows command line
        escape_quote_password = new_password.replace('"', '""')
        error_code = subprocess.call(f'pspasswd {host_arg}{self.login} "{escape_quote_password}"')

        if error_code == 0:
            print(f'Password changed successfully for {self.user_host_msg}.')
            result = True
        else:
            print(f'Password change failed for {self.user_host_msg}.')
            result = False
        return result
