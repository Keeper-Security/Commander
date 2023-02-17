#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2020 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example code to retrieve the password for a record
# stored in the vault.  
# 
# This example shows how to get the record from UID
# or from the full path.  For example:
# 
# By UID:
# -----------
# $ python get.py 
# User(Email): mydemo@company.com
# Master Password: *******
# Enter record UID or full record path: InS1KiJBf1XGK16itcLnyA
#
# By Path:
# -----------
# $ python get.py 
# User(Email): mydemo@company.com
# Master Password: *******
# Enter record UID or full record path: Docs/Customer Data/Hubspot
#
# This code also pulls configuration
# from config.json or writes the config file if it does not exist.
#
# Usage:
#    python get.py

import os

from keepercommander import api, subfolder
from keepercommander.__main__ import get_params_from_config

my_params = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))

if my_params.user:
    print('User(Email): {0}'.format(my_params.user))
else:
    while not my_params.user:
        my_params.user = input('User(Email): ')

api.login(my_params)
if not my_params.session_token:
    exit(1)

api.sync_down(my_params)

record_name = input('Enter record UID or full record path: ')
if record_name:
    record_uid = None
    # check if record_name is record UID
    if record_name in my_params.record_cache:
        record_uid = record_name
    else:
        # check if record_name is a path to the existing record
        record_info = subfolder.try_resolve_path(my_params, record_name)
        if record_info:
            # record_info is a tuple (subfolder.BaseFolderNode, record title)
            folder, record_title = record_info
            if folder and record_title:
                record_uid = None
                # params.subfolder_record_cache holds record uids for every folder
                for uid in my_params.subfolder_record_cache[folder.uid or '']:
                    # load a record by record UID
                    r = api.get_record(my_params, uid)
                    # compare record title with the last component of the full record path
                    if r.title.casefold() == record_title.casefold():
                        record_uid = uid
                        break
    if record_uid:
        record = api.get_record(my_params, record_uid)
        print('Record identified by \"{0}\"'.format(record_name))
        record.display()
    else:
        print('Record identified by \"{0}\" not found.'.format(record_name))
