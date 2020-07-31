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
# stored in the vault.  This example also pulls configuration
# from config.json or writes the config file if it does not exist.
#
# Usage:
#    python get.py

import os
import json
import base64
import getpass

from keepercommander.params import KeeperParams
from keepercommander import display, api, subfolder

def read_config_file(params):
    params.config_filename = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.isfile(params.config_filename):
        with open(params.config_filename, 'r') as f:
            params.config = json.load(f)
            if 'user' in params.config:
                params.user = params.config['user']

            if 'password' in params.config:
                params.password = params.config['password']

            if 'server' in params.config:
                params.server = params.config['server']
            if 'device_id' in params.config:
                device_id = base64.urlsafe_b64decode(params.config['device_id'] + '==')
                params.rest_context.device_id = device_id


my_params = KeeperParams()
read_config_file(my_params)

while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

while not my_params.password:
    my_params.password = getpass.getpass(prompt='Master Password: ', stream=None)

api.sync_down(my_params)

record_uid = getpass.getpass(prompt='Record UID: ', stream=None)

# See record.py for available fields
# or call display.formatted_records(record) to show all record details
record = api.get_record(my_params, record_uid) 
if record:
    print('Record By UID: ' + record_uid)
    display.print_record(my_params, record_uid)

    # Create a path to a record
    record_paths = [subfolder.get_folder_path(my_params, x) for x in subfolder.find_folders(my_params, record_uid)]
    if record_paths:
        record_paths.sort(key=lambda x: len(x), reverse=True)
        record_path = record_paths[0] + '/' + record.title
    else:
        record_path = '/' + record.title
    record_info = subfolder.try_resolve_path(my_params, record_path)
    if record_info:
        folder, record_title = record_info
        if folder and record_title:
            record_uid = None
            for uid in my_params.subfolder_record_cache[folder.uid or '']:
                r = api.get_record(my_params, uid)
                if r.title.casefold() == record_title.casefold():
                    record_uid = uid
                    break
            if record_uid:
                print()
                print('Record By Path: ' + record_path)
                display.print_record(my_params, record_uid)
else:
    print('No record found with that UID')
