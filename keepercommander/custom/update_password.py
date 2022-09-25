#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example code to retrieve the password for a record
# stored in the vault.  This example also pulls configuration
# from config.json or writes the config file if it does not exist.
#
# Usage:
#    python update_password.py

import os
import json
import base64
import getpass
from typing import Optional

from keepercommander.params import KeeperParams
from keepercommander import api, vault, vault_extensions, record_management,generator
from keepercommander.commands.recordv3 import RecordEditCommand


def read_config_file(params):
    params.config_filename = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.isfile(params.config_filename):
        with open(params.config_filename, 'r') as f:
            params.config = json.load(f)
            if 'user' in params.config:
                params.user = params.config['user']

            if 'password' in params.config:
                params.password = params.config['password']

            if 'mfa_token' in params.config:
                params.mfa_token = params.config['mfa_token']

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

record_uid = ''

# Find any login record

# 1. direct API
record_uid = next((x.record_uid for x in vault_extensions.find_records(my_params, record_type='login')), None)

# 2. list command
# list_command = RecordListCommand()
# login_records = list_command.execute(my_params, format='json', type='login')
# record_list = json.loads(login_records)
# if isinstance(record_list, list) and len(record_list) > 0:
#     record_uid = record_list[0]['record_uid']

# update password
password = generator.generate(20)

# 1. record-edit command
if record_uid:
    edit_command = RecordEditCommand()
    edit_command.execute(my_params, password=password, record=record_uid)
    api.sync_down(my_params)

# 2, direct API
#if record_uid:
#    record = vault.KeeperRecord.load(my_params, record_uid)
#    if isinstance(record, vault.TypedRecord):
#        password_field = record.get_typed_field('password')
#        if password_field:
#            password_field.value = [password]
#            record_management.update_record(my_params, record)
#            api.sync_down(my_params)
