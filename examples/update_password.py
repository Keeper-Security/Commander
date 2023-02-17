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

import getpass
import os

from keepercommander import api, vault_extensions, generator
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.record_edit import RecordUpdateCommand

my_params = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))

while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

api.login(my_params)
if not my_params.session_token:
    exit(1)
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

if record_uid:
    # 1. record-update command
    edit_command = RecordUpdateCommand()
    edit_command.execute(my_params, record=record_uid, fields=['password=$GEN'])

    # 2. direct API
    #    record = vault.KeeperRecord.load(my_params, record_uid)
    #    if isinstance(record, vault.TypedRecord):
    #        password = generator.generate(20)
    #        password_field = record.get_typed_field('password')
    #        if password_field:
    #            password_field.value = [password]
    #            record_management.update_record(my_params, record)
    api.sync_down(my_params)
