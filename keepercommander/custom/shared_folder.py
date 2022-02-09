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
#    python shared_folder.py

import os
import json
import base64
import getpass

from keepercommander.params import KeeperParams
from keepercommander import api
from keepercommander.commands.register import ShareFolderCommand


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

folders = ["Shared Folder 1", "Shared Folder 2"]
user1 = "user@company.com"
team1 = "Team1"

command = ShareFolderCommand()
for folder in folders:
    command.execute(my_params, action="grant", user=[user1, team1], folder=folder)

api.sync_down(my_params)
