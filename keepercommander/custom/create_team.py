#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example code to create a Team and add users to the team
#
# This example also pulls configuration from config.json 
# or writes the config file if it does not exist.
#
# Usage:
#    python3 create_team.py

import os
import json
import base64
import getpass

from keepercommander.params import KeeperParams
from keepercommander import api
from keepercommander.commands.enterprise import EnterpriseTeamCommand

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

api.query_enterprise(my_params)

# Create Enterprise Team Command
command = EnterpriseTeamCommand()

# Create Team in Node 'Test'
command.execute(my_params, add=True, node='Test', team=['Test Team 1'])

# Refresh the Enterprise configuration state 
api.query_enterprise(my_params)

# Add existing user to Team
command.execute(my_params, add_user=['test1@company.com', 'test2@company.com'], team=['Test Team 1'])

