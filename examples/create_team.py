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

import logging
from logging import LogRecord

from keepercommander.params import KeeperParams
from keepercommander import api
from keepercommander.commands.enterprise import EnterpriseTeamCommand


# Keeper Commander uses logging module to communicate with the user.
class ScriptLogHandler(logging.Handler):
    def __init__(self):
        super(ScriptLogHandler, self).__init__()
        self.errors = []

    def emit(self, record: LogRecord) -> None:
        message = record.msg % record.args
        self.errors.append(message)

    def clear_errors(self):
        self.errors.clear()

    def has_error(self):
        return len(self.errors) > 0

# Configure logging
slh = ScriptLogHandler()
slh.setLevel(logging.WARNING)
logging.root.addHandler(slh)

# Create parameters
my_params = KeeperParams()
my_params.user = ''  # Keeper account name. 'config.json' file, 'user' property
my_params.password = ''   # Keeper account password.
my_params.device_token = ''  # Device Token. 'config.json' file, 'device_token' property
my_params.device_private_key = ''   # Device Key. 'config.json' file, 'private_key' property

# Login to Keeper
api.login(my_params)

# Load the Enterprise configuration state
api.query_enterprise(my_params)

# Create team/user mapping
if 'users' in my_params.enterprise and 'team_users' in my_params.enterprise:
    # params.enterprise['users'] is a list of all users in enterprise
    # params.enterprise['team_users'] is a list of team <-> user pairs

    # map user ID to active user email.
    user_lookup = {u['enterprise_user_id']: u['username'] for u in my_params.enterprise['users'] if u['status'] == 'active'}

    # team_users. key is team_uid, value is set of emails
    team_users = {}
    for tu in my_params.enterprise['team_users']:
        team_uid = tu['team_uid']
        if team_uid not in team_users:
            team_users[team_uid] = set()
        user_id = tu['enterprise_user_id']
        if user_id in user_lookup:
            email = user_lookup[user_id]
            team_users[team_uid].add(email)

# Create Enterprise Team Command
command = EnterpriseTeamCommand()

# Create Team in Node 'Test'
slh.clear_errors()
command.execute(my_params, add=True, node='Test', team=['Test Team 1'])
if slh.has_error():
    print('\n'.join(slh.errors))
    exit(1)
else:
    print("Team is created")


# Refresh the Enterprise configuration state 
api.query_enterprise(my_params)

# Add existing users to Team
slh.clear_errors()
command.execute(my_params, add_user=['test1@company.com', 'test2@company.com'], team=['Test Team 1'])
if slh.has_error():
    print('\n'.join(slh.errors))
    exit(1)
else:
    print("Users are added to the team")
