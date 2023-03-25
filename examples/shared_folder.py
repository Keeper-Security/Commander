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

import getpass
import os

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.register import ShareFolderCommand

my_params = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))
while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

api.login(my_params)
api.sync_down(my_params)

folders = ["Shared Folder 1", "Shared Folder 2"]
user1 = "user@company.com"
team1 = "Team1"

command = ShareFolderCommand()
for folder in folders:
    command.execute(my_params, action="grant", user=[user1, team1], folder=folder)

api.sync_down(my_params)
