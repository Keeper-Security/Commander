#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
# Example code showing how to search the vault 
#
# Usage:
#    python search.py

import getpass

from keepercommander.params import KeeperParams
from keepercommander import api

my_params = KeeperParams()

while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

while not my_params.password:
    my_params.password = getpass.getpass(prompt='Master Password: ', stream=None)

api.login(my_params)

searchstring = getpass.getpass(prompt='Search String: ', stream=None)
api.sync_down(my_params)

# Search records
results = api.search_records(my_params, searchstring) 
for r in results:
    print('Record UID ' + r.record_uid + ' matches')
    # Note: see recordv2.py for available fields or
    #       call display.formatted_records(results) to show all record details

# Search shared folders
results = api.search_shared_folders(my_params, searchstring) 
for sf in results:
    print('Shared Folder UID ' + sf.shared_folder_uid + ' matches')

# Search teams
results = api.search_teams(my_params, searchstring) 
for t in results:
    print('Team UID ' + t.team_uid + ' matches')
