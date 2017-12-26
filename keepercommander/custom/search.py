#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2017 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
# Example showing how to search the vault 
#

import sys
import getpass

from keepercommander.params import KeeperParams
from keepercommander import display, api

my_params = KeeperParams()

while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

while not my_params.password:
    my_params.password = getpass.getpass(prompt='Master Password: ', stream=None)

api.sync_down(my_params)

# Search for 'Test'
results = api.search_records(my_params, 'Test') 

# Display results. 
# see record.py for available fields or 
# call display.formatted_records(results) to show
# all record details

for r in results:
    print('Record UID ' + r.record_uid + ' matches')


