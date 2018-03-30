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
# Example showing how to add a new or existing record 
# to an existing shared folder. 
#

import os
import sys
import string
import random

from keepercommander.record import Record
from keepercommander.params import KeeperParams
from keepercommander.shared_folder import SharedFolder
from keepercommander import display, api

params = KeeperParams()

# Inputs - hard coded for demo purposes
params.user = 'your_keeper_email'
params.password = 'your_keeper_password'
shared_folder_uid = 'your_shared_folder_uid'

# Login and sync
api.sync_down(params)

# Create a new record with some random password
record = Record()
record.title = 'Test Record'
record.login = 'someone@company.com'
record.login_url = 'https://google.com'
record.notes = 'Here are some notes.'
record.password = ''.join(random.SystemRandom().choice(string.printable) for _ in range(32)) 

# Add the record to your vault
if api.add_record(params, record):
    print('Added record UID='+record.record_uid) 
else:
    print('Error: Unable to add record')
    sys.exit() 

# Get existing shared folder from the cache
if shared_folder_uid in params.shared_folder_cache:
    shared_folder = params.shared_folder_cache[shared_folder_uid]
    print('shared_folder: ' + str(shared_folder))
else:
    print('Error: Shared folder not found')
    sys.exit() 

# Add record to shared folder, preserving default permissions and name
sf = SharedFolder()
sf.default_manage_records = shared_folder['default_manage_records']
sf.default_manage_users = shared_folder['default_manage_users']
sf.default_can_edit = shared_folder['default_can_edit']
sf.default_can_share = shared_folder['default_can_share']
sf.shared_folder_uid = shared_folder['shared_folder_uid']
sf.revision = shared_folder['revision']
sf.name = shared_folder['name']

# Add the record to the shared folder with permissions set
sf.records = [{'record_uid':record.record_uid,'can_share':True,'can_edit':True}]

# Push the shared folder change
if api.update_shared_folder(params, sf):
    print('Updated shared folder') 
else:
    print('Error: Unable to update shared folder')
    sys.exit() 

