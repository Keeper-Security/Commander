#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example showing how to add a new or existing record 
# to an existing shared folder. 
#

from keepercommander.params import KeeperParams
from keepercommander import api
from keepercommander.commands.record import RecordAddCommand

params = KeeperParams()

# Inputs - hard coded for demo purposes
params.user = 'your_keeper_email'
params.password = 'your_keeper_password'
shared_folder_uid = 'your_shared_folder_uid'

# Login and sync
api.sync_down(params)

command = RecordAddCommand()
record_uid = command.execute(params, title='Test Record', login='someone@company.com', url='https://google.com', folder=shared_folder_uid, generate=True, force=True)
print('Added record to shared folder')

