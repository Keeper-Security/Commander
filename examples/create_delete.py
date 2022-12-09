#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2017 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example showing how to create a record and upload
# to the server, then deleting the record from the
# server.
#

import getpass
import string
import random

from keepercommander.record import Record
from keepercommander.params import KeeperParams
from keepercommander import api

my_params = KeeperParams()

while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

while not my_params.password:
    my_params.password = getpass.getpass(prompt='Master Password: ', stream=None)

api.sync_down(my_params)

# Add record 
r = Record()
r.title = 'Test Record'
r.login = 'someone@company.com'

# generate a 32-char random password
r.password = ''.join(random.SystemRandom().choice(string.printable) for _ in range(32)) 

if api.add_record(my_params, r):
    print('Added record UID='+r.record_uid) 

# Delete the record 
if r.record_uid:
    api.delete_record(my_params, r.record_uid)
