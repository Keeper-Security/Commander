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
import os

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.record import RecordAddCommand
from keepercommander.params import KeeperParams


def login(
        email,
        password=None,
        keeper_server='https://keepersecurity.com/api/v2/',
        config_file='myconfig.json'):

    if os.path.exists(config_file):
        params = get_params_from_config(config_file)
    else:
        params = KeeperParams()
        params.config_filename = config_file
        params.user = email
        params.password = password if password else ''
        params.server = keeper_server
        params.config['server'] = params.server

    api.login(params)
    api.sync_down(params)

    return params


def create_new_record(params):
    shared_folder_uid = 'UID'

    command = RecordAddCommand()

    # Inputs - hard coded for demo purposes
    record_uid = command.execute(
        params,
        title='Test Record',
        login='someone@company.com',
        url='https://google.com',
        folder=shared_folder_uid,
        generate=True,
        # force=True disables asking for missing fields
        force=True)

    print('Added record %s to shared folder uid=%s' % (record_uid, shared_folder_uid))


if __name__ == '__main__':

    # Login and sync
    params = login("user@email.com", password="password")

    create_new_record(params)
