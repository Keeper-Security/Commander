#!/usr/bin/env python3
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
# Example showing how to add a new or existing record 
# to an existing shared folder. 
#

import getopt
import os
import sys

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.recordv2 import RecordAddCommand, RecordEditCommand
from keepercommander.params import KeeperParams


def login_to_keeper_with_config(filename):   # type: (str) -> KeeperParams
    # Load connection parameters from file
    my_params = get_params_from_config(filename)
    my_params.password = ''  # Keeper account password. Can be omitted if account is setup for session resumption
    # Login to Keeper
    api.login(my_params)
    api.sync_down(my_params)
    return my_params


def create_or_update_record(params, criteria):
    # Scan vault for shared folder

    sfs = api.search_shared_folders(params, criteria)
    if len(sfs) == 0:
        print(f'Shared folder {criteria} not found')
        return
    shared_folder = sfs[0]
    record_title = 'Test Record'
    record_uid = None
    if shared_folder.records:
        records = [api.get_record(params, x['record_uid']) for x in shared_folder.records]
        record_uid = next((x.record_uid for x in records if x.title.casefold() == record_title.casefold()), None)

    shared_folder_uid = shared_folder.shared_folder_uid
    if record_uid:
        command = RecordEditCommand()
        command.execute(params, record=record_uid, generate=True)
        print(f'Updated record {record_uid} in shared folder uid={shared_folder_uid}')
    else:
        command = RecordAddCommand()
        # Inputs - hard coded for demo purposes
        record_uid = command.execute(
            params,
            title='Test Record',
            login='someone@company.com',
            folder=shared_folder_uid,
            generate=True,
            # force=True disables asking for missing fields
            force=True)
        print(f'Added record {record_uid} to shared folder uid={shared_folder_uid}')


if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], 'c:', ['config='])
    if len(args) == 0:
        print('Shared folder name or UID parameter is required.')
        sys.exit(1)

    config_file = 'myconfig.json'
    for p_name, p_value in opts:
        if p_name == '-c' or p_name == '--config':
            config_file = p_value

    if not os.path.exists(config_file):
        print(f'Config file {config_file} not found')
        sys.exit(1)

    # Login and sync
    params = login_to_keeper_with_config(config_file)

    # Add record to shared folder
    create_or_update_record(params, args[0])
