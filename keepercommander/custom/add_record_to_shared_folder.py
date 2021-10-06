#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: commander@keepersecurity.com

"""Demonstrate how to add a new or existing single record to an existing shared folder."""

import os

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.recordv3 import RecordAddCommand
from keepercommander.params import KeeperParams


def login(
    password=None,
    config_file='myconfig.json',
):
    """Get parameters from either the config file or function arguments, and log in."""
    if config_file and os.path.exists(config_file):
        params = get_params_from_config(config_file)
    else:
        params = KeeperParams()
        # If we set config_filename to a filename, and it doesn't pre-exist, it will be created with minimal content that perplexes
        # subsequent runs.
        params.config_filename = config_file
        params.user = 'your-keeper-account-email@keepersecurity.com'
        params.password = password if password else ''
        params.server = 'https://keepersecurity.com/api/rest'
        params.config['server'] = params.server

    api.login(params)
    api.sync_down(params)

    return params


def create_new_record(params):
    """Create a record."""
    # Fill in a shared folder UID here.  You can obtain a UID for a shared folder from ls -l in Keeper Commander.
    shared_folder_uid = 'sfusfusfusfusfusfusfsf'

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
        force=True,
    )

    print('Added record %s to shared folder uid=%s' % (record_uid, shared_folder_uid))


def main():
    """Login and create the record."""
    # If you want to use function arguments instead of a config file, use this line.
    params = login(config_file=None)

    # Or if you want to use a myconfig.json, use this 'params = login()' line.  Your myconfig.json should look something like:
    # {
    #     "server": "keepersecurity.com",
    #     "user": "your-keeper-account-email@keepersecurity.com"
    # }
    # Note that Commander may add more fields to this file.
    # params = login()

    create_new_record(params)


if __name__ == '__main__':
    main()
