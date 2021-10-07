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
# This script loads LastPass shared folder membership and
# stores it to Keeper import JSON file.
# The JSON file can be imported later with the following command
# > import --format=json --users lastpass_shared_folders.json
# Users and Team missing in the appropriate Keeper's shared folders
# will be added.

import itertools
import json
import os
import sys
import getpass
import logging

from keepercommander.importer.lastpass import fetcher
from keepercommander.importer.lastpass.vault import Vault

JSON_FILE = 'lastpass_shared_folders.json'

if __name__ == '__main__':
    username = input('...' + 'LastPass Username'.rjust(30) + ': ')
    if not username:
        sys.exit(1)
    password = getpass.getpass(prompt='...' + 'LastPass Password'.rjust(30) + ': ', stream=None)
    if not password:
        sys.exit(1)

    print('Press <Enter> if account is not protected with Multifactor Authentication')
    twofa_code = getpass.getpass(prompt='...' + 'Multifactor Password'.rjust(30) + ': ', stream=None)
    if not twofa_code:
        twofa_code = None

    session = None
    added_members = []
    try:
        session = fetcher.login(username, password, twofa_code, None)
        blob = fetcher.fetch(session)
        encryption_key = blob.encryption_key(username, password)
        vault = Vault(blob, encryption_key, session, False)

        lastpass_shared_folder = [x for x in vault.shared_folders]
        json_shared_folders = set()
        if os.path.exists(JSON_FILE):
            try:
                with open(JSON_FILE, 'r') as f:
                    js = json.load(f)
                if 'shared_folders' in js:
                    json_shared_folders.update((x['id'] for x in js['shared_folders']))
            except:
                pass

        for sf in lastpass_shared_folder:
            if sf.id not in json_shared_folders:
                print(f'Loading shared folder membership for "{sf.name}"')
                members, teams, error = fetcher.fetch_shared_folder_members(session, sf.id)
                added_members.append({
                    'id': sf.id,
                    'name': sf.name,
                    'permissions': [{
                        'name': x['username'],
                        'manage_records': x['readonly'] == '0',
                        'manage_users': x['can_administer'] == '1'
                    } for x in itertools.chain(members or (), teams or ())]
                })

    except Exception as e:
        logging.warning(e)
    finally:
        if session:
            fetcher.logout(session)

        if added_members:
            if os.path.exists(JSON_FILE):
                with open(JSON_FILE, 'r') as f:
                    import_file = json.load(f)
            else:
                import_file = {}
            if 'shared_folders' not in import_file:
                import_file['shared_folders'] = []

            import_file['shared_folders'].extend(added_members)
            with open(JSON_FILE, 'w') as f:
                json.dump(import_file, f, indent=2, separators=(',', ': '))

            print(f'{len(added_members)} shared folder memberships retrieved.')
        else:
            print('No folders added')




