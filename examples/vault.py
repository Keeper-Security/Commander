#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example code to retrieve records in a shared folder.
# Usage:
#    python vault.py

import os
import sys
from typing import Optional, Set

from keepercommander import api, record, vault, shared_folder, subfolder
from keepercommander.__main__ import get_params_from_config

# load configuration file.
my_params = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))

# Prompt for Keeper username if configuration file is empty
if not my_params.user:
    my_params.user = input('User(Email): ')
    if not my_params.user:
        sys.exit(1)

# Login to Keeper
api.login(my_params)
if not my_params.session_token:
    sys.exit(1)

# Load Vault data
api.sync_down(my_params)

# Keeper supports several record formats internally
# Version 2 or Legacy or General records, V2
# Version 3 or Typed records, V3
# Version 4 or File records, V4
# ...
# Record versions 3 and up replace legacy v2 record format

# Commander has 2 class sets for Keeper records
# 1. "Record" class in the record.py
#    This class represents V2 records originally.
#    When used with V3 records it maps V3 record fields to V2 data structure.
#    Convenient when reading records
#    Use api.get_record(param, record_uid) method to load record
# 2. Newer record classes in the vault.py
#    "KeeperRecord" the base class for all record types
#    "PasswordRecord" represents V2 or legacy records
#    "TypedRecord" - V3 or typed records
#    "FileRecord" - V4 or file attachment
#    Use vault.KeeperRecord.load(params, record_uid) to load a record

# Old record class example
# Enumerated all records in all shared folders.
# Shared folders are stored in "shared_folder_cache" attribute of KeeperParams object

old_record: Optional[record.Record] = None
if my_params.shared_folder_cache:
    shared_folder: Optional[shared_folder.SharedFolder]
    for shared_folder_uid in my_params.shared_folder_cache:
        # Load shared folder
        shared_folder = api.get_shared_folder(my_params, shared_folder_uid)
        if shared_folder:
            record_no = len(shared_folder.records) if shared_folder.records else 0
            print(f'Shared Folder "{shared_folder.name}" has {record_no} record(s)')
            for record_key in shared_folder.records:
                record_uid = record_key['record_uid']
                # Load a record into old record class
                old_record = api.get_record(my_params, record_uid)
                if old_record:    # V2 or V3
                    print(f'Record "{old_record.title}" has {("" if old_record.password else "no ")}password')

# New record class example
new_record: Optional[vault.KeeperRecord] = None

# get a random shared folder/subfolder in the vault tree
folder: Optional[subfolder.BaseFolderNode] = None
records: Optional[Set[str]] = None
for f_uid, recs in my_params.subfolder_record_cache.items():
    if not f_uid:    # Root folder does not have Folder UID
        continue
    if not recs:   # folder has no records
        continue
    if f_uid not in my_params.folder_cache:
        continue
    f: Optional[subfolder.BaseFolderNode] = my_params.folder_cache[f_uid]    # folder description
    # pick a shared folder/subfolder
    if f.type in (subfolder.BaseFolderNode.SharedFolderType, subfolder.BaseFolderNode.SharedFolderFolderType):
        folder = f
        records = recs
        break

if folder and records:
    print(f'Folder "{folder.name}" has {len(records)} record(s)')
    for record_uid in records:
        # Load record
        new_record = vault.KeeperRecord.load(my_params, record_uid)
        if isinstance(new_record, vault.PasswordRecord):
            print(f'Legacy Record "{new_record.title}" has {("" if new_record.password else "no ")}password')
        elif isinstance(new_record, vault.TypedRecord):
            password_field = new_record.get_typed_field('password')
            if password_field:
                password = password_field.get_default_value(str)
                print(f'Record "{new_record.title}" type "{new_record.record_type}" has {("" if password else "no ")}password')
            else:
                print(f'Record "{new_record.title}" type "{new_record.record_type}" does not have password field')
        elif new_record:
            print(f'Record "{new_record.title}" type "{new_record.record_type}" does not have password field')
        else:
            print(f'Record UID "{record_uid}" is not supported')




