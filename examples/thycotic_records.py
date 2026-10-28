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
# This example also pulls configuration from config.json
#
# Usage:
#   1. initialize Keeper virtual environment
#   2. copy "config.json" file next to this script
#   3. run "python thycotic_records.py". Optional "--debug" parameter enables debug output
#   4. run "sqlite3 thycotic_records.db" to match records

"""
-- Get number of records in Keeper
select count(*) from KeeperRecord;

-- Get number of records in Thycotic Secret Server
select count(*) from ThycoticSecret;

-- List records missing in Keeper
select t.* from ThycoticSecret t left outer join KeeperRecord k ON t.title=k.title and t.path=k.path where k.uid IS NULL;

-- List records missing in Thycotic Secret Server
select k.* from KeeperRecord k left outer join ThycoticSecret t ON t.title=k.title and t.path=k.path where t.id IS NULL;

-- List matching records
select t.id, k.* from KeeperRecord k inner join ThycoticSecret t ON t.title=k.title and t.path=k.path;
"""

import argparse
import getpass
import logging
import os
import sqlite3
import sys
from typing import List

from keepercommander.importer.thycotic import thycotic
from keepercommander.__main__ import get_params_from_config
from keepercommander import api, vault, subfolder
from keepercommander.storage import sqlite_dao, sqlite


parser = argparse.ArgumentParser(description='Matches Keeper and Thycotic records')
parser.add_argument('--debug', action='store_true', help='Enables debug logging')
opts, flags = parser.parse_known_args(sys.argv[1:])

logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.DEBUG, format='%(message)s')

if not os.path.isfile('config.json'):
    logging.error('Please copy config.json file to the current folder.')
    exit(1)

my_params = get_params_from_config('config.json')
logging.info('Connecting to "%s" as "%s"', my_params.server, my_params.user)
api.login(my_params)
if not my_params.session_token:
    exit(1)
api.sync_down(my_params)

logging.info('Connecting to Thycotic Secret Server')
while True:
    thycotic_url = input('{0}: '.format('Thycotic Server URL'.rjust(32)))
    # thycotic_url = 'https://Thycotic/SecretServer'
    thy_auth = thycotic.ThycoticAuth(thycotic_url)

    thycotic_username = input('{0}: '.format('Thycotic Username'.rjust(32)))
    # thycotic_username = 'thycotic'

    thycotic_password = getpass.getpass('{0}: '.format('Thycotic Password'.rjust(32)))
    try:
        thy_auth.authenticate(thycotic_username, thycotic_password)
        break
    except Exception as e:
        logging.warning(e)


thy_folders = thycotic.ThycoticMixin.get_folders(thy_auth, skip_permissions=True)
logging.info(f'Thycotic: Loaded %d folders', len(thy_folders))
thy_secrets = thy_auth.thycotic_search('/v2/secrets')
logging.info(f'Thycotic: Loaded %d secrets', len(thy_secrets))

# root_folders = [x['id'] for x in thy_folders.values() if x['folderName'] == x['folderPath']]
# for folder_id in root_folders:
#     # query = f'/v2/secrets?filter.folderId={folder_id}&filter.includeSubFolders=true'

class KeeperRecord:
    def __init__(self):
        self.uid = ''
        self.title = ''
        self.path = ''

class ThycoticSecret:
    def __init__(self):
        self.id = 0
        self.title = ''
        self.path = ''

keeper_schema = sqlite_dao.TableSchema.load_schema(KeeperRecord, 'uid', indexes={'Record': ['title', 'path']})
thycotic_schema = sqlite_dao.TableSchema.load_schema(ThycoticSecret, 'id', indexes={'Record': ['title', 'path']})

sqlite_file = 'thycotic_records.db'
if os.path.isfile(sqlite_file):
    os.remove(sqlite_file)

connection = sqlite3.connect(sqlite_file)
sqlite_dao.verify_database(connection, (keeper_schema, thycotic_schema), apply_changes=True)

keeper_record_storage = sqlite.SqliteEntityStorage(lambda: connection, keeper_schema)
keeper_records = []    # type: List[KeeperRecord]
for rec in my_params.record_cache.values():
    record = vault.KeeperRecord.load(my_params, rec)
    if isinstance(record, (vault.PasswordRecord, vault.TypedRecord)):
        kr = KeeperRecord()
        kr.uid = record.record_uid
        kr.title = record.title
        folders = [subfolder.get_folder_path(my_params, x, delimiter='\\') for x in subfolder.find_folders(my_params, kr.uid) if x]
        if len(folders) > 0:
            kr.path = folders[0]
        keeper_records.append(kr)
keeper_record_storage.put(keeper_records)

thycotic_secret_storage = sqlite.SqliteEntityStorage(lambda: connection, thycotic_schema)
thycotic_secrets = []    # type: List[ThycoticSecret]
for secret in thy_secrets:
    ts = ThycoticSecret()
    ts.id = secret['id']
    folder_id = secret['folderId']
    ts.title = secret['name']
    if folder_id in thy_folders:
        ts.path = thy_folders[folder_id]['folderPath']
    thycotic_secrets.append(ts)
thycotic_secret_storage.put(thycotic_secrets)

connection.commit()
connection.close()

logging.info('Done')
