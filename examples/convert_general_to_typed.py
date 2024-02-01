import argparse
import logging
import sys

from keepercommander import api, vault_extensions, vault
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands import convert

parser = argparse.ArgumentParser(description='Converts General records with attachments to Typed records with fileRef fields')
parser.add_argument('--debug', action='store_true', help='Enables debug logging')
opts, flags = parser.parse_known_args(sys.argv[1:])

logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.WARNING, format='%(message)s')

my_params = get_params_from_config('')

api.login(my_params)
if not my_params.session_token:
    exit(1)

api.sync_down(my_params)

record_uids = []

for record in vault_extensions.find_records(my_params, record_version=2):
    if isinstance(record, vault.PasswordRecord):
        if isinstance(record.attachments, list) and len(record.attachments) > 0:
            record_uids.append(record.record_uid)
            if len(record_uids) >= 200:
                break

if len(record_uids) > 0:
    if len(record_uids) >= 200:
        print('Found more than 200 records with attachments. Only the first 200 will be converted. Repeat this command to convert the rest.')
    else:
        print(f'Found {len(record_uids)} record(s) with attachments. Converting...')
    cmd = convert.ConvertCommand()
    kwargs = {
        'record-uid-name-patterns': record_uids
    }
    cmd.execute(my_params, **kwargs)
else:
    print('No records found')
