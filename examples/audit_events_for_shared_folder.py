import argparse
import logging
import sys

from keepercommander import api, utils, crypto
from keepercommander.__main__ import get_params_from_config
from keepercommander.proto import folder_pb2
from keepercommander.commands.aram import AuditReportCommand

parser = argparse.ArgumentParser(description='Add user to shared folder')
parser.add_argument('--debug', action='store_true', help='Enables debug logging')
parser.add_argument('--created', dest='created', action='store',
                    help='Filter: Created date. Predefined filters: '
                         'today, yesterday, last_7_days, last_30_days, month_to_date, last_month, '
                         'year_to_date, last_year')
parser.add_argument('shared_folder', help='Shared Folder UID')
opts, flags = parser.parse_known_args(sys.argv[1:])

logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.WARNING, format='%(message)s')

my_params = get_params_from_config('')

api.login(my_params)
if not my_params.session_token:
    exit(1)

shared_folder_uid = opts.shared_folder

sf_rq = {
    'command': 'get_shared_folders',
    'shared_folders': [
        {
            'shared_folder_uid': shared_folder_uid
        }
    ],
    'include': ['sfheaders', 'sfrecords']
}

sf_rs = api.communicate(my_params, sf_rq)
if len(sf_rs['shared_folders']) == 0:
    raise ValueError(f'Shared folder UID "{shared_folder_uid}" not found')

shared_folder_info = sf_rs['shared_folders'][0]

record_uids = list()
if isinstance(shared_folder_info.get('records'), list):
    record_uids.extend((x.get('record_uid') for x in shared_folder_info['records']))

command = AuditReportCommand()
table = command.execute(my_params, report_type='raw', record_uid=record_uids, created=opts.created, limit=-1,
                        max_record_details=True, report_format='fields', format='csv')
print(table)