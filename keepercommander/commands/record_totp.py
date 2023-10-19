#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import itertools
import logging
import os
import sys
import threading
from typing import List, Optional

from . import record_common
from .base import Command, dump_report_data
from .. import api
from .. import vault
from ..error import CommandError
from ..params import KeeperParams
from ..record import get_totp_code
from ..subfolder import find_folders, try_resolve_path, get_folder_path

totp_parser = argparse.ArgumentParser(prog='totp', description='Display the Two Factor Code for a record')
totp_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
totp_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
totp_parser.add_argument('--details', dest='details', action='store_true', help='display 2FA details')
totp_parser.add_argument('--range', dest='range', type=int, action='store', help='display last and next [x] codes')


class TotpEndpoint:
    def __init__(self, record_uid, record_title, paths):
        self.record_uid = record_uid
        self.record_title = record_title
        self.paths = paths


class TotpCommand(Command):
    LastRevision = 0  # int
    Endpoints = []    # type: List[TotpEndpoint]

    def get_parser(self):
        return totp_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None
        record_uid = None
        if record_name:
            if record_name in params.record_cache:
                record_uid = record_name
            else:
                rs = try_resolve_path(params, record_name)
                if rs is not None:
                    folder, record_name = rs
                    if folder is not None and record_name is not None:
                        folder_uid = folder.uid or ''
                        if folder_uid in params.subfolder_record_cache:
                            for uid in params.subfolder_record_cache[folder_uid]:
                                r = api.get_record(params, uid)
                                if r.title.lower() == record_name.lower():
                                    record_uid = uid
                                    break

            if record_uid is None:
                records = api.search_records(params, kwargs['record'])
                if len(records) == 1:
                    logging.info('Record Title: {0}'.format(records[0].title))
                    record_uid = records[0].record_uid
                else:
                    if len(records) == 0:
                        raise CommandError('totp', 'Enter name or uid of existing record')
                    else:
                        raise CommandError('totp', 'More than one record are found for search criteria: {0}'.format(kwargs['record']))

        if record_uid:
            totp_url = ''
            record = vault.KeeperRecord.load(params, record_uid)
            if isinstance(record, vault.PasswordRecord):
                totp_url = record.totp
            elif isinstance(record, vault.TypedRecord):
                field = next((x for x in itertools.chain(record.fields, record.custom) if x.type in ('oneTimeCode', 'otp') and  x.value), None)
                if field and len(field.value) > 0:
                    totp_url = field.value[0]
            if not totp_url:
                raise CommandError('totp', f'Record \"{record.title}\" does not contain TOTP codes')

            if kwargs['details']:
                record_common.display_totp_details(totp_url)
            x_range = kwargs.get('range')
            if isinstance(x_range, int) and x_range > 0:
                x_range = min(x_range, 10)
                last_codes = [x-x_range for x in range(x_range)] + [0] + [x+1 for x in range(x_range)]
                table = []
                for offset in last_codes:
                    title = 'Current' if offset == 0 else str(offset)
                    code, _, _ = get_totp_code(totp_url, offset)
                    table.append([title, code])
                dump_report_data(table, headers=('key', 'value'), no_header=True, right_align=(0,))
            else:
                tmer = None     # type: Optional[threading.Timer]
                done = False

                def print_code():
                    nonlocal tmer
                    if not done:
                        TotpCommand.display_code(totp_url)
                        tmer = threading.Timer(1, print_code).start()

                try:
                    print('Press <Enter> to exit\n')
                    print_code()
                    input()
                finally:
                    done = True
                    if tmer:
                        tmer.cancel()
        else:
            TotpCommand.find_endpoints(params)
            logging.info('')
            headers = ['Record UID', 'Record Title', 'Folder(s)']
            table = []
            for endpoint in TotpCommand.Endpoints:
                title = endpoint.record_title
                if len(title) > 23:
                    title = title[:20] + '...'
                folder = endpoint.paths[0] if len(endpoint.paths) > 0 else '/'
                table.append([endpoint.record_uid, title, folder])
            dump_report_data(table, headers=headers, row_number=True, sort_by=1)

    LastDisplayedCode = ''

    @staticmethod
    def display_code(url):
        code, remains, total = get_totp_code(url)
        progress = ''.rjust(remains, '=')
        progress = progress.ljust(total, ' ')
        if os.isatty(0):
            print('\r', file=sys.stderr, end='', flush=True)
            print('\t{0}\t\t[{1}]'.format(code, progress), file=sys.stderr, end='', flush=True)
        else:
            if TotpCommand.LastDisplayedCode != code:
                print('\t{0}\t\tvalid for {1} seconds.'.format(code, remains))
                TotpCommand.LastDisplayedCode = code

    @staticmethod
    def find_endpoints(params):
        # type: (KeeperParams) -> None
        if TotpCommand.LastRevision < params.revision:
            TotpCommand.LastRevision = params.revision
            TotpCommand.Endpoints.clear()
            for record_uid in params.record_cache:
                record = vault.KeeperRecord.load(params, record_uid)
                if not record:
                    continue

                has_totp_url = False
                if isinstance(record, vault.PasswordRecord):
                    if record.totp:
                        has_totp_url = True
                elif isinstance(record, vault.TypedRecord):
                    has_totp_url = any(x for x in itertools.chain(record.fields, record.custom) if x.type in ('oneTimeCode', 'otp') and  x.value)
                else:
                    continue

                if has_totp_url:
                    paths = []
                    for folder_uid in find_folders(params, record_uid):
                        path = '/' + get_folder_path(params, folder_uid, '/')
                        paths.append(path)
                    TotpCommand.Endpoints.append(TotpEndpoint(record_uid, record.title, paths))
