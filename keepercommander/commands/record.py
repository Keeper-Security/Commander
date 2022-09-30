#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import collections
import datetime
import fnmatch
import json
import logging
import re
from typing import Dict, Any, List, Optional, Iterator, Tuple, Set, Union

from .base import dump_report_data, user_choice, field_to_title, Command, GroupCommand
from .recordv3 import RecordGetUidCommand
from .. import api, display, crypto, utils, vault, vault_extensions
from ..error import CommandError
from ..params import KeeperParams
from ..record_management import update_record
from ..subfolder import try_resolve_path, get_folder_path, find_folders
from ..proto.enterprise_pb2 import SharedRecordResponse
from ..team import Team


def register_commands(commands):
    commands['search'] = SearchCommand()
    commands['trash'] = TrashCommand()
    commands['list'] = RecordListCommand()
    commands['list-sf'] = RecordListSfCommand()
    commands['list-team'] = RecordListTeamCommand()
    commands['record-history'] = RecordHistoryCommand()
    commands['shared-records-report'] = SharedRecordsReport()


def register_command_info(aliases, command_info):
    aliases['s'] = 'search'
    aliases['l'] = 'list'
    aliases['lsf'] = 'list-sf'
    aliases['lt'] = 'list-team'
    aliases['rh'] = 'record-history'
    aliases['srr'] = 'shared-records-report'

    for p in [search_parser, list_parser, list_sf_parser, list_team_parser, record_history_parser, shared_records_report_parser]:
        command_info[p.prog] = p.description
    command_info['trash'] = 'Manage deleted items'


search_parser = argparse.ArgumentParser(prog='search', description='Search the vault. Can use a regular expression.')
search_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
search_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
search_parser.add_argument('-c', '--categories', dest='categories', action='store',
                           help='One or more of these letters for categories to search: "r" = records, '
                                '"s" = shared folders, "t" = teams')


list_parser = argparse.ArgumentParser(prog='list', description='List records.')
list_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
list_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'], default='table',
                         help='output format')
list_parser.add_argument('--output', dest='output', action='store',
                         help='output file name. (ignored for table format)')
list_parser.add_argument('-t', '--type', dest='record_type', action='append',
                         help='List records of certain types. Can be repeated')
list_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')


list_sf_parser = argparse.ArgumentParser(prog='list-sf', description='List shared folders.')
list_sf_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'],
                            default='table', help='output format')
list_sf_parser.add_argument('--output', dest='output', action='store',
                            help='output file name. (ignored for table format)')
list_sf_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')


list_team_parser = argparse.ArgumentParser(prog='list-team', description='List teams.')
list_team_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'],
                              default='table', help='output format')
list_team_parser.add_argument('--output', dest='output', action='store',
                              help='output file name. (ignored for table format)')


record_history_parser = argparse.ArgumentParser(
    prog='history|rh', description='Show the history of a record modifications.')
record_history_parser.add_argument(
    '-a', '--action', dest='action', choices=['list', 'diff', 'view', 'restore'], action='store',
    help="filter by record history type. (default: 'list'). --revision required with 'restore' action.",
)
record_history_parser.add_argument(
    '-r', '--revision', dest='revision', type=int, action='store',
    help='only show the details for a specific revision')
record_history_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help="verbose output")
record_history_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')


shared_records_report_parser = argparse.ArgumentParser(prog='shared-records-report|srr', description='Report shared records for a logged-in user.')
shared_records_report_parser.add_argument('--format', dest='format', choices=['json', 'csv', 'table'], default='table', help='Data format output')
shared_records_report_parser.add_argument('-tu', '--show-team-users', action='store_true',
                                          help='show members of team for records shared via share team folders')
shared_records_report_parser.add_argument('name', type=str, nargs='?', help='file name')


def find_record(params, record_name, types=None):  # type: (KeeperParams, str, Optional[Iterator[str]]) -> Optional[vault.KeeperRecord]
    if not record_name:
        raise Exception(f'Record name cannot be empty.')

    if record_name in params.record_cache:
        return vault.KeeperRecord.load(params, record_name)
    else:
        rs = try_resolve_path(params, record_name)
        if rs is not None:
            folder, record_name = rs
            if folder is not None and record_name is not None:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for uid in params.subfolder_record_cache[folder_uid]:
                        r = vault.KeeperRecord.load(params, uid)
                        if r and r.title.lower() == record_name.lower():
                            return r

    if types:
        ls = RecordListCommand()
        result = ls.execute(params, record_type=types, format='json', verbose=True)
        if result:
            try:
                recs = json.loads(result)
                records = []
                if isinstance(recs, list):
                    for rec in recs:
                        if isinstance(rec, dict):
                            if 'title' in rec:
                                title = rec.get('title', '').strip().lower()
                                if title == record_name.lower():
                                    records.append(rec)
                                    continue
                            if 'description' in rec:
                                description = rec.get('description', '').lower()
                                if description:
                                    if {'serverCredentials', 'databaseCredentials', 'sskKeys'}.issuperset(types):
                                        user, sep, host = description.partition("@")
                                        if sep == '@':
                                            description = host
                                        hostname, _, _ = description.strip().partition(':')
                                        if hostname == record_name.lower():
                                            records.append(rec)
                                            continue
                if len(records) == 1:
                    return vault.KeeperRecord.load(params, records[0].get('record_uid'))
                elif len(records) > 1:
                    raise Exception(f'More than one record found for \"{record_name}\". Please use record UID or full record path.')
            except:
                pass
    raise Exception(f'Record "{record_name}" not found.')


class SearchCommand(Command):
    def get_parser(self):
        return search_parser

    def execute(self, params, **kwargs):
        pattern = kwargs.get('pattern') or ''
        if pattern == '*':
            pattern = '.*'

        categories = (kwargs.get('categories') or 'rst').lower()
        verbose = kwargs.get('verbose', False)
        skip_details = not verbose

        # Search records
        if 'r' in categories:
            records = list(vault_extensions.find_records(params, pattern))
            if records:
                print('')
                table = []
                headers = ['Record UID', 'Type', 'Title', 'Description']
                for record in records:
                    row = [record.record_uid, record.record_type, record.title,
                           vault_extensions.get_record_description(record)]
                    table.append(row)
                table.sort(key=lambda x: (x[2] or '').lower())

                dump_report_data(table, headers, row_number=True, column_width=None if verbose else 40)
                if len(records) < 5:
                    get_command = RecordGetUidCommand()
                    for record in records:
                        get_command.execute(params, uid=record.record_uid)

        # Search shared folders
        if 's' in categories:
            results = api.search_shared_folders(params, pattern)
            if results:
                print('')
                display.formatted_shared_folders(results, params=params, skip_details=skip_details)

        # Search teams
        if 't' in categories:
            results = api.search_teams(params, pattern)
            if results:
                print('')
                display.formatted_teams(results, params=params, skip_details=skip_details)


class RecordListCommand(Command):
    def get_parser(self):
        return list_parser

    def execute(self, params, **kwargs):
        verbose = kwargs.get('verbose', False)
        fmt = kwargs.get('format', 'table')
        pattern = kwargs.get('pattern')
        record_types = kwargs.get('record_type')
        if record_types:
            record_version = set()
            record_type = set()
            if isinstance(record_types, str):
                record_types = [record_types]
            for rt in record_types:
                if rt == 'app':
                    record_version.add(5)
                elif rt == 'file':
                    record_version.update((3, 4))
                    record_type.add('file')
                elif rt == 'general':
                    record_version.update((1, 2))
                else:
                    record_version.add(3)
                    record_type.add(rt)
        else:
            record_version = None if verbose else (1, 2, 3)
            record_type = None

        records = [x for x in vault_extensions.find_records(params, pattern, record_type=record_type, record_version=record_version)]
        if any(records):
            table = []
            headers = ['record_uid', 'type', 'title', 'description'] if fmt == 'json' else \
                ['Record UID', 'Type', 'Title', 'Description']
            for record in records:
                row = [record.record_uid, record.record_type, record.title,
                       vault_extensions.get_record_description(record)]
                table.append(row)
            table.sort(key=lambda x: (x[2] or '').lower())

            return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True, column_width=None if verbose else 40)
        else:
            logging.info('No records are found')


class RecordListSfCommand(Command):
    def get_parser(self):
        return list_sf_parser

    def execute(self, params, **kwargs):
        fmt = kwargs.get('format', 'table')
        pattern = kwargs['pattern'] if 'pattern' in kwargs else None
        results = api.search_shared_folders(params, pattern or '')
        if any(results):
            table = []
            headers = ['shared_folder_uid', 'name'] if fmt == 'json' else ['Shared Folder UID', 'Name']
            for sf in results:
                row = [sf.shared_folder_uid, sf.name]
                table.append(row)
            table.sort(key=lambda x: (x[1] or '').lower())

            return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True)
        else:
            logging.info('No shared folders are found')


class RecordListTeamCommand(Command):
    def get_parser(self):
        return list_team_parser

    def execute(self, params, **kwargs):
        fmt = kwargs.get('format', 'table')
        api.load_available_teams(params)
        results = []
        if type(params.available_team_cache) == list:
            for team in params.available_team_cache:
                team = Team(team_uid=team['team_uid'], name=team['team_name'])
                results.append(team)
        if any(results):
            table = []
            headers = ['team_uid', 'name'] if fmt == 'json' else ['Team UID', 'Name']
            for team in results:
                row = [team.team_uid, team.name]
                table.append(row)
            table.sort(key=lambda x: (x[1] or '').lower())

            return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True)
        else:
            logging.info('No teams are found')


trash_list_parser = argparse.ArgumentParser(prog='trash list', description='Displays a list of deleted records.')
trash_list_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'],
                               default='table', help='output format')
trash_list_parser.add_argument('--output', dest='output', action='store',
                               help='output file name. (ignored for table format)')
trash_list_parser.add_argument('--reload', dest='reload', action='store_true', help='reload deleted records')
trash_list_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')


trash_get_parser = argparse.ArgumentParser(prog='trash get', description='Get the details of a deleted record.')
trash_get_parser.add_argument('record', action='store', help='Deleted record UID')

trash_restore_parser = argparse.ArgumentParser(prog='trash restore', description='Restores deleted records.')
trash_restore_parser.add_argument('-f', '--force', dest='force', action='store_true',
                                  help='do not prompt for confirmation')
trash_restore_parser.add_argument('records', nargs='+', type=str, action='store',
                                  help='Record UID or search pattern')

trash_purge_parser = argparse.ArgumentParser(prog='trash purge',
                                             description='Removes all deleted record from the trash bin.')
trash_purge_parser.add_argument('-f', '--force', dest='force', action='store_true',
                                help='do not prompt for confirmation')


class TrashMixin:
    last_revision = 0
    deleted_record_cache = {}

    @staticmethod
    def get_deleted_records(params, reload=False):    # type: (KeeperParams, bool) -> Dict[str, Any]
        if params.revision != TrashMixin.last_revision or reload:
            deleted_uids = set()
            rq = {
                'command': 'get_deleted_records',
                'client_time': utils.current_milli_time()
            }
            rs = api.communicate(params, rq)
            if 'records' in rs:
                for record in rs['records']:
                    record_uid = record['record_uid']
                    deleted_uids.add(record_uid)
                    if record_uid in TrashMixin.deleted_record_cache:
                        continue
                    try:
                        key_type = record['record_key_type']
                        record_key = utils.base64_url_decode(record['record_key'])
                        if key_type == 1:
                            record_key = crypto.decrypt_aes_v1(record_key, params.data_key)
                        elif key_type == 2:
                            record_key = api.decrypt_rsa(record_key, params.rsa_key)
                        elif key_type == 3:
                            record_key = crypto.decrypt_aes_v2(record_key, params.data_key)
                        elif key_type == 4:
                            record_key = crypto.decrypt_ec(record_key, params.ecc_key)
                        else:
                            logging.debug('Cannot decrypt record key %s', record_uid)
                            continue
                        record['record_key_unencrypted'] = record_key

                        data = utils.base64_url_decode(record['data'])
                        version = record['version']
                        record['data_unencrypted'] = \
                            crypto.decrypt_aes_v2(data, record_key) if version >= 3 else \
                                crypto.decrypt_aes_v1(data, record_key)

                        TrashMixin.deleted_record_cache[record_uid] = record
                    except Exception as e:
                        logging.debug('Cannot decrypt deleted record %s: %s', record_uid, e)

            for record_uid in list(TrashMixin.deleted_record_cache.keys()):
                if record_uid not in deleted_uids:
                    del TrashMixin.deleted_record_cache[record_uid]

        TrashMixin.last_revision = params.revision
        return TrashMixin.deleted_record_cache


class TrashCommand(GroupCommand):
    def __init__(self):
        super(TrashCommand, self).__init__()
        self.register_command('list', TrashListCommand())
        self.register_command('get', TrashGetCommand())
        self.register_command('restore', TrashRestoreCommand())
        self.register_command('purge', TrashPurgeCommand())
        self.default_verb = 'list'


class TrashListCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_list_parser

    def execute(self, params, **kwargs):
        deleted_records = self.get_deleted_records(params, kwargs.get('reload', False))
        if len(deleted_records) == 0:
            logging.info('Trash is empty')
            return

        pattern = kwargs.get('pattern')
        if pattern:
            if pattern == '*':
                pattern = None

        title_pattern = None
        if pattern:
            title_pattern = re.compile(fnmatch.translate(pattern), re.IGNORECASE)

        table = []
        headers = ['Record UID', 'Title', 'Type', 'Deleted']

        for rec in deleted_records.values():
            record = vault.KeeperRecord.load(params, rec)

            if pattern:
                if pattern == record.record_uid:
                    pass
                elif title_pattern and title_pattern.match(record.title):
                    pass
                else:
                    continue

            deleted = rec.get('date_deleted', 0)
            if deleted:
                deleted = datetime.datetime.fromtimestamp(int(deleted / 1000))
            else:
                deleted = None
            table.append([record.record_uid, record.title, record.record_type, deleted])

        table.sort(key=lambda x: x[1].casefold())

        return dump_report_data(table, headers, fmt=kwargs.get('format'),
                                filename=kwargs.get('output'), row_number=True)


class TrashGetCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_get_parser

    def execute(self, params, **kwargs):
        deleted_records = self.get_deleted_records(params)
        if len(deleted_records) == 0:
            logging.info('Trash is empty')
            return

        record_uid = kwargs.get('record')
        if not record_uid:
            logging.info('Record UID parameter is required')
            return

        rec = deleted_records.get(record_uid)
        if not rec:
            logging.info('%s is not a valid deleted record UID', record_uid)
            return

        record = vault.KeeperRecord.load(params, rec)
        if not record:
            logging.info('Cannot restore record %s', record_uid)
            return

        for name, value in record.enumerate_fields():
            if value:
                if isinstance(value, list):
                    value = '\n'.join(value)
                if len(value) > 100:
                    value = value[:99] + '...'
                print('{0:>20s}: {1}'.format(name, value))


class TrashRestoreCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_restore_parser

    def execute(self, params, **kwargs):
        deleted_records = self.get_deleted_records(params)
        if len(deleted_records) == 0:
            logging.info('Trash is empty')
            return

        records = kwargs.get('records')
        if not isinstance(records, (tuple, list)):
            records = None
        if not records:
            logging.info('records parameter is empty.')
            return

        to_restore = set()
        for rec in records:
            if rec in deleted_records:
                to_restore.add(rec)
            else:
                title_pattern = re.compile(fnmatch.translate(rec), re.IGNORECASE)
                for record_uid, del_rec in deleted_records.items():
                    if record_uid in to_restore:
                        continue
                    record = vault.KeeperRecord.load(params, del_rec)
                    if title_pattern.match(record.title):
                        to_restore.add(record_uid)

        if len(to_restore) == 0:
            logging.info('There are no records to restore')
            return

        if not kwargs.get('force'):
            answer = user_choice(f'Do you want to restore {len(to_restore)} record(s)?', 'yn', default='n')
            if answer.lower() == 'y':
                answer = 'yes'
            if answer.lower() != 'yes':
                return

        batch = []
        for record_uid in to_restore:
            rec = deleted_records[record_uid]
            batch.append({
                'command': 'undelete_record',
                'record_uid': record_uid,
                'revision': rec['revision']
            })

        api.execute_batch(params, batch)
        TrashMixin.last_revision = 0
        params.sync_data = True
        for record_uid in to_restore:
            params.queue_audit_event('record_restored', record_uid=record_uid)


class TrashPurgeCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_purge_parser

    def execute(self, params, **kwargs):
        if not kwargs.get('force'):
            answer = user_choice(f'Do you want empty your Trash Bin?', 'yn', default='n')
            if answer.lower() == 'y':
                answer = 'yes'
            if answer.lower() != 'yes':
                return

        rq = {
            'command': 'purge_deleted_records'
        }
        api.communicate(params, rq)
        TrashMixin.last_revision = 0


class RecordHistoryCommand(Command):
    def get_parser(self):
        return record_history_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None
        if not record_name:
            self.get_parser().print_help()
            return

        verbose = kwargs.get('verbose') or False

        record_uid = None
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
            raise CommandError('history', 'Enter name of existing record')

        current_rec = params.record_cache[record_uid]
        if record_uid in params.record_history:
            history = params.record_history[record_uid]
            if history[0].get('revision') < current_rec['revision']:
                del params.record_history[record_uid]

        record_key = current_rec['record_key_unencrypted']

        if record_uid not in params.record_history:
            rq = {
                'command': 'get_record_history',
                'record_uid': record_uid,
                'client_time': utils.current_milli_time()
            }
            rs = api.communicate(params, rq)
            history = rs['history']   # type: list
            history.sort(key=lambda x: x.get('revision', 0), reverse=True)
            for rec in history:
                rec['record_key_unencrypted'] = record_key
                if 'data' in rec:
                    data = utils.base64_url_decode(rec['data'])
                    version = rec.get('version') or 0
                    try:
                        if version <= 2:
                            rec['data_unencrypted'] = crypto.decrypt_aes_v1(data, record_key)
                        else:
                            rec['data_unencrypted'] = crypto.decrypt_aes_v2(data, record_key)
                        if 'extra' in rec:
                            extra = utils.base64_url_decode(rec['extra'])
                            if version <= 2:
                                rec['extra_unencrypted'] = crypto.decrypt_aes_v1(extra, record_key)
                            else:
                                rec['extra_unencrypted'] = crypto.decrypt_aes_v2(extra, record_key)
                    except Exception as e:
                        logging.warning('Cannot decrypt record history revision: %s', e)

            params.record_history[record_uid] = history

        if record_uid in params.record_history:
            action = kwargs.get('action') or 'list'

            history = params.record_history[record_uid]    # type: List[Dict]
            length = len(history)
            if length == 0:
                logging.info('Record does not have history of edit')
                return

            if action == 'list':
                headers = ['Version', 'Modified By', 'Time Modified']
                rows = []
                for i, version in enumerate(history):
                    dt = None
                    if 'client_modified_time' in version:
                        dt = datetime.datetime.fromtimestamp(int(version['client_modified_time'] / 1000.0))
                    rows.append([f'V.{length-i}' if i > 0 else 'Current', version.get('user_name') or '', dt])
                dump_report_data(rows, headers, title='Record History')
                return

            revision = kwargs.get('revision') or 0
            if revision < 0 or revision >= length:
                raise ValueError(f'Invalid revision {revision}: valid revisions 1..{length}')

            index = 0 if revision == 0 else length - revision

            if action == 'view':
                rev = history[index]
                record = vault.KeeperRecord.load(params, rev)

                rows = []
                for name, value in record.enumerate_fields():
                    if value:
                        if isinstance(value, list):
                            value = '\n'.join(value)
                        # if len(value) > 100:
                        #     value = value[:99] + '...'
                        rows.append([name, value])
                modified = datetime.datetime.fromtimestamp(int(rev['client_modified_time'] / 1000.0))
                rows.append(['Modified', modified])
                dump_report_data(rows, headers=['Name', 'Value'], title=f'Record Revision V.{revision}', no_header=True)

            elif action == 'diff':
                count = 5
                current = vault.KeeperRecord.load(params, history[index])
                rows = []
                while count >= 0 and current:
                    previous = vault.KeeperRecord.load(params, history[index + 1]) if index < (length - 1) else None
                    cur = collections.OrderedDict()
                    last_pos = len(rows)
                    for name, value in current.enumerate_fields():
                        if isinstance(value, list):
                            value = '\n'.join(value)
                        cur[name] = value
                    pre = collections.OrderedDict()
                    if previous:
                        for name, value in previous.enumerate_fields():
                            if isinstance(value, list):
                                value = '\n'.join(value)
                            pre[name] = value
                    for name, value in cur.items():
                        if name in pre:
                            pre_value = pre[name]
                            if pre_value != value:
                                rows.append(['', name, value, pre_value])
                            del pre[name]
                        else:
                            if value:
                                rows.append(['', name, value, ''])
                    for name, value in pre.items():
                        if value:
                            if isinstance(value, list):
                                value = '\n'.join(value)
                            rows.append(['', name, '', value])

                    version = 'Current' if index == 0 else f'V.{length - index}'
                    if len(rows) > last_pos:
                        rows[last_pos][0] = version
                    else:
                        rows.append([version, '', '', ''])
                    count -= 1
                    index += 1
                    current = previous

                headers = ('Version', 'Field', 'New Value', 'Old Value')
                if not verbose:
                    for row in rows:
                        for index in (2, 3):
                            value = row[index]
                            if not value:
                                continue
                            lines = [x[:50]+'...' if len(x) > 52 else x for x in value.split('\n')]
                            if len(lines) > 3:
                                lines = lines[:2]
                                lines.append('...')
                            row[index] = '\n'.join(lines)

                dump_report_data(rows, headers)

            elif action == 'restore':
                ro = api.resolve_record_write_path(params, record_uid)    # type: dict
                if not ro:
                    raise CommandError('history', 'You do not have permission to modify this record')
                if revision == 0:
                    raise CommandError('history', f'Invalid revision to restore: Revisions: 1-{length - 1}')

                rev = history[index]
                if current_rec['version'] != rev['version']:
                    raise CommandError('history', 'Cannot restore converted record.')

                record = vault.KeeperRecord.load(params, rev)
                if isinstance(record, vault.TypedRecord):
                    fileRef = record.get_typed_field('fileRef')
                    if fileRef and isinstance(fileRef.value, list):
                        files = [x for x in fileRef.value if x in params.record_cache]
                        if len(files) < len(fileRef.value):
                            fileRef.value.clear()
                            fileRef.value.extend(files)
                update_record(params, record)
                params.queue_audit_event('revision_restored', record_uid=record.record_uid)
                params.sync_data = True
                logging.info('Record \"%s\" revision V.%d has been restored', record.title, revision)


class SharedRecordsReport(Command):
    def get_parser(self):
        return shared_records_report_parser

    def execute(self, params, **kwargs):

        export_format = kwargs['format'] if 'format' in kwargs else None
        export_name = kwargs['name'] if 'name' in kwargs else None

        shared_records_data_rs = api.communicate_rest(params, None, 'report/get_shared_record_report', rs_type=SharedRecordResponse)

        shared_from_mapping = {
            1: "Direct Share",
            2: "Share Folder",
            3: "Share Team Folder"
        }

        def get_share_teams(rec_uid):
            sf_cache = params.shared_folder_cache
            teams = []
            for folder in find_folders(params, rec_uid):
                shared_folder = sf_cache.get(folder)
                sf_teams = shared_folder.get('teams', []) if shared_folder else []
                teams += sf_teams
            return teams

        show_team_users = kwargs.get('show_team_users')
        team_records = set()    # type: Set[Tuple[Union[str, None], str]]
        rows = []
        for e in shared_records_data_rs.events:
            record_uid = api.decode_uid_to_str(e.recordUid)

            cached_record = None

            if record_uid in params.record_cache:   # to avoid not found warning log messages
                cached_record = api.get_record(params, record_uid)

            if not cached_record:   # probably deleted record
                logging.debug("Record uid=%s was not located in current cache." % record_uid)
                continue

            # Folder Path(s)
            folders = [get_folder_path(params, x) for x in find_folders(params, record_uid)]
            path_str = ""
            for i in range(len(folders)):
                path_str = path_str + ('{0}{1}'.format('\n' if i > 0 else '', folders[i]))

            if not e.canEdit and not e.canReshare:
                permissions = "Read Only"
            elif not e.canEdit and e.canReshare:
                permissions = "Can Share"
            elif e.canEdit and e.canReshare:
                permissions = "Can Edit"
            else:
                permissions = "Can Edit & Share"

            user_row = {
                'record_uid': record_uid,
                'title': cached_record.title,
                'share_to': e.userName,
                'shared_from': shared_from_mapping.get(e.shareFrom, 'Other Share'),
                'permissions': permissions,
                'folder_path': path_str
            }

            if e.shareFrom == 3:
                # Show team info for records shared via share team folders
                for share_team in get_share_teams(record_uid):
                    if isinstance(share_team, dict):
                        team_record = share_team.get('team_uid'), record_uid
                        if team_record not in team_records:
                            team_records.add(team_record)
                            team_row = {**user_row, 'share_to': '(Team) ' + share_team.get('name', '')}
                            rows.append(team_row)
                if show_team_users:
                    user_row['share_to'] = '(Team User) ' + user_row.get('share_to')
                    rows.append(user_row)
            else:
                rows.append(user_row)

        fields = ['record_uid', 'title', 'share_to', 'shared_from', 'permissions', 'folder_path']

        table = []
        for raw in rows:
            row = []
            for f in fields:
                row.append(raw[f])
            table.append(row)

        if export_format == 'table':
            fields = [field_to_title(x) for x in fields]
        return dump_report_data(table, fields, fmt=export_format, filename=export_name, row_number=True)
