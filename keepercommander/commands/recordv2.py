#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import base64
import json
import logging
import os
import re
import tempfile
import threading
from typing import Optional

import requests
from Cryptodome.Cipher import AES
from tabulate import tabulate

from . import record_common
from .base import suppress_exit, raise_parse_exception, Command
from .. import api, generator
from ..display import bcolors
from ..error import CommandError
from ..params import KeeperParams, LAST_RECORD_UID
from ..record import Record, get_totp_code
from ..subfolder import BaseFolderNode, find_folders, try_resolve_path, get_folder_path


def register_commands(commands):
    commands['add'] = RecordAddCommand()
    commands['edit'] = RecordEditCommand()
    commands['totp'] = TotpCommand()


def register_command_info(aliases, command_info):
    aliases['a'] = 'add'

    for p in [totp_parser]:
        command_info[p.prog] = p.description


totp_parser = argparse.ArgumentParser(prog='totp', description='Display the Two Factor Code for a record.')
totp_parser.add_argument('-p', '--print', dest='print', action='store_true', help='print TOTP code to standard output')
totp_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
totp_parser.error = raise_parse_exception
totp_parser.exit = suppress_exit


add_parser = argparse.ArgumentParser(prog='add', description='Add a record')
add_parser.add_argument('--login', dest='login', action='store', help='login name')
add_parser.add_argument('--pass', dest='password', action='store', help='password')
add_parser.add_argument('--url', dest='url', action='store', help='url')
add_parser.add_argument('--notes', dest='notes', action='store', help='notes')
add_parser.add_argument('--custom', dest='custom', action='store', help='add custom fields. JSON or name:value pairs separated by comma. CSV Example: --custom "name1: value1, name2: value2". JSON Example: --custom \'{"name1":"value1", "name2":"value: 2,3,4"}\'')
add_parser.add_argument('--folder', dest='folder', action='store', help='folder path or UID where record is to be created')
add_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for omitted fields')
add_parser.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate a random password')
add_parser.add_argument('title', type=str, action='store', help='record title')
add_parser.error = raise_parse_exception
add_parser.exit = suppress_exit


edit_parser = argparse.ArgumentParser(prog='edit', description='Edit a record')
edit_parser.add_argument('--login', dest='login', action='store', help='login name')
edit_parser.add_argument('--pass', dest='password', action='store', help='password')
edit_parser.add_argument('--url', dest='url', action='store', help='url')
edit_parser.add_argument('--notes', dest='notes', action='store', help='set or replace the notes. Use a plus sign (+) in front appends to existing notes')
edit_parser.add_argument('--custom', dest='custom', action='store', help='custom fields. JSON or name:value pairs separated by comma. CSV Example: --custom "name1: value1, name2: value2". JSON Example: --custom \'{"name1":"value1", "name2":"value: 2,3,4"}\'')
edit_parser.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate a random password')
edit_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
edit_parser.error = raise_parse_exception
edit_parser.exit = suppress_exit


get_info_parser = argparse.ArgumentParser(prog='get', description='Get the details of a record/folder/team by UID.')
get_info_parser.add_argument('--format', dest='format', action='store', choices=['detail', 'json', 'password'], default='detail', help='output format.')
get_info_parser.add_argument('--unmask', dest='unmask', action='store_true', help='display hidden field context')
get_info_parser.add_argument('uid', type=str, action='store', help='UID')
get_info_parser.error = raise_parse_exception
get_info_parser.exit = suppress_exit


class RecordUtils(object):
    parameter_pattern = re.compile(r'^\${([^:]+?):([^}]+?)}$')

    @staticmethod
    def custom_field_value(value):  # type: (any) -> str
        if not value:
            return ''
        if type(value) != str:
            return value
        m = RecordUtils.parameter_pattern.match(value.strip())
        if m:
            parts = m.groups()
            if len(parts) == 2:
                if parts[0].lower() == 'file':
                    filename = parts[1].strip()
                    if os.path.isfile(filename):
                        with open(filename, 'r') as f:
                            return f.read()
                elif parts[0].lower() == 'env':
                    if parts[1] in os.environ:
                        return os.environ[parts[1]]

        return value


class RecordAddCommand(Command, RecordUtils):
    def get_parser(self):
        return add_parser

    def execute(self, params, **kwargs):
        title = kwargs['title'] if 'title' in kwargs else None
        login = kwargs['login'] if 'login' in kwargs else None
        password = kwargs['password'] if 'password' in kwargs else None
        url = kwargs['url'] if 'url' in kwargs else None
        custom_list = kwargs['custom'] if 'custom' in kwargs else None
        notes = kwargs['notes'] if 'notes' in kwargs else None

        generate = kwargs['generate'] if 'generate' in kwargs else None
        if generate:
            password = generator.generate(16)

        force = kwargs['force'] if 'force' in kwargs else None
        if not force:
            if not title:
                title = input('...' + 'Title: '.rjust(16))
            if not login:
                login = input('...' + 'Login: '.rjust(16))
            if not password:
                password = input('...' + 'Password: '.rjust(16))
            if not url:
                url = input('...' + 'Login URL: '.rjust(16))
        if not title:
            raise CommandError('add', 'Invalid title. Expected non-empty string.')

        custom = []
        if custom_list:
            if type(custom_list) == str:
                if custom_list[0] == '{' and custom_list[-1] == '}':
                    try:
                        custom_json = json.loads(custom_list)
                        for k, v in custom_json.items():
                            custom.append({
                                'name': k,
                                'value': self.custom_field_value(v)
                            })
                    except ValueError as e:
                        raise CommandError('add', 'Invalid custom fields JSON input: {0}'.format(e))
                else:
                    pairs = custom_list.split(',')
                    for pair in pairs:
                        idx = pair.find(':')
                        if idx > 0:
                            custom.append({
                                'name': pair[:idx].strip(),
                                'value': self.custom_field_value(pair[idx+1:].strip())
                            })
                        else:
                            raise CommandError('add', 'Invalid custom fields input. Expected: "Key:Value". Got: "{0}"'.format(pair))

            elif type(custom_list) == list:
                for c in custom_list:
                    if type(c) == dict:
                        name = c.get('name')
                        value = c.get('value')
                        if name and value:
                            custom.append({
                                'type': 'text',
                                'name': name,
                                'value': self.custom_field_value(value)
                            })

        folder = None
        folder_name = kwargs['folder'] if 'folder' in kwargs else None
        if folder_name:
            if folder_name in params.folder_cache:
                folder = params.folder_cache[folder_name]
            else:
                src = try_resolve_path(params, folder_name)
                if src is not None:
                    folder, name = src
                    if name:
                        raise CommandError('add', 'No such folder: {0}'.format(folder_name))
                else:
                    raise CommandError('add', 'No such folder: {0}'.format(folder_name))
        if not folder:
            folder = params.folder_cache[params.current_folder] if params.current_folder else params.root_folder

        if not force:
            folder_uid = folder.uid or ''
            if folder_uid in params.subfolder_record_cache:
                for uid in params.subfolder_record_cache[folder_uid]:
                    r = api.get_record(params, uid)
                    if r.title == title:
                        raise CommandError('add', 'Record with title "{0}" already exists'.format(title))

        record_key = os.urandom(32)
        record_uid = api.generate_record_uid()
        rq = {
            'command': 'record_add',
            'record_uid': record_uid,
            'record_type': 'password',
            'record_key': api.encrypt_aes(record_key, params.data_key),
            'how_long_ago': 0
        }
        if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            rq['folder_uid'] = folder.uid
            rq['folder_type'] = 'shared_folder' if folder.type == BaseFolderNode.SharedFolderType else 'shared_folder_folder'

            sh_uid = folder.uid if folder.type == BaseFolderNode.SharedFolderType else folder.shared_folder_uid
            sf = params.shared_folder_cache[sh_uid]
            rq['folder_key'] = api.encrypt_aes(record_key, sf['shared_folder_key_unencrypted'])
            if 'key_type' not in sf:
                if 'teams' in sf:
                    for team in sf['teams']:
                        rq['team_uid'] = team['team_uid']
                        if team['manage_records']:
                            break
        else:
            rq['folder_type'] = 'user_folder'
            if folder.type != BaseFolderNode.RootFolderType:
                rq['folder_uid'] = folder.uid

        data = {
            'title': title or '',
            'secret1': login or '',
            'secret2': password or '',
            'link': url or '',
            'notes': notes or '',
            'custom': custom or []
        }
        Record.validate_record_data(data, None, None)

        rq['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key)

        api.communicate(params, rq)
        api.sync_down(params)
        if params.enterprise_ec_key:
            api.add_record_audit_data(params, [record_uid])
        if params.breach_watch:
            params.breach_watch.scan_and_store_record_status(params, record_uid)

        params.sync_data = True
        params.environment_variables[LAST_RECORD_UID] = record_uid
        return record_uid


class RecordEditCommand(Command, RecordUtils):
    def get_parser(self):
        return edit_parser

    def execute(self, params, **kwargs):
        name = kwargs.get('record')

        if not name:
            self.get_parser().print_help()
            return

        record_uid = None
        if name in params.record_cache:
            record_uid = name
        else:
            rs = try_resolve_path(params, name)
            if rs is not None:
                folder, name = rs
                if folder is not None and name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == name.lower():
                                record_uid = uid
                                break

        if record_uid is None:
            raise CommandError('edit', 'Enter name or uid of existing record')

        record = api.get_record(params, record_uid)

        changed = False
        if kwargs.get('title') is not None:
            title = kwargs['title']
            if title:
                record.title = title
                changed = True
            else:
                logging.warning('Record title cannot be empty.')
        if kwargs.get('login') is not None:
            record.login = kwargs['login']
            changed = True
        if kwargs.get('password') is not None:
            record.password = kwargs['password']
            changed = True
        else:
            if kwargs.get('generate'):
                record.password = generator.generate(16)
                changed = True
        if kwargs.get('url') is not None:
            record.login_url = kwargs['url']
            changed = True
        if kwargs.get('notes') is not None:
            notes = kwargs['notes'] # type: str
            if notes:
                if notes.startswith("+"):
                    notes = record.notes + "\n" + notes[1:]
            record.notes = notes
            changed = True

        custom_list = kwargs.get('custom')
        if custom_list:
            custom = []
            if type(custom_list) == str:
                if custom_list[0] == '{' and custom_list[-1] == '}':
                    try:
                        custom_json = json.loads(custom_list)
                        for k,v in custom_json.items():
                            custom.append({
                                'type': 'text',
                                'name': k,
                                'value': self.custom_field_value(v)
                            })
                    except ValueError as e:
                        raise CommandError('edit', 'Invalid custom fields JSON input: {0}'.format(e))
                else:
                    pairs = custom_list.split(',')
                    for pair in pairs:
                        idx = pair.find(':')
                        if idx > 0:
                            custom.append({
                                'name': pair[:idx].strip(),
                                'value': self.custom_field_value(pair[idx+1:].strip())
                            })
                        else:
                            raise CommandError('edit', 'Invalid custom fields input. Expected: "Key:Value". Got: "{0}"'.format(pair))
            elif type(custom_list) == list:
                for c in custom_list:
                    if type(c) == dict:
                        name = c.get('name')
                        value = c.get('value')
                        if name and value:
                            custom.append({
                                'name': name,
                                'value': self.custom_field_value(value)
                            })
            if custom:
                for c in custom:
                    if c['value']:
                        record.set_field(c['name'], c['value'])
                        changed = True
                    else:
                        deleted = record.remove_field(c['name'])
                        if deleted:
                            changed = True

        if changed:
            api.update_record(params, record)
            if params.breach_watch:
                api.sync_down(params)
                params.breach_watch.scan_and_store_record_status(params, record_uid)
            params.sync_data = True


class TotpEndpoint:
    def __init__(self, record_uid, record_title, paths):
        self.record_uid = record_uid
        self.record_title = record_title
        self.paths = paths


class TotpCommand(Command):
    LastRevision = 0 # int
    Endpoints = []          # type: [TotpEndpoint]

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

        print_totp = kwargs.get('print')
        if record_uid:
            rec = api.get_record(params, record_uid)
            if not rec.totp:
                raise CommandError('totp', f'Record \"{rec.title}\" does not contain TOTP codes')
            if print_totp:
                if rec.totp:
                    code, remains, total = get_totp_code(rec.totp)
                    if code: print(code)
            else:
                tmer = None     # type: Optional[threading.Timer]
                done = False
                def print_code():
                    global tmer
                    if not done:
                        TotpCommand.display_code(rec.totp)
                        tmer = threading.Timer(1, print_code).start()

                if kwargs['details']:
                    record_common.display_totp_details(rec.totp)

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
            headers = ["#", 'Record UID', 'Record Title', 'Folder(s)']
            table = []
            for i in range(len(TotpCommand.Endpoints)):
                endpoint = TotpCommand.Endpoints[i]
                title = endpoint.record_title
                if len(title) > 23:
                    title = title[:20] + '...'
                folder = endpoint.paths[0] if len(endpoint.paths) > 0 else '/'
                table.append([i + 1, endpoint.record_uid, title, folder])
            table.sort(key=lambda x: x[2])
            print(tabulate(table, headers=headers))
            print('')

        if print_totp and not record_uid:
            logging.warning(bcolors.FAIL + '--print option requires valid record UID' + bcolors.ENDC)

    LastDisplayedCode = ''
    @staticmethod
    def display_code(url):
        code, remains, total = get_totp_code(url)
        progress = ''.rjust(remains, '=')
        progress = progress.ljust(total, ' ')
        if os.isatty(0):
            print('\r', end='', flush=True)
            print('\t{0}\t\t[{1}]'.format(code, progress), end='', flush=True)
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
                record = api.get_record(params, record_uid)
                if record.totp:
                    paths = []
                    for folder_uid in find_folders(params, record_uid):
                        path = '/' + get_folder_path(params, folder_uid, '/')
                        paths.append(path)
                    TotpCommand.Endpoints.append(TotpEndpoint(record_uid, record.title, paths))
