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
import json
import logging
import os
import re

from keepercommander.breachwatch import BreachWatch

from .base import suppress_exit, raise_parse_exception, Command
from .. import api, generator, utils, crypto
from ..error import CommandError
from ..params import LAST_RECORD_UID
from ..record import Record
from ..subfolder import BaseFolderNode, try_resolve_path


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
            'record_key': utils.base64_url_encode(crypto.encrypt_aes_v1(record_key, params.data_key)),
            'how_long_ago': 0
        }
        if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            rq['folder_uid'] = folder.uid
            rq['folder_type'] = 'shared_folder' if folder.type == BaseFolderNode.SharedFolderType else 'shared_folder_folder'

            sh_uid = folder.uid if folder.type == BaseFolderNode.SharedFolderType else folder.shared_folder_uid
            sf = params.shared_folder_cache[sh_uid]
            rq['folder_key'] = utils.base64_url_encode(
                crypto.encrypt_aes_v1(record_key, sf['shared_folder_key_unencrypted']))
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

        rq['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), record_key))

        api.communicate(params, rq)
        api.sync_down(params)
        if params.enterprise_ec_key:
            api.add_record_audit_data(params, [record_uid])
        BreachWatch.scan_and_update_security_data(params, record_uid, params.breach_watch)

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
        password_changed = False
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
            last_password = record.unmasked_password or record.password
            record.password = kwargs['password']
            password_changed = record.password != last_password
            changed = True
        else:
            if kwargs.get('generate'):
                record.password = generator.generate(16)
                changed = password_changed = True
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
            if password_changed:
                BreachWatch.scan_and_update_security_data(params, record_uid, params.breach_watch)
            params.sync_data = True
