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
from . import base
from .base import suppress_exit, raise_parse_exception, Command
from .. import api, generator
from .. import attachment
from ..display import bcolors
from ..error import CommandError
from ..params import KeeperParams, LAST_RECORD_UID
from ..record import Record, get_totp_code
from ..subfolder import BaseFolderNode, find_folders, try_resolve_path, get_folder_path, SharedFolderFolderNode, \
    SharedFolderNode


def register_commands(commands):
    commands['add'] = RecordAddCommand()
    commands['edit'] = RecordEditCommand()
    commands['rm'] = RecordRemoveCommand()
    commands['append-notes'] = RecordAppendNotesCommand()
    commands['download-attachment'] = RecordDownloadAttachmentCommand()
    commands['upload-attachment'] = RecordUploadAttachmentCommand()
    commands['delete-attachment'] = RecordDeleteAttachmentCommand()
    commands['totp'] = TotpCommand()


def register_command_info(aliases, command_info):
    aliases['a'] = 'add'
    aliases['an'] = 'append-notes'
    aliases['da'] = 'download-attachment'
    aliases['ua'] = 'upload-attachment'

    for p in [totp_parser,  add_parser, edit_parser, rm_parser,
              append_parser, download_parser, upload_parser, delete_attachment_parser]:
        command_info[p.prog] = p.description


totp_parser = argparse.ArgumentParser(prog='totp', description='Display the Two Factor Code for a record.')
totp_parser.add_argument('-p', '--print', dest='print', action='store_true', help='print TOTP code to standard output')
totp_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
totp_parser.error = raise_parse_exception
totp_parser.exit = suppress_exit


add_parser = argparse.ArgumentParser(prog='add|a', description='Add a record')
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


rm_parser = argparse.ArgumentParser(prog='rm', description='Remove a record')
rm_parser.add_argument('--purge', dest='purge', action='store_true', help='remove the record from all folders and purge it from the trash')
rm_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
rm_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
rm_parser.error = raise_parse_exception
rm_parser.exit = suppress_exit


get_info_parser = argparse.ArgumentParser(prog='get|g', description='Get the details of a record/folder/team by UID.')
get_info_parser.add_argument('--format', dest='format', action='store', choices=['detail', 'json', 'password'], default='detail', help='output format.')
get_info_parser.add_argument('--unmask', dest='unmask', action='store_true', help='display hidden field context')
get_info_parser.add_argument('uid', type=str, action='store', help='UID')
get_info_parser.error = raise_parse_exception
get_info_parser.exit = suppress_exit


append_parser = argparse.ArgumentParser(prog='append-notes|an', description='Append notes to an existing record.')
append_parser.add_argument('--notes', dest='notes', action='store', help='notes')
append_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
append_parser.error = raise_parse_exception
append_parser.exit = suppress_exit


download_parser = argparse.ArgumentParser(prog='download-attachment', description='Download record attachments.')
#download_parser.add_argument('--files', dest='files', action='store', help='file names comma separated. All files if omitted.')
download_parser.add_argument('record', action='store', help='record path or UID')
download_parser.error = raise_parse_exception
download_parser.exit = suppress_exit


upload_parser = argparse.ArgumentParser(prog='upload-attachment', description='Upload record attachments.')
upload_parser.add_argument('--file', dest='file', action='append', required=True, help='file name to upload.')
upload_parser.add_argument('record', action='store', help='record path or UID')
upload_parser.error = raise_parse_exception
upload_parser.exit = suppress_exit


delete_attachment_parser = argparse.ArgumentParser(prog='delete-attachment', description='Delete an attachment from a record.', usage="Example to remove two files for a record: delete-attachment {uid} --name secrets.txt --name photo.jpg")
delete_attachment_parser.add_argument('--name', dest='name', action='append', required=True, help='attachment file name or ID. Can be repeated.')
delete_attachment_parser.add_argument('record', action='store', help='record path or UID')
delete_attachment_parser.error = raise_parse_exception
delete_attachment_parser.exit = suppress_exit


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


class RecordAppendNotesCommand(Command):
    def get_parser(self):
        return append_parser

    def execute(self, params, **kwargs):
        notes = kwargs['notes'] if 'notes' in kwargs else None
        while not notes:
            notes = input("... Notes to append: ")

        edit_command = RecordEditCommand()
        kwargs['notes'] = '+' + notes
        edit_command.execute(params, **kwargs)


class RecordRemoveCommand(Command):
    def get_parser(self):
        return rm_parser

    def execute(self, params, **kwargs):
        folder = None
        name = None
        record_path = kwargs['record'] if 'record' in kwargs else None
        if record_path:
            rs = try_resolve_path(params, record_path)
            if rs is not None:
                folder, name = rs

        if folder is None or name is None:
            logging.warning('Enter name of existing record')
            return

        record_uid = None
        if name in params.record_cache:
            record_uid = name
            folders = list(find_folders(params, record_uid))
            if len(folders) > 0:
                folder = params.folder_cache[folders[0]] if len(folders[0]) > 0 else params.root_folder
        else:
            folder_uid = folder.uid or ''
            if folder_uid in params.subfolder_record_cache:
                for uid in params.subfolder_record_cache[folder_uid]:
                    r = api.get_record(params, uid)
                    if r.title.lower() == name.lower():
                        record_uid = uid
                        break

        if record_uid is None:
            raise CommandError('rm', 'Enter name of existing record')

        if kwargs.get('purge'):
            is_owner = False
            if record_uid in params.meta_data_cache:
                md = params.meta_data_cache[record_uid]
                is_owner = md.get('owner') or False
            if not is_owner:
                logging.warning('Record purge error: Not an owner')
                return

            rq = {
                'command': 'record_update',
                'pt': 'Commander',
                'device_id': 'Commander',
                'client_time': api.current_milli_time(),
                'delete_records': [record_uid]
            }
            if not kwargs.get('force'):
                answer = base.user_choice('Do you want to proceed with record purge?', 'yn', default='n')
                if answer.lower() != 'y':
                    return
            rs = api.communicate(params, rq)
            if 'delete_records' in rs:
                for status in rs['delete_records']:
                    if status['status'] != 'success':
                        logging.warning('Record purge error: %s', status.get('status'))
        else:
            del_obj = {
                'delete_resolution': 'unlink',
                'object_uid': record_uid,
                'object_type': 'record'
            }
            if folder.type in {BaseFolderNode.RootFolderType, BaseFolderNode.UserFolderType}:
                del_obj['from_type'] = 'user_folder'
                if folder.type == BaseFolderNode.UserFolderType:
                    del_obj['from_uid'] = folder.uid
            else:
                del_obj['from_type'] = 'shared_folder_folder'
                del_obj['from_uid'] = folder.uid

            rq = {
                'command': 'pre_delete',
                'objects': [del_obj]
            }

            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                pdr = rs['pre_delete_response']

                force = kwargs['force'] if 'force' in kwargs else None
                np = 'y'
                if not force:
                    summary = pdr['would_delete']['deletion_summary']
                    for x in summary:
                        print(x)
                    np = base.user_choice('Do you want to proceed with deletion?', 'yn', default='n')
                if np.lower() == 'y':
                    rq = {
                        'command': 'delete',
                        'pre_delete_token': pdr['pre_delete_token']
                    }
                    api.communicate(params, rq)
                    params.sync_data = True


class RecordDownloadAttachmentCommand(Command):
    def get_parser(self):
        return download_parser

    def execute(self, params, **kwargs):
        name = kwargs['record'] if 'record' in kwargs else None

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
            raise CommandError('download-attachment', 'Enter name or uid of existing record')

        attachments = list(attachment.prepare_attachment_download(params, record_uid))
        if len(attachments) == 0:
            raise CommandError('download-attachment', 'No attachments associated with the record')

        for atta in attachments:
            atta.download_to_file(params, atta.title)


class RecordUploadAttachmentCommand(Command):
    def get_parser(self):
        return upload_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None

        if not record_name:
            self.get_parser().print_help()
            return

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
                        record_add = RecordAddCommand()
                        record_uid = record_add.execute(params, title=record_name, folder=folder_uid, force=True)

        record = None
        if record_uid is None:
            record = Record()
            record.title = kwargs['record']
            if api.add_record(params, record):
                record_uid = record.record_uid
            else:
                return
        if params.sync_data:
            api.sync_down(params)

        record_update = api.resolve_record_write_path(params, record_uid)
        if record_update is None:
            raise CommandError('upload-attachment', 'You do not have edit permissions on this record')

        files = []
        if 'file' in kwargs:
            for name in kwargs['file']:
                file_name = os.path.abspath(os.path.expanduser(name))
                if os.path.isfile(file_name):
                    files.append(file_name)
                else:
                    raise CommandError('upload-attachment', 'File "{0}" does not exists'.format(name))
        if len(files) == 0:
            raise CommandError('upload-attachment', 'No files to upload')

        rq = {
            'command': 'request_upload',
            'file_count': len(files),
            'thumbnail_count': 0
        }
        rs = api.communicate(params, rq)

        attachments = []
        for file_path, uo in zip(files, rs['file_uploads']):
            try:
                file_size = os.path.getsize(file_path)
                if 0 < file_size < uo['max_size']:
                    a = {
                        'key': api.generate_aes_key(),
                        'file_id': uo['file_id'],
                        'name': os.path.basename(file_path)
                    }
                    logging.info('Uploading %s ...', a['name'])
                    with tempfile.TemporaryFile(mode='w+b') as dst:
                        with open(file_path, mode='r+b') as src:
                            iv = os.urandom(16)
                            cipher = AES.new(a['key'], AES.MODE_CBC, iv)
                            dst.write(iv)
                            finished = False
                            while not finished:
                                to_encrypt = src.read(10240)
                                if len(to_encrypt) > 0:
                                    if len(to_encrypt) < 10240:
                                        to_encrypt = api.pad_binary(to_encrypt)
                                        finished = True
                                    encrypted = cipher.encrypt(to_encrypt)
                                    dst.write(encrypted)
                                else:
                                    finished = True
                            a['size'] = src.tell()
                        dst.seek(0)
                        files = {
                            uo['file_parameter']: (a['file_id'], dst, 'application/octet-stream')
                        }
                        response = requests.post(uo['url'], files=files, data=uo['parameters'])
                        if response.status_code == uo['success_status_code']:
                            attachments.append(a)
                            params.queue_audit_event('file_attachment_uploaded', record_uid=record_uid, attachment_id=a['file_id'])
                else:
                    raise CommandError('upload-attachment', '{0}: file size exceeds file plan limits'.format(file_path))
            except Exception as e:
                raise CommandError('upload-attachment', '{0} error: {1}'.format(file_path, e))

        if len(attachments) == 0:
            raise CommandError('upload-attachment', 'No files were successfully uploaded')

        record = params.record_cache[record_uid]
        extra = json.loads(record['extra_unencrypted'].decode('utf-8')) if 'extra_unencrypted' in record else {}
        files = extra.get('files')
        if files is None:
            files = []
            extra['files'] = files
        udata = record['udata'] if 'udata' in record else {}
        file_ids = udata.get('file_ids')
        if file_ids is None:
            file_ids = []
            udata['file_ids'] = file_ids
        for atta in attachments:
            file_ids.append(atta['file_id'])
            files.append({
                'id': atta['file_id'],
                'name': atta['name'],
                'size': atta['size'],
                'key': base64.urlsafe_b64encode(atta['key']).decode().rstrip('=')
            })

        record_update.update({
            'version': 2,
            'client_modified_time': api.current_milli_time(),
            'extra': api.encrypt_aes(json.dumps(extra).encode('utf-8'), record['record_key_unencrypted']),
            'udata': udata,
            'revision': record['revision']
        })
        api.resolve_record_access_path(params, record_uid, path=record_update)
        rq = {
            'command': 'record_update',
            'pt': 'Commander',
            'device_id': 'Commander',
            'client_time': api.current_milli_time(),
            'update_records': [record_update]
        }
        api.communicate(params, rq)
        params.sync_data = True


class RecordDeleteAttachmentCommand(Command):
    def get_parser(self):
        return delete_attachment_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None

        if not record_name:
            self.get_parser().print_help()
            return

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
            raise CommandError('delete-attachment', 'Enter name or uid of existing record')

        names = kwargs['name'] if 'name' in kwargs else None
        if names is None:
            raise CommandError('delete-attachment', 'No file names')

        record_update = api.resolve_record_write_path(params, record_uid)
        if record_update is None:
            raise CommandError('delete-attachment', 'You do not have edit permissions on this record')

        record = params.record_cache[record_uid]
        extra = json.loads(record['extra_unencrypted'].decode('utf-8')) if 'extra_unencrypted' in record else {}
        files = extra.get('files')
        if files is None:
            files = []
            extra['files'] = files
        udata = record['udata'] if 'udata' in record else {}
        file_ids = udata.get('file_ids')
        if file_ids is None:
            file_ids = []
            udata['file_ids'] = file_ids

        has_deleted = False
        for name in names:
            file_uid = None
            thumb_uid = None
            for file in files:
                if name in [file.get('name'), file.get('title'), file.get('id')]:
                    file_uid = file.get('id')
                    if 'thumbs' in file:
                        if type(file['thumbs']) == list:
                            thumb_uid = file['thumbs'][0].get('id')
                    break
            if file_uid is not None:
                has_deleted = True
                files = [x for x in files if x['id'] != file_uid]
                file_ids = [x for x in file_ids if x != file_uid]
                if thumb_uid is not None:
                    file_ids = [x for x in file_ids if x != thumb_uid]
                params.queue_audit_event('file_attachment_deleted', record_uid=record_uid, attachment_id=file_uid)
            else:
                logging.info('Attachment \'%s\' is not found.', name)

        if not has_deleted:
            return

        extra['files'] = files
        udata['file_ids'] = file_ids
        record_update.update({
            'version': 2,
            'client_modified_time': api.current_milli_time(),
            'extra': api.encrypt_aes(json.dumps(extra).encode('utf-8'), record['record_key_unencrypted']),
            'udata': udata,
            'revision': record['revision']
        })
        api.resolve_record_access_path(params, record_uid, path=record_update)
        rq = {
            'command': 'record_update',
            'pt': 'Commander',
            'device_id': 'Commander',
            'client_time': api.current_milli_time(),
            'update_records': [record_update]
        }
        api.communicate(params, rq)
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
