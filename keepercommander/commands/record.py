#_  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import os
import argparse
import json
import requests
import base64
import tempfile

from Cryptodome.Cipher import AES

from .. import generator, api, display
from ..subfolder import BaseFolderNode, find_folders, try_resolve_path
from .base import raise_parse_exception, suppress_exit, user_choice, Command
from ..record import Record


def register_commands(commands):
    commands['add'] = RecordAddCommand()
    commands['rm'] = RecordRemoveCommand()
    commands['search'] = SearchCommand()
    commands['list'] = RecordListCommand()
    commands['list-sf'] = RecordListSfCommand()
    commands['list-team'] = RecordListTeamCommand()
    commands['get'] = RecordGetUidCommand()
    commands['append-notes'] = RecordAppendNotesCommand()
    commands['download-attachment'] = RecordDownloadAttachmentCommand()
    commands['upload-attachment'] = RecordUploadAttachmentCommand()


def register_command_info(aliases, command_info):
    aliases['a'] = 'add'
    aliases['s'] = 'search'
    aliases['l'] = 'list'
    aliases['lsf'] = 'list-sf'
    aliases['lt'] = 'list-team'
    aliases['g'] = 'get'
    aliases['an'] = 'append-notes'
    aliases['da'] = 'download-attachment'
    aliases['ua'] = 'upload-attachment'

    for p in [search_parser, list_parser, get_info_parser, add_parser, rm_parser, append_parser,
              download_parser, upload_parser]:
        command_info[p.prog] = p.description
    command_info['list-sf|lsf'] = 'Display all shared folders'
    command_info['list-team|lt'] = 'Display all teams'


add_parser = argparse.ArgumentParser(prog='add|a', description='Add record')
add_parser.add_argument('--login', dest='login', action='store', help='login name')
add_parser.add_argument('--pass', dest='password', action='store', help='password')
add_parser.add_argument('--url', dest='url', action='store', help='url')
add_parser.add_argument('--notes', dest='notes', action='store', help='notes')
add_parser.add_argument('--custom', dest='custom', action='store', help='comma separated key-value pairs')
add_parser.add_argument('--folder', dest='folder', action='store', help='folder path or UID where record is to be created')
add_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for omitted fields')
add_parser.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate random password')
add_parser.add_argument('title', type=str, action='store', help='record title')
add_parser.error = raise_parse_exception
add_parser.exit = suppress_exit


rm_parser = argparse.ArgumentParser(prog='rm', description='Remove record')
rm_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
rm_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
rm_parser.error = raise_parse_exception
rm_parser.exit = suppress_exit


list_parser = argparse.ArgumentParser(prog='list|l', description='Display all record UID/titles')
list_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
list_parser.error = raise_parse_exception
list_parser.exit = suppress_exit


search_parser = argparse.ArgumentParser(prog='search|s', description='Search with regular expression')
search_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
search_parser.error = raise_parse_exception
search_parser.exit = suppress_exit


get_info_parser = argparse.ArgumentParser(prog='get|g', description='Display specified Keeper record/folder/team')
get_info_parser.add_argument('--format', dest='format', action='store', choices=['detail', 'json'], default='detail', help='output format.')
get_info_parser.add_argument('uid', type=str, action='store', help='UID')
get_info_parser.error = raise_parse_exception
get_info_parser.exit = suppress_exit


append_parser = argparse.ArgumentParser(prog='append-notes|an', description='Append notes to existing record')
append_parser.add_argument('--notes', dest='notes', action='store', help='notes')
append_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
append_parser.error = raise_parse_exception
append_parser.exit = suppress_exit


download_parser = argparse.ArgumentParser(prog='download-attachment', description='Download record attachments')
#download_parser.add_argument('--files', dest='files', action='store', help='file names comma separated. All files if omitted.')
download_parser.add_argument('record', action='store', help='record path or UID')
download_parser.error = raise_parse_exception
download_parser.exit = suppress_exit


upload_parser = argparse.ArgumentParser(prog='upload-attachment', description='Upload record attachments')
upload_parser.add_argument('--file', dest='file', action='append', required=True, help='file name to upload.')
upload_parser.add_argument('record', action='store', help='record path or UID')
upload_parser.error = raise_parse_exception
upload_parser.exit = suppress_exit


class RecordAddCommand(Command):
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

        custom = []
        if custom_list:
            if type(custom_list) == str:
                pairs = custom_list.split(',')
                for pair in pairs:
                    idx = pair.find(':')
                    if idx > 0:
                        custom.append({
                            'name': pair[:idx].strip(),
                            'value': pair[idx+1:].strip()
                        })
            elif type(custom_list) == list:
                for c in custom_list:
                    if type(c) == dict:
                        name = c.get('name')
                        value = c.get('value')
                        if name and value:
                            custom.append({
                                'name': name,
                                'value': value
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
        if folder is None:
            folder = params.folder_cache[params.current_folder] if params.current_folder else params.root_folder

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
            rq['folder_key'] = api.encrypt_aes(record_key, sf['shared_folder_key'])
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
            'custom': custom
        }
        rq['data'] =  api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key)

        rs = api.communicate(params, rq)
        if rs['result'] == 'success':
            params.sync_data = True
            return record_uid
        else:
            print(rs['message'])


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
            print('Enter name of existing record')
            return

        record_uid = None
        if name in params.record_cache:
            record_uid = name
            folders = list(find_folders(params, record_uid))
            #TODO support multiple folders
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
            print('Enter name of existing record')
            return

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
                np = user_choice('Do you want to proceed with deletion?', 'yn', default='n')
            if np.lower() == 'y':
                rq = {
                    'command': 'delete',
                    'pre_delete_token': pdr['pre_delete_token']
                }
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    params.sync_data = True
                else:
                    print(rs['message'])


class SearchCommand(Command):
    def get_parser(self):
        return search_parser

    def execute(self, params, **kwargs):
        pattern = (kwargs['pattern'] if 'pattern' in kwargs else None) or ''

        # Search records
        results = api.search_records(params, pattern)
        if results:
            print('')
            display.formatted_records(results, params=params, skip_details=True)

        # Search shared folders
        results = api.search_shared_folders(params, pattern)
        if results:
            print('')
            display.formatted_shared_folders(results, params=params, skip_details=True)

        # Search teams
        results = api.search_teams(params, pattern)
        if results:
            print('')
            display.formatted_teams(results, params=params, skip_details=True)


class RecordListCommand(Command):
    def get_parser(self):
        return list_parser

    def execute(self, params, **kwargs):
        pattern = kwargs['pattern'] if 'pattern' in kwargs else None
        results = api.search_records(params, pattern or '')
        if results:
            display.formatted_records(results, params=params)


class RecordListSfCommand(Command):
    def execute(self, params, **kwargs):
        results = api.search_shared_folders(params, '')
        if results:
            display.formatted_shared_folders(results)


class RecordListTeamCommand(Command):
    def execute(self, params, **kwargs):
        results = api.search_teams(params, '')
        if results:
            display.formatted_teams(results)


class RecordGetUidCommand(Command):
    def get_parser(self):
        return get_info_parser

    def execute(self, params, **kwargs):
        uid = kwargs['uid'] if 'uid' in kwargs else None
        if not uid:
            print('UID parameter is required')
            return

        format = kwargs.get('format') or 'detail'

        if api.is_shared_folder(params, uid):
            sf = api.get_shared_folder(params, uid)
            if format == 'json':
                sfo = {
                    "shared_folder_uid": sf.shared_folder_uid,
                    "name": sf.name,
                    "manage_users": sf.default_manage_users,
                    "manage_records": sf.default_manage_records,
                    "can_edit": sf.default_can_edit,
                    "can_share": sf.default_can_share
                }
                if sf.records:
                    sfo['records'] = [{
                        'record_uid': r['record_uid'],
                        'can_edit': r['can_edit'],
                        'can_share': r['can_share']
                    } for r in sf.records]
                if sf.users:
                    sfo['users'] = [{
                        'username': u['username'],
                        'manage_records': u['manage_records'],
                        'manage_users': u['manage_users']
                    } for u in sf.users]
                if sf.teams:
                    sfo['teams'] = [{
                        'name': t['name'],
                        'manage_records': t['manage_records'],
                        'manage_users': t['manage_users']
                    } for t in sf.teams]

                print(json.dumps(sfo, indent=2))
            else:
                sf.display()
        elif api.is_team(params, uid):
            team = api.get_team(params, uid)
            if format == 'json':
                to = {
                    'team_uid': team.team_uid,
                    'name': team.name,
                    'restrict_edit': team.restrict_edit,
                    'restrict_view': team.restrict_view,
                    'restrict_share': team.restrict_share
                }
                print(json.dumps(to, indent=2))
            else:
                team.display()
        elif uid in params.folder_cache:
            f = params.folder_cache[uid]
            if format == 'json':
                fo = {
                    'folder_uid': f.uid,
                    'type': f.type,
                    'name': f.name
                }
                print(json.dumps(fo, indent=2))
            else:
                f.display(params=params)
        else:
            api.get_record_shares(params, [uid])
            r = api.get_record(params, uid)
            if r:
                if format == 'json':
                    ro = {
                        'record_uid': r.record_uid,
                        'title': r.title
                    }
                    if r.login:
                        ro['login'] = r.login
                    if r.password:
                        ro['password'] = r.password
                    if r.login_url:
                        ro['login_url'] = r.login_url
                    if r.notes:
                        ro['notes'] = r.notes
                    if r.custom_fields:
                        ro['custom_fields'] = r.custom_fields
                    if r.attachments:
                        ro['attachments'] = [{
                            'id': a.get('id'),
                            'name': a.get('name'),
                            'size': a.get('size')
                        } for a in r.attachments]

                    if r.record_uid in params.record_cache:
                        rec = params.record_cache[r.record_uid]
                        if 'shares' in rec:
                            if 'user_permissions' in rec['shares']:
                                permissions = rec['shares']['user_permissions']
                                ro['shared_with'] = [{
                                    'username': su['username'],
                                    'owner': su.get('ownser') or False,
                                    'editable': su.get('editable') or False,
                                    'sharable': su.get('sharable') or False
                                } for su in permissions]

                    print(json.dumps(ro, indent=2))
                else:
                    r.display(params=params)


class RecordAppendNotesCommand(Command):
    def get_parser(self):
        return append_parser

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
            print('Enter name or uid of existing record')
            return

        notes = kwargs['notes'] if 'notes' in kwargs else None
        while not notes:
            notes = input("... Notes to append: ")

        record = api.get_record(params, record_uid)

        if record.notes:
            record.notes += '\n'
        record.notes += notes
        params.sync_data = True
        api.update_record(params, record)


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
            print('Enter name or uid of existing record')
            return

        file_ids = []
        r = params.record_cache[record_uid]
        extra = json.loads(r['extra'].decode())
        if 'files' in extra:
            for f_info in extra['files']:
                file_ids.append(f_info['id'])

        if len(file_ids) == 0:
            print('No attachments associated with the record')
            return

        rq = {
            'command': 'request_download',
            'file_ids': file_ids,
        }
        api.resolve_record_access_path(params, record_uid, path=rq)

        rs = api.communicate(params, rq)
        if rs['result'] == 'success':
            for file_id, dl in zip(file_ids, rs['downloads']):
                if 'url' in dl:
                    file_key = None
                    file_name = None
                    extra = json.loads(r['extra'].decode())
                    if 'files' in extra:
                        for f_info in extra['files']:
                            if f_info['id'] == file_id:
                                file_key = base64.urlsafe_b64decode(f_info['key'] + '==')
                                file_name = f_info['name']
                                break

                    if file_key:
                        rq_http = requests.get(dl['url'], stream=True)
                        with open(file_name, 'wb') as f:
                            api.print_info('Downloading \'{0}\''.format(os.path.abspath(f.name)))
                            iv = rq_http.raw.read(16)
                            cipher = AES.new(file_key, AES.MODE_CBC, iv)
                            finished = False
                            while not finished:
                                to_decrypt = rq_http.raw.read(10240)
                                if len(to_decrypt) > 0:
                                    decrypted = cipher.decrypt(to_decrypt)
                                    f.write(decrypted)
                                else:
                                    finished = True
                    else:
                        api.print_error('File \'{0}\': Failed to file encryption key'.format(file_name))
                else:
                    api.print_error('File \'{0}\' download error: {1}'.format(file_id, dl['message']))


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
            api.print_error('You do not have edit permissions on this record')
            return

        files = []
        if 'file' in kwargs:
            for name in kwargs['file']:
                file_name = os.path.abspath(os.path.expanduser(name))
                if os.path.isfile(file_name):
                    files.append(file_name)
                else:
                    api.print_error('File {0} does not exists'.format(name))
        if len(files) == 0:
            api.print_error('No files to upload')
            return

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
                    api.print_info('Uploading {0} ...'.format(a['name']), end_line=False)
                    with tempfile.TemporaryFile(mode='w+b') as dst:
                        with open(file_path, mode='r+b') as src:
                            iv = os.urandom(16)
                            cipher = AES.new(a['key'], AES.MODE_CBC, iv)
                            dst.write(iv)
                            finished = False
                            while not finished:
                                to_encrypt = src.read(10240)
                                if len(to_encrypt) > 0:
                                    if len(to_encrypt) % api.BS != 0:
                                        to_encrypt = api.pad_binary(to_encrypt)
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
                    api.print_info('Done')
                else:
                    api.print_error('{0}: file size exceeds file plan limits'.format(file_path))
            except Exception as e:
                api.print_error('{0} error: {1}'.format(file_path, e))

        if len(attachments) == 0:
            api.print_error('No files were successfully uploaded')
            return

        record = params.record_cache[record_uid]
        extra = json.loads(record['extra'].decode('utf-8')) if 'extra' in record else {}
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
            'data': api.encrypt_aes(record['data'], record['record_key_unencrypted']),
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
