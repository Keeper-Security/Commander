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
from datetime import datetime
import json
import requests
import base64
import tempfile
import logging
import threading
from Cryptodome.Cipher import AES
from tabulate import tabulate
from pypager.source import GeneratorSource
from pypager.pager import Pager
from typing import List

from ...team import Team
from ... import api, display, generator
from ...subfolder import BaseFolderNode, find_folders, try_resolve_path, get_folder_path
from ..base import raise_parse_exception, suppress_exit, user_choice, Command, ParseException
from ...record import Record, get_totp_code
from ...params import KeeperParams, LAST_RECORD_UID
from ...display import TablePager
from ...error import KeeperApiError, InputError


def register_commands(commands):
    commands['add'] = RecordAddCommand()
    commands['edit'] = RecordEditCommand()
    commands['rm'] = RecordRemoveCommand()
    commands['search'] = SearchCommand()
    commands['list'] = RecordListCommand()
    commands['list-sf'] = RecordListSfCommand()
    commands['list-team'] = RecordListTeamCommand()
    commands['get'] = RecordGetUidCommand()
    commands['append-notes'] = RecordAppendNotesCommand()
    commands['download-attachment'] = RecordDownloadAttachmentCommand()
    commands['upload-attachment'] = RecordUploadAttachmentCommand()
    commands['delete-attachment'] = RecordDeleteAttachmentCommand()
    commands['clipboard-copy'] = ClipboardCommand()
    commands['record-history'] = RecordHistoryCommand()
    commands['totp'] = TotpCommand()


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
    aliases['cc'] = 'clipboard-copy'
    aliases['rh'] = 'record-history'

    for p in [SearchCommand.PARSER, RecordListCommand.PARSER, RecordGetUidCommand.PARSER,
             ClipboardCommand.PARSER, RecordHistoryCommand.PARSER, TotpCommand.PARSER,  RecordAppendNotesCommand.PARSER,
             RecordEditCommand.PARSER, RecordRemoveCommand.PARSER, RecordAppendNotesCommand.PARSER,
             RecordDownloadAttachmentCommand.PARSER, RecordUploadAttachmentCommand.PARSER, RecordDownloadAttachmentCommand.PARSER]:
        command_info[p.prog] = p.description
    command_info['list-sf|lsf'] = 'Display all shared folders'
    command_info['list-team|lt'] = 'Display all teams'

class PagerOption():
    """pager option"""
    PARSER = argparse.ArgumentParser(prog='pager', add_help=False)
    PARSER.add_argument('-p', '--pager', dest='pager', action='store_true', help='Show each pages output.')
    PAGER = Pager()

from abc import ABCMeta,abstractmethod

class UidListReturnCommand(metaclass=ABCMeta):
    @abstractmethod
    def execute(self, params: KeeperParams, **kwargs) -> List[str]: # record_uid
        pass

Command.register(UidListReturnCommand)

class RecordAddCommand(Command):
    PARSER = argparse.ArgumentParser(prog='add|a', description='Add record')
    PARSER.add_argument('--login', dest='login', action='store', help='login name')
    PARSER.add_argument('--pass', dest='password', action='store', help='password')
    PARSER.add_argument('--url', dest='url', action='store', help='url')
    PARSER.add_argument('--notes', dest='notes', action='store', help='notes')
    PARSER.add_argument('--custom', dest='custom', action='store', help='custom fields. name:value pairs separated by comma. Example: "name1: value1, name2: value2"')
    PARSER.add_argument('--folder', dest='folder', action='store', help='folder path or UID where record is to be created')
    PARSER.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for omitted fields')
    PARSER.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate random password')
    PARSER.add_argument('title', type=str, action='store', help='record title')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

    def execute(self, params, **kwargs) -> str:
        '''Add a new record
        return: uid as str if success in api call else raise 
        '''
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
                try:
                    custom_json = json.loads(custom_list)
                    for k,v in custom_json.items():
                        custom.append({
                            'name': k,
                            'value': str(v)
                        })
                except ValueError as e:
                    pass
                if len(custom) == 0:
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

        if not force:
            folder_uid = folder.uid or ''
            if folder_uid in params.subfolder_record_cache:
                for uid in params.subfolder_record_cache[folder_uid]:
                    r = api.get_record(params, uid)
                    if r.title == title:
                        logging.error('Record with title "%s" already exists', title)
                        return

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
            'custom': custom
        }
        rq['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key)

        try:
            res = api.communicate(params, rq)
        except KeeperApiError as e:
            logging.error(f"AddRecord API call failed!:{e}")
            return

        params.sync_data = True
        logging.info('Record UID is added: %s', record_uid)
        params.environment_variables[LAST_RECORD_UID] = record_uid
        return record_uid


class RecordEditCommand(Command):
    PARSER = argparse.ArgumentParser(prog='edit', description='Edit record')
    PARSER.add_argument('--login', dest='login', action='store', help='login name')
    PARSER.add_argument('--pass', dest='password', action='store', help='password')
    PARSER.add_argument('--url', dest='url', action='store', help='url')
    PARSER.add_argument('--notes', dest='notes', action='store', help='notes. + in front of notes appends text to existing notes')
    PARSER.add_argument('--custom', dest='custom', action='store', help='custom fields. name:value pairs separated by comma. Example: "name1: value1, name2: value2"')
    PARSER.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate random password')
    PARSER.add_argument('record', type=str, action='store', help='record name(title) or UID') # nargs='?', path
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

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
                logging.info('Could not resolve record name(title) or uid. Enter record name(title) or uid of existing record.')
                return
        record = api.get_record(params, record_uid)

        changed = dict() #False
        fd = 'title'
        if kwargs.get('title') is not None:
            title = kwargs['title']
            if title and len(title.split()) > 0:
                record.title = title
                changed['title'] = title #True
            else:
                logging.warning('Record title cannot be empty.')
        if kwargs.get('login') is not None:
            changed['login'] = record.login = kwargs['login']
            
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
                try:
                    custom_json = json.loads(custom_list)
                    for k,v in custom_json.items():
                        custom.append({
                            'name': k,
                            'value': str(v)
                        })
                except ValueError as e:
                    pass
                if len(custom) == 0:
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
            params.sync_data = True
            api.update_record(params, record)


class RecordAppendNotesCommand(Command):
    PARSER = argparse.ArgumentParser(prog='append-notes|an', description='Append notes to existing record')
    PARSER.add_argument('--notes', dest='notes', action='store', help='notes')
    PARSER.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')

    def execute(self, params, **kwargs):
        notes = kwargs['notes'] if 'notes' in kwargs else None
        while not notes:
            notes = input("... Notes to append: ")

        edit_command = RecordEditCommand()
        kwargs['notes'] = '+' + notes
        edit_command.execute(params, **kwargs)


class RecordRemoveCommand(Command):
    PARSER = argparse.ArgumentParser(prog='rm', description='Remove record')
    PARSER.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
    PARSER.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

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
            logging.warning('Enter name of existing record')
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
                api.communicate(params, rq)
                params.sync_data = True

class SortOption():
    """parser sort arguments"""
    PARSER = argparse.ArgumentParser(prog='sort', add_help=False)
    PARSER.add_argument('-r', '--reverse', dest='reverse', action='store_true', help='Reverse sort order.')
    SORT_CHOICES = ['record_uid', 'folder', 'title', 'login', 'password', 'revision', 'notes', 'login_url'] 
    SORT_ARGUMENTS = {'dest':'sort', 'action':'store', 'const':'title', 'nargs':'?',
        'choices':SORT_CHOICES, 
        'help':f"Sort records by {', '.join(SORT_CHOICES)}"}
    PARSER.add_argument('-s', '--sort', **SORT_ARGUMENTS)



class RecordHistoryCommand(Command):
    PARSER = argparse.ArgumentParser(prog='record-history|rh', description='Record History')
    PARSER.add_argument('-a', '--action', dest='action', choices=['list', 'diff', 'show', 'restore'], action='store', help='record history action. \'list\' if omitted')
    PARSER.add_argument('-r', '--revision', dest='revision', type=int, action='store', help='history revision')
    PARSER.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

    def get_parser(self):
        return PARSER

    def execute(self, params, print=print, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None
        if not record_name:
            self.get_parser().print_help()
            return None

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
            logging.error('Enter name or uid of existing record')
            return None

        current_rec = params.record_cache[record_uid]
        if record_uid in params.record_history:
            _,revision = params.record_history[record_uid]
            if revision < current_rec['revision']:
                del params.record_history[record_uid]
        if record_uid not in params.record_history:
            rq = {
                'command': 'get_record_history',
                'record_uid': record_uid,
                'client_time': api.current_milli_time
            }
            rs = api.communicate(params, rq)
            params.record_history[record_uid] = (rs['history'], current_rec['revision'])

        if record_uid in params.record_history:
            action = kwargs.get('action') or 'list'
            history,_ = params.record_history[record_uid]
            history.sort(key=lambda x: x['revision'])
            history.reverse()
            length = len(history)
            if length == 0:
                logging.info('Record does not have history of edit')
                return None

            if 'revision' in kwargs and kwargs['revision'] is not None:
                revision = kwargs['revision']
                if revision < 1 or revision > length+1:
                    logging.error('Invalid revision %d: valid revisions 1..%d'.format(revision, length + 1))
                    return None
                if not kwargs.get('action'):
                    action = 'show'
            else:
                revision = 0

            if action == 'list':
                headers = ['Version', 'Modified By', 'Time Modified']
                rows = []
                raws = []
                for i, revision in enumerate(history):
                    if 'client_modified_time' in revision:
                        dt = datetime.fromtimestamp(revision['client_modified_time']/1000.0)
                        tm = dt.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        tm = ''
                    rows.append(['V.{}'.format(length-i), revision.get('user_name') or '', tm])
                    raws.append([length-i, revision.get('user_name') or '', dt])
                if print:
                    print(tabulate(rows, headers=headers))
                return raws
            elif action == 'show':
                if revision == 0:
                    revision = length + 1
                current_rec = params.record_cache[record_uid]
                key = current_rec['record_key_unencrypted']
                rev = history[length - revision]
                rec = RecordHistoryCommand.load_revision(params, key, rev)
                if print:
                    print('\n{0:>20s}: V.{1}'.format('Revision', revision))
                    rec.display()
                return revision, rec
            elif action == 'diff':
                if revision == 0:
                    revision = 1
                current_rec = params.record_cache[record_uid]
                key = current_rec['record_key_unencrypted']
                rev = history[0]
                record_next = RecordHistoryCommand.load_revision(params, key, rev)
                rows = []
                for current_revision in range(length, revision-1, -1):
                    current_rev = history[length - current_revision]
                    record_current = RecordHistoryCommand.load_revision(params, key, current_rev)
                    added = False
                    for d in RecordHistoryCommand.get_record_diffs(record_next, record_current):
                        rows.append(['V.{}'.format(current_revision+1) if not added else '', d[0], d[1], d[2]])
                        added = True
                    record_next = record_current
                record_current = Record()
                added = False
                for d in RecordHistoryCommand.get_record_diffs(record_next, record_current):
                    rows.append(['V.{}'.format(1) if not added else '', d[0], d[1], d[2]])
                    added = True
                if print:
                    headers = ('Version', 'Field', 'New Value', 'Old Value')
                    print(tabulate(rows, headers=headers))
                return rows
            elif action == 'restore':
                ro = api.resolve_record_write_path(params, record_uid)    # type: dict
                if not ro:
                    logging.error('You do not have permission to modify this record')
                    return
                if revision == 0:
                    logging.error('Invalid revision to restore: Revisions: 1-{0}'.format(length))
                    return
                rev = history[length - revision]
                if rev['version'] in {1,2}:
                    current_rec = params.record_cache[record_uid]
                    ro.update({
                        'version': rev['version'],
                        'client_modified_time': api.current_milli_time(),
                        'revision': current_rec['revision'],
                        'data': rev['data']
                    })
                    udata = current_rec.get('udata') or {}
                    extra = {}
                    if 'extra_unencrypted' in current_rec:
                        extra = json.loads(current_rec['extra_unencrypted'].decode('utf-8'))
                    if 'udata' in rev:
                        udata.update(rev['udata'])
                    udata['file_ids'] = []
                    if 'files' in extra:
                        del extra['files']

                    key = current_rec['record_key_unencrypted']
                    if 'extra' in rev:
                        decrypted_extra = api.decrypt_data(rev['extra'], key)
                        extra_object = json.loads(decrypted_extra.decode('utf-8'))
                        extra.update(extra_object)
                        if 'files' in extra:
                            for atta in extra_object['files']:
                                udata['file_ids'].append(atta['id'])
                                if 'thumbnails' in atta:
                                    for thumb in atta['thumbnails']:
                                        udata['file_ids'].append(thumb['id'])
                    ro['extra'] = api.encrypt_aes(json.dumps(extra).encode('utf-8'), key)
                    ro['udata'] = udata
                    rq = {
                        'command': 'record_update',
                        'update_records': [ro]
                    }
                    rs = api.communicate(params, rq)
                    if 'update_records' in rs:
                        params.sync_data = True
                        if rs['update_records']:
                            status = rs['update_records'][0]
                            if status['status'] == 'success':
                                logging.info('Revision V.{0} is restored'.format(revision))
                                params.queue_audit_event('revision_restored', record_uid=record_uid)
                            else:
                                logging.error('Failed to restore record revision: {0}'.format(status['status']))
                else:
                    logging.error('Cannot restore this revision')
            return None

    @staticmethod
    def load_revision(params, record_key, revision):
        # type: (KeeperParams, bytes, dict) -> Record
        data = json.loads(api.decrypt_data(revision['data'], record_key).decode('utf-8'))
        if 'extra' in revision:
            extra = json.loads(api.decrypt_data(revision['extra'], record_key).decode('utf-8'))
        else:
            extra = {}
        rec = Record(revision['record_uid'])
        rec.load(data, extra=extra)
        return rec

    @staticmethod
    def get_diff_index(value1, value2):
        length = min(len(value1), len(value2))
        for i in range(length):
            if value1[i] != value2[i]:
                return i
        return length

    TargetValueLength = 32
    @staticmethod
    def to_diff_str(value, index=0):
        if len(value) > RecordHistoryCommand.TargetValueLength:
            if index > 6:
                tail_len = len(value) - index
                if tail_len >= RecordHistoryCommand.TargetValueLength - 6:
                    value = '... ' + value[index-2:]
                else:
                    value = '... ' + value[-(RecordHistoryCommand.TargetValueLength - 6):]
            if len(value) > RecordHistoryCommand.TargetValueLength:
                value = value[:26] + ' ...'
        return value

    @staticmethod
    def compare_values(value1, value2):
        # type: (str, str) -> (str, str) or None
        if not value1 and not value2:
            return None
        if value1 and value2:
            if value1 == value2:
                return None
            idx = RecordHistoryCommand.get_diff_index(value1, value2)
            return RecordHistoryCommand.to_diff_str(value1, idx), RecordHistoryCommand.to_diff_str(value2, idx)
        else:
            return RecordHistoryCommand.to_diff_str(value1 or ''), RecordHistoryCommand.to_diff_str(value2 or '')

    @staticmethod
    def to_attachment_str(attachment):
        # type: (dict) -> str
        value = ''
        if attachment:
            value += attachment.get('title') or attachment.get('name') or attachment.get('id')
            size = attachment.get('size') or 0
            scale = 'b'
            if size > 0:
                if size > 2000:
                    size = size / 1024
                    scale = 'Kb'
                if size > 2000:
                    size = size / 1024
                    scale = 'Mb'
                if size > 2000:
                    size = size / 1024
                    scale = 'Gb'
                value += ': ' + '{0:.2f}'.format(size).rstrip('0').rstrip('.') + scale
        return value

    @staticmethod
    def get_record_diffs(record1, record2):
        # type: (Record, Record) -> [(str, str, str)]
        d1 = record1.__dict__
        d2 = record2.__dict__
        for field in [('title', 'Title'), ('login', 'Login'), ('password', 'Password'), ('login_url', 'URL'), ('notes', 'Notes'), ('totp', 'Two Factor')]:
            v1 = d1.get(field[0]) or ''
            v2 = d2.get(field[0]) or ''
            cmp_result = RecordHistoryCommand.compare_values(v1, v2)
            if cmp_result:
                yield field[1], cmp_result[0], cmp_result[1]
        if record1.custom_fields or record2.custom_fields:
            all_keys = set()
            all_keys.update([x['name'] for x in record1.custom_fields if 'name' in x])
            all_keys.update([x['name'] for x in record2.custom_fields if 'name' in x])
            keys = [x for x in all_keys]
            keys.sort()
            for key in keys:
                v1 = record1.get(key) or ''
                v2 = record2.get(key) or ''
                cmp_result = RecordHistoryCommand.compare_values(v1, v2)
                if cmp_result:
                    yield key[:24], cmp_result[0], cmp_result[1]
        if record1.attachments or record2.attachments:
            att1 = {}
            att2 = {}
            if record1.attachments:
                for atta in record1.attachments:
                    if 'id' in atta:
                        att1[atta['id']] = atta
            if record2.attachments:
                for atta in record2.attachments:
                    if 'id' in atta:
                        att2[atta['id']] = atta
            s = set()
            s.update(att1.keys())
            s.symmetric_difference_update(att2.keys())
            if len(s) > 0:
                for id in s:
                    yield 'Attachment', RecordHistoryCommand.to_attachment_str(att1.get(id)), RecordHistoryCommand.to_attachment_str(att2.get(id))

class ModefiedOption():
    """parser modefied arguments"""
    PARSER = argparse.ArgumentParser(prog='modefied', add_help=False)
    PARSER.add_argument('-m', '--modefied', dest='modefied', action='store_true', help='add modified date time field.')

class PagerOption():
    """parser pager arguments"""
    PARSER = argparse.ArgumentParser(prog='pager', add_help=False)
    PARSER.add_argument('-p', '--pager', dest='pager', action='store_true', help='Show content page by page.')

class HistoryOption():
    """parser history arguments"""
    PARSER = argparse.ArgumentParser(prog='history', add_help=False)
    PARSER.add_argument('-his', '--history', dest='history', action='store_true', help='List only records with history(ever modified).')
    COMMAND = RecordHistoryCommand()
    ACTION = {'action':'list'}

class WebOption():
    """parser web arguments"""
    PARSER = argparse.ArgumentParser(prog='webview', add_help=False)
    PARSER.add_argument('-w', '--webview', dest='webview', action='store', 
        nargs='?', const='6080', help='Show content page by web(http/https) protocol with port number WEBVIEW(const=6080)).')


class RecordListCommand(Command):
    """List records"""
    PARSER = argparse.ArgumentParser(parents=[SortOption.PARSER, ModefiedOption.PARSER, PagerOption.PARSER, WebOption.PARSER], prog='list|l', description='Display all record UID/titles')
    PARSER.add_argument('pattern', nargs='?', type=str, action='store', help='regex pattern')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

    def execute(self, params:KeeperParams, print=print, **kwargs):
        '''List record : history if 'history' in params
        '''
        pattern = kwargs.get('pattern')
        records = api.search_records(params, pattern or '')
        if not records:
            return None
        append_funcs = []
        if kwargs.get('modefied'):
            kwargs.pop('sort', None)
            current_time = datetime.now()
            def modified_time(r):
                mt = get_modified_time(params, r.record_uid)
                if not mt:
                    logging.error("Failed in getting record modified time!")
                    return current_time
                return mt
            modified_times = [modified_time(r) for r in records]
            zipped = list(zip(records, modified_times))
            sorted_zipped = sorted(zipped, key=lambda z: z[1], reverse=kwargs.get('reverse'))
            records = [r[0] for r in sorted_zipped]
            uid_dict_datetime = {r[0].record_uid : r[1] for r in zipped}
            def get_cmtime(uid):
                return uid_dict_datetime[uid].isoformat() if uid else "Modefied time"
            append_funcs += [get_cmtime]

        #if len(results) < 5:
        #    api.get_record_shares(params, [x.record_uid for x in results])
        #if 'time' in kwargs: display.formatted_records(results, time=True) else:
        '''
        history = kwargs.get('history')
        if history:
            def get_history(record_uid):
                return HistoryOption.COMMAND.execute(params, print=None, record=record_uid, **HistoryOption.ACTION) if record_uid else 'History'
            modified_records = [x for x in records if get_history(x.record_uid)]
        else:
            get_history = None
        '''
        if kwargs.get('pager'):
            pgprint = PagerOption.pager = Pager()
        else:
            pgprint = print
        params.last_record_table = records
        formatted = display.formatted_records(records, appends=append_funcs, print_func=pgprint, **kwargs)
        return formatted            

class RecordListSfCommand(Command):
    """List Shared Folders
     - execute method sorts records by Title
    """
    PARSER = argparse.ArgumentParser(prog='search|s', description='Search shared folders with regular expression')
    PARSER.add_argument('pattern', nargs='?', type=str, action='store', help='regex pattern')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

    def execute(self, params, **kwargs):
        pattern = kwargs['pattern'] if 'pattern' in kwargs else None
        results = api.search_shared_folders(params, pattern or '')
        if results:
            display.formatted_shared_folders(results)

class SearchCommand(Command):
    PARSER = argparse.ArgumentParser(parents=[SortOption.PARSER, ModefiedOption.PARSER, PagerOption.PARSER], prog='search|s', description='Search with regular expression')
    PARSER.add_argument('pattern', nargs='?', type=str, action='store', help='regex pattern')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 
    
    def execute(self, params, print=print, **kwargs):
        """Return: (records, shared_folders, team_folders)
        """
        pattern = kwargs.get('pattern', '')
        records = api.search_records(params, pattern)
        if records and print:
            display.formatted_records(records, print=print, appends=None, **kwargs)
        shared_folders = api.search_shared_folders(params, pattern)
        if shared_folders and print:
            print("\nShared folders:")
            display.formatted_shared_folders(shared_folders, print=print, **kwargs)
        teams = api.search_teams(params, pattern)
        if teams and print:
            print("\nTeams:")
            display.formatted_teams(teams, print=print, appends=None, **kwargs)
        return records, shared_folders, teams


class RecordListTeamCommand(Command):
    PARSER = argparse.ArgumentParser(parents=[SortOption.PARSER], prog='search|s', description='Search teams with regular expression')
    PARSER.add_argument('pattern', nargs='?', type=str, action='store', help='regex pattern')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 
    
    def execute(self, params, **kwargs):
        rq = {
            'command': 'get_available_teams'
        }

        rs = api.communicate(params, rq)
        result = []
        for team in rs['teams']:
            team = Team(team_uid=team['team_uid'], name=team['team_name'])
            result.append(team)

        display.formatted_teams(result, skip_details=True)


class RecordGetUidCommand(Command):
    PARSER = argparse.ArgumentParser(prog='get|g', description='Display specified Keeper record/folder/team')
    PARSER.add_argument('--format', dest='format', action='store', choices=['detail', 'json', 'password'], default='detail', help='output format.')
    PARSER.add_argument('uid', type=str, action='store', help='UID or last pager output 1st column number(#)')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

    def execute(self, params, **kwargs):
        uid = kwargs['uid'] if 'uid' in kwargs else None
        if not uid:
            print('UID parameter is required')
            return
        import re
        mt = re.fullmatch(r"(\d+)", uid)
        if mt:
            if not TablePager.table:
                print("Record number specify needs to be after pager or web showed records.")
                return
            num = int(mt.group(0))
            if num <= 0:
                print(f"Specify number 1 or larger.")
                return
            lines = TablePager.table
            if num > len(lines):
                print(f"Specify (0 < number <= ({len(lines)}).")
                return
            uid = lines[num - 1][1]

        fmt = kwargs.get('format') or 'detail'

        if api.is_shared_folder(params, uid):
            sf = api.get_shared_folder(params, uid)
            if fmt == 'json':
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
            if fmt == 'json':
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
            if fmt == 'json':
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
                params.queue_audit_event('open_record', record_uid=uid)
                if fmt == 'json':
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
                                    'owner': su.get('owner') or False,
                                    'editable': su.get('editable') or False,
                                    'sharable': su.get('sharable') or False
                                } for su in permissions]

                    print(json.dumps(ro, indent=2))
                elif fmt == 'password':
                    print(r.password)
                else:
                    r.display(params=params)


class RecordDownloadAttachmentCommand(Command):
    PARSER = argparse.ArgumentParser(prog='download-attachment', description='Download record attachments')
    #download_parser.add_argument('--files', dest='files', action='store', help='file names comma separated. All files if omitted.')
    PARSER.add_argument('record', action='store', help='record path or UID')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

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
            logging.warning('Enter name or uid of existing record')
            return

        file_ids = []
        r = params.record_cache[record_uid]
        extra = json.loads(r['extra_unencrypted'].decode())
        if 'files' in extra:
            for f_info in extra['files']:
                file_ids.append(f_info['id'])

        if len(file_ids) == 0:
            logging.warning('No attachments associated with the record')
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
                    if 'files' in extra:
                        for f_info in extra['files']:
                            if f_info['id'] == file_id:
                                file_key = base64.urlsafe_b64decode(f_info['key'] + '==')
                                file_name = f_info['name']
                                break

                    if file_key:
                        rq_http = requests.get(dl['url'], stream=True)
                        with open(file_name, 'wb') as f:
                            logging.info('Downloading \'%s\'', os.path.abspath(f.name))
                            iv = rq_http.raw.read(16)
                            cipher = AES.new(file_key, AES.MODE_CBC, iv)
                            finished = False
                            decrypted = None
                            while not finished:
                                if decrypted:
                                    f.write(decrypted)
                                    decrypted = None

                                to_decrypt = rq_http.raw.read(10240)
                                finished = len(to_decrypt) < 10240
                                if len(to_decrypt) > 0:
                                    decrypted = cipher.decrypt(to_decrypt)
                            if decrypted:
                                decrypted = api.unpad_binary(decrypted)
                                f.write(decrypted)
                            params.queue_audit_event('file_attachment_downloaded', record_uid=record_uid, attachment_id=file_id)
                    else:
                        logging.error('File "%s": Failed to file encryption key', file_name)
                else:
                    logging.error('File "%s" download error: %s', file_id, dl['message'])


class RecordUploadAttachmentCommand(Command):
    PARSER = argparse.ArgumentParser(prog='upload-attachment', description='Upload record attachments')
    PARSER.add_argument('--file', dest='file', action='append', required=True, help='file name to upload.')
    PARSER.add_argument('record', action='store', help='record path or UID')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

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
            logging.error('You do not have edit permissions on this record')
            return

        files = []
        if 'file' in kwargs:
            for name in kwargs['file']:
                file_name = os.path.abspath(os.path.expanduser(name))
                if os.path.isfile(file_name):
                    files.append(file_name)
                else:
                    logging.error('File %s does not exists', name)
        if len(files) == 0:
            logging.error('No files to upload')
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
                    logging.error('%s: file size exceeds file plan limits', file_path)
            except Exception as e:
                logging.error('%s error: %s', file_path, e)

        if len(attachments) == 0:
            logging.error('No files were successfully uploaded')
            return

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
    PARSER = argparse.ArgumentParser(prog='delete-attachment', description='Delete attachment file')
    PARSER.add_argument('--name', dest='name', action='append', required=True, help='attachment file name or ID. Can be repeated.')
    PARSER.add_argument('record', action='store', help='record path or UID')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

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
            logging.error('Enter name or uid of existing record')
            return

        names = kwargs['name'] if 'name' in kwargs else None
        if names is None:
            logging.error('No file names')
            return

        record_update = api.resolve_record_write_path(params, record_uid)
        if record_update is None:
            logging.error('You do not have edit permissions on this record')
            return

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


class ClipboardCommand(Command):
    PARSER = argparse.ArgumentParser(prog='clipboard-copy|cc', description='Copy record password to clipboard')
    PARSER.add_argument('-l', '--login', dest='login', action='store_true', help='login name')
    PARSER.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

    def get_parser(self):
        return clipboard_copy_parser

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
            records = api.search_records(params, kwargs['record'])
            if len(records) == 1:
                logging.info('Record Title: {0}'.format(records[0].title))
                record_uid = records[0].record_uid
            else:
                if len(records) == 0:
                    logging.error('Enter name or uid of existing record')
                else:
                    logging.error('More than one record are found for search criteria: {0}'.format(kwargs['record']))
                return

        rec = api.get_record(params, record_uid)
        txt = rec.login if kwargs.get('login') else rec.password
        if txt:
            import pyperclip
            pyperclip.copy(txt)
            logging.info('Copied to clipboard')
            if not kwargs.get('login'):
                params.queue_audit_event('copy_password', record_uid=record_uid)


class TotpEndpoint:
    def __init__(self, record_uid, record_title, paths):
        self.record_uid = record_uid
        self.record_title = record_title
        self.paths = paths


class TotpCommand(Command):
    '''Display Two Factor Code '''
    LastRevision = 0 # int
    Endpoints = []          # type: [TotpEndpoint]
    PARSER = argparse.ArgumentParser(prog='totp', description='Display Two Factor Code')
    PARSER.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
    PARSER.error = Command.parser_error
    PARSER.exit = suppress_exit 

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
                        logging.error('Enter name or uid of existing record')
                    else:
                        logging.error('More than one record are found for search criteria: {0}'.format(kwargs['record']))

        if record_uid:
            rec = api.get_record(params, record_uid)
            tmer = None     # type: threading.Timer or None
            done = False
            def print_code():
                global tmer
                if not done:
                    TotpCommand.display_code(rec.totp)
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


def get_modified_time(params, record_uid):
    """get modified time from cache in params"""
    current_rec = params.record_cache[record_uid]
    if not current_rec:
        return None
    client_modified_time = current_rec.get('client_modified_time')
    if not client_modified_time:
        return None
    dt = None
    try:
        dt = datetime.fromtimestamp(client_modified_time / 1000)
    except OverflowError as e:
        logging.error(f"Out of range of datetime timestamp:{e}")
    except OSError as e:
        logging.error(f"getting datetime os call failed.:{e}")
    finally:
        return dt