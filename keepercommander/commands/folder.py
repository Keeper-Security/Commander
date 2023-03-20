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
import logging
import re
import fnmatch
import shutil
import functools
import os
import json
from collections import OrderedDict
from typing import Tuple, List, Optional, Dict, Set, Any

from . import base
from .. import api, display, vault, vault_extensions, crypto, utils
from ..proto import folder_pb2, record_pb2
from ..recordv3 import RecordV3
from ..subfolder import BaseFolderNode, try_resolve_path, find_folders
from ..params import KeeperParams
from ..record import Record
from .base import user_choice, dump_report_data, suppress_exit, raise_parse_exception, Command, GroupCommand, RecordMixin
from ..params import LAST_SHARED_FOLDER_UID, LAST_FOLDER_UID
from ..error import CommandError, KeeperApiError, Error


def register_commands(commands):
    commands['ls'] = FolderListCommand()
    commands['cd'] = FolderCdCommand()
    commands['tree'] = FolderTreeCommand()
    commands['mkdir'] = FolderMakeCommand()
    commands['rmdir'] = FolderRemoveCommand()
    commands['rndir'] = FolderRenameCommand()
    commands['mv'] = FolderMoveCommand()
    commands['ln'] = FolderLinkCommand()
    commands['shortcut'] = ShortcutCommand()
    commands['arrange-folders'] = ArrangeFolderCommand()
    commands['transform-folder'] = FolderTransformCommand()


def register_command_info(aliases, command_info):
    parsers = [cd_parser, ls_parser, tree_parser, mkdir_parser, rmdir_parser, rndir_parser, mv_parser, ln_parser,
               transform_parser]
    for p in parsers:
        command_info[p.prog] = p.description

    command_info['shortcut'] = 'Manage record shortcuts'


ls_parser = argparse.ArgumentParser(prog='ls', description='List folder contents.')
ls_parser.add_argument('-l', '--list', dest='detail', action='store_true', help='show detailed list')
ls_parser.add_argument('-f', '--folders', dest='folders', action='store_true', help='display folders')
ls_parser.add_argument('-r', '--records', dest='records', action='store_true', help='display records')
ls_parser.add_argument('-s', '--short', dest='short', action='store_true',
                       help='Do not display record details. (Not used)')
ls_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
ls_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
ls_parser.error = raise_parse_exception
ls_parser.exit = suppress_exit


cd_parser = argparse.ArgumentParser(prog='cd', description='Change current folder.')
cd_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or UID')
cd_parser.error = raise_parse_exception
cd_parser.exit = suppress_exit


tree_parser = argparse.ArgumentParser(prog='tree', description='Display the folder structure.')
tree_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
tree_parser.add_argument('-r', '--records', action='store_true', help='show records within each folder')
show_shares_help = 'show share permissions info (shown in parentheses) for each shared folder'
tree_parser.add_argument('-s', '--shares', action='store_true', help=show_shares_help)
perms_key_help = 'hide share permissions key (valid only when used with --shares flag, which shows key by default)'
tree_parser.add_argument('-hk', '--hide-shares-key', action='store_true', help=perms_key_help)
tree_parser.add_argument('-t', '--title', action='store', help='show optional title for folder structure')
tree_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or UID')
tree_parser.error = raise_parse_exception
tree_parser.exit = suppress_exit


rmdir_parser = argparse.ArgumentParser(prog='rmdir', description='Remove a folder and its contents.')
rmdir_parser.add_argument('-f', '--force', dest='force', action='store_true', help='remove folder without prompting')
rmdir_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', help='remove folder without folder info')
rmdir_parser.add_argument('pattern', nargs='*', type=str, action='store', help='folder path or UID')
rmdir_parser.error = raise_parse_exception
rmdir_parser.exit = suppress_exit

rndir_parser = argparse.ArgumentParser(prog='rndir', description='Rename a folder.')
rndir_parser.add_argument('-n', '--name', dest='name', action='store', required=True, help='folder new name')
rndir_parser.add_argument('-q', '--quiet', action='store_true', help='rename folder without folder info')
rndir_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or UID')


mkdir_parser = argparse.ArgumentParser(prog='mkdir', description='Create a folder.')
mkdir_parser.add_argument('-sf', '--shared-folder', dest='shared_folder', action='store_true', help='create shared folder')
mkdir_parser.add_argument('-uf', '--user-folder', dest='user_folder', action='store_true', help='create user folder')
mkdir_parser.add_argument('-a', '--all', dest='grant', action='store_true', help='anyone has all permissions by default')
mkdir_parser.add_argument('-u', '--manage-users', dest='manage_users', action='store_true', help='anyone can manage users by default')
mkdir_parser.add_argument('-r', '--manage-records', dest='manage_records', action='store_true', help='anyone can manage records by default')
mkdir_parser.add_argument('-s', '--can-share', dest='can_share', action='store_true', help='anyone can share records by default')
mkdir_parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true', help='anyone can edit records by default')
mkdir_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path')
mkdir_parser.error = raise_parse_exception
mkdir_parser.exit = suppress_exit


mv_parser = argparse.ArgumentParser(prog='mv', description='Move a record or folder to another folder.')
mv_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
mv_parser.add_argument('-s', '--can-reshare', dest='can_reshare', action='store_true', help='anyone can re-share records')
mv_parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true', help='anyone can edit records')
group = mv_parser.add_mutually_exclusive_group()
group.add_argument('--shared-folder', dest='shared_folder', action='store_true', help='apply search pattern to shared folders')
group.add_argument('--user-folder', dest='user_folder', action='store_true', help='apply search pattern to user folders')
mv_parser.add_argument('src', nargs='?', type=str, action='store',
                       help='source path to folder/record, search pattern or record UID')
mv_parser.add_argument('dst', nargs='?', type=str, action='store', help='destination folder or UID')
mv_parser.error = raise_parse_exception
mv_parser.exit = suppress_exit


ln_parser = argparse.ArgumentParser(prog='ln', description='Create a link between a record and a folder.')
ln_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
ln_parser.add_argument('-s', '--can-reshare', dest='can_reshare', action='store_true', help='anyone can reshare records')
ln_parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true', help='anyone can edit records')
ln_parser.add_argument('src', nargs='?', type=str, action='store',
                       help='source path to folder/record, search pattern or record UID')
ln_parser.add_argument('dst', nargs='?', type=str, action='store', help='destination folder or UID')
ln_parser.error = raise_parse_exception
ln_parser.exit = suppress_exit


shortcut_list_parser = argparse.ArgumentParser(prog='shortcut-list')
shortcut_list_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'],
                                  default='table', help='output format')
shortcut_list_parser.add_argument('--output', dest='output', action='store',
                                  help='output file name. (ignored for table format)')
shortcut_list_parser.add_argument('target', nargs='?', help='Full record or folder path')

shortcut_keep_parser = argparse.ArgumentParser(prog='shortcut-keep')
shortcut_keep_parser.add_argument('target', nargs='?', help='Full record or folder path')
shortcut_keep_parser.add_argument('folder', nargs='?', help='Optional. Folder name or UID. Overwrites current folder.')

transform_desc = 'Transform a folder from a shared folder to a personal folder and vice versa'
transform_parser = argparse.ArgumentParser(prog='transform-folder', description=transform_desc)
transform_parser.add_argument('folder', nargs='+', help='Folder UID or path/name (accepts multiple values)')
children_help = 'Apply transformation to target folder\'s children only (target folder will remain unchanged).'
transform_parser.add_argument('-c', '--children', action='store_true', help=children_help)
dry_run_help = 'Preview the folder transformation without updating'
transform_parser.add_argument('-n', '--dry-run', action='store_true', help=dry_run_help)
transform_parser.add_argument('-f', '--force', action='store_true', help='Skip confirmation prompt and minimize output')
transform_parser.error = raise_parse_exception
transform_parser.exit = suppress_exit


class FolderListCommand(Command, RecordMixin):
    @staticmethod
    def folder_match_strings(folder):   # type: (BaseFolderNode) -> collections.Iterable[str]
        return filter(lambda f: isinstance(f, str) and len(f) > 0, [folder.name, folder.uid])

    @staticmethod
    def record_match_strings(record):     # type: (Record) -> collections.Iterable[str]
        return filter(lambda f: isinstance(f, str) and len(f) > 0, [record.title, record.record_uid, record.login, record.login_url, record.notes])

    @staticmethod
    def chunk_list(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def get_parser(self):
        return ls_parser

    def execute(self, params, **kwargs):
        show_folders = kwargs['folders'] if 'folders' in kwargs else None
        show_records = kwargs['records'] if 'records' in kwargs else None
        show_detail = kwargs['detail'] if 'detail' in kwargs else False
        if not show_folders and not show_records:
            show_folders = True
            show_records = True

        folder = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder
        pattern = kwargs['pattern'] if 'pattern' in kwargs else None
        if pattern:
            rs = try_resolve_path(params, kwargs['pattern'])
            if rs is not None:
                folder, pattern = rs

        regex = None
        if pattern:
            regex = re.compile(fnmatch.translate(pattern), re.IGNORECASE).match

        folders = []    # type: List[BaseFolderNode]
        records = []    # type: List[vault.KeeperRecord]

        if show_folders:
            for uid in folder.subfolders:
                f = params.folder_cache[uid]
                if any(filter(lambda x: regex(x) is not None, FolderListCommand.folder_match_strings(f))) if regex is not None else True:
                    folders.append(f)

        if show_records and params.record_cache:
            folder_uid = folder.uid or ''
            if folder_uid in params.subfolder_record_cache:
                for uid in params.subfolder_record_cache[folder_uid]:
                    if uid not in params.record_cache:
                        continue
                    rec = params.record_cache[uid]
                    rv = rec.get('version', 0)
                    if rv in (0, 4, 5):
                        continue    # skip fileRef and application records - they use file-report command

                    r = vault.KeeperRecord.load(params, rec)
                    if not r:
                        continue

                    if regex and not regex(r.title):
                        continue
                    records.append(r)

        if len(folders) == 0 and len(records) == 0:
            if pattern:
                raise CommandError('ls', '{0}: No such folder or record'.format(pattern))
        else:
            if show_detail:
                if len(folders) > 0:
                    display.formatted_folders(folders)
                if len(records) > 0:
                    table = []
                    headers = ['Record UID', 'Type', 'Title', 'Description']
                    for record in records:
                        row = [record.record_uid, record.record_type, record.title, vault_extensions.get_record_description(record)]
                        table.append(row)
                    table.sort(key=lambda x: (x[2] or '').lower())
                    dump_report_data(table, headers, row_number=True)
            else:
                names = []
                for f in folders:
                    name = f.name or f.uid
                    if len(name) > 40:
                        name = name[:25] + '...' + name[-12:]
                    names.append(name + '/')
                names.sort()

                rnames = []
                for r in records:
                    name = r.title or r.record_uid
                    if len(name) > 40:
                        name = name[:25] + '...' + name[-12:]
                    rnames.append(name)
                rnames.sort()

                names.extend(rnames)

                width, _ = shutil.get_terminal_size(fallback=(1, 1))
                max_name = functools.reduce(lambda val, elem: len(elem) if len(elem) > val else val, names, 0)
                cols = width // max_name
                if cols == 0:
                    cols = 1

                if cols > 2:
                    if ((max_name * cols) + (cols - 1) * 2) > width:
                        cols = cols - 1

                tbl = FolderListCommand.chunk_list([x.ljust(max_name) if cols > 1 else x for x in names], cols)

                rows = ['  '.join(x) for x in tbl]
                print('\n'.join(rows))


class FolderCdCommand(Command):
    def get_parser(self):
        return cd_parser

    def execute(self, params, **kwargs):
        folder_name = kwargs['folder'] if 'folder' in kwargs else ''
        if folder_name:
            if folder_name in params.folder_cache:
                params.current_folder = folder_name
            else:
                rs = try_resolve_path(params, folder_name)
                if rs is not None:
                    folder, pattern = rs
                    if len(pattern) == 0:
                        params.current_folder = folder.uid
                    else:
                        raise CommandError('cd', 'Folder {0} not found'.format(folder_name))


class FolderTreeCommand(Command):
    def get_parser(self):
        return tree_parser

    def execute(self, params, **kwargs):
        folder_name = kwargs['folder'] if 'folder' in kwargs else None
        verbose = kwargs.get('verbose', False)
        records = kwargs.get('records')
        shares = kwargs.get('shares')
        hide_key = kwargs.get('hide_shares_key', not shares)
        title = kwargs.get('title')
        if folder_name in params.folder_cache:
            folder = params.folder_cache.get(folder_name)
            display.formatted_tree(params, folder, verbose=verbose, show_records=records, shares=shares,
                                   hide_shares_key=hide_key, title=title)
        else:
            rs = try_resolve_path(params, folder_name)
            if rs is not None:
                folder, pattern = rs
                if len(pattern) == 0:
                    display.formatted_tree(params, folder, verbose=verbose, show_records=records, shares=shares,
                                           hide_shares_key=hide_key, title=title)
                else:
                    raise CommandError('tree', f'Folder {folder_name} not found')


class FolderRenameCommand(Command):
    def get_parser(self):
        return rndir_parser

    def execute(self, params, **kwargs):
        new_name = kwargs.get('name')
        if not new_name:
            raise CommandError('rendir', 'New folder name parameter is required.')

        folder_name = kwargs.get('folder')
        if not folder_name:
            raise CommandError('rendir', 'Enter the path or UID of existing folder.')

        folder_uid = None
        if folder_name in params.folder_cache:
            folder_uid = folder_name
        else:
            rs = try_resolve_path(params, folder_name)
            if rs is not None:
                folder, pattern = rs
                if len(pattern) == 0:
                    folder_uid = folder.uid
                else:
                    raise CommandError('rendir', f'Folder {folder_name} not found')

        sub_folder = params.subfolder_cache[folder_uid]    # type: Dict
        rq = {
            'command': 'folder_update',
            'folder_uid': folder_uid,
            'folder_type': sub_folder['type'],
        }

        if sub_folder['type'] == 'user_folder':
            encryption_key = sub_folder['folder_key_unencrypted']
            encrypted_data = sub_folder.get('data')
        elif sub_folder['type'] == 'shared_folder':
            if folder_uid not in params.shared_folder_cache:
                raise CommandError('rendir', f'Shared Folder UID \"{folder_uid}\" not found.')
            rq['shared_folder_uid'] = folder_uid
            shared_folder = params.shared_folder_cache[folder_uid]
            encryption_key = shared_folder['shared_folder_key_unencrypted']
            encrypted_data = shared_folder.get('data')
            rq['name'] = utils.base64_url_encode(crypto.encrypt_aes_v1(new_name.encode('utf-8'), encryption_key))
        elif sub_folder['type'] == 'shared_folder_folder':
            rq['shared_folder_uid'] = sub_folder['shared_folder_uid']
            encryption_key = sub_folder['folder_key_unencrypted']
            encrypted_data = sub_folder.get('data')
        else:
            return

        if encrypted_data:
            try:
                decrypted_data = crypto.decrypt_aes_v1(utils.base64_url_decode(encrypted_data), encryption_key)
                data = json.loads(decrypted_data.decode())
            except:
                data = {}
        else:
            data = {}

        data['name'] = new_name
        rq['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), encryption_key))

        api.communicate(params, rq)
        params.sync_data = True
        folder = params.folder_cache[folder_uid]
        if not kwargs.get('quiet'):
            logging.info('Folder \"%s\" has been renamed to \"%s\"', folder.name, new_name)


class FolderMakeCommand(Command):
    def get_parser(self):
        return mkdir_parser

    def execute(self, params, **kwargs):
        base_folder = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder

        name = kwargs['folder'] if 'folder' in kwargs else None
        if name:
            rs = try_resolve_path(params, name)
            if rs is not None:
                base_folder, name = rs
                if len(name) == 0:
                    logging.warning('mkdir: Folder "%s" already exists', kwargs['folder'])
                    return

        shared_folder = kwargs['shared_folder'] if 'shared_folder' in kwargs else None
        user_folder = kwargs['user_folder'] if 'user_folder' in kwargs else None

        request = {"command": "folder_add"}
        if shared_folder:
            if base_folder.type in {BaseFolderNode.RootFolderType, BaseFolderNode.UserFolderType}:
                request['folder_type'] = 'shared_folder'
                grant = kwargs['grant'] if 'grant' in kwargs else None
                for flag in ['manage_users', 'manage_records', 'can_share', 'can_edit']:
                    if grant or (flag in kwargs and kwargs[flag]):
                        request[flag] = True
            else:
                raise CommandError('mkdir', 'Shared folders cannot be nested')

        elif user_folder:
            if base_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                request['folder_type'] = 'shared_folder_folder'
            else:
                request['folder_type'] = 'user_folder'

        if request.get('folder_type') is None:
            if base_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                request['folder_type'] = 'shared_folder_folder'

        if request.get('folder_type') is None:
            inp = user_choice('Do you want to create a shared folder?', 'yn', default='n')
            if inp.lower() == 'y':
                request['folder_type'] = 'shared_folder'
                pq = 'Default user permissions: (A)ll | Manage (U)sers / (R)ecords; Can (E)dit / (S)hare records?'
                inp = user_choice(pq, 'aures', multi_choice=True)
                request['manage_users'] = False
                request['manage_records'] = False
                request['can_edit'] = False
                request['can_share'] = False
                if len(inp) > 0:
                    s1 = set([x.lower() for x in inp])
                    if 'a' in s1:
                        request['manage_users'] = True
                        request['manage_records'] = True
                        request['can_edit'] = True
                        request['can_share'] = True
                    else:
                        if 'u' in s1:
                            request['manage_users'] = True
                        if 'r' in s1:
                            request['manage_records'] = True
                        if 'e' in s1:
                            request['can_edit'] = True
                        if 's' in s1:
                            request['can_share'] = True
            else:
                request['folder_type'] = 'user_folder'

        folder_uid = api.generate_record_uid()
        request['folder_uid'] = folder_uid

        folder_key = os.urandom(32)
        encryption_key = params.data_key
        if request['folder_type'] == 'shared_folder_folder':
            sf_uid = base_folder.shared_folder_uid if base_folder.type == BaseFolderNode.SharedFolderFolderType else base_folder.uid
            sf = params.shared_folder_cache[sf_uid]
            encryption_key = sf['shared_folder_key_unencrypted']
            request['shared_folder_uid'] = sf_uid

        request['key'] = api.encrypt_aes(folder_key, encryption_key)
        if base_folder.type not in {BaseFolderNode.RootFolderType, BaseFolderNode.SharedFolderType}:
            request['parent_uid'] = base_folder.uid

        name = name or ''
        while len(name.strip()) == 0:
            name = input("... Folder Name: ")

        name = name.strip()

        is_slash = False
        for x in range(0, len(name)-2):
            if name[x] == '/':
                is_slash = not is_slash
            else:
                if is_slash:
                    raise CommandError('mkdir', 'Character "/" is reserved. Use "//" inside folder name')

        name = name.replace('//', '/')

        if request['folder_type'] == 'shared_folder':
            request['name'] = api.encrypt_aes(name.encode('utf-8'), folder_key)

        data = {'name': name}
        request['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)

        api.communicate(params, request)
        params.sync_data = True
        params.environment_variables[LAST_FOLDER_UID] = folder_uid
        if request['folder_type'] == 'shared_folder':
            params.environment_variables[LAST_SHARED_FOLDER_UID] = folder_uid


def get_folder_path(params, uid):
    path = ''
    folder = params.folder_cache.get(uid)
    while folder:
        path = f'{folder.name}/{path}'
        folder = params.folder_cache.get(folder.parent_uid)
    return path


def get_shared_subfolder_delete_rq(params, user_folder, user_folder_ids):
    """Recursively searches a user folder for shared folders to delete"""
    delete_rq_added = False
    user_folder_ids.add(user_folder.uid)
    for uid in user_folder.subfolders:
        subfolder = params.folder_cache[uid]
        if uid not in user_folder_ids:
            delete_rq_added = get_shared_subfolder_delete_rq(params, subfolder, user_folder_ids)
    return delete_rq_added


class FolderRemoveCommand(Command):
    def get_parser(self):
        return rmdir_parser

    def execute(self, params, **kwargs):
        folder = params.folder_cache.get(params.current_folder, params.root_folder)
        folders = []
        pattern_list = kwargs.get('pattern', [])
        for pattern in pattern_list:
            rs = try_resolve_path(params, pattern)
            if rs is None:
                regex_pattern = pattern
            else:
                folder, regex_pattern = rs
                if regex_pattern == '':
                    folders.append(folder)
                    continue

            regex = re.compile(fnmatch.translate(regex_pattern)).match
            subfolders = []
            for uid in folder.subfolders:
                f = params.folder_cache[uid]
                if any(filter(lambda x: regex(x) is not None, FolderListCommand.folder_match_strings(f))):
                    subfolders.append(f)
            if len(subfolders) == 0:
                logging.warning(f'Folder "{pattern}" was not found.')
            else:
                folders.extend(subfolders)

        if len(folders) == 0:
            raise CommandError('rmdir', 'Enter name of an existing folder.')

        force = kwargs['force'] if 'force' in kwargs else None
        quiet = kwargs['quiet'] if 'quiet' in kwargs else None
        user_folder_objects = OrderedDict()
        search_user_folder_ids = set()
        shared_subfolder_delete_rq_added = False
        for folder in folders:
            if folder.uid not in user_folder_objects:
                shared_subfolder_delete_rq_added = get_shared_subfolder_delete_rq(
                    params, folder, search_user_folder_ids
                )
                del_obj = {
                    'delete_resolution': 'unlink',
                    'object_uid': folder.uid,
                    'object_type': folder.type
                }
                parent = params.folder_cache.get(folder.parent_uid)
                if parent is None:
                    del_obj['from_type'] = 'user_folder'
                else:
                    del_obj['from_uid'] = parent.uid
                    del_obj['from_type'] = parent.type
                    if parent.type == BaseFolderNode.SharedFolderType:
                        del_obj['from_type'] = 'shared_folder_folder'

                user_folder_objects[folder.uid] = del_obj

        user_folder_count = len(user_folder_objects)
        np = 'n'
        if user_folder_count > 0:
            if shared_subfolder_delete_rq_added and np.lower() == 'n':
                print(f'Cannot remove {user_folder_count} user folder(s) without the removal of shared subfolders.')
            else:
                if not quiet or not force:
                    user_folder_names = [get_folder_path(params, uid) for uid in user_folder_objects]
                    print(f'\nThe following user folder(s) will be removed:\n{", ".join(user_folder_names)}')
                rq = {
                    'command': 'pre_delete',
                    'objects': list(user_folder_objects.values())
                }
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    pdr = rs['pre_delete_response']

                    if not force or not quiet:
                        summary = pdr['would_delete']['deletion_summary']
                        for x in summary:
                            print(x)

                    prompt_msg = 'Do you want to proceed with the user folder deletion?'
                    np = 'y' if force else user_choice(f'\n{prompt_msg}', 'yn', default='n')
                    if np.lower() == 'y':
                        rq = {
                            'command': 'delete',
                            'pre_delete_token': pdr['pre_delete_token']
                        }
                        api.communicate(params, rq)
                        params.sync_data = True


class FolderMoveCommand(Command):
    @staticmethod
    def get_transition_key(record, encryption_key):
        # transition key is the key of the object being moved
        # encrypted with the shared folder key if going to a shared folder,
        # or encrypted with the user's data key
        if record.get('version', -1) >= 3:
            tkey = crypto.encrypt_aes_v2(record['record_key_unencrypted'], encryption_key)
        else:
            tkey = crypto.encrypt_aes_v1(record['record_key_unencrypted'], encryption_key)
        return utils.base64_url_encode(tkey)

    @staticmethod
    def prepare_transition_keys(params, folder, keys, encryption_key):
        for f_uid in folder.subfolders:
            f = params.folder_cache[f_uid]
            FolderMoveCommand.prepare_transition_keys(params, f, keys, encryption_key)

        sf = params.subfolder_cache[folder.uid]
        transition_key = api.encrypt_aes(sf['folder_key_unencrypted'], encryption_key)
        keys.append({
            'uid': folder.uid,
            'key': transition_key
        })
        if folder.uid in params.subfolder_record_cache:
            for r_uid in params.subfolder_record_cache[folder.uid]:
                rec = params.record_cache[r_uid]
                transition_key = FolderMoveCommand.get_transition_key(rec, encryption_key)
                keys.append({
                    'uid': r_uid,
                    'key': transition_key
                })

    def get_parser(self):
        return mv_parser

    def is_move(self):
        return True

    def execute(self, params, **kwargs):
        src_path = kwargs['src'] if 'src' in kwargs else None
        dst_path = kwargs['dst'] if 'dst' in kwargs else None

        if not src_path or not dst_path:
            parser = self.get_parser()
            parser.print_help()
            return

        if dst_path in params.folder_cache:
            dst_folder = params.folder_cache[dst_path]
        else:
            dst = try_resolve_path(params, dst_path)
            if dst is None:
                raise CommandError('mv', 'Destination path should be existing folder')
            dst_folder, name = dst
            if len(name) > 0:
                raise CommandError('mv', 'Destination path should be existing folder')

        source = []    # type: List[Tuple[BaseFolderNode, Optional[str]]]   # (folder, record_uid)
        if src_path in params.record_cache:    # record UID
            record_uid = src_path
            src_folder = None
            folder_uids = list(find_folders(params, record_uid))
            if folder_uids:
                if params.current_folder:
                    if params.current_folder in folder_uids:
                        src_folder = params.folder_cache[params.current_folder]
                else:
                    if '' in params.subfolder_record_cache:
                        if record_uid in params.subfolder_record_cache['']:
                            src_folder = params.root_folder
                if not src_folder:
                    src_folder = params.folder_cache[folder_uids[0]]
            else:
                src_folder = params.root_folder

            if src_folder is dst_folder:
                raise CommandError('mv', 'Source and Destination folders are the same')
            source.append((src_folder, record_uid))
        elif src_path in params.folder_cache:   # folder UID
            src_folder = params.folder_cache[src_path]
            if src_folder is dst_folder:
                raise CommandError('mv', 'Source and Destination folders are the same')
            source.append((src_folder, None))
        else:
            src = try_resolve_path(params, src_path)
            if src is None:
                raise CommandError('mv', 'Source path should be existing record or folder')

            src_folder, name = src
            if src_folder is dst_folder:
                raise CommandError('mv', 'Source and Destination folders are the same')

            if len(name) > 0:
                regex = re.compile(fnmatch.translate(name), re.IGNORECASE).match
                src_folder_uid = src_folder.uid or ''
                if kwargs.get('shared_folder') or kwargs.get('user_folder'):
                    for subfolder_uid in src_folder.subfolders or []:
                        if subfolder_uid in params.folder_cache:
                            is_shared = subfolder_uid in params.shared_folder_cache
                            if (is_shared and kwargs.get('shared_folder')) or (not is_shared and kwargs.get('user_folder')):
                                folder = params.folder_cache[subfolder_uid]
                                if regex(folder.name):
                                    source.append((folder, None))
                else:
                    if src_folder_uid in params.subfolder_record_cache:
                        for record_uid in params.subfolder_record_cache[src_folder_uid]:
                            if record_uid == name:
                                source.append((src_folder, record_uid))
                            else:
                                record = vault.KeeperRecord.load(params, record_uid)
                                if isinstance(record, vault.PasswordRecord) or isinstance(record, vault.TypedRecord):
                                    if regex(record.title):
                                        source.append((src_folder, record_uid))
            else:
                source.append((src_folder, None))

            if len(source) == 0:
                raise CommandError('mv', f'Record "{name}" not found')

        rq = {
            'command': 'move',
            'link': not self.is_move(),
            'move': []
        }
        if dst_folder.type == BaseFolderNode.RootFolderType:
            rq['to_type'] = BaseFolderNode.UserFolderType
        else:
            rq['to_type'] = dst_folder.type
            rq['to_uid'] = dst_folder.uid

        transition_keys = []
        for src_folder, record_uid in source:
            if len(rq['move']) > 990:
                logging.info('The command limit has been reached. Please repeat this command to resume operation.')
                break

            if not record_uid:   # move folder
                if src_folder.type == BaseFolderNode.RootFolderType:
                    raise CommandError('mv', 'Root folder cannot be a source folder')

                dp = set()
                f = dst_folder
                while f is not None and f.uid is not None:
                    if len(f.uid) > 0:
                        dp.add(f.uid)
                    f = params.folder_cache.get(f.parent_uid) if f.parent_uid is not None else None
                if src_folder.uid in dp:
                    raise CommandError('mv', 'Cannot move/link folder to self or a child')

                parent_folder = params.folder_cache[src_folder.parent_uid] if src_folder.parent_uid is not None else None
                move = {
                    'uid': src_folder.uid,
                    'type': src_folder.type,
                    'cascade': True
                }
                if parent_folder is None:
                    move['from_type'] = BaseFolderNode.UserFolderType
                else:
                    move['from_type'] = parent_folder.type
                    move['from_uid'] = parent_folder.uid

                rq['move'].append(move)
                if src_folder.type == BaseFolderNode.UserFolderType:
                    if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        shf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else dst_folder.shared_folder_uid
                        shf = params.shared_folder_cache[shf_uid]
                        FolderMoveCommand.prepare_transition_keys(params, src_folder, transition_keys, shf['shared_folder_key_unencrypted'])

                elif src_folder.type == BaseFolderNode.SharedFolderFolderType:
                    if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else dst_folder.shared_folder_uid

                        if hasattr(src_folder, 'shared_folder_uid'):
                            ssf_uid = src_folder.shared_folder_uid
                            if ssf_uid != dsf_uid:
                                dsf = params.shared_folder_cache[dsf_uid]
                                FolderMoveCommand.prepare_transition_keys(params, src_folder, transition_keys, dsf['shared_folder_key_unencrypted'])
                    else:
                        FolderMoveCommand.prepare_transition_keys(params, src_folder, transition_keys, params.data_key)

            else:
                move = {
                    'uid': record_uid,
                    'type': 'record',
                    'cascade': False
                }
                if src_folder.type == BaseFolderNode.RootFolderType:
                    move['from_type'] = BaseFolderNode.UserFolderType
                else:
                    move['from_type'] = src_folder.type
                    move['from_uid'] = src_folder.uid
                if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    for flag in ['can_reshare', 'can_edit']:
                        if flag in kwargs and kwargs[flag]:
                            move[flag] = True
                rq['move'].append(move)

                transition_key = None
                rec = params.record_cache[record_uid]
                if src_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        ssf_uid = src_folder.uid \
                            if src_folder.type == BaseFolderNode.SharedFolderType else src_folder.shared_folder_uid
                        dsf_uid = dst_folder.uid \
                            if dst_folder.type == BaseFolderNode.SharedFolderType else dst_folder.shared_folder_uid
                        if ssf_uid != dsf_uid:
                            shf = params.shared_folder_cache[dsf_uid]
                            transition_key = FolderMoveCommand.get_transition_key(rec, shf['shared_folder_key_unencrypted'])
                    else:
                        transition_key = FolderMoveCommand.get_transition_key(rec, params.data_key)
                else:
                    if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                            dst_folder.shared_folder_uid
                        shf = params.shared_folder_cache[dsf_uid]
                        transition_key = FolderMoveCommand.get_transition_key(rec, shf['shared_folder_key_unencrypted'])

                if transition_key is not None:
                    transition_keys.append({
                        'uid': record_uid,
                        'key': transition_key
                    })
        if transition_keys:
            rq['transition_keys'] = transition_keys

        api.communicate(params, rq)
        params.sync_data = True


class FolderLinkCommand(FolderMoveCommand):
    def is_move(self):
        return False

    def get_parser(self):
        return ln_parser


class ShortcutCommand(GroupCommand):
    def __init__(self):
        super(ShortcutCommand, self).__init__()
        self.register_command('list', ShortcutListCommand(), 'Displays shortcuts')
        self.register_command('keep', ShortcutKeepCommand(), 'Removes shortcuts except one')
        self.default_verb = 'list'

    @staticmethod
    def get_record_shortcuts(params):    # type: (KeeperParams) -> Dict[str, Set[str]]
        records = {}
        for folder_uid in params.subfolder_record_cache:
            for record_uid in params.subfolder_record_cache[folder_uid]:
                if record_uid in params.record_cache:
                    if params.record_cache[record_uid].get('version') in {2, 3}:
                        if record_uid not in records:
                            records[record_uid] = set()
                        records[record_uid].add(folder_uid)

        shortcuts = [k for k, v in records.items() if len(v) <= 1]
        for record_uid in shortcuts:
            del records[record_uid]

        return records


class ShortcutListCommand(Command):
    def get_parser(self):
        return shortcut_list_parser

    def execute(self, params, **kwargs):
        records = ShortcutCommand.get_record_shortcuts(params)
        target = kwargs.get('target')
        to_show = set()
        if target:
            if target in params.record_cache:    # record UID
                if target not in records:
                    raise CommandError('shortcut-get', f'Record UID {target} does not have shortcuts')
                to_show.add(target)

            elif target in params.folder_cache:    # folder UID
                for record_uid in records:
                    if target in records[record_uid]:
                        to_show.add(record_uid)

            else:
                path = try_resolve_path(params, target)
                if path is None:
                    raise CommandError('shortcut-keep', 'Target path should be existing record or folder')
                folder, name = path
                if name:
                    regex = re.compile(fnmatch.translate(name)).match
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for record_uid in params.subfolder_record_cache[folder_uid]:
                            if record_uid == name:
                                if record_uid in records:
                                    if folder_uid in records[record_uid]:
                                        to_show.add(record_uid)
                            else:
                                record = vault.KeeperRecord.load(params, record_uid)
                                if isinstance(record, vault.PasswordRecord) or isinstance(record, vault.TypedRecord):
                                    if regex(record.title):
                                        if record_uid in records:
                                            if folder_uid in records[record_uid]:
                                                to_show.add(record_uid)
                else:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for record_uid in params.subfolder_record_cache[folder_uid]:
                            if record_uid in records:
                                if folder_uid in records[record_uid]:
                                    to_show.add(record_uid)
        else:
            logging.info('Displaying all shortcuts')
            to_show.update(records.keys())

        table = []
        json_headers = ['record_uid', 'record_title', 'folder']
        headers = ['Record UID', 'Record Title', 'Folder']
        fmt = kwargs.get('format')
        for record_uid in to_show:
            record = vault.KeeperRecord.load(params, record_uid)
            if record:
                folders = [params.folder_cache.get(x, params.root_folder) for x in records[record_uid]]
                folders.sort(key=lambda x: x.name)
                f = []
                for x in folders:
                    is_shared = True if x.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType} else False
                    folder_path = get_folder_path(params, x.uid)
                    if fmt == 'json':
                        f.append({
                            'folder_uid': x.uid,
                            'path': f'/{folder_path}',
                            'shared': is_shared
                        })
                    else:
                        f.append(f'{("[Shared]" if is_shared else "[ User ]")} /{folder_path}')
                table.append([record.record_uid, record.title, f])

        return dump_report_data(table, json_headers if fmt == 'json' else headers,
                                fmt=fmt, filename=kwargs.get('output'))


class ShortcutKeepCommand(Command):
    def get_parser(self):
        return shortcut_keep_parser

    def execute(self, params, **kwargs):
        target = kwargs.get('target')
        if not target:
            parser = self.get_parser()
            parser.print_help()
            return

        folder_override = kwargs.get('folder')
        folder_override_uid = None
        if folder_override:
            if folder_override in params.folder_cache:
                folder_override_uid = folder_override
            else:
                path = try_resolve_path(params, folder_override)
                if path is None:
                    raise CommandError('shortcut-keep', 'Folder parameter should be folder name or UID')
                folder, name = path
                if name:
                    raise CommandError('shortcut-keep', 'Folder parameter should be folder name or UID')
                folder_override_uid = folder.uid

        records = ShortcutCommand.get_record_shortcuts(params)
        to_keep = {}    # type: Dict[str, str]   # (record_uid, folder_uid)

        if target in params.record_cache:    # record UID
            record_uid = target
            if record_uid not in records:
                raise CommandError('shortcut-keep', f'Record UID {record_uid} does not have shortcuts')
            record_folder = folder_override_uid or params.current_folder or ''
            if record_folder:
                if record_folder in records[record_uid]:
                    to_keep[record_uid] = record_folder
        elif target in params.folder_cache:    # folder UID
            folder_uid = target
            for record_uid in records:
                if folder_uid in records[record_uid]:
                    to_keep[record_uid] = folder_uid
        else:
            saved_wd = params.current_folder
            try:
                if folder_override_uid:
                    params.current_folder = folder_override_uid
                path = try_resolve_path(params, target)
            finally:
                params.current_folder = saved_wd
            if path is None:
                raise CommandError('shortcut-keep', 'Target path should be existing record or folder')
            folder, name = path
            if name:
                regex = re.compile(fnmatch.translate(name)).match
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for record_uid in params.subfolder_record_cache[folder_uid]:
                        if record_uid == name:
                            if record_uid in records:
                                if folder_uid in records[record_uid]:
                                    to_keep[record_uid] = folder_uid
                        else:
                            record = vault.KeeperRecord.load(params, record_uid)
                            if isinstance(record, vault.PasswordRecord) or isinstance(record, vault.TypedRecord):
                                if regex(record.title):
                                    if record_uid in records:
                                        if folder_uid in records[record_uid]:
                                            to_keep[record_uid] = folder_uid
            else:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for record_uid in params.subfolder_record_cache[folder_uid]:
                        if record_uid in records:
                            if folder_uid in records[record_uid]:
                                to_keep[record_uid] = folder_uid

        if len(to_keep) == 0:
            if folder_override:
                raise CommandError('shortcut-keep', f'There are no shortcut for record "{target}" in folder {folder_override} found')
            else:
                raise CommandError('shortcut-keep', f'There are no shortcut for path "{target}" found')

        unlink_records = []
        for record_uid, keep_folder_uid in to_keep.items():
            if record_uid not in records:
                continue
            if keep_folder_uid not in records[record_uid]:
                continue

            for folder_uid in records[record_uid]:
                if folder_uid == keep_folder_uid:
                    continue
                folder = params.folder_cache.get(folder_uid) if folder_uid else params.root_folder

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

                unlink_records.append(del_obj)

        if not unlink_records:
            return

        while unlink_records:
            rq = {
                'command': 'pre_delete',
                'objects': unlink_records[:999]
            }
            unlink_records = unlink_records[999:]

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


arrange_folders_parser = argparse.ArgumentParser(
    prog='arrange-folders',  description='Moves shared folders from the root folder to sub-folders.')
arrange_folders_parser.add_argument(
    '--pattern', dest='pattern', action='store', help='Action to perform on the licenses', default=r'^([^-]*)-.+$')
arrange_folders_parser.add_argument('--folder', dest='folder', action='store', help='Sub folder name or UID', default='Customers')
arrange_folders_parser.add_argument('-f', '--force', dest='force', action='store_true', help='rearrange folder without prompting')


class ArrangeFolderCommand(Command):
    def get_parser(self):
        return arrange_folders_parser

    def execute(self, params, **kwargs):
        pattern = kwargs.get('pattern')
        regex = re.compile(pattern, re.IGNORECASE).match

        group_folders = {}
        for f_uid in params.root_folder.subfolders:
            if f_uid in params.shared_folder_cache:
                shared_folder = api.get_shared_folder(params, f_uid)
                m = regex(shared_folder.name)
                if m:
                    sub_folder = m[1]
                    logging.info('Shared folder \"%s\" will be moved to \"%s\"', shared_folder.name, sub_folder)
                    if sub_folder.lower() not in group_folders:
                        group_folders[sub_folder.lower()] = sub_folder
                else:
                    logging.info('Shared folder \"%s\" does not match pattern. Skipping', shared_folder.name)
        if not group_folders:
            logging.info('There are no shared folders found for pattern \"%s\"', pattern)
            return

        folder = kwargs.get('folder')
        if not folder:
            raise CommandError(self.get_parser().prog, 'Target path should be existing record or folder')

        if not kwargs.get('force'):
            answer = user_choice('Do you want to proceed?', 'yn', default='n')
            if answer.lower() == 'y':
                answer = 'yes'
            if answer.lower() != 'yes':
                return

        folder_uid = None
        for f_uid in params.root_folder.subfolders:
            if folder_uid:
                f = params.folder_cache[folder_uid]
                if f.type != 'user_folder':
                    raise CommandError(self.get_parser().prog, f'\"{f.name}\" cannot be shared folder')
                break
            if f_uid == folder:
                folder_uid = f_uid
            elif f_uid in params.folder_cache:
                f = params.folder_cache[f_uid]
                if f.name.lower() == folder.lower():
                    folder_uid = f.uid

        cd_command = FolderCdCommand()
        cd_command.execute(params, folder='/')

        mkdir_command = FolderMakeCommand()
        if not folder_uid:
            mkdir_command.execute(params, folder=folder, user_folder=True)
            folder_uid = params.environment_variables[LAST_FOLDER_UID]
            api.sync_down(params)

        cd_command.execute(params, folder=folder_uid)
        subfolders = {x for x in params.folder_cache[folder_uid].subfolders if x in params.folder_cache}
        for key in list(group_folders.keys()):
            for f_uid in subfolders:
                f = params.folder_cache[f_uid]
                if f.name.lower() == key:
                    group_folders[key] = f.uid
                    break
            if group_folders[key] not in params.folder_cache:
                mkdir_command.execute(params, folder=group_folders[key], user_folder=True)
                group_folders[key] = params.environment_variables[LAST_FOLDER_UID]
            else:
                subfolders.remove(group_folders[key])
        if params.sync_data:
            api.sync_down(params)

        mv_command = FolderMoveCommand()
        for key in group_folders:
            mv_command.execute(params, shared_folder=True, src=f'/{key}*', dst=group_folders[key])


class FolderTransformCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return transform_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, Any) -> Any
        def get_folder_uid(path):
            rs = try_resolve_path(params, path)
            if rs is not None:
                folder, pattern = rs
                if len(pattern) == 0:
                    return folder.uid
                else:
                    raise CommandError('transform-folder', f'Folder {path} not found')

        def validate(root_folders):   # type: (List[BaseFolderNode]) -> None
            if any([folder for folder in root_folders if folder.type == BaseFolderNode.SharedFolderFolderType]):
                raise CommandError('transform-folder', 'You cannot transform a folder within a shared-folder')

            SF_UID_KEY = 'shared_folder_uid'
            shared_folders = []
            contained_recs = []
            for folder in root_folders:
                shared_folders.extend(get_shared_folders(folder).values())
                contained_recs.extend(get_contained_records(folder))

            # Check contained shared folders (including root)
            def has_full_sf_privs(sf):   # type: (Dict[str, Any]) -> bool
                return sf.get('manage_records') and sf.get('manage_users')

            f_path_fn = lambda f_uid: get_folder_path(params, f_uid)
            blockers = []
            rq = record_pb2.AmIShareAdmin()
            for sf in shared_folders:
                if not has_full_sf_privs(sf):
                    blockers.append(sf)
                    uid = utils.base64_url_decode(sf.get('shared_folder_uid'))
                    if isinstance(uid, bytes) and len(uid) == 16:
                        osa = record_pb2.IsObjectShareAdmin()
                        osa.uid = uid
                        osa.objectType = record_pb2.CHECK_SA_ON_SF
                        rq.isObjectShareAdmin.append(osa)
            rs = api.communicate_rest(params, rq, 'vault/am_i_share_admin', rs_type=record_pb2.AmIShareAdmin)
            non_admin_objs = [rs_osa for rs_osa in rs.isObjectShareAdmin if not rs_osa.isAdmin]
            if any(non_admin_objs):
                nao_uids = [utils.base64_url_encode(nao.uid) for nao in non_admin_objs]
                blockers = [sf for sf in blockers if sf.get('shared_folder_uid') in nao_uids]
                sfs = [f'Folder Path: {f_path_fn(sf.get(SF_UID_KEY))}\tUID: {sf.get(SF_UID_KEY)}' for sf in blockers]
                sfs = [f'{idx + 1}) ' + sf_info for idx, sf_info in enumerate(sfs)]
                msg = 'Transform prohibited - You need either 1) share-admin rights or 2) full share privileges ' \
                      '("Can Manage Users", "Can Manage Records") for all shared-folders ' \
                      'contained within the specified folder-tree(s)\n'
                msg += 'Shared Folders With Inadequate Share Privileges or Share-Admin Rights:\n'
                msg += '======================================================================\n'
                msg += '\n'.join(sfs)
                raise CommandError('transform-folder', msg)

            # Check contained records
            can_reshare_fn = lambda rec_md: rec_md is None or rec_md.get('owner') or rec_md.get('can_share')
            rec_path_fn = lambda folder_path, record: folder_path + RecordV3.get_title(record)

            blockers = []
            rq = record_pb2.AmIShareAdmin()
            for folder, record_uids in contained_recs:
                for r in record_uids:
                    rec = params.record_cache.get(r)
                    rec_share = params.meta_data_cache.get(r)
                    if not can_reshare_fn(rec_share):
                        folder_path = f_path_fn(folder.uid)
                        blockers.append((folder_path, rec))
                        uid = utils.base64_url_decode(r)
                        if isinstance(uid, bytes) and len(uid) == 16:
                            osa = record_pb2.IsObjectShareAdmin()
                            osa.uid = uid
                            osa.objectType = record_pb2.CHECK_SA_ON_RECORD
                            rq.isObjectShareAdmin.append(osa)
            rs = api.communicate_rest(params, rq, 'vault/am_i_share_admin', rs_type=record_pb2.AmIShareAdmin)
            non_admin_objs = [rs_osa for rs_osa in rs.isObjectShareAdmin if not rs_osa.isAdmin]
            if any(non_admin_objs):
                nao_uids = [utils.base64_url_encode(nao.uid) for nao in non_admin_objs]
                blockers = [(path, rec) for path, rec in blockers if rec.get('record_uid') in nao_uids]
                recs = [f'Record Path: {rec_path_fn(fp, rec)}\tUID: {rec.get("record_uid")}' for fp, rec in blockers]
                recs = [f'{idx + 1}) ' + rec_info for idx, rec_info in enumerate(recs)]
                msg = 'Transform prohibited - You need either 1) share-admin rights or 2) "Can Share" privilege for ' \
                      'all non-owned records contained within the specified folder-tree(s)\n'
                msg += 'Non-shareable Records:\n'
                msg += '======================\n'
                msg += '\n'.join(recs)
                raise CommandError('transform-folder', msg)

        def get_shared_folders(folder):     # type: (BaseFolderNode) -> Dict[str, Dict[str, Any]]
            api.sync_down(params)
            shared_folders = dict()

            def on_folder(f):   # type: (BaseFolderNode) -> None
                if f.type == BaseFolderNode.SharedFolderType:
                    shared_folders[f.uid] = params.shared_folder_cache.get(f.uid)

            base.FolderMixin.traverse_folder_tree(params, folder.uid, on_folder)
            return shared_folders

        def get_contained_folders(folder):  # type: (BaseFolderNode) -> List[BaseFolderNode]
            sub_folders = []
            base.FolderMixin.traverse_folder_tree(params, folder.uid, lambda f: sub_folders.append(f))
            return [f for f in sub_folders if f.uid != folder.uid]

        def get_contained_records(folder):  # type: (BaseFolderNode) -> List[Tuple[BaseFolderNode, Set[str]]]
            folder_records = []

            def on_folder(f):   # type: (BaseFolderNode) -> None
                if f.uid in params.subfolder_record_cache:
                    contained_recs = params.subfolder_record_cache.get(f.uid)
                    folder_records.append((f, contained_recs))

            base.FolderMixin.traverse_folder_tree(params, folder.uid, on_folder)
            return folder_records

        def move_contained_records(folder):
            rqs = []
            limit = 1000
            rq_base = {
                'command': 'move',
                'link': True,
            }

            def save_request(req, mv_objs, t_keys):
                req = {**req, 'move': mv_objs}
                if t_keys:
                    req['transition_keys'] = t_keys
                rqs.append(req)

            def new_mv_request(dst):
                return {**rq_base, 'to_uid': dst.uid, 'to_type': dst.type}

            for src_folder, r_uids in get_contained_records(folder):
                dst_folder = get_copy(src_folder)
                rq = new_mv_request(dst_folder)
                transition_keys = []
                moves = []
                for r_uid in r_uids:
                    if len(moves) >= limit:
                        save_request(rq, moves[:limit], transition_keys[:limit])
                        moves = moves[limit:]
                        transition_keys = transition_keys[limit:]
                        rq = new_mv_request(dst_folder)
                    move = {
                        'uid': r_uid,
                        'type': 'record',
                        'cascade': False,
                        'from_type': src_folder.type,
                        'from_uid': src_folder.uid
                    }
                    moves.append(move)
                    rec = params.record_cache.get(r_uid)
                    transition_key = None
                    sf_key_prop = 'shared_folder_key_unencrypted'
                    if src_folder.type in (BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType):
                        if dst_folder.type in (BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType):
                            ssf_uid = src_folder.uid if src_folder.type == BaseFolderNode.SharedFolderType \
                                else src_folder.shared_folder_uid
                            dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType \
                                else dst_folder.shared_folder_uid
                            if ssf_uid != dsf_uid:
                                shf = params.shared_folder_cache[dsf_uid]
                                transition_key = FolderMoveCommand.get_transition_key(rec, shf[sf_key_prop])
                        else:
                            transition_key = FolderMoveCommand.get_transition_key(rec, params.data_key)
                    else:
                        if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                            dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType \
                                else dst_folder.shared_folder_uid
                            shf = params.shared_folder_cache[dsf_uid]
                            transition_key = FolderMoveCommand.get_transition_key(rec, shf[sf_key_prop])
                    if transition_key is not None:
                        transition_keys.append({
                            'uid': r_uid,
                            'key': transition_key
                        })
                save_request(rq, moves, transition_keys)
            rs = api.execute_batch(params, rqs)
            api.sync_down(params)
            fails = [move_rs for move_rs in rs if move_rs.get('result') == 'fail']
            if any(fails):
                move_rs = next(iter(fails))
                ka_msg = move_rs.get('message')
                result_code = move_rs.get('result_code')
                error_msg = f'One or more records in folder {folder.name} (UID: {folder.uid}) is preventing its ' \
                            f'transformation.\nReason: {ka_msg}'
                raise KeeperApiError(result_code, error_msg)

        def get_copy_name(folder, dest):
            copy_name = folder.name + '(TRANSFORMED)' if folder.parent_uid == dest.uid else folder.name
            while True:
                rs = try_resolve_path(params, copy_name)
                if rs is None:
                    break
                else:
                    folder, pattern = rs
                    if len(pattern) == 0:
                        copy_name += '_'
                    else:
                        break
            return copy_name

        folder_copies = dict()  # type: Dict[str, str]

        def copy_folder(folder, transform=True):
            folders_cache = params.folder_cache
            parent_copy_uid = folder_copies.get(folder.parent_uid)
            parent_copy = folders_cache.get(parent_copy_uid)
            dest = parent_copy or folders_cache.get(folder.parent_uid, params.root_folder)
            params.current_folder = dest.uid or ''

            # Create copy folder of appropriate type
            mkdir_cmd = FolderMakeCommand()
            copy_name = get_copy_name(folder, dest)
            cmd_kwargs = {'folder': copy_name}
            is_folder_sf = folder.type == BaseFolderNode.SharedFolderType
            is_dest_uf = dest.type in (BaseFolderNode.UserFolderType, BaseFolderNode.RootFolderType)
            is_copy_sf = transform and is_dest_uf and not is_folder_sf
            copy_folder_type = 'shared_folder' if is_copy_sf else 'user_folder'
            cmd_kwargs[copy_folder_type] = True
            mkdir_cmd.execute(params, **cmd_kwargs)
            api.sync_down(params)
            copy_uid = get_folder_uid(copy_name)
            folder_copies[folder.uid] = copy_uid
            return params.folder_cache.get(copy_uid)

        def get_copy(folder):   # type: (BaseFolderNode) -> BaseFolderNode
            copy_uid = folder_copies.get(folder.uid)
            return params.folder_cache.get(copy_uid)

        def remove_trees(roots):
            if roots:
                rmdir_cmd = FolderRemoveCommand()
                rmdir_cmd.execute(params, pattern=[root.uid for root in roots], force=True, quiet=True)
                api.sync_down(params)

        def transform_tree(root):   # type: (BaseFolderNode) -> None
            shared_folders = dict(get_shared_folders(root))

            # Transform root folder (UF -> SF, SF -> UF)
            root_copy = copy_folder(root)

            # Transform child folder nodes (SF -> UF, UF -> SF)
            children = [params.folder_cache.get(f) for f in root.subfolders]
            children_copies = [copy_folder(c) for c in children]

            # Copy children's contained folders
            for child in children:
                inner_folders = get_contained_folders(child)
                for f in inner_folders:
                    copy_folder(f, transform=False)

            def apply_transform_shares():
                def get_sf_update_request(src_sfs, dst_sf):
                    sf_key = dst_sf.get('shared_folder_key_unencrypted')
                    req = folder_pb2.SharedFolderUpdateV3Request()
                    req.sharedFolderUid = utils.base64_url_decode(dst_sf.get('shared_folder_uid'))
                    req.revision = dst_sf.get('revision')
                    MU_KEY = 'manage_users'
                    MR_KEY = 'manage_records'
                    TEAM_SHARE_KEY = 'team_uid'
                    USER_SHARE_KEY = 'username'
                    users = [us for sf in src_sfs for us in sf.get('users', [])]
                    teams = [ts for sf in src_sfs for ts in sf.get('teams', [])]

                    def consolidate_shares(shares, id_key):
                        consolidated_shares = dict()
                        for share in shares:
                            share_key = share.get(id_key)
                            saved_share = consolidated_shares.get(share_key) or share
                            mr = saved_share.get(MR_KEY)
                            mu = saved_share.get(MU_KEY)
                            saved_share[MU_KEY] = mu or share.get(MU_KEY, False)
                            saved_share[MR_KEY] = mr or share.get(MR_KEY, False)
                            consolidated_shares[share_key] = saved_share
                        return consolidated_shares

                    users = consolidate_shares(users, USER_SHARE_KEY)
                    teams = consolidate_shares(teams, TEAM_SHARE_KEY)

                    for sf in src_sfs:
                        if sf.get('default_manage_records'):
                            req.defaultManageRecords = folder_pb2.BOOLEAN_TRUE
                        if sf.get('default_manage_users'):
                            req.defaultManageUsers = folder_pb2.BOOLEAN_TRUE
                        if sf.get('default_can_edit'):
                            req.defaultCanEdit = folder_pb2.BOOLEAN_TRUE
                        if sf.get('default_can_share'):
                            req.defaultCanShare = folder_pb2.BOOLEAN_TRUE

                    emails = list(users.keys())
                    api.load_user_public_keys(params, emails)
                    for email, ushare in users.items():
                        uo = folder_pb2.SharedFolderUpdateUser()
                        if email == params.user:
                            continue
                        uo.username = email
                        uo.manageUsers = folder_pb2.BOOLEAN_TRUE if ushare.get(MU_KEY) else folder_pb2.BOOLEAN_FALSE
                        uo.manageRecords = folder_pb2.BOOLEAN_TRUE if ushare.get(MR_KEY) else folder_pb2.BOOLEAN_FALSE
                        keys = params.key_cache.get(email)
                        if keys and keys.rsa:
                            rsa_key = crypto.load_rsa_public_key(keys.rsa)
                            uo.sharedFolderKey = crypto.encrypt_rsa(sf_key, rsa_key)
                        req_user_list = req.sharedFolderAddUser
                        req_user_list.append(uo)

                    team_uids = list(teams.keys())
                    api.load_team_keys(params, team_uids)
                    for team_uid, tshare in teams.items():
                        to = folder_pb2.SharedFolderUpdateTeam()
                        team_uid = tshare.get('team_uid')
                        to.teamUid = utils.base64_url_decode(team_uid)
                        to.manageRecords = tshare.get(MR_KEY)
                        to.manageUsers = tshare.get(MU_KEY)
                        keys = params.key_cache.get(team_uid)
                        if keys.aes:
                            to.sharedFolderKey = crypto.encrypt_aes_v1(sf_key, keys.aes)
                        elif keys.rsa:
                            rsa_key = crypto.load_rsa_public_key(keys.rsa)
                            to.sharedFolderKey = crypto.encrypt_rsa(sf_key, rsa_key)
                        req.sharedFolderAddTeam.append(to)

                    return req

                get_sf_fn = lambda sf_node: params.shared_folder_cache.get(sf_node.uid)

                if root.type == BaseFolderNode.UserFolderType:
                    new_sf = get_sf_fn(root_copy)
                    rqs = [get_sf_update_request(shared_folders.values(), new_sf)]
                else:
                    new_sfs = [get_sf_fn(cc) for cc in children_copies]
                    rqs = [get_sf_update_request(shared_folders.values(), sf) for sf in new_sfs]

                for rq in rqs:
                    rs = api.communicate_rest(params, rq, 'vault/shared_folder_update_v3',
                                              rs_type=folder_pb2.SharedFolderUpdateV3Response)
                    params.sync_data = True

            apply_transform_shares()
            move_contained_records(root)
            return root_copy

        def preview_transform(xform_pairs):
            logging.info('\nORIGINAL vs. TRANSFORMED folder structures:')
            logging.info('===========================================\n')
            hide_key = False
            for root, xformed in xform_pairs:
                params.current_folder = root.parent_uid or ''
                tree_cmd = FolderTreeCommand()
                tree_cmd.execute(params, folder=root.name, records=True, shares=True, hide_shares_key=hide_key,
                                 title='ORIGINAL:\n=========')
                tree_cmd.execute(params, folder=xformed.name, records=True, shares=True, hide_shares_key=True,
                                 title='TRANSFORMED:\n============')
                hide_key = True

        def rename_copies():
            for orig_uid, copy_uid in folder_copies.items():
                orig = params.folder_cache.get(orig_uid)
                copy = params.folder_cache.get(copy_uid)
                if orig.name != copy.name:
                    orig_name = orig.name
                    rn_cmd = FolderRenameCommand()
                    orig_new_name = orig_name + '@delete'
                    rn_cmd.execute(params, quiet=True, name=orig_new_name, folder=orig_uid)
                    api.sync_down(params)
                    rn_cmd.execute(params, quiet=True, name=orig_name, folder=copy_uid)
            api.sync_down(params)

        def finalize_transform(old_roots):
            rename_copies()
            remove_trees(old_roots)

        def on_abort(roots):
            new_roots = [params.folder_cache.get(folder_copies.get(r.uid)) for r in roots]
            new_roots = [r for r in new_roots if r]
            remove_trees(new_roots)

        current_folder = params.current_folder
        dry_run = kwargs.get('dry_run')
        force = kwargs.get('force')
        if force and dry_run:
            raise CommandError('transform-folder', '"--force" and "--dry-run" options are mutually exclusive')

        folders = kwargs.get('folder')
        if not isinstance(folders, list):
            folders = [folders]

        targets = []
        for f in folders:
            folder_uid = f if f in params.folder_cache else get_folder_uid(f)
            target_folder = params.folder_cache.get(folder_uid)
            if not target_folder:
                raise CommandError('transform-folder', f'Folder {f} not found')
            else:
                targets.append(target_folder)

        if kwargs.get('children'):
            targets = [params.folder_cache.get(sub_f) for t in targets for sub_f in t.subfolders]

        validate(targets)

        transformed = []
        for t in targets:
            try:
                transformed.append(transform_tree(t))
            except Error as e:
                params.current_folder = current_folder
                on_abort(targets)
                raise CommandError('transform-folder', f'Folder {t.name} could not be transformed.\n{e.message}')

        transform_pairs = zip(targets, transformed)
        if force:
            finalize_transform(targets)
        elif dry_run:
            logging.info('Executing command in "dry-run" mode...')
            preview_transform(transform_pairs)
            remove_trees(transformed)
        else:
            preview_transform(transform_pairs)
            inp = user_choice('Are you sure you want to proceed with this/these transformation(s)?', 'yn', default='n')
            if inp.lower() == 'y':
                logging.info('Executing transformation(s)...')
                finalize_transform(targets)
            else:
                logging.info('Transformation cancelled by user.')
                remove_trees(transformed)
        params.current_folder = current_folder

