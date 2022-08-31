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
from typing import Tuple, List, Optional, Dict, Set

from .. import api, display, vault, vault_extensions, crypto, utils
from ..subfolder import BaseFolderNode, try_resolve_path, find_folders
from ..params import KeeperParams
from ..record import Record
from .base import user_choice, dump_report_data, suppress_exit, raise_parse_exception, Command, GroupCommand, RecordMixin
from ..params import LAST_SHARED_FOLDER_UID, LAST_FOLDER_UID
from ..error import CommandError


def register_commands(commands):
    commands['ls'] = FolderListCommand()
    commands['cd'] = FolderCdCommand()
    commands['tree'] = FolderTreeCommand()
    commands['mkdir'] = FolderMakeCommand()
    commands['rmdir'] = FolderRemoveCommand()
    commands['mv'] = FolderMoveCommand()
    commands['ln'] = FolderLinkCommand()
    commands['shortcut'] = ShortcutCommand()
    commands['arrange-folders'] = ArrangeFolderCommand()


def register_command_info(aliases, command_info):
    for p in [cd_parser, ls_parser, tree_parser, mkdir_parser, rmdir_parser, mv_parser, ln_parser]:
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
tree_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or UID')
tree_parser.error = raise_parse_exception
tree_parser.exit = suppress_exit


rmdir_parser = argparse.ArgumentParser(prog='rmdir', description='Remove a folder and its contents.')
rmdir_parser.add_argument('-f', '--force', dest='force', action='store_true', help='remove folder without prompting')
rmdir_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', help='remove folder without folder info')
rmdir_parser.add_argument('pattern', nargs='*', type=str, action='store', help='folder path or UID')
rmdir_parser.error = raise_parse_exception
rmdir_parser.exit = suppress_exit


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
        if folder_name in params.folder_cache:
            display.formatted_tree(params, params.folder_cache[folder_name], verbose=verbose)
        else:
            rs = try_resolve_path(params, folder_name)
            if rs is not None:
                folder, pattern = rs
                if len(pattern) == 0:
                    display.formatted_tree(params, folder, verbose=verbose)
                else:
                    raise CommandError('tree', f'Folder {folder_name} not found')


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


def get_shared_folder_delete_rq(params, sf_requests, uid):
    """Adds a delete request to given dictionary for specified shared folder uid"""
    if uid in params.shared_folder_cache and uid not in sf_requests:
        sf = params.shared_folder_cache[uid]

        rq = {
            'command': 'shared_folder_update',
            'operation': 'delete',
            'shared_folder_uid': sf['shared_folder_uid']
        }
        if 'shared_folder_key' not in sf:
            if 'teams' in sf:
                for team in sf['teams']:
                    rq['from_team_uid'] = team['team_uid']
                    break
        sf_requests[uid] = rq


def get_shared_subfolder_delete_rq(params, sf_requests, user_folder, user_folder_ids):
    """Recursively searches a user folder for shared folders to delete"""
    delete_rq_added = False
    user_folder_ids.add(user_folder.uid)
    for uid in user_folder.subfolders:
        subfolder = params.folder_cache[uid]
        if subfolder.type == BaseFolderNode.SharedFolderType:
            delete_rq_added = True
            get_shared_folder_delete_rq(params, sf_requests, uid)
        elif uid not in user_folder_ids:
            delete_rq_added = get_shared_subfolder_delete_rq(params, sf_requests, subfolder, user_folder_ids)
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
        shared_folder_requests = OrderedDict()
        user_folder_objects = OrderedDict()
        search_user_folder_ids = set()
        shared_subfolder_delete_rq_added = False
        for folder in folders:
            if folder.type == BaseFolderNode.SharedFolderType:
                get_shared_folder_delete_rq(params, shared_folder_requests, folder.uid)
            elif folder.uid not in user_folder_objects:
                shared_subfolder_delete_rq_added = get_shared_subfolder_delete_rq(
                    params, shared_folder_requests, folder, search_user_folder_ids
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

        shared_folder_count = len(shared_folder_requests)
        user_folder_count = len(user_folder_objects)
        np = 'n'
        if shared_folder_count > 0:
            if not quiet or not force:
                user_folder_msg = f' and {user_folder_count} user folder(s)' if user_folder_count > 0 else ''
                print(f'Removing {shared_folder_count} shared folder(s){user_folder_msg}.')
                shared_folder_names = [get_folder_path(params, uid) for uid in shared_folder_requests]
                print(f'\nThe following shared folder(s) will be removed:\n{", ".join(shared_folder_names)}')

            prompt_msg = 'Do you want to proceed with the shared folder deletion?'
            np = 'y' if force else user_choice(f'\n{prompt_msg}', 'yn', default='n')
            if np.lower() == 'y':
                api.execute_batch(params, list(shared_folder_requests.values()))
                params.sync_data = True

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
