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
import fnmatch
import functools
import json
import logging
import os
import re
import shutil
from collections import OrderedDict
from typing import Tuple, List, Optional, Dict, Set, Any, Iterable

from asciitree import LeftAligned, BoxStyle, drawing
from colorama import Style

from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText


from . import base
from .base import user_choice, dump_report_data, suppress_exit, raise_parse_exception, Command, GroupCommand, RecordMixin
from .. import api, display, vault, vault_extensions, crypto, utils
from ..error import CommandError, KeeperApiError, Error
from ..params import KeeperParams
from ..params import LAST_SHARED_FOLDER_UID, LAST_FOLDER_UID
from ..proto import folder_pb2, record_pb2
from ..record import Record
from ..recordv3 import RecordV3
from ..subfolder import BaseFolderNode, try_resolve_path, find_folders, SharedFolderNode, get_contained_record_uids, \
    get_contained_folder_uids


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

    aliases['xf'] = 'transform-folder'
    command_info['shortcut'] = 'Manage record shortcuts'


ls_parser = argparse.ArgumentParser(prog='ls', description='List folder contents.', parents=[base.report_output_parser])
ls_parser.add_argument('-l', '--list', dest='detail', action='store_true', help='show detailed list')
ls_parser.add_argument('-f', '--folders', dest='folders_only', action='store_true', help='display folders only')
ls_parser.add_argument('-r', '--records', dest='records_only', action='store_true', help='display records only')
ls_parser.add_argument('-s', '--short', dest='short', action='store_true',
                       help='Do not display record details. (Not used)')
ls_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
recursive_help = 'list all folders/records in subfolders'
ls_parser.add_argument('-R', '--recursive', dest='recursive', action='store_true', help=recursive_help)
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
rndir_parser.add_argument('-n', '--name', dest='name', action='store', help='folder new name')
rndir_parser.add_argument('--color', dest='color', action='store', choices=['none', 'red', 'green', 'blue', 'orange', 'yellow', 'gray'],
                          help='folder color')
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
mkdir_parser.add_argument('--color', dest='color', action='store', choices=['none', 'red', 'green', 'blue', 'orange', 'yellow', 'gray'],
                          help='folder color')
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
transform_parser.add_argument('--clear-shares', action='store_true', help='Don\'t apply parent or subfolder share permissions to transformed folder tree')
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
        show_folders = kwargs.get('folders_only') is True
        show_records = kwargs.get('records_only') is True
        show_detail = kwargs['detail'] if 'detail' in kwargs else False
        if not show_folders and not show_records:
            show_folders = True
            show_records = True
        fmt = kwargs.get('format') or ''
        if fmt in ('json', 'csv'):
            show_detail = True
            if show_folders and show_records:
                fmt = 'table'

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

        recursive_search = kwargs.get('recursive')
        folder_uid = folder.uid or ''
        if show_folders:
            sub_folder_uids = get_contained_folder_uids(params, folder_uid, not recursive_search)
            for uid in sub_folder_uids:
                f = params.folder_cache[uid]
                if any(filter(lambda x: regex(x) is not None, FolderListCommand.folder_match_strings(f))) if regex is not None else True:
                    folders.append(f)

        if show_records and params.record_cache:
            if folder_uid in params.subfolder_record_cache or recursive_search:
                record_uids_by_folder = get_contained_record_uids(params, folder_uid, not recursive_search)
                record_uids = {rec_uid for recs in record_uids_by_folder.values() for rec_uid in recs}
                for uid in record_uids:
                    if uid not in params.record_cache:
                        continue
                    rec = params.record_cache[uid]
                    rv = rec.get('version', 0)
                    if rv not in (2, 3):
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
                    table = []
                    headers = ['folder_uid', 'name', 'flags']

                    def folder_flags(f):
                        if f.type == 'shared_folder':
                            flags = 'S'
                        else:
                            flags = ''
                        return flags
                    colors = {}
                    for f in folders:
                        if f.color:
                            colors[f.name] = f.color
                        row = [f.uid, f.name, folder_flags(f)]
                        table.append(row)
                    table.sort(key=lambda x: (x[1] or '').lower())
                    for i in range(len(table)):
                        name = table[i][1]
                        if name in colors:
                            table[i][1] = display.keeper_colorize(name, colors[name])
                    if fmt != 'json':
                        headers = base.fields_to_titles(headers)
                    if fmt in ('json', 'csv'):
                        return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))
                    else:
                        dump_report_data(table, headers, row_number=True)
                if len(records) > 0:
                    table = []
                    headers = ['record_uid', 'type', 'title', 'description']
                    for record in records:
                        row = [record.record_uid, record.record_type, record.title, vault_extensions.get_record_description(record)]
                        table.append(row)
                    table.sort(key=lambda x: (x[2] or '').lower())
                    if fmt != 'json':
                        headers = base.fields_to_titles(headers)
                    if fmt in ('json', 'csv'):
                        return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))
                    else:
                        dump_report_data(table, headers, row_number=True, append=True)
            else:
                names = []   # type: List[Tuple[str, Optional[str]]]
                for f in folders:
                    name = f.name or f.uid
                    if len(name) > 40:
                        name = name[:25] + '...' + name[-12:]
                    name = name + '/'
                    names.append((name, f.color))
                names.sort(key=lambda x: x[0])

                rnames = []
                for r in records:
                    name = r.title or r.record_uid
                    if len(name) > 40:
                        name = name[:25] + '...' + name[-12:]
                    rnames.append(name)
                rnames.sort()

                names.extend(((x, None) for x in rnames))

                width, _ = shutil.get_terminal_size(fallback=(1, 1))
                max_name = functools.reduce(lambda val, elem: len(elem[0]) if len(elem[0]) > val else val, names, 0)
                cols = width // max_name
                if cols == 0:
                    cols = 1

                while ((max_name * cols) + (cols - 1) * 2) > width:
                    if cols > 2:
                        cols = cols - 1
                    else:
                        break

                tbl = FolderListCommand.chunk_list([display.keeper_colorize(x[0].ljust(max_name), x[1]) for x in names], cols)
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
            formatted_tree(params, folder, verbose=verbose, show_records=records, shares=shares, hide_shares_key=hide_key, title=title)
        else:
            folders, pattern = try_resolve_path(params, folder_name, find_all_matches=True)
            if not pattern:
                for idx, folder in enumerate(folders):
                    formatted_tree(params, folder, verbose=verbose, show_records=records, shares=shares, hide_shares_key=hide_key or idx > 0, title=title)
            else:
                raise CommandError('tree', f'Folder {folder_name} not found')


class FolderRenameCommand(Command):
    def get_parser(self):
        return rndir_parser

    def execute(self, params, **kwargs):
        color = kwargs.get('color')
        new_name = kwargs.get('name')
        if not new_name and not color:
            raise CommandError('', 'New folder name and/or color parameters are required.')

        folder_name = kwargs.get('folder')
        if not folder_name:
            raise CommandError('', 'Enter the path or UID of existing folder.')

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
                    raise CommandError('', f'Folder {folder_name} not found')

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
                raise CommandError('', f'Shared Folder UID \"{folder_uid}\" not found.')
            rq['shared_folder_uid'] = folder_uid
            shared_folder = params.shared_folder_cache[folder_uid]
            encryption_key = shared_folder['shared_folder_key_unencrypted']
            encrypted_data = shared_folder.get('data')
            if new_name:
                rq['name'] = utils.base64_url_encode(crypto.encrypt_aes_v1(new_name.encode('utf-8'), encryption_key))
            else:
                rq['name'] = shared_folder['name']
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

        if new_name:
            data['name'] = new_name
        if color:
            if color == 'none':
                if 'color' in data:
                    del data['color']
            else:
                data['color'] = color

        rq['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), encryption_key))
        api.communicate(params, rq)
        params.sync_data = True
        if not kwargs.get('quiet'):
            folder = params.folder_cache[folder_uid]
            if new_name:
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

        request['key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(folder_key, encryption_key))
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
            request['name'] = utils.base64_url_encode(crypto.encrypt_aes_v1(name.encode('utf-8'), folder_key))
        data_dict = {'name': name}
        color = kwargs.get('color')
        if isinstance(color, str) and len(color) > 0 and color != 'none':
            data_dict['color'] = kwargs['color']
        data = json.dumps(data_dict)
        request['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(data.encode('utf-8'), folder_key))

        api.communicate(params, request)
        params.sync_data = True
        params.environment_variables[LAST_FOLDER_UID] = folder_uid
        if request['folder_type'] == 'shared_folder':
            params.environment_variables[LAST_SHARED_FOLDER_UID] = folder_uid
        return folder_uid


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
        transition_key = utils.base64_url_encode(crypto.encrypt_aes_v1(sf['folder_key_unencrypted'], encryption_key))
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

        def validate(root_folders):   # type: (Iterable[BaseFolderNode]) -> None
            SF_UID_KEY = 'shared_folder_uid'
            shared_folders = []
            contained_recs = []
            for folder in root_folders:
                shared_folders.extend(get_shared_folders(folder))
                contained_recs.extend(get_contained_records(folder))

            # Check for overlapping trees
            root_uids = set()
            contained_folder_uids = set()
            for rf in root_folders:
                root_uids.add(rf.uid)
                contained_folder_uids.update(get_contained_folder_uids(params, rf.uid, children_only=False))
            if contained_folder_uids.intersection(root_uids):
                error_msg = 'Transformation of overlapping folder trees in the same command is not allowed.'
                raise CommandError('transform-folder', error_msg)

            # Check relevant shared folders in each tree: descendants, root, and/or ancestor shared-folders
            def has_full_sf_privs(sf):   # type: (Dict[str, Any]) -> bool
                # Check if user has been directly granted full share-permissions for this folder
                user_permissions = next((ushare for ushare in sf.get('users') if ushare.get('username') == params.user), None)
                can_manage_records = user_permissions.get('manage_records') if user_permissions else False
                can_manage_users = user_permissions.get('manage_users') if user_permissions else False
                if not (can_manage_users and can_manage_records):
                    # User shares don't grant the user full permissions => check team permissions instead
                    if not params.team_cache or not sf.get('teams'):
                        return False
                    user_team_shares = [tshare for tshare in sf.get('teams') if tshare.get('team_uid') in params.team_cache]
                    for team_share in user_team_shares:
                        can_manage_records = team_share.get('manage_records') or can_manage_records
                        can_manage_users = team_share.get('manage_users') or can_manage_users
                        if can_manage_users and can_manage_records:
                            break
                return can_manage_users and can_manage_records

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

        def get_shared_folders(folder):     # type: (BaseFolderNode) -> List[Dict[str, Any]]
            api.sync_down(params)
            shared_folders = []
            # Folder is a shared-folder subfolder, return only the containing shared-folder
            if folder.type == BaseFolderNode.SharedFolderFolderType:
                while folder.type is not BaseFolderNode.SharedFolderType:
                    folder = params.folder_cache.get(folder.parent_uid)
                shared_folders.append(params.shared_folder_cache.get(folder.uid))

            def on_folder(f):   # type: (BaseFolderNode) -> None
                if f.type == BaseFolderNode.SharedFolderType:
                    shared_folders.append(params.shared_folder_cache.get(f.uid))

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
                # This folder has no records to move, skip to the next one
                if not r_uids:
                    continue
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
            def get_path_tokens(f):   # type: (BaseFolderNode) -> List[str]
                result = []
                while f and f is not params.root_folder:
                    result = [f.name, *result]
                    f = params.folder_cache.get(f.parent_uid) or params.root_folder \
                        if f is not params.root_folder \
                        else None
                return result or []

            rebasing_copy = dest.uid is None and folder.parent_uid
            if rebasing_copy:
                path_tokens = get_path_tokens(folder)
                name = ' - '.join(path_tokens)
                copy_name = name
            else:
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

            # To allow new folder creation via FolderAddCommand, make sure the name provided adheres to the naming rules
            pattern = re.compile(r'(?<!/)/(?!/)')
            copy_name = re.sub(pattern, r'//', copy_name)
            return copy_name

        copy_uid_lookup = dict()    # type: Dict[str, str]

        def copy_folder(original_folder, new_folder_type='user_folder', rebase=False):
            # type: (BaseFolderNode, Optional[str], Optional[bool]) -> BaseFolderNode
            folders_cache = params.folder_cache
            vault_root = params.root_folder
            dest_uid = copy_uid_lookup.get(original_folder.parent_uid) or original_folder.parent_uid or ''
            dest = vault_root if rebase else folders_cache.get(dest_uid) or vault_root
            params.current_folder = dest.uid or ''

            # Create folder copy of appropriate type
            mkdir_cmd = FolderMakeCommand()
            copy_name = get_copy_name(original_folder, dest)
            cmd_kwargs = {'folder': copy_name, new_folder_type: True}
            copy_uid = mkdir_cmd.execute(params, **cmd_kwargs)
            api.sync_down(params)
            copy_uid_lookup.update({original_folder.uid: copy_uid})
            return params.folder_cache.get(copy_uid)

        def get_copy(original_folder):   # type: (BaseFolderNode) -> BaseFolderNode
            copy_uid = copy_uid_lookup.get(original_folder.uid)
            return params.folder_cache.get(copy_uid)

        def remove_trees(roots):    # type: (Iterable[BaseFolderNode]) -> None
            if roots:
                rmdir_cmd = FolderRemoveCommand()
                rmdir_cmd.execute(params, pattern=[root.uid for root in roots], force=True, quiet=True)
                api.sync_down(params)

        def transform_tree(root):   # type: (BaseFolderNode) -> BaseFolderNode
            shared_folders = get_shared_folders(root)
            clear_shares = kwargs.get('clear_shares')
            is_root_sf = root.type == BaseFolderNode.SharedFolderType
            is_root_sf_sub = root.type == BaseFolderNode.SharedFolderFolderType
            make_root_copy_sf = not is_root_sf and not clear_shares
            make_children_sfs = not make_root_copy_sf and not clear_shares

            # Transform root folder (UF -> SF, SF -> UF, SF-sub -> rebased UF/SF depending on clear_shares)
            copy_type = 'shared_folder' if make_root_copy_sf else 'user_folder'
            root_copy = copy_folder(root, new_folder_type=copy_type, rebase=is_root_sf_sub)

            children = [params.folder_cache.get(f) for f in root.subfolders]
            children_copy_type = 'shared_folder' if make_children_sfs else 'user_folder'
            children_copies = [copy_folder(c, new_folder_type=children_copy_type) for c in children]

            # Copy children's contained folders
            for child in children:
                inner_folders = get_contained_folders(child)
                for f in inner_folders:
                    copy_folder(f)

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
                        if team_uid in params.team_cache:
                            team = params.team_cache[team_uid]
                            if 'team_key_unencrypted' in team:
                                team_key = team['team_key_unencrypted']
                                to.sharedFolderKey = crypto.encrypt_aes_v1(sf_key, team_key)
                            else:
                                continue
                        elif team_uid in params.key_cache:
                            team_keys = params.key_cache[team_uid]
                            if team_keys.aes:
                                to.sharedFolderKey = crypto.encrypt_aes_v1(sf_key, team_keys.aes)
                            elif team_keys.rsa:
                                rsa_key = crypto.load_rsa_public_key(team_keys.rsa)
                                to.sharedFolderKey = crypto.encrypt_rsa(sf_key, rsa_key)
                            else:
                                continue
                        req.sharedFolderAddTeam.append(to)

                    return req

                get_sf_fn = lambda sf_node: params.shared_folder_cache.get(sf_node.uid)

                if make_root_copy_sf:
                    new_sf = get_sf_fn(root_copy)
                    rqs = [get_sf_update_request(shared_folders, new_sf)]
                else:
                    new_sfs = [get_sf_fn(cc) for cc in children_copies]
                    rqs = [get_sf_update_request(shared_folders, sf) for sf in new_sfs]

                while len(rqs) > 0:
                    chunk = rqs[:999]
                    rqs = rqs[999:]
                    rq = folder_pb2.SharedFolderUpdateV3RequestV2()
                    for x in chunk:
                        if isinstance(x, folder_pb2.SharedFolderUpdateV3Request):
                            rq.sharedFoldersUpdateV3.append(x)
                    rss = api.communicate_rest(params, rq, 'vault/shared_folder_update_v3', payload_version=1,
                                               rs_type=folder_pb2.SharedFolderUpdateV3ResponseV2)
                params.sync_data = True

            if not clear_shares:
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
                tree_cmd.execute(params, folder=root.uid, records=True, shares=True, hide_shares_key=hide_key,
                                 title='ORIGINAL:\n=========')
                params.current_folder = xformed.parent_uid or ''
                tree_cmd.execute(params, folder=xformed.uid, records=True, shares=True, hide_shares_key=True,
                                 title='TRANSFORMED:\n============')
                hide_key = True

        def rename_copies():
            for orig_uid, copy_uid in copy_uid_lookup.items():
                orig = params.folder_cache.get(orig_uid)    # type: BaseFolderNode
                copy = params.folder_cache.get(copy_uid)    # type: BaseFolderNode
                if orig.name != copy.name and orig.type is not BaseFolderNode.SharedFolderFolderType:
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
            new_roots = [params.folder_cache.get(copy_uid_lookup.get(r.uid)) for r in roots]
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

        children_transform = kwargs.get('children')
        folder_uids = {(f if f in params.folder_cache else get_folder_uid(f)) for f in folders}
        folder_nodes = dict()
        targets = dict()
        for f_uid in folder_uids:
            folder_node = params.folder_cache.get(f_uid)
            if not folder_node:
                raise CommandError('transform-folder', f'Folder {f_uid} not found')
            else:
                folder_map = {f_uid: folder_node}
                folder_nodes.update(folder_map)
                if not children_transform:
                    targets.update(folder_map)

        if children_transform:
            targets.update({sub_f: params.folder_cache.get(sub_f) for f in folder_nodes.values() for sub_f in f.subfolders})

        validate(targets.values())

        transformed = []
        for t in targets.values():
            try:
                transformed.append(transform_tree(t))
            except Error as e:
                params.current_folder = current_folder
                on_abort(targets.values())
                raise CommandError('transform-folder', f'Folder {t.name} could not be transformed.\n{e.message}')

        transform_pairs = zip(targets.values(), transformed)
        if force:
            finalize_transform(targets.values())
        elif dry_run:
            logging.info('Executing command in "dry-run" mode...')
            preview_transform(transform_pairs)
            remove_trees(transformed)
        else:
            preview_transform(transform_pairs)
            inp = user_choice('Are you sure you want to proceed with this/these transformation(s)?', 'yn', default='n')
            if inp.lower() == 'y':
                logging.info('Executing transformation(s)...')
                finalize_transform(targets.values())
            else:
                logging.info('Transformation cancelled by user.')
                remove_trees(transformed)
        params.current_folder = current_folder


def formatted_tree(params, folder, verbose=False, show_records=False, shares=False, hide_shares_key=False, title=None):
    def print_share_permissions_key():
        perms_key = 'Share Permissions Key:\n' \
                    '======================\n' \
                    'RO = Read-Only\n' \
                    'MU = Can Manage Users\n' \
                    'MR = Can Manage Records\n' \
                    'CE = Can Edit\n' \
                    'CS = Can Share\n' \
                    '======================\n'
        print(perms_key)

    def get_share_info(node):
        MU_KEY = 'manage_users'
        MR_KEY = 'manage_records'
        DMR_KEY = 'default_manage_records'
        DMU_KEY = 'default_manage_user'
        DCE_KEY = 'default_can_edit'
        DCS_KEY = 'default_can_share'
        perm_abbrev_lookup = {MU_KEY: 'MU', MR_KEY: 'MR', DMR_KEY: 'MU', DMU_KEY: 'MU', DCE_KEY: 'CE', DCS_KEY: 'CS'}

        def get_users_info(users):
            info = []
            for u in users:
                email = u.get('username')
                if email == params.user:
                    continue
                privs = [v for k, v in perm_abbrev_lookup.items() if u.get(k)] or ['RO']
                info.append(f'[{email}:{",".join(privs)}]')
            return 'users:' + ','.join(info) if info else ''

        def get_teams_info(teams):
            info = []
            for t in teams:
                name = t.get('name')
                privs = [v for k, v in perm_abbrev_lookup.items() if t.get(k)] or ['RO']
                info.append(f'[{name}:{",".join(privs)}]')
            return 'teams:' + ','.join(info) if info else ''

        result = ''
        if isinstance(node, SharedFolderNode):
            sf = params.shared_folder_cache.get(node.uid)
            teams_info = get_teams_info(sf.get('teams', []))
            users_info = get_users_info(sf.get('users', []))
            default_perms = [v for k, v in perm_abbrev_lookup.items() if sf.get(k)] or ['RO']
            default_perms = 'default:' + ','.join(default_perms)
            user_perms = [v for k, v in perm_abbrev_lookup.items() if sf.get(k)] or ['RO']
            user_perms = 'user:' + ','.join(user_perms)
            perms = [default_perms, user_perms, teams_info, users_info]
            perms = [p for p in perms if p]
            result = f' ({"; ".join(perms)})' if shares else ''

        return result

    def tree_node(node):
        node_uid = node.record_uid if isinstance(node, Record) else node.uid or ''
        node_name = node.title if isinstance(node, Record) else node.name
        node_name = f'{node_name} ({node_uid})'
        share_info = get_share_info(node) if isinstance(node, SharedFolderNode) and shares else ''
        node_name = f'{Style.DIM}{node_name} [Record]{Style.NORMAL}' if isinstance(node, Record) \
            else f'{node_name}{Style.BRIGHT} [SHARED]{Style.NORMAL}{share_info}' if isinstance(node, SharedFolderNode) \
            else node_name

        dir_nodes = [] if isinstance(node, Record) \
            else [params.folder_cache.get(fuid) for fuid in node.subfolders]
        rec_nodes = []
        if show_records and isinstance(node, BaseFolderNode):
            node_uid = '' if node.type == '/' else node.uid
            rec_uids = {rec for recs in get_contained_record_uids(params, node_uid).values() for rec in recs}
            records = [api.get_record(params, rec_uid) for rec_uid in rec_uids]
            records = [r for r in records if isinstance(r, Record)]
            rec_nodes.extend(records)

        dir_nodes.sort(key=lambda f: f.name.lower(), reverse=False)
        rec_nodes.sort(key=lambda r: r.title.lower(), reverse=False)
        child_nodes = dir_nodes + rec_nodes

        tns = [tree_node(n) for n in child_nodes]
        return node_name, OrderedDict(tns)

    root, branches = tree_node(folder)
    tree = {root: branches}
    tr = LeftAligned(draw=BoxStyle(gfx=drawing.BOX_LIGHT))
    if shares and not hide_shares_key:
        print_share_permissions_key()
    if title:
        print(title)
    tree_txt = tr(tree)
    tree_txt = re.sub(r'\s+\(\)', '', tree_txt)
    if not verbose:
        lines = tree_txt.splitlines()
        for idx, line in enumerate(lines):
            line = re.sub(r'\s+\(.+?\)', '', line, count=1)
            lines[idx] = line
        tree_txt = '\n'.join(lines)
    print(tree_txt)
    print('')
