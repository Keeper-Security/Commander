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
from typing import Tuple, List, Optional, Dict, Set, Any, Union

from asciitree import LeftAligned, BoxStyle, drawing
from colorama import Style

from . import base
from .base import user_choice, dump_report_data, suppress_exit, raise_parse_exception, Command, GroupCommand, \
    RecordMixin, FolderMixin
from .. import api, display, vault, vault_extensions, crypto, utils
from ..error import CommandError
from ..params import KeeperParams
from ..params import LAST_SHARED_FOLDER_UID, LAST_FOLDER_UID
from ..proto import folder_pb2
from ..record import Record
from ..subfolder import BaseFolderNode, SharedFolderNode, UserFolderNode, SharedFolderFolderNode, try_resolve_path, \
    find_folders, get_contained_record_uids, get_contained_folder_uids


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


tree_parser = argparse.ArgumentParser(prog='tree', description='Display the folder structure.',
                                      parents=[base.json_output_parser])
tree_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
tree_parser.add_argument('-r', '--records', action='store_true',
                         help='show records within each folder (includes record type)')
tree_parser.add_argument('-s', '--shares', action='store_true',
                         help='show classic shared-folder permissions; with -r also classic record shares')
tree_parser.add_argument('-ns', '--nsf-shares', dest='nsf_shares', action='store_true',
                         help='show NSF folder permissions (ACL API); with -r also NSF record shares')
perms_key_help = 'hide share permissions key (valid with --shares / --nsf-shares)'
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


shortcut_list_parser = argparse.ArgumentParser(prog='shortcut-list', parents=[base.report_output_parser])
shortcut_list_parser.add_argument('target', nargs='?', help='Full record or folder path')

shortcut_keep_parser = argparse.ArgumentParser(prog='shortcut-keep')
shortcut_keep_parser.add_argument('target', nargs='?', help='Full record or folder path')
shortcut_keep_parser.add_argument('folder', nargs='?', help='Optional. Folder name or UID. Overwrites current folder.')

transform_desc = 'Move a folder another location'
transform_parser = argparse.ArgumentParser(prog='transform-folder', description=transform_desc)
transform_parser.add_argument('folder', nargs='+', help='Folder UID or path/name (accepts multiple values)')
transform_parser.add_argument('--link', dest='link', action='store_true',
                              help='Do not delete the source folder(s)')
transform_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                              help='Preview the folder transformation without updating')
transform_parser.add_argument('-f', '--force', dest='force', action='store_true',
                              help='Skip confirmation prompt and minimize output')
transform_target = transform_parser.add_mutually_exclusive_group()
transform_target.add_argument('--target', dest='target', action='store',
                              help='Target Folder UID or path/name (root folder if omitted)')
transform_target.add_argument('--folder-type', dest='folder_type', choices=['personal', 'shared'],
                              action='store', help='Folder type: Personal or Shared if target folder parameter is omitted')
# children_help = 'Apply transformation to target folder\'s children only (target folder will remain unchanged).'
# transform_parser.add_argument('-c', '--children', action='store_true', help=children_help)


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

    @staticmethod
    def _collect_nsf_record_uids(params, folder_uid, recursive_search):
        nsf_folders = getattr(params, 'nested_share_folders', {})
        nsf_folder_records = getattr(params, 'nested_share_folder_records', {})
        nsf_records = getattr(params, 'nested_share_records', {})
        if not nsf_records:
            return set()

        if folder_uid in nsf_folders:
            from .nested_share_folder.helpers import collect_records_in_folder
            return set(collect_records_in_folder(params, folder_uid, recursive=bool(recursive_search)))

        record_uids = set()
        if recursive_search:
            record_uids.update(nsf_records.keys())
        elif not folder_uid:
            for fuid, rec_set in nsf_folder_records.items():
                if fuid not in nsf_folders:
                    record_uids.update(rec_set)
        return record_uids

    @staticmethod
    def _load_record_for_ls(params, uid):
        for cache in (getattr(params, 'nested_share_records', {}), params.record_cache or {}):
            if uid not in cache:
                continue
            cached = cache[uid]
            if cached.get('version', 0) not in (2, 3):
                continue
            r = vault.KeeperRecord.load(params, cached)
            if r:
                return r

        nsf_record_data = getattr(params, 'nested_share_record_data', {})
        if uid in nsf_record_data and 'data_json' in nsf_record_data[uid]:
            dj = nsf_record_data[uid]['data_json']
            rec = vault.TypedRecord(version=3)
            rec.record_uid = uid
            rec.title = dj.get('title', uid)
            rec.record_type = dj.get('type', '')
            rec.load_record_data(dj, None)
            return rec
        return None

    @staticmethod
    def _record_source(params, record_uid):
        if hasattr(params, 'nested_share_records') and record_uid in params.nested_share_records:
            return 'nested'
        return 'classic'

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

        if show_records:
            record_uids = set()
            if params.record_cache and (folder_uid in params.subfolder_record_cache or recursive_search):
                record_uids_by_folder = get_contained_record_uids(params, folder_uid, not recursive_search)
                record_uids.update(rec for recs in record_uids_by_folder.values() for rec in recs)
            record_uids.update(FolderListCommand._collect_nsf_record_uids(params, folder_uid, recursive_search))

            for uid in record_uids:
                r = FolderListCommand._load_record_for_ls(params, uid)
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
                # Helper function to get folder flags
                def folder_flags(f):
                    if f.type == BaseFolderNode.SharedFolderType:
                        flags = 'S'
                    else:
                        flags = ''
                    return flags
                
                if fmt in ('json', 'csv'):
                    combined_table = []
                    combined_headers = ['type', 'uid', 'name', 'details', 'source']
                    
                    if len(folders) > 0:
                        for f in folders:
                            # Check if folder is from Nested Share Folder
                            is_nested_share = hasattr(params, 'nested_share_folders') and f.uid in params.nested_share_folders
                            source = 'nested_share_folder' if is_nested_share else 'classic_folder'
                            row = ['folder', f.uid, f.name, f'Flags: {folder_flags(f)}, Parent: {f.parent_uid or "/"}', source]
                            combined_table.append(row)
                    
                    if len(records) > 0:
                        for record in records:
                            source = FolderListCommand._record_source(params, record.record_uid)
                            row = ['record', record.record_uid, record.title, 
                                   f'Type: {record.record_type}, Description: {vault_extensions.get_record_description(record)}', source]
                            combined_table.append(row)
                    
                    combined_table.sort(key=lambda x: (x[0], (x[2] or '').lower()))
                    return dump_report_data(combined_table, combined_headers, fmt=fmt, filename=kwargs.get('output'))
                
                else:
                    if len(folders) > 0:
                        table = []
                        headers = ['folder_uid', 'name', 'flags', 'parent_uid', 'source']
                        colors = {}
                        for f in folders:
                            if f.color:
                                colors[f.name] = f.color
                            # Check if folder is from Nested Share Folder
                            is_nested_share = hasattr(params, 'nested_share_folders') and f.uid in params.nested_share_folders
                            source = 'nested_share_folder' if is_nested_share else 'classic_folder'
                            row = [f.uid, f.name, folder_flags(f), f.parent_uid or '/', source]
                            table.append(row)
                        table.sort(key=lambda x: (x[1] or '').lower())
                        # Only apply colorization if not JSON format
                        for i in range(len(table)):
                            name = table[i][1]
                            if name in colors:
                                table[i][1] = display.keeper_colorize(name, colors[name])
                        headers = base.fields_to_titles(headers)
                        dump_report_data(table, headers, row_number=True)
                    
                    if len(records) > 0:
                        table = []
                        headers = ['record_uid', 'type', 'title', 'description', 'source']
                        for record in records:
                            source = FolderListCommand._record_source(params, record.record_uid)
                            row = [record.record_uid, record.record_type, record.title, vault_extensions.get_record_description(record), source]
                            table.append(row)
                        table.sort(key=lambda x: (x[2] or '').lower())
                        headers = base.fields_to_titles(headers)
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
            if folder_name in params.folder_cache or folder_name in params.nested_share_folders:
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
        nsf_shares = kwargs.get('nsf_shares')
        fmt = kwargs.get('format') or 'table'
        show_key = bool(shares or nsf_shares)
        hide_key = kwargs.get('hide_shares_key', not show_key)
        title = kwargs.get('title')
        trees = []
        if folder_name in params.folder_cache:
            folder = params.folder_cache.get(folder_name)
            trees.append(formatted_tree(
                params, folder, verbose=verbose, show_records=records, shares=shares,
                nsf_shares=nsf_shares, hide_shares_key=hide_key, title=title, fmt=fmt))
        else:
            folders, pattern = try_resolve_path(params, folder_name, find_all_matches=True)
            if not pattern:
                for idx, folder in enumerate(folders):
                    trees.append(formatted_tree(
                        params, folder, verbose=verbose, show_records=records, shares=shares,
                        nsf_shares=nsf_shares, hide_shares_key=hide_key or idx > 0, title=title,
                        fmt=fmt))
            else:
                raise CommandError('tree', f'Folder {folder_name} not found')
        if fmt == 'json':
            payload = trees[0] if len(trees) == 1 else {'trees': [t for t in trees if t]}
            text = _tree_json_dumps(payload)
            output = kwargs.get('output')
            if output:
                _, ext = os.path.splitext(output)
                path = output if ext else output + '.json'
                with open(path, 'w', encoding='utf-8') as fd:
                    fd.write(text)
                    fd.write('\n')
                logging.info('Report path: %s', os.path.abspath(path))
                return None
            return text


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
        from ..enforcement import MasterPasswordReentryEnforcer
        if not MasterPasswordReentryEnforcer.check_and_enforce(params, "record_level"):
            raise CommandError('rndir', 'Operation cancelled: Re-authentication failed')

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
        parent_path = get_folder_path(params, base_folder.uid) if base_folder.uid else ''
        path = f'{parent_path}{name}'
        response_data = {'folder_uid': folder_uid, 'name': name, 'path': path}
        logging.info(json.dumps(response_data))
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
        from ..enforcement import MasterPasswordReentryEnforcer
        if not MasterPasswordReentryEnforcer.check_and_enforce(params, "record_level"):
            raise CommandError('rmdir', 'Operation cancelled: Re-authentication failed')

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

                if src_folder.type == BaseFolderNode.NestedShareFolderType:
                    if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        raise CommandError('mv', 'Nested Share Folders cannot be moved inside a Shared folder.')
                    raise CommandError('mv', 'Moving Nested Share Folders is currently not supported.')

                if dst_folder.type == BaseFolderNode.NestedShareFolderType:
                    if src_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        raise CommandError('mv', 'Shared folders cannot be moved inside a Nested Share Folder.')
                    raise CommandError('mv', 'Folders cannot be moved inside a Nested Share Folder.')

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
                if src_folder.type == BaseFolderNode.NestedShareFolderType:
                    raise CommandError('mv', 'Moving Nested Share Folder records is currently not supported.')

                if record_uid in getattr(params, 'nested_share_records', {}) \
                        and dst_folder.type != BaseFolderNode.NestedShareFolderType:
                    raise CommandError(
                        'mv',
                        'Nested Share Records cannot be linked or moved into legacy folders.'
                    )

                if dst_folder.type == BaseFolderNode.NestedShareFolderType:
                    raise CommandError(
                        'mv',
                        'Legacy records cannot be linked or moved into a Nested Share Folder.'
                    )

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
                folders.sort(key=lambda x: x.name or '')
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
                if f.type != BaseFolderNode.UserFolderType:
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


class FolderTransformCommand(Command, RecordMixin):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return transform_parser

    @staticmethod
    def rename_source_folders(params, source_folders):   # type: (KeeperParams, List[str]) -> None
        rename_rqs = []
        for folder_uid in source_folders:
            sub_folder = params.subfolder_cache.get(folder_uid)    # type: Dict
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
                    continue
                rq['shared_folder_uid'] = folder_uid
                shared_folder = params.shared_folder_cache[folder_uid]
                encryption_key = shared_folder['shared_folder_key_unencrypted']
                encrypted_data = shared_folder.get('data')
            elif sub_folder['type'] == 'shared_folder_folder':
                rq['shared_folder_uid'] = sub_folder['shared_folder_uid']
                encryption_key = sub_folder['folder_key_unencrypted']
                encrypted_data = sub_folder.get('data')
            else:
                return

            decrypted_data = crypto.decrypt_aes_v1(utils.base64_url_decode(encrypted_data), encryption_key)
            data = json.loads(decrypted_data)
            folder_name = data.get('name') or ''
            folder_name = f'{folder_name}@delete'
            data['name'] = folder_name
            encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), encryption_key)
            rq['data'] = utils.base64_url_encode(encrypted_data)
            if (sub_folder['type'] == 'shared_folder'):
                rq['name'] = utils.base64_url_encode(crypto.encrypt_aes_v1(folder_name.encode('utf-8'), encryption_key))
            rename_rqs.append(rq)
        try:
            api.execute_batch(params, rename_rqs)
        except Exception as e:
            logging.debug('Error renaming source folders: %s', e)

    @staticmethod
    def move_records(params, folder_map, is_link):   # type: (KeeperParams, Tuple[str, str], bool) -> None
        move_rqs = []    # type: List[Dict]
        record_permissions = {}    # type: Dict[str, Dict[str, Tuple[bool, bool]]]
        def get_record_permissions(sf_uid, r_uid):    # type: (str, str) -> Optional[Tuple[bool, bool]]
            nonlocal record_permissions
            if sf_uid in record_permissions:
                return record_permissions[sf_uid].get(r_uid)

            sf = params.shared_folder_cache.get(sf_uid)
            if sf:
                record_permissions[sf_uid] = {}
                recs = sf.get('records')
                if isinstance(records, dict):
                    for rp in recs:
                        rec_uid = rp.get('record_uid')
                        can_share = rp.get('can_share') or False
                        can_edit = rp.get('can_edit') or False
                        if rec_uid:
                            record_permissions[sf_uid][rec_uid] = (can_edit, can_share)

        for src_folder_uid, dst_folder_uid in folder_map:
            src_folder = params.folder_cache.get(src_folder_uid)
            dst_folder = params.folder_cache.get(dst_folder_uid)
            if not src_folder:
                continue
            if not dst_folder:
                continue
            src_scope = ''
            dst_scope = ''
            if src_folder.type == BaseFolderNode.SharedFolderType:
                src_scope = src_folder.uid
            elif src_folder.type == BaseFolderNode.SharedFolderFolderType:
                src_scope = src_folder.shared_folder_uid

            if dst_folder.type == BaseFolderNode.SharedFolderType:
                dst_scope = dst_folder.uid
            elif dst_folder.type == BaseFolderNode.SharedFolderFolderType:
                dst_scope = dst_folder.shared_folder_uid

            if dst_scope != src_scope:
                if dst_scope:
                    shared_folder = params.shared_folder_cache.get(dst_scope)
                    scope_key = shared_folder['shared_folder_key_unencrypted']
                else:
                    scope_key = params.data_key
            else:
                scope_key = None
            if src_scope:
                src_type = 'shared_folder' if src_folder.type == BaseFolderNode.SharedFolderType else 'shared_folder_folder'
            else:
                src_type = 'user_folder'

            records = list(params.subfolder_record_cache.get(src_folder.uid) or [])
            while len(records) > 0:
                rq = {
                    'command': 'move',
                    'to_type': 'shared_folder_folder' if dst_scope else 'user_folder',
                    'to_uid': dst_folder.uid,
                    'link': is_link,
                    'move': [],
                    'transition_keys': []
                }
                chunk = records[:990]
                records = records[990:]
                for record_uid in chunk:
                    move = {
                        'type': 'record',
                        'uid': record_uid,
                        'from_type': src_type,
                        'from_uid': src_folder_uid,
                        'cascade': False,
                    }
                    if scope_key and src_scope and dst_scope:
                        perms = get_record_permissions(src_scope, record_uid)
                        if isinstance(perms, tuple):
                            move['can_edit'] = perms[0]
                            move['can_reshare'] = perms[1]

                    rq['move'].append(move)
                    if scope_key:
                        record = params.record_cache.get(record_uid)
                        if record:
                            version = record.get('version', 0)
                            record_key = record.get('record_key_unencrypted')
                            if version < 3:
                                transfer_key = crypto.encrypt_aes_v1(record_key, scope_key)
                            else:
                                transfer_key = crypto.encrypt_aes_v2(record_key, scope_key)
                            tko = {
                                'uid': record_uid,
                                'key': utils.base64_url_encode(transfer_key)
                            }
                            rq['transition_keys'].append(tko)
                move_rqs.append(rq)


        while len(move_rqs) > 0:
            record_count = 0
            requests = []
            while len(move_rqs) > 0:
                rq = move_rqs.pop()
                record_rq = len(rq['move'])
                if (record_count + record_rq) > 1000:
                    if record_count > 0:
                        move_rqs.append(rq)
                    else:
                        requests.append(rq)
                    break
                else:
                    requests.append(rq)
            rs = api.execute_batch(params, requests)

    @staticmethod
    def delete_source_tree(params, folders_to_remove):   # type: (KeeperParams, List[str]) -> None
        # chunk into scopes
        folder_by_scope = {}    # type: Dict[str, List[str]]
        for folder_uid in folders_to_remove:
            folder = params.folder_cache.get(folder_uid)  # type: Optional[Union[UserFolderNode, SharedFolderNode, SharedFolderFolderNode]]
            if folder.type == BaseFolderNode.UserFolderType:
                folder_scope = ''
            elif folder.type == BaseFolderNode.SharedFolderType:
                folder_scope = folder.uid
            elif folder.type == BaseFolderNode.SharedFolderFolderType:
                folder_scope = folder.shared_folder_uid
            else:
                continue
            if folder_scope not in folder_by_scope:
                folder_by_scope[folder_scope] = []
            folder_by_scope[folder_scope].append(folder_uid)
        user_folders = folder_by_scope.pop('', None)
        scopes = list(folder_by_scope.values())
        if user_folders:
            scopes.append(user_folders)
        for folders in scopes:
            while len(folders) > 0:
                chunk = folders[-450:]
                folders = folders[:-450]
                folder_roots = set(chunk)
                for folder_uid in chunk:
                    if folder_uid in folder_roots:
                        FolderMixin.traverse_folder_tree(params, folder_uid,
                                                         lambda f: folder_roots.difference_update(f.subfolders or []))
                chunk = [x for x in chunk if x in folder_roots]
                delete_rq = {
                    'command': 'pre_delete',
                    'objects': [],
                }
                for folder_uid in chunk:
                    folder = params.folder_cache.get(folder_uid)
                    if folder is None:
                        continue
                    rq = {
                        'delete_resolution': 'unlink',
                        'object_uid': folder.uid,
                        'object_type': folder.type,
                    }
                    if folder.parent_uid:
                        folder = params.folder_cache.get(folder.parent_uid)
                        if folder:
                            rq['from_uid'] = folder.uid
                            rq['from_type'] = folder.type
                    else:
                        rq['from_type'] = folder.UserFolderType
                    delete_rq['objects'].append(rq)
                try:
                    delete_rs = api.communicate(params, delete_rq)
                except Exception as e:
                    logging.debug('Error deleting source tree: %s', e)
                    continue

                token = ''
                if 'pre_delete_response' in delete_rs:
                    pre_delete = delete_rs['pre_delete_response']
                    if 'pre_delete_token' in pre_delete:
                        token = pre_delete['pre_delete_token']
                if token:
                    delete_rq = {
                        'command': 'delete',
                        'pre_delete_token': token
                    }
                    try:
                        delete_rs = api.communicate(params, delete_rq)
                    except Exception as e:
                        logging.debug('Error deleting source tree: %s', e)

    @staticmethod
    def create_target_folder(params, source_folder_uid, dst_parent_uid, dst_scope_uid, dst_scope_key):
        src_subfolder = params.folder_cache.get(source_folder_uid)
        dst_folder_uid = utils.generate_uid()
        sf = folder_pb2.FolderRequest()
        sf.folderUid = utils.base64_url_decode(dst_folder_uid)
        if dst_scope_uid:
            sf.folderType = folder_pb2.shared_folder_folder
            if dst_parent_uid != dst_scope_uid:
                sf.parentFolderUid = utils.base64_url_decode(dst_parent_uid)
            sf.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(dst_scope_uid)
        else:
            sf.folderType = folder_pb2.user_folder
            sf.parentFolderUid = utils.base64_url_decode(dst_parent_uid)

        subfolder_key = utils.generate_aes_key()
        subfolder_data = {'name': src_subfolder.name}
        sf.folderData = crypto.encrypt_aes_v1(json.dumps(subfolder_data).encode('utf-8'), subfolder_key)
        sf.encryptedFolderKey = crypto.encrypt_aes_v1(subfolder_key, dst_scope_key)
        return sf

    def execute(self, params, **kwargs):  # type: (KeeperParams, Any) -> Any
        target = kwargs.get('target')
        if target:
            target_folder_uid = FolderMixin.resolve_folder(params, target)
            if not target_folder_uid:
                raise CommandError('transform-folder', '"folder" parameter is required')
        else:
            target_folder_uid = None

        source_folder_uids = set()        # type: Set[str]
        folder_names = kwargs.get('folder')
        if not folder_names:
            raise CommandError('transform-folder', '"folder" parameter is required')
        if isinstance(folder_names, str):
            folder_names = [folder_names]
        for folder_name in folder_names:
            folder_uid = FolderMixin.resolve_folder(params, folder_name)
            if not folder_uid:
                raise CommandError('transform-folder', f'Folder "{folder_name}" cannot be found')
            source_folder_uids.add(folder_uid)

        for folder_uid in source_folder_uids:
            src_folder = params.folder_cache.get(folder_uid)   # type: Optional[Union[UserFolderNode, SharedFolderNode, SharedFolderFolderNode]]
            if target_folder_uid and src_folder.parent_uid == target_folder_uid:
                raise CommandError('transform-folder',
                                   f'Folder "{src_folder.uid}" is already in the target')

            while src_folder and src_folder.parent_uid:
                if src_folder.parent_uid in source_folder_uids:
                    raise CommandError('transform-folder',
                                       f'Folder "{src_folder.parent_uid}" is a parent of "{folder_uid}"\n' +
                                       f'Move folder "{folder_uid}" first')
                src_folder = params.folder_cache.get(src_folder.parent_uid)

        is_link = kwargs.get('link') is True

        # create folder structure
        table = []
        headers = ['Source Folder', 'Folder Count', 'Record Count']

        folders_to_remove = []    # type: List[str]
        folders_to_create = []    # type: List[folder_pb2.FolderRequest]
        src_to_dst_map = {}       # type: Dict[str, str]
        for source_uid in source_folder_uids:
            target_scope_uid = ''
            target_scope_key = params.data_key

            source_folder = params.folder_cache.get(source_uid)
            if not source_folder:
                continue
            target_uid = utils.generate_uid()
            target_key = params.data_key
            f = folder_pb2.FolderRequest()
            f.folderUid = utils.base64_url_decode(target_uid)
            folder_key = utils.generate_aes_key()
            data = {'name': source_folder.name}
            f.folderData = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), folder_key)
            if target_folder_uid is None:
                if source_folder.parent_uid:
                    is_target_shared = kwargs.get('folder_type') == 'shared'
                else:
                    is_target_shared = source_folder.type == BaseFolderNode.UserFolderType
                if is_target_shared:
                    f.folderType = folder_pb2.shared_folder
                    f.sharedFolderFields.encryptedFolderName = crypto.encrypt_aes_v1(source_folder.name.encode(), folder_key)
                    target_scope_uid = target_uid
                    target_scope_key = folder_key
                else:
                    f.folderType = folder_pb2.user_folder
            else:
                target_folder = params.folder_cache.get(target_folder_uid)  # type: Optional[BaseFolderNode]
                assert target_folder is not None
                if target_folder.type == BaseFolderNode.UserFolderType:
                    f.folderType = folder_pb2.user_folder
                    target_scope_key = params.data_key
                    f.parentFolderUid = utils.base64_url_decode(target_folder.uid)
                elif target_folder.type == BaseFolderNode.SharedFolderType:
                    f.folderType = folder_pb2.shared_folder_folder
                    shared_folder = params.shared_folder_cache.get(target_folder.uid)
                    if not shared_folder:
                        raise CommandError('transform-folder', f'Shared Folder "{target_folder.uid}" not found')
                    target_scope_key = shared_folder['shared_folder_key_unencrypted']
                    target_scope_uid = target_folder.uid
                    f.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(target_scope_uid)
                    target_key = target_scope_key
                elif target_folder.type == BaseFolderNode.SharedFolderFolderType:
                    f.folderType = folder_pb2.shared_folder_folder
                    target_scope_uid = target_folder.shared_folder_uid
                    shared_folder = params.shared_folder_cache.get(target_scope_uid)
                    if not shared_folder:
                        raise CommandError('transform-folder', f'Shared Folder "{target_folder.uid}" not found')
                    target_scope_key = shared_folder['shared_folder_key_unencrypted']
                    target_key = target_scope_key
                    f.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(target_scope_uid)
                    f.parentFolderUid = utils.base64_url_decode(target_folder.uid)
                else:
                    continue

            f.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, target_key)
            folders_to_create.append(f)
            folders_to_remove.append(source_uid)
            src_to_dst_map[source_uid] = target_uid

            subfolder_count = 0
            record_count = 0
            source_folder = params.folder_cache.get(source_uid)  # type: Optional[BaseFolderNode]
            if source_folder is None:
                continue


            def add_subfolders(folder):    # type: (BaseFolderNode) -> None
                nonlocal subfolder_count
                nonlocal record_count
                subfolder_count += 1
                records = params.subfolder_record_cache.get(folder.uid)
                if isinstance(records, set):
                    record_count += len(records)

                dst_folder_uid = src_to_dst_map.get(folder.uid)
                if dst_folder_uid:
                    for src_subfolder_uid in folder.subfolders:
                        folder_rq = self.create_target_folder(
                            params, src_subfolder_uid, dst_folder_uid, target_scope_uid, target_scope_key)
                        dst_subfolder_uid = utils.base64_url_encode(folder_rq.folderUid)
                        folders_to_create.append(folder_rq)
                        folders_to_remove.append(src_subfolder_uid)
                        src_to_dst_map[src_subfolder_uid] = dst_subfolder_uid

            FolderMixin.traverse_folder_tree(params, source_uid, add_subfolders)

            table.append([get_folder_path(params, source_uid), subfolder_count, record_count])

        # Display statistics
        operation = 'copied' if is_link else 'moved'
        target_name = get_folder_path(params, target_folder_uid) if target_folder_uid else 'My Vault'
        title = f'The following folders will be {operation} to "{target_name}"'
        base.dump_report_data(table, headers=headers, title=title)
        if kwargs.get('dry_run') is True:
            return
        if kwargs.get('force') is not True:
            inp = user_choice('Are you sure you want to proceed with this action?', 'yn', default='n')
            if inp.lower() == 'y':
                logging.info('Executing transformation(s)...')
            else:
                logging.info('Cancelled.')
                return

        while len(folders_to_create) > 0:
            chunk = folders_to_create[:990]
            folders_to_create = folders_to_create[990:]
            rq = folder_pb2.ImportFolderRecordRequest()
            for e in chunk:
                rq.folderRequest.append(e)
            rs = api.communicate_rest(params, rq, 'folder/import_folders_and_records', rs_type=folder_pb2.ImportFolderRecordResponse)
            errors = [x for x in rs.folderResponse if x.status.upper() != 'SUCCESS']
            if len(errors) > 0:
                raise CommandError('transform-folder',
                                   f'Failed to re-create folder structure: {errors[0].status}')
        api.sync_down(params)

        # Rename source folders
        if not is_link:
            self.rename_source_folders(params, source_folder_uids)
            api.sync_down(params)

        # Move records
        self.move_records(params, src_to_dst_map.items(), is_link)
        api.sync_down(params)

        # Delete source tree
        if not is_link:
            self.delete_source_tree(params, folders_to_remove)

        api.sync_down(params)


def _resolve_tree_team_name(params, team_uid):
    if params.enterprise:
        for t in params.enterprise.get('teams') or []:
            if t.get('team_uid') == team_uid:
                name = t.get('name')
                if name:
                    return name
    return team_uid


def _is_compact_share_entry(obj):
    """True for leaf share objects like {email, permissions} / {name, uid, permissions}."""
    if not isinstance(obj, dict) or not obj:
        return False
    allowed = {'email', 'name', 'uid', 'permissions'}
    if set(obj.keys()) - allowed:
        return False
    for k, v in obj.items():
        if k == 'permissions':
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                return False
        elif not isinstance(v, str):
            return False
    return True


def _dump_compact_share_entry(obj):
    """Dump a share entry on one line; keep field order name/email, uid, permissions."""
    parts = []
    for key in ('name', 'email', 'uid', 'permissions'):
        if key not in obj:
            continue
        val = obj[key]
        if key == 'permissions':
            inner = ', '.join(json.dumps(x) for x in val)
            parts.append(f'"{key}": [{inner}]')
        else:
            parts.append(f'"{key}": {json.dumps(val)}')
    return '{ ' + ', '.join(parts) + ' }'


def _tree_json_dumps(obj, level=0, indent=2):
    """Pretty JSON with share entries / permission arrays kept on one line."""
    sp = ' ' * (indent * level)
    sp1 = ' ' * (indent * (level + 1))
    if isinstance(obj, dict):
        if not obj:
            return '{}'
        if _is_compact_share_entry(obj):
            return _dump_compact_share_entry(obj)
        lines = ['{']
        items = list(obj.items())
        for i, (k, v) in enumerate(items):
            comma = ',' if i < len(items) - 1 else ''
            dumped = _tree_json_dumps(v, level + 1, indent)
            lines.append(f'{sp1}{json.dumps(k)}: {dumped}{comma}')
        lines.append(sp + '}')
        return '\n'.join(lines)
    if isinstance(obj, list):
        if not obj:
            return '[]'
        if all(isinstance(x, str) for x in obj):
            return '[' + ', '.join(json.dumps(x) for x in obj) + ']'
        if all(_is_compact_share_entry(x) for x in obj):
            lines = ['[']
            for i, x in enumerate(obj):
                comma = ',' if i < len(obj) - 1 else ''
                lines.append(f'{sp1}{_dump_compact_share_entry(x)}{comma}')
            lines.append(sp + ']')
            return '\n'.join(lines)
        lines = ['[']
        for i, x in enumerate(obj):
            comma = ',' if i < len(obj) - 1 else ''
            dumped = _tree_json_dumps(x, level + 1, indent)
            lines.append(f'{sp1}{dumped}{comma}')
        lines.append(sp + ']')
        return '\n'.join(lines)
    return json.dumps(obj)


_NSF_ROLE_ABBREV = {
    'viewer': 'VW',
    'contributor': 'CT',
    'share-manager': 'SM',
    'content-manager': 'CM',
    'content-share-manager': 'CSM',
    'full-manager': 'FM',
    'unresolved': 'UN',
    'owner': 'OW',
}


def _nsf_role_label(accessor):
    from .nested_share_folder.helpers import format_role_display, get_access_role_label
    role = accessor.get('role')
    if role:
        return format_role_display(role)
    return get_access_role_label(accessor) or 'viewer'


def _nsf_role_abbrev(accessor):
    label = _nsf_role_label(accessor)
    return _NSF_ROLE_ABBREV.get(label, (label[:2].upper() if label else 'VW'))


def _looks_like_uid(value):
    if not value or not isinstance(value, str) or '@' in value:
        return False
    # Keeper UIDs are typically 22-char base64url
    return bool(re.fullmatch(r'[A-Za-z0-9_-]{16,28}', value))


def _resolve_nsf_user_email(params, accessor):
    """Resolve AT_USER accessor to an email; never return a raw UID as email."""
    email = (accessor.get('username') or '').strip()
    if email and not _looks_like_uid(email):
        return email
    auid = accessor.get('accessor_uid') or ''
    if not auid:
        return email if email and not _looks_like_uid(email) else ''
    cached = getattr(params, 'user_cache', {}).get(auid) if hasattr(params, 'user_cache') else None
    if cached:
        return cached
    if params.enterprise:
        for u in params.enterprise.get('users') or []:
            if u.get('user_account_uid') == auid and u.get('username'):
                return u.get('username')
    try:
        from ..nested_share_folder.folder_api import _resolve_uid_to_username
        resolved = _resolve_uid_to_username(params, auid)
        if resolved:
            if not hasattr(params, 'user_cache') or params.user_cache is None:
                params.user_cache = {}
            params.user_cache[auid] = resolved
            return resolved
    except Exception as exc:
        logging.debug('NSF user resolve failed for %s: %s', auid, exc)
    return ''


def _resolve_nsf_app_name(params, app_uid):
    if not app_uid:
        return ''
    try:
        from .ksm import KSMCommand
        rec = KSMCommand.get_app_record(params, app_uid)
        if rec:
            data = rec.get('data_unencrypted')
            if data:
                if isinstance(data, (bytes, bytearray)):
                    data = data.decode('utf-8')
                title = json.loads(data).get('title')
                if title:
                    return title
    except Exception as exc:
        logging.debug('NSF app resolve via KSM failed for %s: %s', app_uid, exc)
    if app_uid in (params.record_cache or {}):
        try:
            r = api.get_record(params, app_uid)
            if r and getattr(r, 'title', None):
                return r.title
        except Exception as exc:
            logging.debug('NSF app resolve via record cache failed for %s: %s', app_uid, exc)
    return ''


def _nsf_folder_share_data(params, folder_uid, *, include_uids=False):
    """Return structured NSF folder share perms and a compact text suffix.

    Owner is listed under ``users`` with permission ``OW`` (not a separate label).
    Applications are listed separately (never as fake user emails / UIDs).
    """
    from .. import nested_share_folder as _nsf
    accessors = _nsf.get_nsf_folder_share_accessors(params, folder_uid)
    folder_info = (getattr(params, 'nested_share_folders', {}) or {}).get(folder_uid) or {}
    owner = (folder_info.get('owner_username') or '').strip()
    if owner and _looks_like_uid(owner):
        owner = ''
    users = []
    teams = []
    applications = []
    user_parts = []
    team_parts = []
    app_parts = []
    seen_users = set()

    if owner:
        users.append({'email': owner, 'permissions': ['OW']})
        user_parts.append(f'[{owner}:OW]')
        seen_users.add(owner.lower())

    for a in accessors:
        at = a.get('access_type') or ''
        abbrev = _nsf_role_abbrev(a)
        auid = a.get('accessor_uid') or ''

        if at == 'AT_OWNER':
            if not owner:
                email = _resolve_nsf_user_email(params, a)
                if email and email.lower() not in seen_users:
                    users.append({'email': email, 'permissions': ['OW']})
                    user_parts.append(f'[{email}:OW]')
                    seen_users.add(email.lower())
            continue

        if at == 'AT_TEAM':
            name = _resolve_tree_team_name(params, auid)
            entry = {'name': name, 'permissions': [abbrev]}
            if include_uids and auid:
                entry['uid'] = auid
            teams.append(entry)
            team_parts.append(f'[{name}:{abbrev}]')
            continue

        if at == 'AT_APPLICATION':
            app_name = _resolve_nsf_app_name(params, auid) or (auid if include_uids else 'application')
            entry = {'name': app_name, 'permissions': [abbrev]}
            if include_uids and auid:
                entry['uid'] = auid
            applications.append(entry)
            app_parts.append(f'[{app_name}:{abbrev}]')
            continue

        if at in ('AT_USER', 'AT_UNKNOWN', ''):
            email = _resolve_nsf_user_email(params, a)
            if not email:
                # Unresolved user: only expose UID when -v, never as email.
                if include_uids and auid:
                    entry = {'uid': auid, 'permissions': [abbrev]}
                    users.append(entry)
                    user_parts.append(f'[{auid}:{abbrev}]')
                continue
            if email.lower() in seen_users or email == params.user:
                continue
            users.append({'email': email, 'permissions': [abbrev]})
            user_parts.append(f'[{email}:{abbrev}]')
            seen_users.add(email.lower())

    data = {}
    if users:
        data['users'] = users
    if teams:
        data['teams'] = teams
    if applications:
        data['applications'] = applications
    if not data:
        state = (getattr(params, 'nested_share_folder_sharing_states', {}) or {}).get(folder_uid) or {}
        if state.get('shared') or state.get('count', 0) > 0:
            data['shared'] = True
            data['count'] = state.get('count', 0)

    parts = []
    if user_parts:
        parts.append('users:' + ','.join(user_parts))
    if team_parts:
        parts.append('teams:' + ','.join(team_parts))
    if app_parts:
        parts.append('applications:' + ','.join(app_parts))
    if not parts and data.get('shared'):
        parts.append(f'shared:count={data.get("count", 0)}')
    text = f' ({"; ".join(parts)})' if parts else ''
    return data or None, text


def _classic_folder_share_data(params, sf, *, include_uids=False):
    """Return structured classic SF share perms and compact text suffix.

    Tree text uses a single ``default:`` blob (all default flags).
    JSON splits folder-user defaults vs default record rights:
      - user_permissions: MU / MR (manage users / manage records on the folder)
      - record_permissions: CE / CS (default can-edit / can-share on records)
    Named people/teams remain under ``users`` / ``teams``.
    """
    USER_PERM_KEYS = {
        'manage_users': 'MU',
        'manage_records': 'MR',
        'default_manage_users': 'MU',
        'default_manage_user': 'MU',  # legacy alias if present
        'default_manage_records': 'MR',
    }
    RECORD_PERM_KEYS = {
        'default_can_edit': 'CE',
        'default_can_share': 'CS',
    }
    # Per-user / per-team folder ACL on the shared folder
    MEMBER_PERM_KEYS = {
        'manage_users': 'MU',
        'manage_records': 'MR',
    }

    sf = sf or {}
    user_permissions = [abbr for key, abbr in USER_PERM_KEYS.items() if sf.get(key)]
    # Preserve stable order MU then MR
    user_permissions = [a for a in ('MU', 'MR') if a in user_permissions]
    record_permissions = [abbr for key, abbr in RECORD_PERM_KEYS.items() if sf.get(key)]
    record_permissions = [a for a in ('CE', 'CS') if a in record_permissions]

    default_perms = user_permissions + record_permissions
    if not default_perms:
        default_perms = ['RO']

    users = []
    user_parts = []
    for u in sf.get('users') or []:
        email = u.get('username')
        if not email or email == params.user:
            continue
        privs = [abbr for key, abbr in MEMBER_PERM_KEYS.items() if u.get(key)] or ['RO']
        privs = [a for a in ('MU', 'MR') if a in privs] or ['RO']
        users.append({'email': email, 'permissions': privs})
        user_parts.append(f'[{email}:{",".join(privs)}]')
    teams = []
    team_parts = []
    for t in sf.get('teams') or []:
        name = t.get('name')
        privs = [abbr for key, abbr in MEMBER_PERM_KEYS.items() if t.get(key)] or ['RO']
        privs = [a for a in ('MU', 'MR') if a in privs] or ['RO']
        entry = {'name': name, 'permissions': privs}
        team_uid = t.get('team_uid') or ''
        if include_uids and team_uid:
            entry['uid'] = team_uid
        teams.append(entry)
        team_parts.append(f'[{name}:{",".join(privs)}]')

    data = {
        'user_permissions': user_permissions,
        'record_permissions': record_permissions,
    }
    # Match tree text default:RO when no folder/record default flags are set
    if not user_permissions and not record_permissions:
        data['record_permissions'] = ['RO']
    if users:
        data['users'] = users
    if teams:
        data['teams'] = teams

    # Tree: single default segment (no duplicate "user:")
    parts = ['default:' + ','.join(default_perms)]
    if team_parts:
        parts.append('teams:' + ','.join(team_parts))
    if user_parts:
        parts.append('users:' + ','.join(user_parts))
    return data, f' ({"; ".join(parts)})'


def _classic_record_share_data(params, record_uid, *, include_uids=False):
    """Classic record share perms → structured data + compact text.

    Only direct user shares are listed. Shared-folder inheritance is omitted:
    the tree already places the record under its parent shared folder(s).
    """
    rec = (params.record_cache or {}).get(record_uid) or {}
    shares_data = rec.get('shares') or {}
    users = []
    user_parts = []
    for up in shares_data.get('user_permissions') or []:
        email = up.get('username') or ''
        if not email:
            continue
        if up.get('owner'):
            users.append({'email': email, 'permissions': ['OW']})
            user_parts.append(f'[{email}:OW]')
            continue
        if email == params.user:
            continue
        privs = []
        if up.get('editable'):
            privs.append('CE')
        if up.get('shareable'):
            privs.append('CS')
        if not privs:
            privs = ['RO']
        users.append({'email': email, 'permissions': privs})
        user_parts.append(f'[{email}:{",".join(privs)}]')
    if not users:
        return None, ''
    data = {'users': users}
    text = f' (users:{",".join(user_parts)})'
    return data, text


def _nsf_record_share_data(params, record_uid, *, include_uids=False):
    """NSF record share perms → structured data + compact text.

    Uses warmed ``nested_share_record_share_cache``. Direct (non-inherited)
    accessors win over folder-inherited rows for the same identity. When the
    record ACL cache is empty, falls back to the parent NSF folder ACL.
    """
    from .. import nested_share_folder as _nsf
    accessors = list(_nsf.get_nsf_record_share_accessors(params, record_uid) or [])
    if not accessors:
        try:
            parent_uids = _nsf.find_nested_share_folders_for_record(params, record_uid) or []
        except Exception as exc:
            logging.debug('NSF parent folder lookup failed for %s: %s', record_uid, exc)
            parent_uids = []
        for fuid in parent_uids:
            data, text = _nsf_folder_share_data(params, fuid, include_uids=include_uids)
            if data:
                return data, text
        return None, ''

    # Direct shares first so inherited folder rows do not hide them.
    accessors.sort(key=lambda a: 1 if a.get('inherited') else 0)

    users = []
    teams = []
    applications = []
    user_parts = []
    team_parts = []
    app_parts = []
    seen_users = set()
    seen_teams = set()
    seen_apps = set()

    for a in accessors:
        at = a.get('access_type') or ''
        abbrev = _nsf_role_abbrev(a)
        auid = a.get('access_type_uid') or a.get('accessor_uid') or ''

        if a.get('owner') or at == 'AT_OWNER':
            email = (a.get('accessor_name') or '').strip()
            if email and _looks_like_uid(email):
                email = ''
            if not email:
                email = _resolve_nsf_user_email(params, {
                    'username': a.get('accessor_name') or a.get('username'),
                    'accessor_uid': auid,
                })
            if email and email.lower() not in seen_users:
                users.append({'email': email, 'permissions': ['OW']})
                user_parts.append(f'[{email}:OW]')
                seen_users.add(email.lower())
            elif not email and include_uids and auid and auid not in seen_users:
                users.append({'uid': auid, 'permissions': ['OW']})
                user_parts.append(f'[{auid}:OW]')
                seen_users.add(auid)
            continue

        if at == 'AT_TEAM':
            if auid and auid in seen_teams:
                continue
            name = _resolve_tree_team_name(params, auid)
            entry = {'name': name, 'permissions': [abbrev]}
            if include_uids and auid:
                entry['uid'] = auid
            teams.append(entry)
            team_parts.append(f'[{name}:{abbrev}]')
            if auid:
                seen_teams.add(auid)
            continue

        if at == 'AT_APPLICATION':
            if auid and auid in seen_apps:
                continue
            app_name = _resolve_nsf_app_name(params, auid) or (auid if include_uids else 'application')
            entry = {'name': app_name, 'permissions': [abbrev]}
            if include_uids and auid:
                entry['uid'] = auid
            applications.append(entry)
            app_parts.append(f'[{app_name}:{abbrev}]')
            if auid:
                seen_apps.add(auid)
            continue

        email = (a.get('accessor_name') or '').strip()
        if email and _looks_like_uid(email):
            email = ''
        if not email:
            email = _resolve_nsf_user_email(params, {
                'username': a.get('accessor_name') or a.get('username'),
                'accessor_uid': auid,
            })
        if not email:
            if include_uids and auid and auid not in seen_users:
                users.append({'uid': auid, 'permissions': [abbrev]})
                user_parts.append(f'[{auid}:{abbrev}]')
                seen_users.add(auid)
            continue
        if email.lower() in seen_users or email == params.user:
            continue
        users.append({'email': email, 'permissions': [abbrev]})
        user_parts.append(f'[{email}:{abbrev}]')
        seen_users.add(email.lower())

    data = {}
    if users:
        data['users'] = users
    if teams:
        data['teams'] = teams
    if applications:
        data['applications'] = applications
    if not data:
        try:
            parent_uids = _nsf.find_nested_share_folders_for_record(params, record_uid) or []
        except Exception as exc:
            logging.debug('NSF parent folder lookup failed for %s: %s', record_uid, exc)
            parent_uids = []
        for fuid in parent_uids:
            folder_data, folder_text = _nsf_folder_share_data(
                params, fuid, include_uids=include_uids)
            if folder_data:
                return folder_data, folder_text
        return None, ''

    parts = []
    if user_parts:
        parts.append('users:' + ','.join(user_parts))
    if team_parts:
        parts.append('teams:' + ','.join(team_parts))
    if app_parts:
        parts.append('applications:' + ','.join(app_parts))
    text = f' ({"; ".join(parts)})' if parts else ''
    return data, text


def _join_tree_path(parent_path, name):
    name = name or ''
    if not parent_path or parent_path == '/':
        return '/' + name if name else '/'
    return parent_path.rstrip('/') + '/' + name


def _collect_tree_share_targets(params, folder, show_records):
    """Collect NSF folder UIDs and record UIDs under *folder* for ACL warming."""
    nsf_folder_uids = set()
    classic_record_uids = set()
    nsf_record_uids = set()
    nsf_folders = getattr(params, 'nested_share_folders', {}) or {}
    nsf_records = getattr(params, 'nested_share_records', {}) or {}
    nsf_folder_records = getattr(params, 'nested_share_folder_records', {}) or {}
    visited = set()

    def walk(node):
        if isinstance(node, Record):
            ruid = node.record_uid
            if ruid in nsf_records:
                nsf_record_uids.add(ruid)
            else:
                classic_record_uids.add(ruid)
            return

        node_uid = node.uid if hasattr(node, 'uid') else ''
        walk_key = node_uid or id(node)
        if walk_key in visited:
            return
        visited.add(walk_key)

        is_nsf = (
            (hasattr(node, 'type') and node.type == 'nested_share_folder')
            or (node_uid and node_uid in nsf_folders)
        )
        if is_nsf and node_uid:
            nsf_folder_uids.add(node_uid)

        dir_nodes = []
        if hasattr(node, 'subfolders'):
            dir_nodes = [params.folder_cache.get(fuid) for fuid in node.subfolders if params.folder_cache.get(fuid)]

        is_root = (isinstance(node, BaseFolderNode) and (node.type == '/' or node_uid == '')) or (
            hasattr(node, 'type') and node.type == 'nested_share_folder' and not node_uid)

        if is_root and nsf_folders:
            for nsf_uid, nsf_folder in nsf_folders.items():
                parent_uid = nsf_folder.get('parent_uid')
                is_root_folder = (
                    parent_uid is None or parent_uid == '' or parent_uid == 'root'
                    or parent_uid == 'AAAAAAAAAAAAAAAAAPmtNA'
                    or (parent_uid and parent_uid not in nsf_folders)
                )
                if not is_root_folder:
                    continue
                nsf_folder_uids.add(nsf_uid)
                if nsf_uid in params.folder_cache:
                    dir_nodes.append(params.folder_cache.get(nsf_uid))
                else:
                    dir_nodes.append(type('FolderNode', (), {
                        'uid': nsf_uid, 'name': nsf_folder.get('name', ''),
                        'type': 'nested_share_folder', 'subfolders': []
                    })())
        elif node_uid and nsf_folders:
            for child_uid, child_folder in nsf_folders.items():
                if child_folder.get('parent_uid', '') == node_uid:
                    nsf_folder_uids.add(child_uid)
                    if child_uid in params.folder_cache:
                        dir_nodes.append(params.folder_cache.get(child_uid))
                    else:
                        dir_nodes.append(type('FolderNode', (), {
                            'uid': child_uid, 'name': child_folder.get('name', ''),
                            'type': 'nested_share_folder', 'subfolders': []
                        })())

        if show_records and isinstance(node, BaseFolderNode):
            node_uid_for_recs = '' if node.type == '/' else node.uid
            rec_uids = {rec for recs in get_contained_record_uids(params, node_uid_for_recs).values() for rec in recs}
            for ruid in rec_uids:
                if ruid in nsf_records:
                    nsf_record_uids.add(ruid)
                else:
                    classic_record_uids.add(ruid)
            if is_root:
                shown = set(rec_uids)
                for folder_uid, nsf_rec_uids in nsf_folder_records.items():
                    if folder_uid not in nsf_folders:
                        for ruid in nsf_rec_uids:
                            if ruid not in shown:
                                nsf_record_uids.add(ruid)
                                shown.add(ruid)
                all_filed = set()
                for uids in nsf_folder_records.values():
                    all_filed.update(uids)
                for ruid in nsf_records:
                    if ruid not in all_filed and ruid not in shown:
                        nsf_record_uids.add(ruid)
            elif node_uid_for_recs in nsf_folder_records:
                for ruid in nsf_folder_records[node_uid_for_recs]:
                    nsf_record_uids.add(ruid)
        elif show_records and is_nsf and node_uid and node_uid in nsf_folder_records:
            # Temp NSF nodes are not BaseFolderNode; still warm their records.
            for ruid in nsf_folder_records[node_uid]:
                nsf_record_uids.add(ruid)

        for child in dir_nodes:
            if child:
                walk(child)

    walk(folder)
    return nsf_folder_uids, classic_record_uids, nsf_record_uids


def formatted_tree(params, folder, verbose=False, show_records=False, shares=False,
                   nsf_shares=False, hide_shares_key=False, title=None, fmt='table'):
    as_json = (fmt == 'json')
    need_nsf_folders = bool(nsf_shares)
    need_nsf_records = bool(nsf_shares and show_records)
    need_classic_records = bool(shares and show_records)
    if need_nsf_folders or need_nsf_records or need_classic_records:
        nsf_folder_uids, classic_record_uids, nsf_record_uids = _collect_tree_share_targets(
            params, folder, show_records)
        from .. import nested_share_folder as _nsf
        _nsf.warm_for_tree(
            params,
            nsf_folder_uids=nsf_folder_uids if need_nsf_folders else None,
            classic_record_uids=classic_record_uids if need_classic_records else None,
            nsf_record_uids=nsf_record_uids if need_nsf_records else None,
        )

    def print_share_permissions_key():
        lines = [
            'Share Permissions Key:',
            '======================',
        ]
        if shares:
            lines.extend([
                'RO = Read-Only',
                'MU = Can Manage Users',
                'MR = Can Manage Records',
                'CE = Can Edit',
                'CS = Can Share',
                'OW = Owner',
            ])
        if nsf_shares:
            lines.extend([
                'OW = NSF Owner',
                'VW = NSF Viewer',
                'CT = NSF Contributor',
                'SM = NSF Share Manager',
                'CM = NSF Content Manager',
                'CSM = NSF Content + Share Manager',
                'FM = NSF Full Manager',
            ])
        lines.append('======================')
        print('\n'.join(lines) + '\n')

    def tree_node(node, parent_path=''):
        node_uid = node.record_uid if isinstance(node, Record) else (node.uid if hasattr(node, 'uid') else '')
        node_name = node.title if isinstance(node, Record) else (node.name if hasattr(node, 'name') else 'Unknown')

        is_nested_share = False
        if isinstance(node, Record):
            is_nested_share = hasattr(params, 'nested_share_records') and node.record_uid in params.nested_share_records
        elif hasattr(node, 'type') and node.type == 'nested_share_folder':
            is_nested_share = True
        elif isinstance(node, BaseFolderNode) and not isinstance(node, Record):
            is_nested_share = hasattr(params, 'nested_share_folders') and node_uid in params.nested_share_folders
            if is_nested_share and node_uid in params.nested_share_folders:
                nsf_folder_name = params.nested_share_folders[node_uid].get('name', node_name)
                if nsf_folder_name:
                    node_name = nsf_folder_name

        base_name = node_name
        if is_nested_share and not isinstance(node, Record) and node_uid in getattr(params, 'nested_share_folders', {}):
            base_name = params.nested_share_folders[node_uid].get('name') or base_name

        is_vault_root = isinstance(node, BaseFolderNode) and (getattr(node, 'type', None) == '/' or not node_uid)
        if is_vault_root and not isinstance(node, Record):
            node_path = '/'
        else:
            node_path = _join_tree_path(parent_path, base_name)

        display_name = f'{node_name} ({node_uid})' if verbose else node_name
        share_text = ''
        share_data = None
        kind = 'folder'
        record_type = None

        if isinstance(node, Record):
            kind = 'nested_record' if is_nested_share else 'record'
            record_type = getattr(node, 'record_type', None) or ''
            type_label = f' [{record_type}]' if record_type else ''
            nsf_label = ' [Nested Record]' if is_nested_share else ' [Record]'
            if is_nested_share and nsf_shares:
                share_data, share_text = _nsf_record_share_data(
                    params, node_uid, include_uids=verbose)
            elif (not is_nested_share) and shares:
                share_data, share_text = _classic_record_share_data(
                    params, node_uid, include_uids=verbose)
            display_name = f'{Style.DIM}{display_name}{type_label}{nsf_label}{share_text}{Style.NORMAL}'
        elif isinstance(node, SharedFolderNode):
            kind = 'shared_folder'
            if shares:
                share_data, share_text = _classic_folder_share_data(
                    params, params.shared_folder_cache.get(node.uid), include_uids=verbose)
            display_name = f'{display_name}{Style.BRIGHT} [SHARED]{Style.NORMAL}{share_text}'
        elif is_nested_share:
            kind = 'nested_share_folder'
            if nsf_shares and node_uid:
                share_data, share_text = _nsf_folder_share_data(
                    params, node_uid, include_uids=verbose)
            display_name = f'{display_name}{Style.BRIGHT} [Nested Share Folder]{Style.NORMAL}{share_text}'

        dir_nodes = []
        if not isinstance(node, Record):
            if hasattr(node, 'subfolders'):
                dir_nodes = [params.folder_cache.get(fuid) for fuid in node.subfolders if params.folder_cache.get(fuid)]

        is_root = (isinstance(node, BaseFolderNode) and (node.type == '/' or node_uid == '')) or \
                  (hasattr(node, 'type') and node.type == 'nested_share_folder' and not node_uid)

        if is_root and hasattr(params, 'nested_share_folders') and params.nested_share_folders:
            for nsf_uid, nsf_folder in params.nested_share_folders.items():
                parent_uid = nsf_folder.get('parent_uid')
                is_root_folder = (
                    parent_uid is None or
                    parent_uid == '' or
                    parent_uid == 'root' or
                    parent_uid == 'AAAAAAAAAAAAAAAAAPmtNA' or
                    (parent_uid and parent_uid not in params.nested_share_folders)
                )
                if is_root_folder:
                    already_added = any(hasattr(n, 'uid') and n.uid == nsf_uid for n in dir_nodes if n)
                    if not already_added:
                        if nsf_uid in params.folder_cache:
                            nsf_node = params.folder_cache.get(nsf_uid)
                            if nsf_node:
                                dir_nodes.append(nsf_node)
                        else:
                            temp_node = type('FolderNode', (), {
                                'uid': nsf_uid,
                                'name': nsf_folder.get('name', 'Unnamed'),
                                'type': 'nested_share_folder',
                                'subfolders': []
                            })()
                            dir_nodes.append(temp_node)

        elif not isinstance(node, Record) and hasattr(params, 'nested_share_folders') and node_uid:
            for child_uid, child_folder in params.nested_share_folders.items():
                parent_uid = child_folder.get('parent_uid', '')
                if parent_uid == node_uid:
                    already_added = any(hasattr(n, 'uid') and n.uid == child_uid for n in dir_nodes if n)
                    if not already_added:
                        if child_uid in params.folder_cache:
                            child_node = params.folder_cache.get(child_uid)
                            if child_node:
                                dir_nodes.append(child_node)
                        else:
                            temp_node = type('FolderNode', (), {
                                'uid': child_uid,
                                'name': child_folder.get('name', 'Unnamed'),
                                'type': 'nested_share_folder',
                                'subfolders': []
                            })()
                            dir_nodes.append(temp_node)

        rec_nodes = []
        if show_records and isinstance(node, BaseFolderNode):
            node_uid_for_recs = '' if node.type == '/' else node.uid
            rec_uids = {rec for recs in get_contained_record_uids(params, node_uid_for_recs).values() for rec in recs}
            records = [api.get_record(params, rec_uid) for rec_uid in rec_uids]
            records = [r for r in records if isinstance(r, Record)]
            rec_nodes.extend(records)

            if hasattr(params, 'nested_share_folder_records'):
                if is_root:
                    nsf_folders = getattr(params, 'nested_share_folders', {})
                    shown_rec_uids = set(rec_uids)
                    for folder_uid, nsf_rec_uids in params.nested_share_folder_records.items():
                        if folder_uid not in nsf_folders:
                            for rec_uid in nsf_rec_uids:
                                if rec_uid not in shown_rec_uids:
                                    rec = api.get_record(params, rec_uid)
                                    if isinstance(rec, Record):
                                        rec_nodes.append(rec)
                                        shown_rec_uids.add(rec_uid)
                    if hasattr(params, 'nested_share_records'):
                        all_filed = set()
                        for uids in params.nested_share_folder_records.values():
                            all_filed.update(uids)
                        for rec_uid in params.nested_share_records:
                            if rec_uid not in all_filed and rec_uid not in shown_rec_uids:
                                rec = api.get_record(params, rec_uid)
                                if isinstance(rec, Record):
                                    rec_nodes.append(rec)
                                    shown_rec_uids.add(rec_uid)
                elif node_uid_for_recs in params.nested_share_folder_records:
                    nsf_rec_uids = params.nested_share_folder_records[node_uid_for_recs]
                    for rec_uid in nsf_rec_uids:
                        if rec_uid not in rec_uids:
                            rec = api.get_record(params, rec_uid)
                            if isinstance(rec, Record):
                                rec_nodes.append(rec)

        dir_nodes.sort(key=lambda f: f.name.lower() if f.name else '', reverse=False)
        rec_nodes.sort(key=lambda r: r.title.lower(), reverse=False)
        child_nodes = dir_nodes + rec_nodes

        child_path = '' if is_vault_root else node_path
        child_results = [tree_node(n, child_path) for n in child_nodes]
        ascii_children = OrderedDict((disp, br) for disp, br, _ in child_results)

        # Nested JSON node (omit empty children; uid only with -v)
        item = {'name': base_name, 'path': node_path}
        if verbose and node_uid:
            item['uid'] = node_uid
        item['kind'] = kind
        if record_type:
            item['record_type'] = record_type
        if share_data:
            item['share_permissions'] = share_data
        json_children = [jr for _, _, jr in child_results if jr]
        if json_children:
            item['children'] = json_children
        return display_name, ascii_children, item

    root_name, branches, json_root = tree_node(folder, '')
    payload = {'tree': json_root}
    if title:
        payload['title'] = title
    if (shares or nsf_shares) and not hide_shares_key:
        key = {}
        if shares:
            key['classic'] = {
                'RO': 'Read-Only', 'MU': 'Can Manage Users', 'MR': 'Can Manage Records',
                'CE': 'Can Edit', 'CS': 'Can Share', 'OW': 'Owner',
            }
        if nsf_shares:
            key['nsf'] = {
                'OW': 'Owner', 'VW': 'Viewer', 'CT': 'Contributor', 'SM': 'Share Manager',
                'CM': 'Content Manager', 'CSM': 'Content + Share Manager', 'FM': 'Full Manager',
            }
        payload['share_permissions_key'] = key

    if as_json:
        return payload

    tr = LeftAligned(draw=BoxStyle(gfx=drawing.BOX_LIGHT))
    if (shares or nsf_shares) and not hide_shares_key:
        print_share_permissions_key()
    if title:
        print(title)
    tree_txt = tr({root_name: branches})
    tree_txt = re.sub(r'\s+\(\)', '', tree_txt)
    print(tree_txt)
    print('')
    return None
