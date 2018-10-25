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

import argparse
import re
import fnmatch
import shutil
import functools
import os
import json

from .. import api, display
from ..subfolder import BaseFolderNode, try_resolve_path, find_folders
from ..record import Record
from .base import user_choice, suppress_exit, raise_parse_exception, Command


def register_commands(commands):
    commands['ls'] = FolderListCommand()
    commands['cd'] = FolderCdCommand()
    commands['tree'] = FolderTreeCommand()
    commands['mkdir'] = FolderMakeCommand()
    commands['rmdir'] = FolderRemoveCommand()
    commands['mv'] = FolderMoveCommand()
    commands['ln'] = FolderLinkCommand()


def register_command_info(aliases, command_info):
    for p in [cd_parser, ls_parser, tree_parser, mkdir_parser, rmdir_parser, mv_parser, ln_parser]:
        command_info[p.prog] = p.description


ls_parser = argparse.ArgumentParser(prog='ls', description='List folder content')
ls_parser.add_argument('-l', '--list', dest='detail', action='store_true', help='show detailed list')
ls_parser.add_argument('-f', '--folders', dest='folders', action='store_true', help='display folders')
ls_parser.add_argument('-r', '--records', dest='records', action='store_true', help='display records')
ls_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
ls_parser.error = raise_parse_exception
ls_parser.exit = suppress_exit


cd_parser = argparse.ArgumentParser(prog='cd', description='Change current folder')
cd_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or UID')
cd_parser.error = raise_parse_exception
cd_parser.exit = suppress_exit


tree_parser = argparse.ArgumentParser(prog='tree', description='Display folder structure')
tree_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or UID')
tree_parser.error = raise_parse_exception
tree_parser.exit = suppress_exit


rmdir_parser = argparse.ArgumentParser(prog='rmdir', description='Remove folder and its content')
rmdir_parser.add_argument('-f', '--force', dest='force', action='store_true', help='remove folder without prompting')
rmdir_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or UID')
rmdir_parser.error = raise_parse_exception
rmdir_parser.exit = suppress_exit


mkdir_parser = argparse.ArgumentParser(prog='mkdir', description='Create folder')
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


mv_parser = argparse.ArgumentParser(prog='mv', description='Move record or folder')
mv_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
mv_parser.add_argument('-s', '--can-reshare', dest='can_reshare', action='store_true', help='anyone can reshare records')
mv_parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true', help='anyone can edit records')
mv_parser.add_argument('src', nargs='?', type=str, action='store', help='source path to folder/record or UID')
mv_parser.add_argument('dst', nargs='?', type=str, action='store', help='destination folder or UID')
mv_parser.error = raise_parse_exception
mv_parser.exit = suppress_exit


ln_parser = argparse.ArgumentParser(prog='ln', description='Create a link between record or folder')
ln_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
ln_parser.add_argument('-s', '--can-reshare', dest='can_reshare', action='store_true', help='anyone can reshare records')
ln_parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true', help='anyone can edit records')
ln_parser.add_argument('src', nargs='?', type=str, action='store', help='source path to folder/record or UID')
ln_parser.add_argument('dst', nargs='?', type=str, action='store', help='destination folder or UID')
ln_parser.error = raise_parse_exception
ln_parser.exit = suppress_exit


class FolderListCommand(Command):

    @staticmethod
    def folder_match_strings(folder):
        """
        :type folder: BaseFolder
        """
        return filter(lambda f: type(f) == str and len(f) > 0, [folder.name, folder.uid])

    @staticmethod
    def record_match_strings(record):
        """
        :type record: Record
        """
        return filter(lambda f: type(f) == str and len(f) > 0, [record.title, record.record_uid, record.login, record.login_url, record.notes])

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
            regex = re.compile(fnmatch.translate(pattern)).match

        folders = []
        records = []

        if show_folders:
            for uid in folder.subfolders:
                f = params.folder_cache[uid]
                if any(filter(lambda x: regex(x) is not None, FolderListCommand.folder_match_strings(f))) if regex is not None else True:
                    folders.append(f)

        if show_records:
            folder_uid = folder.uid or ''
            if folder_uid in params.subfolder_record_cache:
                for uid in params.subfolder_record_cache[folder_uid]:
                    r = api.get_record(params, uid)
                    if any(filter(lambda x: regex(x) is not None, FolderListCommand.record_match_strings(r))) if regex is not None else True:
                        records.append(r)

        if len(folders) == 0 and len(records) == 0:
            if pattern:
                api.print_error("ls: {0}: No such folder or record".format(pattern))
        else:
            if show_detail:
                if len(folders) > 0:
                    display.formatted_folders(folders)
                if len(records) > 0:
                    display.formatted_records(records, params=params, folder=folder.uid)
            else:
                names = []
                for f in folders:
                    name = f.name
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
                max_name = max_name
                cols = width // max_name
                if cols == 0:
                    cols = 1

                if cols > 3:
                    max_name = max_name + 2
                    cols = width // max_name

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
                        print('cd: Folder {0} not found'.format(folder_name))


class FolderTreeCommand(Command):
    def get_parser(self):
        return tree_parser

    def execute(self, params, **kwargs):
        folder_name = kwargs['folder'] if 'folder' in kwargs else None
        if folder_name in params.folder_cache:
            display.formatted_tree(params, params.folder_cache[folder_name])
        else:
            rs = try_resolve_path(params, folder_name)
            if rs is not None:
                folder, pattern = rs
                if len(pattern) == 0:
                    display.formatted_tree(params, folder)
                else:
                    print('cd: Folder {0} not found'.format(folder_name))


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
                    print('Folder "{0}" already exists'.format(name))
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
                print('Shared folders cannot be nested')
                return

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

        request['folder_uid'] = api.generate_record_uid()

        folder_key = os.urandom(32)
        encryption_key = params.data_key
        if request['folder_type'] == 'shared_folder_folder':
            sf_uid = base_folder.shared_folder_uid if base_folder.type == BaseFolderNode.SharedFolderFolderType else base_folder.uid
            sf = params.shared_folder_cache[sf_uid]
            encryption_key = sf['shared_folder_key']
            request['shared_folder_uid'] = sf_uid

        request['key'] = api.encrypt_aes(folder_key, encryption_key)
        if base_folder.type not in {BaseFolderNode.RootFolderType, BaseFolderNode.SharedFolderType}:
            request['parent_uid'] = base_folder.uid

        name = name or ''
        while len(name.strip()) == 0:
            name = input("... Folder Name: ")

        name = name.strip()

        is_slash = False
        for x in range(0, len(name) -2):
            if name[x] == '/':
                is_slash = not is_slash
            else:
                if is_slash:
                    print('Character "/" is reserved. Use "//" inside folder name')
                    return

        name = name.replace('//', '/')

        if request['folder_type'] == 'shared_folder':
            request['name'] = api.encrypt_aes(name.encode('utf-8'), folder_key)

        data = {'name': name}
        request['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)

        rs = api.communicate(params, request)
        if rs is not None:
            if rs['result'] == 'success':
                params.sync_data = True
            else:
                print(rs['message'])


class FolderRemoveCommand(Command):
    def get_parser(self):
        return rmdir_parser

    def execute(self, params, **kwargs):
        folder = None
        name = kwargs['folder'] if 'folder' in kwargs else None
        if name:
            if name in params.folder_cache:
                folder = params.folder_cache[name]
            else:
                rs = try_resolve_path(params, name)
                if rs is not None:
                    folder, name = rs
                    if len(name or '') > 0:
                        folder = None
                    elif folder.type == BaseFolderNode.RootFolderType:
                        folder = None

        if folder is None:
            print('Enter name of the existing folder')
            return

        force = kwargs['force'] if 'force' in kwargs else None
        parent = params.folder_cache[folder.uid] if folder.uid is not None else None
        if folder.type == BaseFolderNode.SharedFolderType:
            if folder.uid in params.shared_folder_cache:
                sf = params.shared_folder_cache[folder.uid]

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

                np = 'y' if force else user_choice('Do you want to proceed with deletion?', 'yn', default='n')
                if np.lower() == 'y':
                    rs = api.communicate(params, rq)
                    if rs['result'] == 'success':
                        params.sync_data = True
                    else:
                        print(rs['message'])
        else:
            del_obj = {
                'delete_resolution': 'unlink',
                'object_uid': folder.uid,
                'object_type': 'user_folder' if folder.type == BaseFolderNode.UserFolderType else 'shared_folder_folder'
            }
            if parent is None:
                del_obj['from_type'] = 'user_folder'
            else:
                del_obj['from_uid'] = parent.uid
                del_obj['from_type'] = parent.type
                if parent.type == BaseFolderNode.SharedFolderType:
                    del_obj['from_type'] = 'shared_folder_folder'

            rq = {
                'command': 'pre_delete',
                'objects': [del_obj]
            }

            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                pdr = rs['pre_delete_response']

                np = 'y'
                if not force:
                    summary = pdr['would_delete']['deletion_summary']
                    for x in summary:
                        print(x)
                    np = user_choice('Do you like to proceed with deletion?', 'yn', default='n')
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
            else:
                print(rs['message'])


class FolderMoveCommand(Command):

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
                transition_key = api.encrypt_aes(rec['record_key_unencrypted'], encryption_key)
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

        src_record_uid = None
        src_folder = None

        if src_path in params.record_cache:
            src_record_uid = src_path
            if '' in params.subfolder_record_cache:
                if src_record_uid in params.subfolder_record_cache['']:
                    src_folder = params.root_folder
            if src_folder is None:
                for folder_uid in find_folders(params, src_record_uid):
                    src_folder = params.folder_cache[folder_uid]
                    break
            if src_folder is None:
                src_folder = params.root_folder
        elif src_path in params.folder_cache:
            src_folder = params.folder_cache[src_path]
        else:
            src = try_resolve_path(params, src_path)
            if src is None:
                print('Source path should be existing record or folder')
                return

            src_folder, name = src
            if len(name) > 0:
                src_folder_uid = src_folder.uid or ''
                if src_folder_uid in params.subfolder_record_cache:
                    for uid in params.subfolder_record_cache[src_folder_uid]:
                        r = params.record_cache[uid]
                        rec = api.get_record(params, uid)
                        if name in {rec.title, rec.record_uid}:
                            src_record_uid = rec.record_uid
                            break

                if src_record_uid is None:
                    print('Record "{0}" not found'.format(name))
                    return

        dst_folder = None
        if dst_path in params.folder_cache:
            dst_folder = params.folder_cache[dst_path]
        else:
            dst = try_resolve_path(params, dst_path)
            if dst is None:
                print('Destination path should be existing folder')
                return
            dst_folder, name = dst
            if len(name) > 0:
                print('Destination path should be existing folder')
                return

        rq = {
            'command': 'move',
            'link': not self.is_move(),
            'move': []
        }
        if dst_folder.type == BaseFolderNode.RootFolderType:
            rq['to_type'] = BaseFolderNode.UserFolderType
        else:
            rq['to_type'] = dst_folder.type
            rq['to_uid'] =  dst_folder.uid

        if src_record_uid is None:
            ''' folder '''
            if src_folder.type == BaseFolderNode.RootFolderType:
                print('Root folder cannot be a source folder')
                return
            sp = set()
            dp = set()
            f = src_folder
            while f is not None:
                if len(f.uid) > 0:
                    sp.add(f.uid)
                f = params.folder_cache.get(f.parent_uid) if f.parent_uid is not None else None
            f = dst_folder
            while f is not None and f.parent_uid is not None:
                if len(f.uid) > 0:
                    dp.add(f.uid)
                f = params.folder_cache.get(f.parent_uid) if f.parent_uid is not None else None
            if sp <= dp:
                print('Cannot move/link folder to self or a child')
                return

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
                move['from_uid'] =  parent_folder.uid

            rq['move'].append(move)
            transition_keys = []
            if src_folder.type == BaseFolderNode.UserFolderType:
                if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    shf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else dst_folder.shared_folder_uid
                    shf = params.shared_folder_cache[shf_uid]
                    FolderMoveCommand.prepare_transition_keys(params, src_folder, transition_keys, shf['shared_folder_key'])

            elif src_folder.type == BaseFolderNode.SharedFolderFolderType:
                if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                              dst_folder.shared_folder_uid

                    ssf_uid = src_folder.shared_folder_uid
                    if ssf_uid != dsf_uid:
                        dsf = params.shared_folder_cache[dsf_uid]
                        FolderMoveCommand.prepare_transition_keys(params, src_folder, transition_keys, dsf['shared_folder_key'])
                else:
                    FolderMoveCommand.prepare_transition_keys(params, src_folder, transition_keys, params.data_key)

            rq['transition_keys'] = transition_keys
        else:
            move = {
                'uid': src_record_uid,
                'type': 'record',
                'cascade': False
            }
            if src_folder.type == BaseFolderNode.RootFolderType:
                move['from_type'] = BaseFolderNode.UserFolderType
            else:
                move['from_type'] = src_folder.type
                move['from_uid'] =  src_folder.uid
            if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                for flag in ['can_reshare', 'can_edit']:
                    if flag in kwargs and kwargs[flag]:
                        move[flag] = True
            rq['move'].append(move)

            transition_key = None
            rec = params.record_cache[src_record_uid]
            if src_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    ssf_uid = src_folder.uid if src_folder.type == BaseFolderNode.SharedFolderType else \
                        src_folder.shared_folder_uid
                    dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                              dst_folder.shared_folder_uid
                    if ssf_uid != dsf_uid:
                        shf = params.shared_folder_cache[dsf_uid]
                        transition_key = api.encrypt_aes(rec['record_key_unencrypted'], shf['shared_folder_key'])
                else:
                    transition_key = api.encrypt_aes(rec['record_key_unencrypted'], params.data_key)
            else:
                if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                        dst_folder.shared_folder_uid
                    shf = params.shared_folder_cache[dsf_uid]
                    transition_key = api.encrypt_aes(rec['record_key_unencrypted'], shf['shared_folder_key'])

            transition_keys = []
            if transition_key is not None:
                transition_keys.append({
                    'uid': src_record_uid,
                    'key': transition_key
                })
            rq['transition_keys'] = transition_keys

        rs = api.communicate(params, rq)
        if rs['result'] == 'success':
            params.sync_data = True
        else:
            print(rs['message'])


class FolderLinkCommand(FolderMoveCommand):
    def is_move(self):
        return False

    def get_parser(self):
        return ln_parser





