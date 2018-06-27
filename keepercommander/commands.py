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
import shlex
import re
import fnmatch
import shutil
import functools
import os
import json

from keepercommander.subfolder import try_resolve_path
from keepercommander import api
from keepercommander import display
from keepercommander.subfolder import BaseFolderNode, get_folder_path, find_folders
from keepercommander.record import Record
from keepercommander import generator

def raise_parse_exception(m):
    raise Exception(m)


def suppress_exit():
    raise Exception()


def register_commands(commands):
    commands['ls'] = FolderListCommand()
    commands['cd'] = FolderCdCommand()
    commands['tree'] = FolderTreeCommand()
    commands['mkdir'] = FolderMakeCommand()
    commands['rmdir'] = FolderRemoveCommand()
    commands['mv'] = FolderMoveCommand()
    commands['ln'] = commands['mv']
    commands['add'] = RecordAddCommand()
    commands['rm'] = RecordRemoveCommand()


ls_parser = argparse.ArgumentParser(prog='ls')
ls_parser.add_argument('-l', '--list', dest='detail', action='store_true', help='show detailed list')
ls_parser.add_argument('-f', '--folders', dest='folders', action='store_true', help='display folders')
ls_parser.add_argument('-r', '--records', dest='records', action='store_true', help='display records')
ls_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
ls_parser.error = raise_parse_exception
ls_parser.exit = suppress_exit


cd_parser = argparse.ArgumentParser(prog='cd|tree')
cd_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder name')
cd_parser.error = raise_parse_exception
cd_parser.exit = suppress_exit


rmdir_parser = argparse.ArgumentParser(prog='rmdir')
rmdir_parser.add_argument('-f', '--force', dest='force', action='store_true', help='remove folder without prompting')
rmdir_parser.add_argument('name', nargs='?', type=str, action='store', help='folder path')
rmdir_parser.error = raise_parse_exception
rmdir_parser.exit = suppress_exit


mkdir_parser = argparse.ArgumentParser(prog='mkdir')
mkdir_parser.add_argument('--shared', dest='shared_folder', action='store_true', help='create shared folder')
mkdir_parser.add_argument('--user', dest='user_folder', action='store_true', help='create user folder')
mkdir_parser.add_argument('-a', '--all', dest='grant', action='store_true', help='anyone has all permissions by default')
mkdir_parser.add_argument('-u', '--manage-users', dest='manage_users', action='store_true', help='anyone can manage users by default')
mkdir_parser.add_argument('-r', '--manage-records', dest='manage_records', action='store_true', help='anyone can manage records by default')
mkdir_parser.add_argument('-s', '--can-share', dest='can_share', action='store_true', help='anyone can share records by default')
mkdir_parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true', help='anyone can edit records by default')
mkdir_parser.add_argument('name', nargs='?', type=str, action='store', help='folder path')
mkdir_parser.error = raise_parse_exception
mkdir_parser.exit = suppress_exit


mv_parser = argparse.ArgumentParser(prog='mv|ln')
mv_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
mv_parser.add_argument('-s', '--can-reshare', dest='can_reshare', action='store_true', help='anyone can reshare records')
mv_parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true', help='anyone can edit records')
mv_parser.add_argument('src', nargs='?', type=str, action='store', help='source path')
mv_parser.add_argument('dst', nargs='?', type=str, action='store', help='destination folder')
mv_parser.error = raise_parse_exception
mv_parser.exit = suppress_exit


add_parser = argparse.ArgumentParser(prog='add')
add_parser.add_argument('--login', dest='login', action='store', help='login name')
add_parser.add_argument('--password', dest='password', action='store', help='password')
add_parser.add_argument('--url', dest='url', action='store', help='url')
add_parser.add_argument('--notes', dest='notes', action='store', help='notes')
add_parser.add_argument('--custom', dest='custom', action='store', help='comma separated key-value pairs')
add_parser.add_argument('--folder', dest='folder', action='store', help='folder where record is to be created')
add_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for omitted fields')
add_parser.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate random password')
add_parser.add_argument('title', type=str, action='store', help='record title')
add_parser.error = raise_parse_exception
add_parser.exit = suppress_exit


rm_parser = argparse.ArgumentParser(prog='rm')
rm_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
rm_parser.add_argument('name', nargs='?', type=str, action='store', help='record path')
rm_parser.error = raise_parse_exception
rm_parser.exit = suppress_exit


class Command:
    def execute(self, params, args, **kwargs):
        raise NotImplemented()


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

    def execute(self, params, args, **kwargs):
        try:
            opts, _ = ls_parser.parse_known_args(shlex.split(args))
            if opts.folders == False and opts.records == False:
                opts.folders = True
                opts.records = True

            folder = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder
            pattern = '*'
            if opts.pattern is not None:
                rs = try_resolve_path(params, opts.pattern)
                if rs is not None:
                    folder, pattern = rs
                else:
                    pattern = opts.pattern

            regex = None
            if len(pattern) > 0:
                regex = re.compile(fnmatch.translate(pattern)).match

            folders = []
            records = []

            if opts.folders:
                for uid in folder.subfolders:
                    f = params.folder_cache[uid]
                    if any(filter(lambda x: regex(x) is not None, FolderListCommand.folder_match_strings(f))) if regex is not None else True:
                        folders.append(f)

            if opts.records:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for uid in params.subfolder_record_cache[folder_uid]:
                        r = api.get_record(params, uid)
                        if any(filter(lambda x: regex(x) is not None, FolderListCommand.record_match_strings(r))) if regex is not None else True:
                            records.append(r)

            if len(folders) == 0 and len(records) == 0:
                if len(pattern) > 0:
                    pass
                    #print("ls: {0}: No such folder or record".format(opts.pattern or ''))
            else:
                if opts.detail:
                    if len(folders) > 0:
                        display.formatted_folders(folders)
                    if len(records) > 0:
                        display.formatted_records(records, params=params)
                else:
                    names = []
                    for f in folders:
                        name = f.name
                        if len(name) > 40:
                            name = name[:25] + '...' + name[-12:]
                        if f.type == BaseFolderNode.SharedFolderType:
                            name = name + '$'
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

                    width, _ = shutil.get_terminal_size()
                    max_name = functools.reduce(lambda val, elem: len(elem) if len(elem) > val else val, names, 0)
                    max_name = max_name
                    cols = width // max_name
                    if cols == 0:
                        cols = 1

                    if cols > 3:
                        max_name = max_name + 2
                        cols = width // max_name

                    tbl = FolderListCommand.chunk_list([x.ljust(max_name) for x in names], cols)
                    #print(tabulate(tbl, tablefmt='plain'))

                    rows = ['  '.join(x) for x in tbl]
                    print('\n'.join(rows))



        except Exception as e:
            print(e)


class FolderCdCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts, _ = cd_parser.parse_known_args(shlex.split(args))
            if opts.folder is not None:
                rs = try_resolve_path(params, opts.folder)
                if rs is not None:
                    folder, pattern = rs
                    if len(pattern) == 0:
                        params.current_folder = folder.uid
                    else:
                        print('cd: Folder {0} not found'.format(opts.folder))

        except Exception as e:
            print(e)


class FolderTreeCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts, _ = cd_parser.parse_known_args(shlex.split(args))
            rs = try_resolve_path(params, opts.folder or '')
            if rs is not None:
                folder, pattern = rs
                if len(pattern) == 0:
                    display.formatted_tree(params,  folder)
                else:
                    print('cd: Folder {0} not found'.format(opts.folder))

        except Exception as e:
            print(e)


class FolderMakeCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts = mkdir_parser.parse_args(shlex.split(args))

            base_folder = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder

            name = None
            if opts.name is not None:
                rs = try_resolve_path(params, opts.name)
                if rs is not None:
                    base_folder, name = rs

            request = {"command": "folder_add"}
            if opts.shared_folder:
                if base_folder.type in {BaseFolderNode.RootFolderType, BaseFolderNode.UserFolderType}:
                    request['folder_type'] = 'shared_folder'
                    if opts.grant:
                        request['manage_users'] = True
                        request['manage_records'] = True
                        request['can_edit'] = True
                        request['can_share'] = True
                    else:
                        request['manage_users'] = opts.manage_users or False
                        request['manage_records'] = opts.manage_records or False
                        request['can_share'] = opts.can_share or False
                        request['can_edit'] = opts.can_edit or False
                else:
                    print('Shared folders cannot be nested')
                    return

            elif opts.user_folder:
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
                            if 'r' is s1:
                                request['manage_records'] = True
                            if 'e' is s1:
                                request['can_edit'] = True
                            if 's' is s1:
                                request['can_share'] = True
                else:
                    request['folder_type'] = 'user_folder'

            request['folder_uid'] = api.generate_record_uid()

            folder_key = os.urandom(32)
            encryption_key = params.data_key
            if request['folder_type'] == 'shared_folder_folder':
                if base_folder.type == BaseFolderNode.SharedFolderFolderType:
                    sf = params.folder_cache[base_folder.shared_folder_uid]
                    encryption_key = sf.key
                    request['shared_folder_uid'] = sf.uid
                elif base_folder.type == 'shared_folder':
                    encryption_key = base_folder.key
                    request['shared_folder_uid'] = base_folder.uid

            request['key'] = api.encrypt_aes(folder_key, encryption_key)
            if base_folder.type not in {BaseFolderNode.RootFolderType, BaseFolderNode.SharedFolderType}:
                request['parent_uid'] = base_folder.uid

            if len(name.strip()) == 0 and opts.name is not None:
                print('Folder "{0}" already exists'.format(opts.name))
                return

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

        except Exception as e:
            print(e)


class FolderRemoveCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts = rmdir_parser.parse_args(shlex.split(args))

            folder = None
            if opts.name is not None:
                rs = try_resolve_path(params, opts.name)
                if rs is not None:
                    folder, name = rs
                    if len(name or '') > 0:
                        folder = None

            if folder.type == BaseFolderNode.RootFolderType:
                folder = None

            if folder is None:
                print('Enter name of existing folder')
                return

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

                    np = 'y'
                    if not opts.force:
                        np = user_choice('Do you want to proceed with deletion?', 'yn', default='n')
                    if np.lower() == 'y':
                        rs = api.communicate(params, rq)
                        if rs['result'] != 'success':
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
                    if not opts.force:
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

        except Exception as e:
            print(e)


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

    def execute(self, params, args, **kwargs):
        try:
            opts = mv_parser.parse_args(shlex.split(args))
            if opts.src is None or opts.dst is None:
                mv_parser.print_help()
                return

            src = try_resolve_path(params, opts.src)
            if src is None:
                print('Source path should be existing record or folder')
                return
            src_folder, name = src
            src_record_uid = None
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

            is_link = False
            if 'command' in kwargs:
                is_link = kwargs['command'] == 'ln'

            dst = try_resolve_path(params, opts.dst)
            if dst is None:
                print('Destination path should be existing folder')
                return
            dst_folder, name = dst
            if len(name) > 0:
                print('Destination path should be existing folder')
                return

            rq = {
                'command': 'move',
                'link': is_link,
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
                    print('Cannot move/link folder to self oa a child')
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
                    if opts.can_reshare:
                        move['can_reshare'] = True
                    if opts.can_edit:
                        move['can_edit'] = True
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
        except Exception as e:
            print(e)


class RecordAddCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts = add_parser.parse_args(shlex.split(args))
            if opts.generate:
                opts.password = generator.generate(16)

            if not opts.force:
                if opts.login is None:
                    opts.login = input('...' + 'Login: '.rjust(16))
                if opts.password is None:
                    opts.password = input('...' + 'Password: '.rjust(16))
                if opts.url is None:
                    opts.url = input('...' + 'Login URL: '.rjust(16))

            custom = []
            if opts.custom is not None:
                pairs = opts.custom.split(',')
                for pair in pairs:
                    idx = pair.find(':')
                    if idx > 0:
                        custom.append({
                            'name': pair[:idx].trim(),
                            'value': pair[idx+1:].trim()
                        })

            folder = None
            if opts.folder is not None:
                src = try_resolve_path(params, opts.folder)
                if src is not None:
                    folder, name = src
            if folder is None:
                folder = params.folder_cache[params.current_folder] if len(params.current_folder) > 0 else params.root_folder

            record_key = os.urandom(32)
            rq = {
                'command': 'record_add',
                'record_uid': api.generate_record_uid(),
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
                'title': opts.title,
                'secret1': opts.login or '',
                'secret2': opts.password or '',
                'link': opts.url or '',
                'notes': opts.notes or '',
                'custom': custom
            }
            rq['data'] =  api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key)

            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                params.sync_data = True
            else:
                print(rs['message'])

        except Exception as e:
            print(e)


class RecordRemoveCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts = rm_parser.parse_args(shlex.split(args))

            folder = None
            name = None
            if opts.name is not None:
                rs = try_resolve_path(params, opts.name)
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

                np = 'y'
                if not opts.force:
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

        except Exception as e:
            print(e)


def user_choice(question, choice, default= '', show_choice=True, multi_choice=False):
    choices = [ch.upper() if ch.upper() == default.upper() else ch.lower()  for ch in choice]

    result = ''
    while True:
        pr = question
        if show_choice:
            pr = pr + ' [' + '/'.join(choices) + ']'

        pr = pr + ': '
        result = input(pr)

        if len(result) == 0:
            return default

        if multi_choice:
            s1 = set([x.lower() for x in choices])
            s2 = set([x.lower() for x in result])
            if s2 < s1:
                return ''.join(s2)
            pass
        elif any(map(lambda x: x.upper() == result.upper(), choices)):
            return result

        print('Error: invalid input')
