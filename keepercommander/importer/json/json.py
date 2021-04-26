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

import json
import sys

from ..importer import BaseFileImporter, BaseExporter, Record, Folder, SharedFolder, Permission


class KeeperJsonImporter(BaseFileImporter):
    def do_import(self, filename):
        with open(filename, "r", encoding='utf-8') as json_file:
            j = json.load(json_file)
            records = j if type(j) == list else j.get('records')
            folders = None if type(j) == list else j.get('shared_folders')
            if folders:
                for shf in folders:
                    fol = SharedFolder()
                    fol.uid = shf.get('uid')
                    fol.path = shf.get('path')
                    fol.manage_records = shf.get('manage_records') or False
                    fol.manage_users = shf.get('manage_users') or False
                    fol.can_edit = shf.get('can_edit') or False
                    fol.can_share = shf.get('can_share') or False
                    if 'permissions' in shf:
                        fol.permissions = []
                        for perm in shf['permissions']:
                            p = Permission()
                            p.uid = perm.get('uid')
                            p.name = perm.get('name')
                            p.manage_records = perm.get('manage_records') or False
                            p.manage_users = perm.get('manage_users') or False
                            fol.permissions.append(p)

                    yield fol

            if records:
                for r in records:
                    record = Record()
                    record.title = r.get('title')
                    record.login = r.get('login')
                    record.password = r.get('password')
                    record.login_url = r.get('login_url')
                    record.notes = r.get('notes')
                    if 'custom_fields' in r:
                        custom_fields = r['custom_fields']
                        if custom_fields:
                            record.custom_fields.update(custom_fields)
                    if 'folders' in r:
                        record.folders = []
                        for f in r['folders']:
                            folder = Folder()
                            folder.domain = f.get('shared_folder')
                            folder.path = f.get('folder')
                            folder.can_edit = f.get('can_edit')
                            folder.can_share = f.get('can_share')
                            record.folders.append(folder)

                    yield record

    def extension(self):
        return 'json'


class KeeperJsonExporter(BaseExporter):

    def do_export(self, filename, records, file_password):
        sfs = []
        rs = []
        for elem in records:
            if type(elem) == Record:
                r = elem    # type: Record
                ro = {
                    'uid': r.uid or '',
                    'title': r.title or '',
                    'login': r.login or '',
                    'password': r.password or '',
                    'login_url': r.login_url or '',
                    'notes': r.notes or '',
                    'custom_fields': {}
                }
                if r.custom_fields:
                    ro['custom_fields'].update(r.custom_fields)
                if r.folders:
                    ro['folders'] = []
                    for folder in r.folders:
                        if folder.domain or folder.path:
                            fo = {}
                            ro['folders'].append(fo)
                            if folder.domain:
                                fo['shared_folder'] = folder.domain
                            if folder.path:
                                fo['folder'] = folder.path
                            if folder.can_edit:
                                fo['can_edit'] = True
                            if folder.can_share:
                                fo['can_share'] = True
                rs.append(ro)
            elif type(elem) == SharedFolder:
                sf = elem      # type: SharedFolder
                sfo = {
                    'uid': sf.uid,
                    'path': sf.path,
                    'manage_users': sf.manage_users,
                    'manage_records': sf.manage_records,
                    'can_edit': sf.can_edit,
                    'can_share': sf.can_share
                }
                if sf.permissions:
                    sfo['permissions'] = []
                    for perm in sf.permissions:
                        po = {
                            'name': perm.name,
                            'manage_users': perm.manage_users,
                            'manage_records': perm.manage_records
                        }
                        if perm.uid:
                            po['uid'] = perm.uid
                        sfo['permissions'].append(po)
                sfs.append(sfo)

        jo = {'shared_folders': sfs, 'records': rs}
        if filename:
            with open(filename, mode="w", encoding='utf-8') as f:
                json.dump(jo, f, indent=2, ensure_ascii=False)
        else:
            json.dump(jo, sys.stdout, indent=2, ensure_ascii=False)
            print('')

    def has_shared_folders(self):
        return True

    def has_attachments(self):
        return False

    def extension(self):
        return 'json'

    def supports_stdout(self):
        return True
