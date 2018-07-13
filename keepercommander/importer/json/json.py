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

from ..importer import BaseImporter, BaseExporter, Record, Folder


class KeeperJsonImporter(BaseImporter):
    def do_import(self, filename):
        with open(filename, "r", encoding='utf-8') as jsonfile:
            j = json.load(jsonfile)
            if type(j) == list:
                for r in j:
                    record = Record()
                    record.title = r['title']
                    record.login = r['login']
                    record.password = r['password']
                    record.login_url = r['login_url']
                    record.notes = r['notes']
                    if 'custom_fields' in r:
                        custom_fields = r['custom_fields']
                        for cf in custom_fields:
                            record.custom_fields.append({'name': cf, 'value': custom_fields[cf]})
                    if 'folders' in r:
                        record.folders = []
                        for f in r['folders']:
                            folder = Folder()
                            folder.domain = f.get('shared_folder')
                            folder.path = f.get('folder')
                            folder.can_edit = f.get('can_edit') or False
                            folder.can_share = f.get('can_share') or False
                            record.folders.append(folder)

                    yield record


class KeeperJsonExporter(BaseExporter):
    def do_export(self, filename, records):
        rs = []
        for r in records:
            ro = {
                'title': r.title or '',
                'login': r.login or '',
                'password': r.password or '',
                'login_url': r.login_url or '',
                'notes': r.notes or '',
                'custom_fields': {}
            }
            for cf in r.custom_fields:
                name = cf.get('name')
                value = cf.get('value')
                if name and value:
                    ro['custom_fields'][name] = value
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

        with open(filename, mode="w", encoding='utf-8') as f:
            json.dump(rs, f, indent=2, ensure_ascii=False)
