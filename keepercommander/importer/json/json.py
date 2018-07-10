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

from ..importer import BaseImporter, BaseExporter, Record


class KeeperJsonImporter(BaseImporter):
    def do_import(self, filename):
        with open(filename, "r", encoding='utf-8') as jsonfile:
            j = json.load(jsonfile)
            if type(j) == list:
                for r in j:
                    record = Record()
                    record.folder = r['folder']
                    record.title = r['title']
                    record.login = r['login']
                    record.password = r['password']
                    record.login_url = r['login_url']
                    record.notes = r['notes']
                    if 'custom_fields' in r:
                        for cf in r['custom_fields']:
                            record.custom_fields.append({'name': cf['name'], 'value': cf['value']})

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
                'custom_fields': r.custom_fields
            }
            if r.folder:
                ro['folder'] = r.folder
            rs.append(ro)

        with open(filename, mode="w", encoding='utf-8') as f:
            json.dump(rs, f, indent=2, ensure_ascii=False)
