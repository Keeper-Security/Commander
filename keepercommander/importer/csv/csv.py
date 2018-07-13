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

import csv
from ..importer import strip_path_delimiter, path_components, PathDelimiter, BaseImporter, BaseExporter, Record, Folder


'''
0 - folder
1 - title
2 - login
3 - password
4 - url
5 - notes
6 - shared folder
7 + custom fields
'''


class KeeperCsvImporter(BaseImporter):

    def do_import(self, filename):
        with open(filename, "r", encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) >= 7:
                    record = Record()
                    record.title = row[1]
                    record.login = row[2]
                    record.password = row[3]
                    record.login_url = row[4]
                    record.notes = row[5]

                    if row[0] or row[6]:
                        folder = Folder()
                        folder.domain = row[6]
                        found = True
                        while found:
                            found = False
                            for flag in ['reshare', 'edit']:
                                suffix = '#' + flag
                                if folder.domain.endswith(suffix):
                                    found = True
                                    if flag == 'reshare':
                                        folder.can_share = True
                                    elif flag == 'edit':
                                        folder.can_edit = True
                                    folder.domain = folder.domain[:-len(suffix)]
                        folder.path = row[0]
                        record.folders = [folder]

                    if len(row) > 7:
                        for i in range(7, len(row)-1, 2):
                            if i+1 < len(row):
                                key = row[i]
                                value = row[i+1]
                                if len(key) > 0 and len(value) > 0:
                                    record.custom_fields.append({'name': key, 'value': value})
                    yield record


class KeeperCsvExporter(BaseExporter):

    def do_export(self, filename, records):
        with open(filename, 'w', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            for r in records:
                domain = ''
                path = ''
                if r.folders:
                    for folder in r.folders:
                        domain = folder.domain or ''
                        path = folder.path or ''
                        if domain:
                            if folder.can_edit:
                                domain = domain + '#edit'
                            if folder.can_share:
                                domain = domain + '#reshare'
                        break
                row = [path, r.title or '', r.login or '', r.password or '', r.login_url or '', r.notes or '', domain]
                if r.custom_fields is not None:
                    for x in r.custom_fields:
                        if 'name' in x and 'value' in x:
                            row.append(x['name'])
                            row.append(x['value'])
                writer.writerow(row)