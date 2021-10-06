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
import sys

from ..importer import (BaseFileImporter, BaseExporter, Record, Folder, RecordField, TWO_FACTOR_CODE,
                        FIELD_TYPE_ONE_TIME_CODE)


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


class KeeperCsvImporter(BaseFileImporter):

    def do_import(self, filename, **kwargs):
        with open(filename, "r", encoding='utf-8-sig') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) >= 6:
                    record = Record()
                    record.title = (row[1] or '').strip()
                    record.login = (row[2] or '').strip()
                    record.password = (row[3] or '').strip()
                    record.login_url = (row[4] or '').strip()
                    record.notes = (row[5] or '').strip()
                    sh_folder = (row[6] if len(row) > 6 else '').strip()
                    if row[0] or sh_folder:
                        folder = Folder()
                        folder.domain = sh_folder
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
                        folder.path = (row[0] or '').strip()
                        record.folders = [folder]

                    if len(row) > 7:
                        for i in range(7, len(row)-1, 2):
                            if i+1 < len(row):
                                key = (row[i] or '').strip()
                                value = (row[i+1] or '').strip()
                                if key and value:
                                    if key == '$record_uid':
                                        record.uid = value
                                    else:
                                        field = RecordField()
                                        if key == TWO_FACTOR_CODE:
                                            field.type = FIELD_TYPE_ONE_TIME_CODE
                                        else:
                                            field.label = key
                                        field.value = value
                                        record.fields.append(field)
                    yield record

    def extension(self):
        return 'csv'


class KeeperCsvExporter(BaseExporter):

    def do_export(self, filename, records, file_password=None):
        csvfile = open(filename, 'w', encoding='utf-8', newline='') if filename else sys.stdout
        writer = csv.writer(csvfile)
        for r in records:
            if type(r) == Record:
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
                if r.fields:
                    for cf in r.fields:
                        if cf.type == FIELD_TYPE_ONE_TIME_CODE:
                            row.append(TWO_FACTOR_CODE)
                            row.append(str(cf.value))
                        elif cf.label:
                            row.append(cf.label)
                            row.append(str(cf.value))
                row.append('$record_uid')
                row.append(r.uid)
                writer.writerow(row)
        if filename:
            csvfile.flush()
            csvfile.close()

    def extension(self):
        return 'csv'

    def supports_stdout(self):
        return True

    def supports_v3_record(self):
        return False
