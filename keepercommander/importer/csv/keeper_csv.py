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
from keepercommander.importer.importer import strip_path_delimiter, path_components, PathDelimiter, BaseImporter, BaseExporter, Record

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
                    folder = strip_path_delimiter(row[6])
                    if len(folder) > 0:
                        folder = folder + '$'

                    sf = strip_path_delimiter(row[0])
                    if len(sf) > 0:
                        if len(folder) > 0:
                            folder = folder + PathDelimiter
                        folder = folder + sf

                    record.folder = folder
                    record.title = row[1]
                    record.login = row[2]
                    record.password = row[3]
                    record.login_url = row[4]
                    record.notes = row[5]

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
                subfolder = ''
                if len(r.folder or '') > 0:
                    for x in path_components(r.folder):
                        name = x.replace(PathDelimiter, 2*PathDelimiter)
                        if len(subfolder) > 0:
                            subfolder = subfolder + PathDelimiter
                        subfolder = subfolder + name
                        if subfolder.endswith('$'):
                            subfolder = subfolder[:-1]
                            domain = subfolder
                            subfolder = ''
                row = [subfolder, r.title or '', r.login or '', r.password or '', r.login_url or '', r.notes or '', domain]
                if r.custom_fields is not None:
                    for x in r.custom_fields:
                        if 'name' in x and 'value' in x:
                            row.append(x['name'])
                            row.append(x['value'])
                writer.writerow(row)