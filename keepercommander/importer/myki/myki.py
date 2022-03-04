# __  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import csv
from urllib.parse import urlunsplit, urlencode

from ..importer import BaseFileImporter, Record, RecordField, FIELD_TYPE_ONE_TIME_CODE


# TOTP
TOTP_URL_SCHEME = 'otpauth'
TOTP_URL_NETLOC = 'totp'
TOTP_URL_PATH = '/lastpass_import'
TOTP_URL_QUERY_MAPPING = [
    ('algorithm', 'SHA1'),
    ('digits', '6'),
    ('period', '30')
]


'''
nickname       - title
username       - login
password       - password
url            - login_url
additionalInfo - notes
twofaSecret    - TOTP
status         - custom text field
'''


class MyKiCsvImporter(BaseFileImporter):

    def do_import(self, filename, **kwargs):
        with open(filename, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                record = Record()
                record.title = row.get('nickname', '').strip()
                record.login = row.get('username', '').strip()
                record.password = row.get('password', '').strip()
                record.login_url = row.get('url', '').strip()
                record.notes = row.get('additionalInfo', '').strip()

                totp_secret = row.get('twofaSecret', '').strip().replace(' ', '')
                if len(totp_secret) > 0:
                    totp_query_string = urlencode([('secret', totp_secret)] + TOTP_URL_QUERY_MAPPING)
                    totp_url = urlunsplit((TOTP_URL_SCHEME, TOTP_URL_NETLOC, TOTP_URL_PATH, totp_query_string, ''))
                    record.fields.append(RecordField(type=FIELD_TYPE_ONE_TIME_CODE, value=totp_url))

                status = row.get('status', '').strip()
                if len(status) > 0:
                    record.fields.append(RecordField(type='text', label='status', value=status))

                yield record

    def extension(self):
        return 'csv'
