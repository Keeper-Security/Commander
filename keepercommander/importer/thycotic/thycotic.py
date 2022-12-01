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

import csv
import datetime
import io
import getpass
import json
import logging
import os
import warnings
from contextlib import contextmanager
from urllib3.exceptions import InsecureRequestWarning

import requests

from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional, Iterable, Union, Dict, Callable

from ..importer import BaseImporter, Record, SharedFolder, Folder, Attachment, Permission, RecordField, BytesAttachment
from ...params import KeeperParams
from ... import record_types


class ThycoticImporter(BaseImporter):
    def __init__(self):
        super().__init__()

    @staticmethod
    def pop_field(fields, key):  # type: (Dict[str, Dict[str, str]], str) -> Tuple[str, Optional[Dict[str, str]]]
        field = fields.pop(key, None)
        value = field.get('itemValue', '') if isinstance(field, dict) else ''
        return str(value), field

    @staticmethod
    def pop_field_value(fields, key):  # type: (Dict[str, Dict[str, str]], str) -> str
        return ThycoticImporter.pop_field(fields, key)[0]

    @staticmethod
    def request_totp():
        return input('Enter TOTP code: '.rjust(25))

    def do_import(self, filename, **kwargs):
        # type: (BaseImporter, str, dict) -> Iterable[Union[Record, SharedFolder]]
        loaderd_record_types = {}
        params = kwargs.get('params')
        if isinstance(params, KeeperParams):
            if params.record_type_cache:
                for rts in params.record_type_cache.values():
                    try:
                        rto = json.loads(rts)
                        if '$id' in rto and 'fields' in rto:
                            loaderd_record_types[rto['$id']] = rto['fields']
                    except:
                        pass

        if filename.startswith('https://'):
            username = ''
            host = filename
        else:
            username, sep, host = filename.partition('@')
            if sep:
                host = f'https://{host}/'
            else:
                logging.warning('Thycotic connection parameters:')
                logging.warning('  <Username>@<Secret server host>.')
                logging.warning('  https://<Secret server host>/<Endpoint>. Full URL')
                raise Exception('Import canceled')

        print('Secret Server URL: '.rjust(25) + host)
        username_prompt = 'Thycotic Username: '.rjust(25)
        if not username:
            username = input(username_prompt)
            if not username:
                raise Exception('Import canceled')
        else:
            print(username_prompt + username)

        password_prompt = 'Thycotic Password: '.rjust(25)
        password = getpass.getpass(prompt=password_prompt, stream=None)
        if not password:
            raise Exception('Import canceled')

        auth = ThycoticAuth(host)
        auth.proxy = params.rest_context.proxies
        auth.authenticate(username, password, ThycoticImporter.request_totp)

        totp_codes = {}
        csv_file = 'secrets-export.csv'
        if not os.path.isfile('secrets-export.csv'):
            home_dir = os.path.expanduser('~/')
            home_dir = os.path.join(home_dir, csv_file)
            if os.path.isfile(home_dir):
                csv_file = home_dir
        if os.path.isfile(csv_file):
            print('"secrets-export.csv" file is detected. ', flush=True, end='')

            try:
                totp_index = -1
                with open(csv_file, "r", encoding='utf-8-sig') as csvfile:
                    reader = csv.reader(csvfile)
                    for row in reader:
                        if row[0] == 'Secret Name':
                            try:
                                totp_index = row.index('TOTP Key')
                            except:
                                pass
                        elif totp_index > 0:
                            if totp_index < len(row) and row[totp_index]:
                                totp_codes[row[0]] = row[totp_index]
            except Exception as e:
                pass
            print(f'Loaded {len(totp_codes)} code(s)', flush=True)

        print('Loading folders ...', flush=True, end='')
        try:
            user_rs = auth.thycotic_search('/v1/users')
            users = {x['id']: {
                'emailAddress': x.get('emailAddress', ''),
                'userName': x.get('userName', ''),
            } for x in user_rs}
        except:
            users = []

        try:
            group_rs = auth.thycotic_search('/v1/groups/lookup')
            for group in group_rs:
                group_id = group['id']
                group_name = group.pop('value', None)
                if group_name:
                    group['name'] = group_name
                members = auth.thycotic_search(f'/v1/groups/{group_id}/users')
                group['members'] = [x['userId'] for x in members]
            groups = {x['id']: x for x in group_rs}
        except:
            groups = {}

        folder_rs = auth.thycotic_search('/v1/folders?filter.onlyIncludeRootFolders=true')
        pos = 0
        while pos < len(folder_rs):
            folder = folder_rs[pos]
            pos += 1
            folder_id = folder['id']
            fs = auth.thycotic_search(f'/v1/folders?filter.parentFolderId={folder_id}')
            folder_rs.extend(fs)
        folders = {x['id']: {
            'folderName': x['folderName'],
            'folderPath': x['folderPath'],
            'parentFolderId': x['parentFolderId'],
        } for x in folder_rs}

        personal_name = folders[1]['folderName'] if 1 in folders else ''
        for folder in folders.values():
            path = folder['folderPath']   # type: str
            path = path.strip('\\')
            if personal_name and path.startswith(personal_name):
                path = path[len(personal_name):]
                path = path.strip('\\')
            folder['folderPath'] = path

        for folder_id in folders:
            folder = folders[folder_id]
            if folder_id > 1:
                permissions = auth.thycotic_search(f'/v1/folder-permissions?filter.folderId={folder_id}')
                folder['permissions'] = [x for x in permissions if x['secretAccessRoleName'] != 'Owner' or x['folderAccessRoleName'] != 'Owner']
            else:
                folder['permissions'] = []

        # remove permissions from Shared Folder Folders
        user_folders = []
        shared_folders = set()
        for folder_id, folder in folders.items():
            parent_folder_id = folder.get('parentFolderId', -1)
            if parent_folder_id > 0:
                continue
            permissions = folder.get('permissions', [])
            if len(permissions) == 0:
                user_folders.append(folder_id)
            else:
                shared_folders.add(folder_id)

        pos = 0
        while pos < len(user_folders):
            parent_folder_id = user_folders[pos]
            pos += 1
            for folder_id, folder in folders.items():
                if folder['parentFolderId'] != parent_folder_id:
                    continue
                permissions = folder.get('permissions', [])
                if len(permissions) == 0:
                    user_folders.append(folder_id)
                else:
                    shared_folders.add(folder_id)
        for folder_id in shared_folders:
            folder = folders[folder_id]
            shared_folder = SharedFolder()
            shared_folder.path = folder['folderPath']
            shared_folder.permissions = []
            for p in folder.get('permissions', []):
                folder_permission = p.get('folderAccessRoleName')
                manage_users = folder_permission in ('Owner', 'Edit')
                secret_permission = p.get('secretAccessRoleName')
                manage_records = secret_permission in ('Owner', 'Edit') or folder_permission == 'Add Secret'

                user_id = p.get('userId', -1)
                if user_id in users:
                    user = users[user_id]
                    email = user.get('emailAddress')
                    if email:
                        perm = Permission()
                        perm.name = email
                        perm.manage_users = manage_users
                        perm.manage_records = manage_records
                        shared_folder.permissions.append(perm)
                else:
                    group_id = p.get('groupId', -1)
                    if group_id in groups:
                        group = groups[group_id]
                        team_name = group.get('name')
                        if team_name:
                            perm = Permission()
                            perm.name = team_name
                            perm.manage_users = manage_users
                            perm.manage_records = manage_records
                            shared_folder.permissions.append(perm)
            yield shared_folder

        print(' Done')

        secrets_ids = [x['id'] for x in auth.thycotic_search(f'/v1/secrets/lookup')]
        print(f'Loading {len(secrets_ids)} Records ', flush=True, end='')
        secrets = []
        for secret_id in secrets_ids:
            secret = auth.thycotic_entity(f'/v1/secrets/{secret_id}')
            secrets.append(secret)
            if len(secrets) % 10 == 9:
                print('.', flush=True, end='')

        for secret in secrets:
            record = Record()
            record.title = secret.get('name', '')
            items = {x['slug']: x for x in secret.get('items', [])}
            folder_id = secret.get('folderId')
            if folder_id in folders:
                folder = folders[folder_id]
                path = folder.get('folderPath', '')
                if path:
                    record.folders = []
                    record_folder = Folder()
                    record_folder.path = path
                    record.folders.append(record_folder)

            secret_id = secret['id']
            file_items = [x for x in items.values() if x.get('isFile') is True]
            for item in file_items:
                slug = item['slug']
                item['itemValue'] = ''
                attachment_id = item.get('fileAttachmentId')
                endpoint = f'/v1/secrets/{secret_id}/fields/{slug}'
                if slug in ('private-key', 'public-key'):
                    if attachment_id:
                        with auth.thycotic_raw(endpoint) as rs:
                            if rs.status_code == 200:
                                try:
                                    key_text = rs.content.decode()
                                except:
                                    key_text = ''
                                is_key = 30 < len(key_text) < 5000
                                if is_key:
                                    item['itemValue'] = key_text
                                else:
                                    if not isinstance(record.attachments, list):
                                        record.attachments = []
                                    file_name = item.get('filename')
                                    attachment = BytesAttachment(file_name, key_text.encode('utf-8'))
                                    if not isinstance(record.attachments, list):
                                        record.attachments = []
                                    record.attachments.append(attachment)
                                    del items[slug]
                else:
                    if attachment_id:
                        if not isinstance(record.attachments, list):
                            record.attachments = []
                        file_name = item.get('filename')
                        attachment = ThycoticAttachment(auth, endpoint, file_name)
                        if not isinstance(record.attachments, list):
                            record.attachments = []
                        record.attachments.append(attachment)
                    del items[slug]

            template_name = secret.get('secretTemplateName', '')
            if template_name in ('Pin', 'Security Alarm Code'):
                record.type = 'encryptedNotes'
            elif template_name == 'Contact':
                record.type = 'address'
            elif template_name == 'Credit Card':
                record.type = 'bankCard'
            elif 'private-key' in items:
                record.type = 'sshKeys'
            elif 'card-number' in items:
                record.type = 'bankCard'
            elif 'account-number' in items and 'routing-number' in items:
                record.type = 'bankAccount'
            elif 'ssn' in items:
                record.type = 'ssnCard'
            elif 'license-key' in items:
                record.type = 'softwareLicense'
            elif 'combination' in items:
                record.type = 'encryptedNotes'
            elif 'healthcare-provider-name' in items:
                record.type = 'healthInsurance'
            elif any(True for x in ('host', 'server', 'machine', 'ip-address---host-name') if x in items):
                if 'database' in items:
                    record.type = 'databaseCredentials'
                else:
                    record.type = 'serverCredentials'
            else:
                record.type = 'login'

            rt = loaderd_record_types.get(record.type, [])

            record.notes = ThycoticImporter.pop_field_value(items, 'notes')

            if 'private-key' in items:
                key_pair_value = record_types.FieldTypes['privateKey'].value.copy()
                key_pair_value['privateKey'], pk_field = ThycoticImporter.pop_field(items, 'private-key')
                key_pair_value['publicKey'] = ThycoticImporter.pop_field_value(items, 'public-key')
                if any(True for x in key_pair_value.values() if x):
                    field_label = pk_field.get('fieldName') or ''
                    field_label = ThycoticImporter.adjust_field_label(record, 'keyPair', field_label, rt)
                    record.fields.append(RecordField('keyPair', field_label, key_pair_value))
                passphrase = ThycoticImporter.pop_field_value(items, 'private-key-passphrase')
                if passphrase:
                    if record.password:
                        record.fields.append(RecordField('password', 'passphrase', passphrase))
                    else:
                        record.password = passphrase

            if record.type == 'bankAccount':
                bank_account = record_types.FieldTypes['bankAccount'].value.copy()
                bank_account['accountType'] = ''
                bank_account['accountNumber'] = ThycoticImporter.pop_field_value(items, 'account-number')
                bank_account['routingNumber'] = ThycoticImporter.pop_field_value(items, 'routing-number')
                record.fields.append(RecordField(type='bankAccount', label='', value=bank_account))

            if record.type == 'bankCard':
                bank_card = record_types.FieldTypes['paymentCard'].value.copy()
                bank_card['cardNumber'] = ThycoticImporter.pop_field_value(items, 'card-number')
                _ = ThycoticImporter.pop_field_value(items, 'card-type')
                exp = ThycoticImporter.pop_field_value(items, 'expiration-date')
                if len(exp) >= 4:
                    month, sep, year = exp.partition('/')
                    if not sep:
                        month = exp[:2]
                        year = exp[2:]
                    if len(month) == 2:
                        pass
                    elif len(month) == 1:
                        month = '0' + month
                    else:
                        month = ''
                    if len(year) == 4:
                        pass
                    elif len(year) == 2:
                        year = '20' + year
                    else:
                        year = ''
                    if month and year:
                        bank_card['cardExpirationDate'] = f'{month}/{year}'
                record.fields.append(RecordField(type='paymentCard', label='', value=bank_card))
                name_on_card = ThycoticImporter.pop_field_value(items, 'full-name')
                if name_on_card:
                    record.fields.append(RecordField(type='text', label='cardholderName', value=name_on_card))

            for login_field in ('username', 'client-id'):
                if login_field in items:
                    username, field = ThycoticImporter.pop_field(items, login_field)
                    if username:
                        if record.login:
                            field_label = field.get('fieldName') or ''
                            field_label = ThycoticImporter.adjust_field_label(record, 'login', field_label, rt)
                            record.fields.append(RecordField(type='login', label=field_label, value=username))
                        else:
                            record.login = username

            for password_field in ('password', 'client-secret'):
                if password_field in items:
                    password, field = ThycoticImporter.pop_field(items, password_field)
                    if password:
                        if record.password:
                            field_label = field.get('fieldName') or ''
                            field_label = ThycoticImporter.adjust_field_label(record, 'password', field_label, rt)
                            record.fields.append(RecordField(type='password', label=field_label, value=password))
                        else:
                            record.password = password

            if 'address-1' in items:
                address = record_types.FieldTypes['address'].value.copy()
                address['street1'] = ThycoticImporter.pop_field_value(items, 'address-1')
                address['street2'] = ThycoticImporter.pop_field_value(items, 'address-2')
                addr = ThycoticImporter.pop_field_value(items, 'address-3')
                if addr:
                    city, sep, addr = addr.partition(',')
                    address['city'] = city
                    if sep:
                        addr = addr.strip()
                        state, sep, zip_code = addr.rpartition(',')
                        if not sep:
                            state, sep, zip_code = addr.rpartition(' ')
                        address['state'] = state
                        address['zip'] = zip_code
                field_label = ThycoticImporter.adjust_field_label(record, 'address', '', rt)
                record.fields.append(RecordField(type='address', label=field_label, value=address))

            if 'address1' in items:
                address = record_types.FieldTypes['address'].value.copy()    # type: dict
                address['street1'] = ThycoticImporter.pop_field_value(items, 'address1')
                a2 = ThycoticImporter.pop_field_value(items, 'address2')
                a3 = ThycoticImporter.pop_field_value(items, 'address3')
                if a3:
                    a2 += ' ' + a3
                a2 = a2.strip()
                address['street2'] = a2
                address['city'] = ThycoticImporter.pop_field_value(items, 'city')
                address['state'] = ThycoticImporter.pop_field_value(items, 'state')
                address['zip'] = ThycoticImporter.pop_field_value(items, 'zip')
                address['country'] = ThycoticImporter.pop_field_value(items, 'country')
                if any(True for x in address.values() if x):
                    field_label = ThycoticImporter.adjust_field_label(record, 'address', '', rt)
                    record.fields.append(RecordField(type='address', label=field_label, value=address))

            if 'last-name' in items:
                name = record_types.FieldTypes['name'].value.copy()
                name['last'] = ThycoticImporter.pop_field_value(items, 'last-name')
                name['first'] = ThycoticImporter.pop_field_value(items, 'first-name')
                if any(True for x in name.values() if x):
                    field_label = ThycoticImporter.adjust_field_label(record, 'name', '', rt)
                    record.fields.append(RecordField(type='name', label=field_label, value=name))

            for full_name_field in ('name'):
                if full_name_field in items:
                    full_name, field = ThycoticImporter.pop_field(items, full_name_field)
                    if full_name:
                        name = BaseImporter.import_name_field(full_name)
                        if name:
                            field_label = field.get('fieldName') or ''
                            field_label = ThycoticImporter.adjust_field_label(record, 'name', field_label, rt)
                            record.fields.append(RecordField(type='name', label=field_label, value=name))

            for ssn in ('social-security-number', 'ssn'):
                number = ThycoticImporter.pop_field_value(items, ssn)
                if number:
                    record.fields.append(RecordField(type='accountNumber', label='identityNumber', value=number))

            if 'combination' in items and record.type == 'encryptedNotes':
                combination = ThycoticImporter.pop_field_value(items, 'combination')
                if combination:
                    record.fields.append(RecordField(type='note', label='', value=combination))

            for phone_slug in ('contact-number', 'work-phone', 'home-phone', 'mobile-phone', 'fax'):
                phone_number, field = ThycoticImporter.pop_field(items, phone_slug)
                if phone_number:
                    phone = BaseImporter.import_phone_field(phone_number)
                    if phone:
                        if phone_slug.startswith('work'):
                            phone['type'] = 'Work'
                        elif phone_slug.startswith('mobile'):
                            phone['type'] = 'Mobile'
                        elif phone_slug.startswith('home'):
                            phone['type'] = 'Home'
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'phone', field_label, rt)
                        record.fields.append(RecordField(type='phone', label=field_label, value=phone))

            for url_slug in ('website', 'blog', 'resource', 'url', 'tenant'):
                url, field = ThycoticImporter.pop_field(items, url_slug)
                if url:
                    if record.login_url:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'url', field_label, rt)
                        record.fields.append(RecordField(type='url', label=field_label, value=url))
                    else:
                        record.login_url = url
            for host_slug in ('server', 'host', 'machine', 'ip-address---host-name'):
                host_address, field = ThycoticImporter.pop_field(items, host_slug)
                port = ThycoticImporter.pop_field_value(items, host_slug)
                if host_address:
                    host = BaseImporter.import_host_field(host_address)
                    if port:
                        host['port'] = port
                    field_label = field.get('fieldName') or ''
                    field_label = ThycoticImporter.adjust_field_label(record, 'host', field_label, rt)
                    record.fields.append(RecordField(type='host', label=field_label, value=host))

            for num_slug in ('policy-number', 'group-number'):
                if num_slug in items:
                    number, field = ThycoticImporter.pop_field(items, num_slug)
                    if number:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'accountNumber', field_label, rt)
                        record.fields.append(RecordField(type='accountNumber', label=field_label, value=number))

            for email_slug in ('email'):
                if email_slug in items:
                    email, field = ThycoticImporter.pop_field(items, email_slug)
                    if email:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'email', field_label, rt)
                        record.fields.append(RecordField(type='email', label=field_label, value=email))

            for slug in list(items.keys()):
                field_value, field = ThycoticImporter.pop_field(items, slug)
                if not field_value:
                    continue
                is_password = field.get('isPassword') or False
                is_url = field.get('isUrl') or False
                is_note = field.get('isNote') or False

                if is_password and not record.password:
                    record.password = field_value
                    continue

                field_type = 'secret' if is_password else 'url' if is_url else 'note' if is_note else 'text'
                field_label = field.get('fieldName') or ''
                field_label = ThycoticImporter.adjust_field_label(record, field_type, field_label, rt)
                record.fields.append(RecordField(type=field_type, label=field_label, value=field_value))

            if record.title in totp_codes:
                field_value = f'otpauth://totp/?secret={totp_codes[record.title]}'
                field_label = ThycoticImporter.adjust_field_label(record, 'oneTimeCode', '', rt)
                record.fields.append(RecordField(type='oneTimeCode', label=field_label, value=field_value))

            yield record
        print(' Done', flush=True)


class ThycoticAuth:
    def __init__(self, base_url):    # type: (str) -> None
        if not base_url.endswith('/'):
            base_url += '/'
        self.base_url = base_url
        self.access_token = ''
        self.expires_in = 0
        self.refresh_token = ''
        self.last_login = 0
        self.proxy = None
        warnings.simplefilter('ignore', InsecureRequestWarning)

    def authenticate(self, username, password, on_totp=None):  # type: (str, str, Optional[Callable[[], str]]) -> None
        request_data = {
            'grant_type': 'password',
            'username': username,
            'password': password
        }
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        rs = requests.post(self.base_url + 'oauth2/token', data=request_data, headers=headers,
                           verify=False, proxies=self.proxy)
        if rs.status_code != 200:
            if rs.status_code == 400:
                error_rs = rs.json()
                error = error_rs['error']
                if 'totp' in error.lower() and callable(on_totp):
                    code = on_totp()
                    if code:
                        request_data['OTP'] = code
                        rs = requests.post(self.base_url + 'oauth2/token', data=request_data, headers=headers,
                                           verify=False, proxies=self.proxy)
        if rs.status_code == 200:
            auth_rs = rs.json()
            self.access_token = auth_rs['access_token']
            self.expires_in = auth_rs.get('expires_in')
            self.refresh_token = auth_rs.get('refresh_token')
            self.last_login = int(datetime.datetime.now().timestamp())
        else:
            error_rs = rs.json()
            raise Exception(error_rs['error'])

    def refresh_auth_token(self):
        if not self.refresh_token:
            raise Exception('Not logged in')
        request_data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token
        }
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        rs = requests.post(self.base_url + 'oauth2/token', data=request_data, headers=headers,
                           verify=False, proxies=self.proxy)
        if rs.status_code == 200:
            auth_rs = rs.json()
            self.access_token = auth_rs['access_token']
            self.expires_in = auth_rs.get('expires_in')
            self.refresh_token = auth_rs.get('refresh_token')
            self.last_login = int(datetime.datetime.now().timestamp())
        else:
            error_rs = rs.json()
            raise Exception(error_rs['error'])

    def ensure_auth_token(self):
        if self.access_token:
            now = int(datetime.datetime.now().timestamp())
            now -= 10
            if self.last_login + self.expires_in < now:
                self.refresh_auth_token()

    def thycotic_search(self, endpoint):  # type: (str) -> list
        self.ensure_auth_token()
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }

        urlp = urlparse(self.base_url + 'api/' + endpoint)
        queries = tuple(x for x in urlp.query.split(sep='&') if x)
        result = []
        skip = 0
        while True:
            q = list(queries)
            q.append('take=100')
            if skip > 0:
                q.append(f'skip={skip}')
            url = urlunparse((urlp.scheme or 'https', urlp.netloc, urlp.path, None, '&'.join(q), None))
            rs = requests.get(url, headers=headers, verify=False, proxies=self.proxy)
            if rs.status_code != 200:
                error_rs = rs.json()
                raise Exception(error_rs['message'])
            chunk_rs = rs.json()
            records = chunk_rs.get('records')
            if isinstance(records, list):
                result.extend(records)
            else:
                break
            if chunk_rs.get('hasNext') is True:
                skip = chunk_rs['nextSkip']
            else:
                break
        return result

    def thycotic_entity(self, endpoint):  # type: (str) -> dict
        self.ensure_auth_token()
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }
        rs = requests.get(self.base_url + 'api' + endpoint, headers=headers, verify=False, proxies=self.proxy)
        if rs.status_code != 200:
            error_rs = rs.json()
            raise Exception(error_rs['message'])
        return rs.json()

    def thycotic_raw(self, endpoint):    # type: (str) -> requests.Response
        self.ensure_auth_token()
        headers = {
            'Authorization': f'Bearer {self.access_token}'
        }
        return requests.get(self.base_url + 'api' + endpoint, headers=headers,
                            verify=False, proxies=self.proxy, stream=True)


class ThycoticAttachment(Attachment):
    def __init__(self, auth, endpoint, name):     # type: (ThycoticAuth, str, str) -> None
        super().__init__()
        self.auth = auth
        self.endpoint = endpoint
        self.name = name
        self._file_content = b''

    @contextmanager
    def open(self):
        yield io.BytesIO(self._file_content)
        self._file_content = b''

    def prepare(self):
        with self.auth.thycotic_raw(self.endpoint) as rs:
            if rs.status_code == 200:
                length = rs.headers.get('Content-Length', 0)
                try:
                    self.size = int(length)
                except:
                    pass
                self._file_content = rs.content
