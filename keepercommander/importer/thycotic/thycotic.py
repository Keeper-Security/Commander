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
import copy
import csv
import datetime
import io
import getpass
import json
import logging
import os
import time
import warnings
from contextlib import contextmanager
from urllib3.exceptions import InsecureRequestWarning

import xml.etree.ElementTree as ET

import requests

from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional, Iterable, Union, Dict, Callable, Any, List

from ..importer import (BaseImporter, BaseDownloadMembership, Record, SharedFolder, Folder, Attachment, Permission,
                        RecordField, BytesAttachment, Team, BaseDownloadRecordType, RecordType, RecordTypeField)
from ...params import KeeperParams
from ... import record_types, vault, api


class ThycoticMixin:
    @staticmethod
    def connect_to_server(url=None):  # type: (Optional[str]) -> ThycoticAuth
        if not url:
            url = input('...' + 'Thycotic Host or URL'.rjust(30) + ': ')
            if not url:
                logging.warning('Thycotic Host or URL is required')
                return

        if not url.startswith('http'):
            url = f'https://{url}'
        username = input('...' + 'Thycotic Username'.rjust(30) + ': ')
        if not username:
            logging.warning('Thycotic username is required')
            return
        password = getpass.getpass(prompt='...' + 'Thycotic Password'.rjust(30) + ': ', stream=None)
        if not password:
            logging.warning('Thycotic password is required')
            return

        def request_totp():
            return input('...' + 'Enter TOTP Code'.rjust(30) + ': ')

        auth = ThycoticAuth(url)
        auth.authenticate(username, password, on_totp=request_totp)
        return auth

    @staticmethod
    def get_user_lookup(auth):  # type: (ThycoticAuth) -> Optional[Dict[int, Dict]]
        try:
            user_rs = auth.thycotic_search('/v1/users')
            return {x['id']: {
                'emailAddress': x.get('emailAddress', ''),
                'userName': x.get('userName', ''),
                'domainName': x.get('domainName', ''),
            } for x in user_rs}
        except:
            pass

    @staticmethod
    def get_group_lookup(auth, on_progress=None):
        # type: (ThycoticAuth, Optional[Callable[[int, int], None]]) -> Optional[Dict[int, Dict]]
        try:
            group_rs = auth.thycotic_search('/v1/groups')
            lookup = {}
            total = len(group_rs)
            for i in range(total):
                group = group_rs[i]
                group_id = group['id']
                g = {
                    'name': group['name'],
                    'users': [],   # type: List[int]
                    'groups': [],  # type: List[int]
                }
                if group.get('memberCount', 0) > 0:
                    member_rs = auth.thycotic_search(f'/v1/groups/{group_id}/users')
                    if on_progress:
                        on_progress(i, total)
                    g['users'].extend((x['userId'] for x in member_rs if 'userId' in x and x['userId'] > 0))
                    g['groups'].extend((x['groupId'] for x in member_rs if 'groupId' in x and x['groupId'] > 0))
                lookup[group_id] = g
            return lookup
        except:
            pass

    @staticmethod
    def get_folders(auth, skip_permissions=False):       # type: (ThycoticAuth, bool) -> Optional[Dict[int, Dict]]
        logging.debug('Enter get_folders')
        folder_rs = auth.thycotic_search('/v1/folders')
        folders = {x['id']: {
            'id': x['id'],
            'folderName': x['folderName'],
            'folderPath': x['folderPath'],
            'inheritPermissions': x['inheritPermissions'],
            'parentFolderId': x['parentFolderId'],
        } for x in folder_rs}   # type: Dict[int, Dict[str, Any]]
        logging.debug('Loaded %d folders', len(folders))

        if not skip_permissions:        # load permissions for shared folders
            folder_ids = [x['id'] for x in folders.values() if (x.get('inheritPermissions') is False) and x['id'] != 1]
            for pos in range(len(folder_ids)):
                folder_id = folder_ids[pos]
                if pos % 10 == 0:
                    logging.debug('Permission check progress: %d of %d', pos, len(folder_ids))

                folder = folders.get(folder_id)
                if not folder:
                    continue

                permissions = auth.thycotic_search(f'/v1/folder-permissions?filter.folderId={folder_id}')
                if isinstance(permissions, list):
                    if len(permissions) == 1:
                        permission = permissions[0]
                        user_id = permission.get('userId') or 0
                        if user_id > 0:
                            permissions = []
                else:
                    permissions = []
                if len(permissions) > 0:
                    folder['permissions'] = permissions
                else:
                    folder['inheritPermissions'] = True

            # check permissions are really modified
            folder_ids = [x['id'] for x in folders.values() if (x.get('inheritPermissions') is False) and x['id'] != 1]
            folder_ids.sort(reverse=False)
            for folder_id in folder_ids:
                folder = folders.get(folder_id)
                if not folder:
                    continue
                permissions = folder.get('permissions')
                if not isinstance(permissions, list):
                    continue

                user_permissions = {x['userId']: (x['folderAccessRoleId'], x['secretAccessRoleId']) for x in permissions if (x.get('userId') or 0) > 0}
                group_permissions = {x['groupId']: (x['folderAccessRoleId'], x['secretAccessRoleId']) for x in permissions if (x.get('groupId') or 0) > 0}
                parent_folder_id = folder.get('parentFolderId') or 0
                while parent_folder_id in folders:
                    parent_folder = folders[parent_folder_id]
                    if parent_folder.get('inheritPermissions') is True:
                        parent_folder_id = parent_folder.get('parentFolderId') or 0
                    else:
                        break
                if parent_folder_id in folders:
                    parent_folder = folders[parent_folder_id]
                    parent_permissions = parent_folder.get('permissions')
                    if not isinstance(parent_permissions, list):
                        continue
                    if len(parent_permissions) != len(permissions):
                        continue
                    parent_user_permissions = {x['userId']: (x['folderAccessRoleId'], x['secretAccessRoleId'])
                                               for x in parent_permissions if (x.get('userId') or 0) > 0}
                    parent_group_permissions = {x['groupId']: (x['folderAccessRoleId'], x['secretAccessRoleId'])
                                                for x in parent_permissions if (x.get('groupId') or 0) > 0}
                    if len(user_permissions) != len(parent_user_permissions):
                        continue
                    if len(group_permissions) != len(parent_group_permissions):
                        continue

                    are_same = True
                    for user_id, user_permission in user_permissions.items():
                        if user_id not in parent_user_permissions:
                            are_same = False
                            break
                        if user_permission != parent_user_permissions[user_id]:
                            are_same = False
                            break
                    for group_id, group_permission in group_permissions.items():
                        if group_id not in parent_group_permissions:
                            are_same = False
                            break
                        if group_permission != parent_group_permissions[group_id]:
                            are_same = False
                            break
                    if are_same:
                        del folder['permissions']
                        folder['inheritPermissions'] = True

        # build folder path
        for folder in folders.values():
            folder_path = folder['folderName']
            parent = folder
            while parent:
                parent_id = parent.get('parentFolderId') or -1
                if parent_id > 1 and parent_id in folders:
                    parent = folders[parent_id]
                    folder_path = parent['folderName'] + '\\' + folder_path
                else:
                    parent = None
            folder['folderPath'] = folder_path
        logging.debug('Folder path built')

        if 1 in folders:
            del folders[1]
        return folders


class ThycoticImporter(BaseImporter, ThycoticMixin):
    def __init__(self):
        super().__init__()
        self._last_keep_alive = int(datetime.datetime.utcnow().timestamp())
        self._keep_alive_period = 30 * 60

    def support_folder_filter(self):
        return True

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

    def _send_keep_alive_if_needed(self, params):   # type: (KeeperParams) -> None
        if isinstance(params, KeeperParams):
            now = int(datetime.datetime.utcnow().timestamp())
            if (now - self._last_keep_alive) > self._keep_alive_period:
                self._last_keep_alive = now
                try:
                    api.send_keepalive(params)
                except:
                    pass

    def do_import(self, filename, **kwargs):
        # type: (ThycoticImporter, str, ...) -> Iterable[Union[Record, SharedFolder]]
        loaded_record_types = {}
        params = kwargs.get('params')
        if isinstance(params, KeeperParams):
            if params.record_type_cache:
                for rts in params.record_type_cache.values():
                    try:
                        rto = json.loads(rts)
                        if '$id' in rto and 'fields' in rto:
                            loaded_record_types[rto['$id']] = rto['fields']
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
        auth.proxy = params.rest_context.proxies if params else None
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
            except Exception:
                pass
            print(f'Loaded {len(totp_codes)} code(s)', flush=True)

        self._send_keep_alive_if_needed(params)
        folders = ThycoticImporter.get_folders(auth, skip_permissions=True)
        filter_folder = kwargs.get('filter_folder')
        if filter_folder:
            if filter_folder == 'Personal Folders':
                folder_ids = [1]
            else:
                folder_ids = [x['id'] for x in folders.values()
                              if x['folderName'] == x['folderPath'] and x['folderName'].lower() == filter_folder.lower()]
            if len(folder_ids) == 0:
                logging.warning('Folder \"%s\" not found', filter_folder)
            pos = 0
            while pos < len(folder_ids):
                folder_id = folder_ids[pos]
                pos += 1
                folder_ids.extend((x['id'] for x in folders.values() if x['parentFolderId'] == folder_id))
            folder_ids = set(folder_ids)
            folders = {i: x for i, x in folders.items() if i in folder_ids}

        if filter_folder:
            if filter_folder == 'Personal Folders':
                root_folder_ids = [1]
            else:
                root_folder_ids = [x['id'] for x in folders.values() if x['folderName'] == x['folderPath']]
            secrets_ids = []
            for folder_id in root_folder_ids:
                query = f'/v1/secrets/lookup?filter.folderId={folder_id}&filter.includeSubFolders=true'
                secrets_ids.extend([x['id'] for x in auth.thycotic_search(query)])
        else:
            secrets_ids = [x['id'] for x in auth.thycotic_search(f'/v1/secrets/lookup')]

        self._send_keep_alive_if_needed(params)
        print(f'Loading {len(secrets_ids)} Records ', flush=True, end='')
        secrets = []
        for secret_id in secrets_ids:
            secret = auth.thycotic_entity(f'/v1/secrets/{secret_id}')
            if not secret:
                continue
            secrets.append(secret)
            if len(secrets) % 10 == 9:
                print('.', flush=True, end='')
            if len(secrets) % 100 == 99:
                self._send_keep_alive_if_needed(params)

        self._send_keep_alive_if_needed(params)
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

            template_name = secret.get('secretTemplateName', '')
            template_name = template_name[:30]
            if template_name in loaded_record_types:
                record.type = template_name
            elif template_name in ('Pin', 'Security Alarm Code'):
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
            elif any(True for x in ('host', 'server', 'ip-address---host-name') if x in items):
                if 'database' in items:
                    record.type = 'databaseCredentials'
                else:
                    record.type = 'serverCredentials'
            else:
                record.type = 'login'

            rt = loaded_record_types.get(record.type, [])

            record.notes = ThycoticImporter.pop_field_value(items, 'notes')

            skip_ssh_key = True
            if record.type in loaded_record_types:
                if any((1 for x in loaded_record_types[record.type] if x['$ref'] == 'keyPair')):
                    skip_ssh_key = False

            secret_id = secret['id']
            if 'lastPasswordChangeAttempt' in secret:
                try:
                    lm = secret['lastPasswordChangeAttempt']
                    if isinstance(lm, str) and lm.endswith('Z'):
                        lm = lm[:-1]
                        dt = datetime.datetime.fromisoformat(lm)
                        record.last_modified = int(dt.timestamp())
                except:
                    pass
            file_items = [x for x in items.values() if x.get('isFile') is True]
            for item in file_items:
                slug = item['slug']
                item['itemValue'] = ''
                attachment_id = item.get('fileAttachmentId')
                if not attachment_id:
                    continue
                file_name = item.get('filename')
                if not file_name:
                    continue

                endpoint = f'/v1/secrets/{secret_id}/fields/{slug}'
                if slug in ('private-key', 'public-key') and skip_ssh_key is not True:
                    with auth.thycotic_get(endpoint) as rs:
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
                                attachment = BytesAttachment(file_name, key_text.encode('utf-8'))
                                if not isinstance(record.attachments, list):
                                    record.attachments = []
                                record.attachments.append(attachment)
                else:
                    if not isinstance(record.attachments, list):
                        record.attachments = []
                    attachment = ThycoticAttachment(auth, endpoint, file_name)
                    if not isinstance(record.attachments, list):
                        record.attachments = []
                    record.attachments.append(attachment)
                    del items[slug]

            if 'private-key' in items:
                key_pair_value = record_types.FieldTypes['privateKey'].value.copy()
                key_pair_value['privateKey'], pk_field = ThycoticImporter.pop_field(items, 'private-key')
                key_pair_value['publicKey'] = ThycoticImporter.pop_field_value(items, 'public-key')
                if any(True for x in key_pair_value.values() if x):
                    field_label = pk_field.get('fieldName') or ''
                    field_label = ThycoticImporter.adjust_field_label(record, 'keyPair', field_label, rt)
                    record.fields.append(RecordField('keyPair', field_label, key_pair_value))

            if 'private-key-passphrase' in items:
                passphrase, field = ThycoticImporter.pop_field(items, 'private-key-passphrase')
                if passphrase:
                    if record.type == 'sshKeys' and not record.password:
                        record.password = passphrase
                    else:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'secret', field_label, rt)
                        record.fields.append(RecordField('secret', field_label, passphrase))

            if 'account-number' in items and 'routing-number' in items:
                bank_account = record_types.FieldTypes['bankAccount'].value.copy()
                bank_account['accountType'] = ''
                bank_account['accountNumber'] = ThycoticImporter.pop_field_value(items, 'account-number')
                bank_account['routingNumber'] = ThycoticImporter.pop_field_value(items, 'routing-number')
                field_label = ThycoticImporter.adjust_field_label(record, 'bankAccount', '', rt)
                record.fields.append(RecordField(type='bankAccount', label=field_label, value=bank_account))

            if 'card-number' in items:
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
                field_label = ThycoticImporter.adjust_field_label(record, 'paymentCard', '', rt)
                record.fields.append(RecordField(type='paymentCard', label=field_label, value=bank_card))
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

            for full_name_field in ('name', 'contact-person'):
                if full_name_field in items:
                    full_name, field = ThycoticImporter.pop_field(items, full_name_field)
                    if full_name:
                        name = vault.TypedField.import_name_field(full_name)
                        if name:
                            field_label = field.get('fieldName') or ''
                            field_label = ThycoticImporter.adjust_field_label(record, 'name', field_label, rt)
                            record.fields.append(RecordField(type='name', label=field_label, value=name))

            for ssn in ('social-security-number', 'ssn'):
                number = ThycoticImporter.pop_field_value(items, ssn)
                if number:
                    record.fields.append(RecordField(type='accountNumber', label='identityNumber', value=number))

            for pin_slug in ('pin', 'pin-code'):
                if pin_slug in items:
                    pin_code, field = ThycoticImporter.pop_field(items, pin_slug)
                    if pin_code:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'pinCode', field_label, rt)
                        record.fields.append(RecordField(type='pinCode', label=field_label, value=pin_code))

            if 'combination' in items and record.type == 'encryptedNotes':
                combination = ThycoticImporter.pop_field_value(items, 'combination')
                if combination:
                    record.fields.append(RecordField(type='note', label='', value=combination))

            for phone_slug in ('contact-number', 'contact-phone', 'work-phone', 'home-phone', 'mobile-phone', 'fax'):
                phone_number, field = ThycoticImporter.pop_field(items, phone_slug)
                if phone_number:
                    phone = vault.TypedField.import_phone_field(phone_number)
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
                    field_label = field.get('fieldName') or ''
                    field_label = ThycoticImporter.adjust_field_label(record, 'url', field_label, rt)
                    if not record.login_url and field_label == '':
                        record.login_url = url
                    else:
                        field_label = ThycoticImporter.adjust_field_label(record, 'url', field_label, rt)
                        record.fields.append(RecordField(type='url', label=field_label, value=url))
            for host_slug in ('server', 'host', 'ip-address---host-name'):
                host_address, field = ThycoticImporter.pop_field(items, host_slug)
                port = ThycoticImporter.pop_field_value(items, host_slug)
                if host_address:
                    host = vault.TypedField.import_host_field(host_address)
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

            for email_slug in ('email', 'email-address'):
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

        urlp = urlparse(self.base_url + 'api' + endpoint)
        queries = tuple(x for x in urlp.query.split(sep='&') if x)
        result = []
        skip = 0
        while True:
            q = list(queries)
            q.append('take=1000')
            if skip > 0:
                q.append(f'skip={skip}')
            url = urlunparse((urlp.scheme or 'https', urlp.netloc, urlp.path, None, '&'.join(q), None))
            try:
                rs = requests.get(url, headers=headers, verify=False, proxies=self.proxy)
            except requests.exceptions.ConnectionError:
                time.sleep(10)
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

    def thycotic_entity(self, endpoint):  # type: (str) -> Optional[dict]
        self.ensure_auth_token()
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }
        try:
            rs = requests.get(self.base_url + 'api' + endpoint, headers=headers, verify=False, proxies=self.proxy)
        except Exception as e:
            logging.warning('"%s" error: %s', endpoint, str(e))
            time.sleep(10)
            try:
                rs = requests.get(self.base_url + 'api' + endpoint, headers=headers, verify=False, proxies=self.proxy)
            except Exception as e:
                logging.warning('Another "%s" error: %s', endpoint, str(e))
                time.sleep(10)
                return
        try:
            if rs.status_code == 200:
                return rs.json()
            else:
                error_rs = rs.json()
                logging.info('"%s" returned %d: %s', endpoint, rs.status_code, error_rs.get('message', ''))
        except Exception as e:
            logging.info('"%s" error: %s', endpoint, str(e))

    def thycotic_get(self, endpoint):    # type: (str) -> requests.Response
        self.ensure_auth_token()
        headers = {
            'Authorization': f'Bearer {self.access_token}'
        }

        try:
            rs = requests.get(self.base_url + 'api' + endpoint, headers=headers,
                              verify=False, proxies=self.proxy, stream=True)
        except requests.exceptions.ConnectionError:
            time.sleep(10)
            rs = requests.get(self.base_url + 'api' + endpoint, headers=headers,
                              verify=False, proxies=self.proxy, stream=True)
        return rs


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
        with self.auth.thycotic_get(self.endpoint) as rs:
            if rs.status_code == 200:
                length = rs.headers.get('Content-Length', 0)
                try:
                    self.size = int(length)
                except:
                    pass
                self._file_content = rs.content


class ThycoticMembershipDownload(BaseDownloadMembership, ThycoticMixin):
    def download_membership(self, params, **kwargs):
        auth = ThycoticMixin.connect_to_server()

        users = ThycoticMembershipDownload.get_user_lookup(auth)

        sf_groups = set()
        folders = ThycoticMembershipDownload.get_folders(auth, skip_permissions=False)
        for folder in folders.values():
            if folder.get('inheritPermissions', True):
                continue
            if 'permissions' not in folder:
                continue
            permissions = folder['permissions']
            if not isinstance(permissions, list):
                continue
            if len(permissions) == 0:
                continue

            shared_folder = SharedFolder()
            shared_folder.uid = folder['id']
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
                    team_name = p.get('groupName') or ''
                    if team_name:
                        perm = Permission()
                        perm.name = team_name
                        perm.manage_users = manage_users
                        perm.manage_records = manage_records
                        shared_folder.permissions.append(perm)
                        group_id = p.get('groupId', -1)
                        if group_id > 0:
                            sf_groups.add(group_id)
            yield shared_folder

        folders_only = kwargs.get('folders_only') is True
        if folders_only is True:
            return

        if len(sf_groups) > 0:
            shown = False

            def progress(position, total):
                nonlocal shown
                if not shown:
                    shown = True
                    print(f'Loading {total} groups ', end='', flush=True)
                if position % 10 == 9:
                    print('.', end='', flush=True)
            groups = ThycoticMembershipDownload.get_group_lookup(auth, on_progress=progress)
            print(' Done', flush=True)

            for group_id in list(sf_groups):
                if group_id in groups:
                    group = groups[group_id]
                    team = Team()
                    team.uid = group_id
                    team.name = group['name']
                    user_ids = set(group['users'])
                    for sub_group_id in group['groups']:
                        if sub_group_id in groups:
                            sub_group = groups[sub_group_id]
                            user_ids.update(sub_group['users'])
                    emails = set((users[x]['emailAddress'] for x in user_ids if x in users and 'emailAddress' in users[x] and users[x]['emailAddress']))
                    team.members = list(emails)

                    yield team


class ThycoticRecordTypeDownload(BaseDownloadRecordType, ThycoticMixin):
    def download_record_type(self, params, **kwargs):
        auth = ThycoticMixin.connect_to_server()
        templates = auth.thycotic_search('/v1/secret-templates?filter.includeInactive=false&filter.includeSecretCount=true')
        logging.debug('Loaded %d secret templates', len(templates))
        for template in templates:
            secret_count = template['secretCount']
            if isinstance(secret_count, int) and secret_count == 0:
                continue

            template_id = template['id']
            if not isinstance(template_id, int):
                continue

            xml = auth.thycotic_entity(f'/v1/secret-templates/{template_id}/export')
            tree = ET.ElementTree(ET.fromstring(xml['exportFileText']))
            root = tree.getroot()
            e_fields = next(root.iter('fields'))
            template['fields'] = {}
            for e_field in e_fields.iter('field'):
                tf = {}
                slug_name = ''
                for el in e_field.iter():
                    if el.tag == 'displayname':
                        tf['name'] = el.text
                    elif el.tag == 'fieldslugname':
                        slug_name = el.text
                        tf['slugName'] = slug_name
                    elif el.tag == 'description':
                        tf['description'] = el.text
                    elif el.tag == 'isurl' and el.text == 'true':
                        tf['type'] = 'URL'
                    elif el.tag == 'ispassword' and el.text == 'true':
                        tf['type'] = 'Password'
                    elif el.tag == 'isnotes' and el.text == 'true':
                        tf['type'] = 'Notes'
                    elif el.tag == 'isfile' and el.text == 'true':
                        tf['type'] = 'File'
                    elif el.tag == 'required' and el.text == 'true':
                        tf['required'] = True
                if 'type' not in tf:
                    tf['type'] = 'Text'

                template['fields'][slug_name] = tf

        for template in templates:
            template_fields = template.get('fields')    # type: Dict[str, Dict[str, Any]]
            if not isinstance(template_fields, dict):
                continue

            fields = copy.copy(template_fields)
            rt = RecordType()
            rt.name = template['name']
            fields.pop('notes', None)

            for login_field in ('username', 'client-id'):
                if login_field in fields:
                    field = fields.pop(login_field)
                    field_name = field['name']
                    rf = RecordTypeField.create('login', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for password_field in ('password', 'client-secret'):
                if password_field in fields:
                    field = fields.pop(password_field)
                    field_name = field['name']
                    rf = RecordTypeField.create('password', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for host_slug in ('server', 'host', 'ip-address---host-name'):
                if host_slug in fields:
                    field = fields.pop(host_slug)
                    _ = fields.pop('port', None)
                    field_name = field['name']
                    rf = RecordTypeField.create('host', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            if 'account-number' in fields and 'routing-number' in fields:
                field = fields.pop('account-number', None)
                f2 = fields.pop('routing-number', None)
                rf = RecordTypeField.create('bankAccount', '')
                if field.get('required') is True and f2.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            if 'card-number' in fields:
                field = fields.pop('card-number', None)
                _ = fields.pop('card-type', None)
                _ = fields.pop('expiration-date', None)
                rf = RecordTypeField.create('paymentCard', '')
                if field.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            if 'address-1' in fields:
                _ = fields.pop('address-1')
                _ = fields.pop('address-2')
                _ = fields.pop('address-3')
                rf = RecordTypeField.create('address', '')
                rt.fields.append(rf)

            if 'address1' in fields:
                _ = fields.pop('address1')
                _ = fields.pop('address2')
                _ = fields.pop('address3')
                _ = fields.pop('city')
                _ = fields.pop('state')
                _ = fields.pop('zip')
                _ = fields.pop('country')
                rf = RecordTypeField.create('address', '')
                rt.fields.append(rf)

            if 'last-name' in fields:
                _ = fields.pop('first-name')
                _ = fields.pop('last-name')
                rf = RecordTypeField.create('name', '')
                rt.fields.append(rf)

            for full_name_field in ('name', 'contact-person'):
                if full_name_field in fields:
                    field = fields.pop(full_name_field)
                    field_name = field['name']
                    rf = RecordTypeField.create('name', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for ssn in ('social-security-number', 'ssn'):
                if ssn in fields:
                    _ = fields.pop(ssn)
                    rf = RecordTypeField.create('accountNumber', 'identityNumber')
                    rt.fields.append(rf)

            for pin_slug in ('pin', 'pin-code'):
                if pin_slug in fields:
                    field = fields.pop(pin_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('pinCode', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            if 'private-key' in fields or 'public-key' in fields:
                private_field = fields.pop('private-key', None)
                public_field = fields.pop('public-key', None)
                field_name = private_field['name'] if private_field else public_field['name'] if public_field else ''
                rt.fields.append(RecordTypeField.create('keyPair', field_name))

            if 'private-key-passphrase' in fields:
                field = fields.pop('private-key-passphrase')
                field_name = field['name']
                rf = RecordTypeField.create('secret', field_name)
                if field.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            if 'combination' in fields:
                field = fields.pop('combination')
                field_name = field['name']
                rf = RecordTypeField.create('secret', field_name)
                if field.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            for num_slug in ('policy-number', 'group-number'):
                if num_slug in fields:
                    field = fields.pop(num_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('accountNumber', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            if 'license-key' in fields:
                field = fields.pop('license-key')
                field_name = field['name']
                rf = RecordTypeField.create('licenseNumber', field_name)
                if field.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            for email_slug in ('email', 'email-address'):
                if email_slug in fields:
                    field = fields.pop(email_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('email', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for url_slug in ('website', 'blog', 'resource', 'url', 'tenant'):
                if url_slug in fields:
                    field = fields.pop(url_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('url', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for phone_slug in ('contact-number', 'contact-phone', 'work-phone', 'home-phone', 'mobile-phone', 'fax'):
                if phone_slug in fields:
                    field = fields.pop(phone_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('phone', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            has_files = False
            for field in fields.values():
                field_name = field.get('name')
                field_type = field.get('type')
                if field_type == 'File':
                    has_files = True
                else:
                    ft = 'text'
                    if field_type == 'Notes':
                        ft = 'multiline'
                    elif field_type == 'Password':
                        ft = 'secret'
                    elif field_type == 'URL':
                        ft = 'url'
                    elif field_type in ('List', 'URL List'):
                        continue
                    rf = RecordTypeField.create(ft, field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)
            if has_files:
                rf = RecordTypeField.create('fileRef', '')
                rt.fields.append(rf)

            yield rt
