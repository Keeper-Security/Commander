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

import collections
import datetime
import io
import json
import logging
import os.path
import zipfile
from contextlib import contextmanager
from typing import Union, Optional, Tuple, Any, Dict, List, Set

from ..importer import (
    BaseImporter, Record, Folder, RecordField, RecordReferences, SharedFolder, Attachment
)
from ... import utils
from ...params import KeeperParams
from ...record_types import FieldTypes


class OnePasswordImporter(BaseImporter):
    def __init__(self):
        super(OnePasswordImporter, self).__init__()

    def extension(self):
        return '1pux'

    @staticmethod
    def get_field_value(field):  # type: (dict) -> Optional[Tuple[str, Any]]
        if isinstance(field, dict):
            if 'value' in field:
                value = field['value']
                if isinstance(value, dict):
                    for key in value:
                        return key, value[key]

    def do_import(self, filename, **kwargs):
        # type: (BaseImporter, str, dict) -> collections.Iterable[Union[Record, SharedFolder]]
        record_types = {}
        params = kwargs.get('params')
        if isinstance(params, KeeperParams):
            if params.record_type_cache:
                for rts in params.record_type_cache.values():
                    try:
                        rto = json.loads(rts)
                        if '$id' in rto and 'fields' in rto:
                            record_types[rto['$id']] = rto['fields']
                    except:
                        pass

        if not os.path.isfile(filename):
            fn = os.path.expanduser(filename)
            if os.path.isfile(fn):
                filename = fn

        with zipfile.ZipFile(filename, mode='r') as zip_file:
            files = set(zip_file.namelist())
            if 'export.data' not in files:
                return
            with zip_file.open('export.data', mode='r') as data_file:
                export_data = json.load(data_file)
            if 'accounts' in export_data:
                for account in export_data['accounts']:
                    for vault in account.get('vaults', []):
                        vault_name = None
                        is_shared = False
                        if 'attrs' in vault:
                            vault_type = vault['attrs'].get('type', '')
                            if vault_type == 'E':
                                vault_name = vault['attrs'].get('name')
                                is_shared = True
                                sf = SharedFolder()
                                sf.path = vault_name
                                yield sf
                            elif vault_type == 'U':
                                vault_name = vault['attrs'].get('name')

                        vault_records = {}
                        references = {}   # type: Dict[str, Set[str]]
                        for item in vault.get('items', []):
                            if item.get('trashed') is True:
                                continue
                            record = Record()
                            record.uid = item.get('uuid') or utils.generate_uid()
                            category = item.get('categoryUuid', '')
                            if category in ('001', '005', '110', '112'):
                                record.type = 'login'
                            elif category == '002':
                                record.type = 'bankCard'
                            elif category == '003':
                                record.type = 'encryptedNotes'
                            elif category == '004':
                                record.type = 'contact'
                            elif category == '006':
                                record.type = 'file'
                            elif category == '100':
                                record.type = 'softwareLicense'
                            elif category == '101':
                                record.type = 'bankAccount'
                            elif category == '102':
                                record.type = 'databaseCredentials'
                            elif category == '103':
                                record.type = 'driverLicense'
                            elif category == '104':
                                record.type = 'membership'
                            elif category == '105':
                                record.type = 'membership'
                            elif category == '106':
                                record.type = 'passport'
                            elif category == '107':
                                record.type = 'membership'
                            elif category == '108':
                                record.type = 'ssnCard'
                            elif category == '109':
                                record.type = 'wifiCredentials'
                            elif category == '111':
                                record.type = 'serverCredentials'
                            elif category == '113':
                                record.type = 'encryptedNotes'
                            elif category == '114':
                                record.type = 'sshKeys'
                            elif category == '115':
                                record.type = 'login'

                            if 'overview' in item:
                                overview = item['overview']
                                record.title = overview['title']
                                if 'urls' in overview:
                                    for url_obj in overview['urls']:
                                        label = url_obj.get('label', '')
                                        url = url_obj.get('url', '')
                                        if url:
                                            if record.login_url:
                                                record.fields.append(RecordField(type='url', label=label, value=url))
                                            else:
                                                record.login_url = url
                                if 'tags' in overview:
                                    record.folders = []
                                    for tag in overview['tags']:    # type: str
                                        tag = tag.replace('/', '\\')
                                        folder = Folder()
                                        if vault_name:
                                            if is_shared:
                                                folder.domain = vault_name
                                            else:
                                                folder.path = vault_name
                                        if folder.path:
                                            folder.path += '\\'
                                        else:
                                            folder.path = ''
                                        folder.path += tag
                                        record.folders.append(folder)
                                if not record.folders and vault_name:
                                    record.folders = []
                                    folder = Folder()
                                    if vault_name:
                                        if is_shared:
                                            folder.domain = vault_name
                                        else:
                                            folder.path = vault_name
                                    record.folders.append(folder)

                            details = item.get('details')
                            if not details:
                                continue
                            if 'loginFields' in details:
                                for login_field in details['loginFields']:
                                    value = login_field.get('value')
                                    if not value:
                                        continue
                                    designation = login_field.get('designation')
                                    if designation == 'username':
                                        record.login = value
                                    elif designation == 'password':
                                        record.password = value
                            if 'password' in details:
                                password = details['password']
                                if password:
                                    if record.password:
                                        record.fields.append(RecordField(type='secret', label='Password', value=password))
                                    else:
                                        record.password = password
                            if 'notesPlain' in details:
                                record.notes = details.get('notesPlain', '')
                            if 'documentAttributes' in details:
                                field_value = details['documentAttributes']
                                if isinstance(field_value, dict):
                                    file_name = field_value.get('fileName')
                                    document_id = field_value.get('documentId')
                                    if file_name and document_id:
                                        if record.attachments is None:
                                            record.attachments = []
                                        size = field_value.get('decryptedSize')
                                        zip_path = f'files/{document_id}__{file_name}'
                                        record.attachments.append(
                                            OnePasswordAttachment(filename, zip_path, file_name, size))
                            if 'sections' in details:
                                rt = record_types.get(record.type, [])
                                for section in details['sections']:
                                    section_label = section.get('title', '')
                                    section_type = section.get('name')
                                    fields = section.get('fields', [])
                                    if not isinstance(fields, list):
                                        continue
                                    field_dict = {x['id']: x for x in fields if 'id' in x}
                                    if section_type == 'security questions':
                                        qs = set()
                                        questions = []
                                        for field_id in field_dict:
                                            field = field_dict[field_id]
                                            if 'value' in field:
                                                field_value = field['value']
                                                if 'concealed' in field_value:
                                                    qa = FieldTypes['securityQuestion'].value.copy()
                                                    qa['question'] = field.get('title', '')
                                                    qa['answer'] = field_value.get('concealed', '')
                                                    questions.append(qa)
                                                    qs.add(field_id)
                                        for field_id in qs:
                                            del field_dict[field_id]
                                        if questions:
                                            record.fields.append(RecordField(type='securityQuestion', label=section_label, value=questions))
                                    if 'hostname' in field_dict:
                                        host = FieldTypes['host'].value.copy()
                                        hostname_field = field_dict.pop('hostname', None)
                                        hostname = OnePasswordImporter.get_field_value(hostname_field)
                                        if hostname and hostname[1]:
                                            host['hostName'] = hostname[1]
                                        port = OnePasswordImporter.get_field_value(field_dict.pop('port', None))
                                        if port and port[1]:
                                            host['port'] = port[1]
                                        field_label = hostname_field.get('title', section_label)
                                        field_label = OnePasswordImporter.adjust_field_label(record, 'host', field_label, rt)
                                        record.fields.append(RecordField(type='host', label=field_label, value=host))
                                    if 'pop_server' in field_dict or 'smtp_server' in field_dict:
                                        for prefix in ('pop', 'smtp'):
                                            type_value = OnePasswordImporter.get_field_value(field_dict.pop(f'{prefix}_type', None))
                                            if type_value and type_value[1]:
                                                account_type = type_value[1].upper()
                                            else:
                                                account_type = prefix.upper()
                                            username_value = OnePasswordImporter.get_field_value(field_dict.pop(f'{prefix}_username', None))
                                            password_value = OnePasswordImporter.get_field_value(field_dict.pop(f'{prefix}_password', None))
                                            server_value = OnePasswordImporter.get_field_value(field_dict.pop(f'{prefix}_server', None))
                                            port_value = OnePasswordImporter.get_field_value(field_dict.pop(f'{prefix}_port', None))
                                            security_value = OnePasswordImporter.get_field_value(field_dict.pop(f'{prefix}_security', None))
                                            authentication_value = OnePasswordImporter.get_field_value(field_dict.pop(f'{prefix}_authentication', None))
                                            username = ''
                                            password = ''
                                            host = None
                                            if username_value:
                                                username = username_value[1]
                                            if password_value:
                                                password = password_value[1]
                                            if server_value and server_value[1]:
                                                host = FieldTypes['host'].value.copy()
                                                host['hostName'] = server_value[1]
                                                if port_value:
                                                    host['port'] = port_value[1]
                                            if username or password or host:
                                                if record.type == 'serverCredentials' and not record.login and not record.password:
                                                    record.login = username
                                                    record.password = password
                                                    if host:
                                                        record.fields.append(RecordField(type='host', label='', value=host))
                                                else:
                                                    if username:
                                                        record.fields.append(RecordField(type='login', label=f'{account_type} Username', value=username))
                                                    if password:
                                                        record.fields.append(RecordField(type='secret', label=f'{account_type} Password', value=password))
                                                    if host:
                                                        record.fields.append(RecordField(type='host', label=f'{account_type} Server', value=host))
                                                if security_value and security_value[1]:
                                                    record.fields.append(RecordField(type='text', label=f'{account_type} Security', value=security_value[1]))
                                                if authentication_value and authentication_value[1]:
                                                    record.fields.append(RecordField(type='text', label=f'{account_type} Auth Method', value=authentication_value[1]))
                                    if 'reminderq' in field_dict and 'remindera' in field_dict:
                                        q = OnePasswordImporter.get_field_value(field_dict.pop('reminderq', None))
                                        a = OnePasswordImporter.get_field_value(field_dict.pop('remindera', None))
                                        if q and q[1]:
                                            qa = FieldTypes['securityQuestion'].value.copy()
                                            qa['question'] = q[1]
                                            if a and a[1]:
                                                qa['answer'] = a[1]
                                            record.fields.append(RecordField(type='securityQuestion', label='Reminder', value=qa))
                                    if 'firstname' in field_dict and 'lastname' in field_dict:   # name field
                                        name = FieldTypes['name'].value.copy()
                                        firstname = OnePasswordImporter.get_field_value(field_dict.pop('firstname', None))
                                        if firstname and firstname[1]:
                                            name['first'] = firstname[1]
                                        lastname = OnePasswordImporter.get_field_value(field_dict.pop('lastname', None))
                                        if lastname and lastname[1]:
                                            name['last'] = lastname[1]
                                        initial = OnePasswordImporter.get_field_value(field_dict.pop('initial', None))
                                        if lastname and lastname[1]:
                                            name['middle'] = initial[1]
                                        field_label = OnePasswordImporter.adjust_field_label(record, 'name', section_label, rt)
                                        record.fields.append(RecordField(type='name', label=field_label, value=name))
                                    if 'ccnum' in field_dict and 'expiry' in field_dict:   # credit card field
                                        cardholder = OnePasswordImporter.get_field_value(field_dict.pop('cardholder', None))
                                        if cardholder and cardholder[1]:
                                            record.fields.append(RecordField(type='text', label='cardholderName', value=cardholder[1]))
                                        card = FieldTypes['paymentCard'].value.copy()
                                        ccnum = OnePasswordImporter.get_field_value(field_dict.pop('ccnum', None))
                                        if ccnum and ccnum[1]:
                                            card['cardNumber'] = ccnum[1]
                                        card_type = OnePasswordImporter.get_field_value(field_dict.pop('type', None))
                                        validFrom = OnePasswordImporter.get_field_value(field_dict.pop('validFrom', None))
                                        cvv = OnePasswordImporter.get_field_value(field_dict.pop('cvv', None))
                                        if cvv and cvv[1]:
                                            card['cardSecurityCode'] = cvv[1]
                                        expiry = OnePasswordImporter.get_field_value(field_dict.pop('expiry', None))
                                        if expiry and expiry[0] == 'monthYear' and isinstance(expiry[1], int):
                                            if expiry[1] > 0:
                                                card['cardExpirationDate'] = f'{expiry[1]%100:02}/{expiry[1]//100}'
                                        field_label = OnePasswordImporter.adjust_field_label(record, 'paymentCard', section_label, rt)
                                        record.fields.append(RecordField(type='paymentCard', label=field_label, value=card))
                                    if 'accountNo' in field_dict and 'routingNo' in field_dict:
                                        bankAccount = FieldTypes['bankAccount'].value.copy()
                                        accountType = OnePasswordImporter.get_field_value(field_dict.pop('accountType', None))
                                        if accountType and accountType[1]:
                                            bankAccount['accountType'] = str(accountType[1]).capitalize()
                                        accountNo = OnePasswordImporter.get_field_value(field_dict.pop('accountNo', None))
                                        if accountNo and accountNo[1]:
                                            bankAccount['accountNumber'] = accountNo[1]
                                        routingNo = OnePasswordImporter.get_field_value(field_dict.pop('routingNo', None))
                                        if routingNo and routingNo[1]:
                                            bankAccount['routingNumber'] = routingNo[1]
                                        field_label = OnePasswordImporter.adjust_field_label(record, 'bankAccount', section_label, rt)
                                        record.fields.append(RecordField(type='bankAccount', label=field_label, value=bankAccount))
                                    if len(field_dict) > 0:
                                        for field_id in field_dict:
                                            field = field_dict[field_id]
                                            value_pair = OnePasswordImporter.get_field_value(field)
                                            if not value_pair:
                                                continue
                                            field_type, field_value = value_pair
                                            if not field_value:
                                                continue
                                            ft = 'text'
                                            fl = field.get('title', '')
                                            if record.type == 'wifiCredentials' and field_id == 'name':
                                                fl = 'SSID'
                                                fv = field_value
                                            elif field_id in ('name', 'owner', 'fullname', 'member_name'):
                                                last, sep, rest = field_value.partition(',')
                                                if sep == ',':
                                                    names = rest.split(' ')
                                                    names.append(last)
                                                else:
                                                    names = field_value.split(' ')
                                                names = [x.strip() for x in names]
                                                names = [x for x in names if x]

                                                ft = 'name'
                                                fv = FieldTypes['name'].value.copy()
                                                if len(names) > 0:
                                                    fv['last'] = names.pop()
                                                if len(names) > 0:
                                                    fv['first'] = names.pop(0)
                                                if len(names) > 0:
                                                    fv['middle'] = ' '.join(names)
                                                fl = OnePasswordImporter.adjust_field_label(record, 'name', fl, rt)
                                            elif field_id.endswith('website'):
                                                ft = 'url'
                                                fv = field_value
                                            elif field_id in ('number', 'membership_no', 'reg_code'):
                                                if record.type in ('ssnCard', 'membership', 'driverLicense', 'healthInsurance', 'passport'):
                                                    ft = 'accountNumber'
                                                elif record.type == 'softwareLicense':
                                                    ft = 'licenseNumber'
                                                fv = field_value
                                                fl = OnePasswordImporter.adjust_field_label(record, ft, fl, rt)
                                            elif field_id == 'url':
                                                if record.login_url:
                                                    ft = 'url'
                                                    fv = field_value
                                                else:
                                                    record.login_url = field_value
                                                    continue
                                            elif field_id == 'email':
                                                ft = 'email'
                                                fv = field_value
                                                fl = OnePasswordImporter.adjust_field_label(record, ft, fl, rt)
                                            elif field_id == 'reason' and record.type == 'encryptedNotes':
                                                ft = 'note'
                                                fv = field_value
                                                fl = ''
                                            elif field_id == 'username':
                                                if record.login:
                                                    ft = 'email' if field_value.find('@') > 0 else 'login'
                                                else:
                                                    record.login = field_value
                                                    continue
                                            elif field_type == 'reference':
                                                ref_uid = field_value
                                                if record.uid not in references:
                                                    references[record.uid] = set()
                                                references[record.uid].add(ref_uid)
                                                continue
                                            elif field_type == 'concealed':
                                                if field_id.endswith('password') or \
                                                        field_id == 'credential' or \
                                                        (field_id == 'pin' and record.type == 'membership'):
                                                    if record.password:
                                                        ft = 'secret'
                                                    else:
                                                        record.password = field_value
                                                        continue
                                                elif record.type == 'sshKeys' and not record.password:
                                                    record.password = field_value
                                                    continue
                                                else:
                                                    ft = 'pinCode'
                                                    if record.type == 'bankCard':
                                                        fl = ''
                                                fv = field_value
                                            elif field_type == 'phone':
                                                ft = 'phone'
                                                fv = FieldTypes['phone'].value.copy()
                                                fv['number'] = field_value
                                                if field_id.startswith('cell'):
                                                    fv['type'] = 'Mobile'
                                                elif field_id.startswith('home'):
                                                    fv['type'] = 'Home'
                                                elif field_id.startswith('bus'):
                                                    fv['type'] = 'Business'
                                                fl = OnePasswordImporter.adjust_field_label(record, ft, fl, rt)
                                            elif field_type == 'url':
                                                if record.login_url:
                                                    ft = 'url'
                                                    fv = field_value
                                                else:
                                                    record.login_url = field_value
                                                    continue
                                            elif field_type == 'email':
                                                ft = 'email'
                                                if isinstance(field_value, dict):
                                                    fv = field_value.get('email_address')
                                                else:
                                                    logging.debug('\"email\" field type expected to be \"dict\"')
                                                    continue
                                            elif field_type in ('date', 'monthYear'):
                                                if isinstance(field_value, int):
                                                    if field_type == 'monthYear':
                                                        month = field_value % 100
                                                        year = field_value // 100
                                                        d = datetime.date(year, month, 1)
                                                        dt = datetime.datetime.combine(d, datetime.time(), tzinfo=datetime.timezone.utc)
                                                        field_value = int(dt.timestamp())
                                                    fv = field_value * 1000
                                                    if field_id == 'birthdate':
                                                        ft = 'birthDate'
                                                        fl = ''
                                                    elif field_id == 'expiry_date':
                                                        ft = 'expirationDate'
                                                        fl = ''
                                                    elif field_id == 'issue_date':
                                                        ft = 'date'
                                                        fl = 'dateIssued'
                                                    elif field_id == 'order_date':
                                                        ft = 'date'
                                                        fl = 'dateActive'
                                                    else:
                                                        ft = 'date'
                                                else:
                                                    continue
                                            elif field_type == 'address' and isinstance(field_value, dict):
                                                ft = 'address'
                                                fv = FieldTypes['address'].value.copy()
                                                fv['street1'] = field_value.get('street', '')
                                                fv['city'] = field_value.get('city', '')
                                                fv['state'] = field_value.get('state', '')
                                                fv['zip'] = field_value.get('zip', '')
                                                # fv['country'] = field_value.get('country', '')
                                                fl = OnePasswordImporter.adjust_field_label(record, ft, fl, rt)
                                            elif field_type == 'file' and isinstance(field_value, dict):
                                                if record.attachments is None:
                                                    record.attachments = []
                                                file_name = field_value.get('fileName')
                                                document_id = field_value.get('documentId')
                                                if file_name and document_id:
                                                    size = field_value.get('decryptedSize')
                                                    zip_path = f'files/{document_id}__{file_name}'
                                                    record.attachments.append(
                                                        OnePasswordAttachment(filename, zip_path, file_name, size))
                                                continue
                                            elif field_type == 'totp' and isinstance(field_value, str):
                                                if field_value.startswith('otpauth://'):
                                                    fv = field_value
                                                else:
                                                    fv = f'otpauth://totp/?secret={field_value}'
                                                ft = 'oneTimeCode'
                                                fl = OnePasswordImporter.adjust_field_label(record, ft, fl, rt)
                                            elif field_type == 'sshKey' and isinstance(field_value, dict):
                                                ft = 'keyPair'
                                                fv = FieldTypes['privateKey'].value.copy()
                                                fv['privateKey'] = field_value.get('privateKey')
                                                if 'metadata' in field_value:
                                                    fv['publicKey'] = field_value['metadata'].get('publicKey')
                                                fl = OnePasswordImporter.adjust_field_label(record, ft, fl, rt)
                                            elif isinstance(field_value, str):
                                                ft = 'text'
                                                fv = field_value
                                            else:
                                                logging.debug('Unsupported 1Password field type: %s', field_type)
                                                continue
                                            record.fields.append(RecordField(type=ft, label=fl, value=fv))

                            vault_records[record.uid] = record

                        if len(references) > 0:
                            for record_uid in references:
                                record = vault_records.get(record_uid)
                                refs = references[record_uid]
                                if record and isinstance(refs, set):
                                    cards = RecordReferences('card')
                                    addresses = RecordReferences('address')
                                    record.references = []
                                    for ref_uid in refs:
                                        ref_record = vault_records.get(ref_uid)
                                        if ref_record:
                                            if ref_record.type == 'bankCard':
                                                cards.uids.append(ref_uid)
                                            elif ref_record.type == 'address':
                                                addresses.uids.append(ref_uid)
                                    if len(addresses.uids) > 0:
                                        record.references.append(addresses)
                                    if len(cards.uids) > 0:
                                        record.references.append(cards)

                            references.clear()
                        for record in vault_records.values():
                            yield record
                        vault_records.clear()

    @staticmethod
    def adjust_field_label(record, field_type, field_label, fields):
        # type: (Record, str, str, List[Dict]) -> str
        if not isinstance(fields, list):
            return field_label
        if field_type == 'text':
            return field_label
        field = next((x for x in fields if x['$ref'] == field_type), None)
        if not field:
            return field_label
        fl = field.get('label', '')
        if fl == field_label:
            return field_label
        for f in record.fields:
            if f.type == field_type and f.label == fl:
                return field_label
        return fl


class OnePasswordAttachment(Attachment):
    def __init__(self, zip_file, zip_path, name, size):
        super().__init__()
        self.zip_file = zip_file
        self.zip_path = zip_path
        self.name = name
        self.size = size

    @contextmanager
    def open(self):  # type: () -> io.BufferedIOBase
        with zipfile.ZipFile(self.zip_file, mode='r') as zip_file:
            yield zip_file.open(self.zip_path, mode='r')









