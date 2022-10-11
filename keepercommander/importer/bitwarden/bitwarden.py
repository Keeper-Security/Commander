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

import json

from typing import Union, Iterable

from .. import importer
from ...record_types import FieldTypes


class BitwardenImporter(importer.BaseFileImporter):
    def do_import(self, filename, **kwargs):
        # type: (importer.BaseImporter, str, dict) -> Iterable[Union[importer.Record]]

        with open(filename, 'r', encoding='utf-8') as bw_file:
            bw_import = json.load(bw_file)
        if 'encrypted' not in bw_import or 'items' not in bw_import:
            raise Exception(f'File {filename}: Not a Bitwarden JSON export file')

        if bw_import['encrypted'] is True:
            raise Exception(f'File {filename}: Encrypted Bitwarden JSON export not supported.')

        folders = {}
        for f in bw_import.get('folders', []):
            if 'id' in f and 'name' in f:
                folders[f['id']] = f['name']

        for i in bw_import.get('items') or []:
            record = importer.Record()
            item_type = i.get('type', 0)
            if item_type == 1:
                record.type = 'login'
            elif item_type == 2:
                record.type = 'encryptedNotes'
            elif item_type == 3:
                record.type = 'bankCard'
            elif item_type == 4:
                record.type = 'address'
            else:
                continue

            record.title = i.get('name') or ''
            note = i.get('notes') or ''
            if note:
                if record.type == 'encryptedNotes':
                    record.fields.append(importer.RecordField('note', '', note))
                else:
                    record.notes = note

            folder_id = i.get('folderId') or ''
            if folder_id in folders:
                f = importer.Folder()
                f.path = folders[folder_id]
                record.folders = [f]
            fields = i.get('fields')
            if isinstance(fields, list):
                for field in fields:
                    field_type = field.get('type', -1)
                    field_name = field.get('name')
                    if not field_name:
                        continue
                    field_value = field.get('value') or ''
                    if field_type == 0:
                        record.fields.append(importer.RecordField('text', field_name, field_value))
                    elif field_type == 1:
                        record.fields.append(importer.RecordField('secret', field_name, field_value))
                    elif field_type == 2:
                        field_value = field_value == 'true'
                        record.fields.append(importer.RecordField('checkbox', field_name, field_value))

            login = i.get('login')
            if isinstance(login, dict):
                record.login = login.get('username') or ''
                record.password = login.get('password') or ''
                totp = login.get('password')
                if totp:
                    if not totp.startswith('otpauth://'):
                        totp = f'otpauth://totp/?secret={totp}'
                    record.fields.append(importer.RecordField('oneTimeCode', '', totp))
                uris = login.get('uris')
                if isinstance(uris, list):
                    for u in uris:
                        if isinstance(u, dict):
                            uri = u.get('uri')
                            if uri:
                                if record.login_url:
                                    record.fields.append(importer.RecordField('url', '', uri))
                                else:
                                    record.login_url = uri

            identity = i.get('identity')
            if isinstance(identity, dict):
                f_name = identity.get('firstName') or ''
                l_name = identity.get('lastName') or ''
                if f_name or l_name:
                    name = FieldTypes['name'].value.copy()
                    name['first'] = f_name
                    name['last'] = l_name
                    name['middle'] = identity.get('middleName') or ''
                    record.fields.append(importer.RecordField('name', '', name))
                address1 = identity.get('address1') or ''
                city = identity.get('city') or ''
                state = identity.get('state') or ''
                postal_code = identity.get('postalCode') or ''
                if address1 or city or state or postal_code:
                    address = FieldTypes['address'].value.copy()
                    address['street1'] = address1
                    address['street2'] = identity.get('address2') or ''
                    address['city'] = city
                    address['state'] = state
                    address['zip'] = postal_code
                    address['country'] = identity.get('country') or ''
                    record.fields.append(importer.RecordField('address', '', address))
                company = identity.get('company') or ''
                if company:
                    record.fields.append(importer.RecordField('text', 'company', company))
                email = identity.get('email') or ''
                if email:
                    record.fields.append(importer.RecordField('email', '', email))
                phone = identity.get('phone') or ''
                if phone:
                    phone_number = FieldTypes['phone'].value.copy()
                    phone_number['number'] = phone
                    record.fields.append(importer.RecordField('phone', '', phone_number))
                ssn = identity.get('ssn') or ''
                if ssn:
                    record.fields.append(importer.RecordField('accountNumber', 'identityNumber', ssn))
                username = identity.get('username') or ''
                if username:
                    if record.login:
                        record.fields.append(importer.RecordField('login', '', username))
                    else:
                        record.login = username
                passport_number = identity.get('passportNumber') or ''
                if passport_number:
                    record.fields.append(importer.RecordField('accountNumber', 'passportNumber', passport_number))
                license_number = identity.get('licenseNumber') or ''
                if license_number:
                    record.fields.append(importer.RecordField('accountNumber', 'licenseNumber', license_number))

            card = i.get('card')
            if isinstance(card, dict):
                cardholder = card.get('cardholderName') or ''
                if cardholder:
                    record.fields.append(importer.RecordField('text', 'cardholderName', cardholder))

                number = card.get('number') or ''
                code = card.get('code') or ''
                if number or code:
                    payment_card = FieldTypes['paymentCard'].value.copy()
                    payment_card['cardNumber'] = number
                    payment_card['cardSecurityCode'] = code
                    month = card.get('expMonth') or ''
                    year = card.get('expYear') or ''
                    if month and year:
                        if len(month) == 1:
                            month = '0' + month
                    payment_card['cardExpirationDate'] = f'{month}/{year}'
                    record.fields.append(importer.RecordField('paymentCard', '', payment_card))

            yield record

    def extension(self):
        return 'json'
