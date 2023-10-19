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

from typing import Union, Iterable

from .. import importer
from ... import vault

"""
name,url,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type
"""


class NordpassCsvImporter(importer.BaseFileImporter):
    def do_import(self, filename, **kwargs):
        # type: (str, dict) -> Iterable[Union[importer.Record, importer.SharedFolder, importer.File]]
        with open(filename, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                record_type = row.get('type') or ''
                if record_type == 'folder':
                    continue

                record = importer.Record()
                if record_type == 'password':
                    record.type = 'login'
                elif record_type == 'credit_card':
                    record.type = 'bankCard'
                elif record_type == 'identity':
                    record.type = 'address'
                elif record_type == 'note':
                    record.type = 'encryptedNotes'
                else:
                    record.type = 'login'

                record.title = row.get('name') or ''
                if not record.title:
                    continue
                record.login = row.get('username') or ''
                record.password = row.get('password') or ''
                record.login_url = row.get('url') or ''

                note = row.get('note') or ''
                if note:
                    if record.type == 'encryptedNotes':
                        record.fields.append(importer.RecordField('note', '', note))
                    else:
                        record.notes = note

                card_number = row.get('cardnumber') or ''
                if card_number:
                    expiration = row.get('expirydate') or ''
                    if expiration:
                        month, sep, year = expiration.partition('/')
                        if sep:
                            if len(year) == 2:
                                expiration = f'{month}/20{year}'
                    card = {
                        'cardNumber': card_number,
                        'cardExpirationDate': expiration,
                        'cardSecurityCode':  row.get('cvc') or '',
                    }
                    record.fields.append(importer.RecordField('paymentCard', '', card))
                card_holder_name = row.get('cardholdername') or ''
                if card_holder_name:
                    record.fields.append(importer.RecordField('text', 'cardholderName', card_holder_name))

                email = row.get('email') or ''
                if email:
                    record.fields.append(importer.RecordField('email', '', email))

                address1 = row.get('address1') or ''
                address2 = row.get('address2') or ''
                if address1 or address2:
                    address = {
                        'street1': address1,
                        'street2': address2,
                        'city': row.get('city') or '',
                        'state': row.get('state') or '',
                        'zip': row.get('zipcode') or '',
                        'country': ''
                    }
                    record.fields.append(importer.RecordField('address', '', address))

                phone_number = row.get('phone_number') or ''
                if phone_number:
                    phone = {
                        'type': '',
                        'region': '',
                        'number': phone_number,
                        'ext': ''
                    }
                    record.fields.append(importer.RecordField('phone', '', phone))

                full_name = row.get('full_name') or ''
                if full_name:
                    record.fields.append(importer.RecordField('name', '', vault.TypedField.import_name_field(full_name)))

                folder = row.get('folder') or ''
                if folder:
                    f = importer.Folder()
                    f.path = folder
                    record.folders = [f]

                yield record

    def extension(self):
        return 'csv'
