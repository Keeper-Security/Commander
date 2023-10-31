import csv
import logging
from typing import List

from keepercommander.importer.importer import Record, RecordField, RecordReferences
from keepercommander import vault
from keepercommander.importer.json import Exporter

records = []           # type: List[Record]

with open('contacts.csv', "r", encoding='utf-8-sig') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:   # type: dict
        r = Record()
        r.type = 'contact'
        name = [str(row.pop(x, '')).strip() for x in ('First Name', 'Middle Name', 'Last Name')]
        if any(name):
            rf = RecordField('name', '', {
                'first': name[0], 'middle': name[1], 'last': name[2]
            })
            r.fields.append(rf)
            r.title = vault.TypedField.export_name_field(rf.value)
        r.notes = str(row.pop('Notes', '')).strip()
        company = str(row.pop('Company', '')).strip()
        if company:
            rf = RecordField('text', 'company', company)
            r.fields.append(rf)
            if not r.title:
                r.title = company

        name = [str(row.pop(x, '')).strip() for x in ('Given Yomi', 'Surname Yomi')]
        if any(name):
            rf = RecordField('name', 'Yomi', {
                'first': name[0], 'middle': '', 'last': name[1]
            })
            r.fields.append(rf)

        address_refs = []
        for prefix in ('Business', 'Home', 'Other'):
            address = [str(row.pop(x, '')).strip() for x in (f'{prefix} Street',
                                                             f'{prefix} City',
                                                             f'{prefix} State',
                                                             f'{prefix} Postal Code',
                                                             f'{prefix} Country/Region')]
            if any(address):
                if address[-1] == 'USA':
                    address[-1] = 'US'
                rf = RecordField('address', '', {
                    'street1': address[0],
                    'street2': '',
                    'city': address[1],
                    'state': address[2],
                    'zip': address[3],
                    'country': address[4],
                })
                ar = Record()
                ar.title = f'{prefix}: {r.title}'
                ar.type = 'address'
                ar.fields.append(rf)
                records.append(ar)
                ar.uid = len(records)
                address_refs.append(ar.uid)
        if address_refs:
            if r.references is None:
                r.references = []
            rr = RecordReferences('address')
            rr.uids = address_refs
            r.references.append(rr)

        phones = []
        for label, value in row.items():
            if not isinstance(value, str):
                continue
            value = value.strip()
            if not value:
                continue
            if 'E-mail' in label:
                label = label.replace('Address', '').replace('  ', ' ').strip()
                if label == 'E-mail':
                    label = ''
                rf = RecordField('email', '', value)
                r.fields.append(rf)
            elif 'Phone' in label:
                label = label.replace('Phone', '').replace('  ', ' ').strip()
                rv = {
                    'type': label,
                    'region': '',
                    'number': value,
                    'ext': '',
                }
                phones.append(rv)
            elif 'Web Page' in label:
                rf = RecordField('url', label, value)
                r.fields.append(rf)
            else:
                rf = RecordField('text', label, value)
                r.fields.append(rf)
        if phones:
            rf = RecordField('phone', '', phones)
            r.fields.append(rf)
        records.append(r)
        r.uid = len(records)
        if not r.title:
            r.title = f'Contact #{r.uid}'

if records:
    exporter = Exporter()
    exporter.execute('contacts.json', records)
    logging.info('Exported %d records', len(records))





