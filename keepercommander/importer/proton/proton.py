import json
import os.path
import zipfile

from typing import Iterable, Union, Optional

from .. import importer


class ProtonJsonImporter(importer.BaseFileImporter):
    def do_import(self, filename, **kwargs):
        # type: (str, dict) -> Iterable[Union[importer.Record, importer.SharedFolder, importer.File]]
        name, ext = os.path.splitext(filename)
        proton_export = None     # type: Optional[dict]
        if ext == '.json':
            with open(filename, 'r') as f:
                proton_export = json.load(f)
        elif ext == '.zip':
            with zipfile.ZipFile(filename, 'r') as zf:
                proton_export = json.loads(zf.read('Proton Pass/data.json'))

        if not proton_export:
            raise Exception(f'Proton export file \"{filename}\" format is not supported')

        vaults = proton_export.get('vaults')
        if not isinstance(vaults, dict):
            return
        for vault in vaults.values():
            name = vault.get('name') or ''
            if name == 'Personal':
                name = ''
            if name:
                fol = importer.SharedFolder()
                fol.path = name
                yield fol
            items = vault.get('items')
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                data = item.get('data')
                if not isinstance(data, dict):
                    continue
                record_type = data.get('type') or ''
                record = importer.Record()
                if record_type == 'login':
                    record.type = 'login'
                elif record_type == 'creditCard':
                    record.type = 'bankCard'
                elif record_type == 'note':
                    record.type = 'encryptedNotes'
                else:
                    record.type = 'login'
                metadata = data.get('metadata')
                if not isinstance(metadata, dict):
                    continue
                record.title = metadata.get('name') or ''
                if not record.title:
                    continue
                record.uid = metadata.get('itemUuid') or ''
                note = metadata.get('note') or ''
                if note:
                    if record.type == 'encryptedNotes':
                        record.fields.append(importer.RecordField('note', '', note))
                    else:
                        record.notes = note
                content = data.get('content')
                if isinstance(content, dict):
                    record.login = content.get('username') or ''
                    record.password = content.get('password') or ''
                    for url in content.get('urls') or []:
                        if record.login_url:
                            record.fields.append(importer.RecordField('url', '', url))
                        else:
                            record.login_url = url
                    totp = content.get('totpUri') or ''
                    if totp:
                        record.fields.append(importer.RecordField(type=importer.FIELD_TYPE_ONE_TIME_CODE, value=totp))
                    if 'cardholderName' in content:
                        expiration = content.get('expirationDate') or ''
                        if len(expiration) == 6:
                            expiration = expiration[:2] + '/' + expiration[2:]
                        card = {
                            'cardNumber': content.get('number') or '',
                            'cardExpirationDate': expiration,
                            'cardSecurityCode': content.get('verificationNumber') or ''
                        }
                        record.fields.append(importer.RecordField('paymentCard', '', card))
                        pin = content.get('pin') or ''
                        if pin:
                            record.fields.append(importer.RecordField('pinCode', '', pin))
                extra_fields = data.get('extraFields') or []
                for extra in extra_fields:    # type: dict
                    extra_name = extra.get('fieldName')
                    extra_type = extra.get('type') or ''
                    extra_data = extra.get('data')
                    if extra_name and isinstance(extra_data, dict):
                        if extra_type in ('text', 'hidden'):
                            extra_content = extra_data.get('content') or ''
                        elif extra_type == 'totp':
                            extra_content = extra_data.get('totpUri') or ''
                        else:
                            extra_content = ''
                        if isinstance(extra_content, str) and len(extra_content) > 0:
                            if extra_type == 'text':
                                keeper_type = 'text'
                                if '\n' in extra_content:
                                    keeper_type = 'multiline'
                                record.fields.append(importer.RecordField(keeper_type, extra_name, extra_content))
                            elif extra_type == 'hidden':
                                keeper_type = 'secret'
                                record.fields.append(importer.RecordField(keeper_type, extra_name, extra_content))
                            elif extra_type == 'totp':
                                if not extra_content.startswith('otpauth:'):
                                    extra_content = f'otpauth://totp/?secret={extra_content}'
                                has_totp = any((True for x in record.fields if x.type == importer.FIELD_TYPE_ONE_TIME_CODE))
                                if has_totp:
                                    keeper_type = 'otp'
                                else:
                                    keeper_type = importer.FIELD_TYPE_ONE_TIME_CODE
                                    extra_name = ''
                                record.fields.append(importer.RecordField(keeper_type, extra_name, extra_content))

                yield record

"""
        def split_pgp_message(m):  # type: (bytes) -> Iterable[Tuple[int, bytes]]
            start_pos = 0
            while start_pos < len(m):
                tag = m[start_pos] & ~0xC0
                lb1 = m[start_pos+1]
                if lb1 < 192:
                    l = lb1
                    l_length = 1
                elif lb1 < 255:
                    lb2 = m[start_pos+2]
                    l = ((lb1 - 192) << 8) + lb2 + 192
                    l_length = 2
                else:
                    lb2 = m[start_pos+2]
                    lb3 = m[start_pos+3]
                    lb4 = m[start_pos+4]
                    lb5 = m[start_pos+5]
                    l = (lb2 << 24) + (lb3 << 16) + (lb4 << 8) + lb5
                    l_length = 5

                start_pos += l + 1 + l_length
                data = m[start_pos-l:start_pos]
                yield tag, data
                
        no = 0
        for t, d in split_message(ee):
            no += 1
            if t == 3:
                self.assertEqual(d[0], 4)
                alg = d[1]
                self.assertEqual(d[2], 3)
                hash_alg = d[3]
                salt = d[4:12]
                count = d[12]
                hashable_length = (16 + (count & 0x0f)) << ((count >> 4) + 6)
                s2k_element = salt + 'password'
                l = len(s2k_element)
                while (s2k_element) > l:
                    // hash s2k_element
                    s2k_element -= l
                if len(d) > 12:
                    sess_alg = d[13]
                    session_key = d[14:46]
            elif t == 18:
                pass
                
"""