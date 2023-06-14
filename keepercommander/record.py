#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#

import datetime
import hashlib
import hmac
import itertools
from typing import Tuple, Optional

from urllib import parse

from .base32hex import b32decode


def get_totp_code(url, offset=None):   # type: (str, Optional[int]) -> Optional[Tuple[str, int, int]]
    comp = parse.urlparse(url)
    if comp.scheme == 'otpauth':
        secret = None
        algorithm = 'SHA1'
        digits = 6
        period = 30
        for k, v in parse.parse_qsl(comp.query):
            if k == 'secret':
                secret = v
            elif k == 'algorithm':
                algorithm = v
            elif k == 'digits':
                digits = int(v)
            elif k == 'period':
                period = int(v)
        if secret:
            tm_base = int(datetime.datetime.now().timestamp())
            tm = tm_base / period
            if isinstance(offset, int):
                tm += offset
            alg = algorithm.lower()
            if alg in hashlib.__dict__:
                reminder = len(secret) % 8
                if reminder in {2, 4, 5, 7}:
                    padding = '=' * (8 - reminder)
                    secret += padding
                key = bytes(b32decode(secret))
                msg = int(tm).to_bytes(8, byteorder='big')
                hash = hashlib.__dict__[alg]
                hm = hmac.new(key, msg=msg, digestmod=hash)
                digest = hm.digest()
                offset = digest[-1] & 0x0f
                base = bytearray(digest[offset:offset + 4])
                base[0] = base[0] & 0x7f
                code_int = int.from_bytes(base, byteorder='big')
                code = str(code_int % (10 ** digits))
                if len(code) < digits:
                    code = code.rjust(digits, '0')
                return code, period - (tm_base % period), period
            else:
                raise Exception(f'Unsupported hash algorithm: {algorithm}')


class Record:
    """Defines a user-friendly Keeper Record for display purposes"""

    @staticmethod
    def xstr(s):
        return str(s or '')

    def __init__(self, record_uid='', folder='', title='', login='', password='', login_url='', notes='',
                 custom_fields=None, revision=''):
        self.record_uid = record_uid
        self.record_type = ''
        self.folder = Record.xstr(folder)
        self.title = Record.xstr(title)
        self.login = Record.xstr(login)
        self.password = Record.xstr(password)
        self.login_url = Record.xstr(login_url)
        self.notes = Record.xstr(notes)
        self.custom_fields = custom_fields or []  # type: list
        self.attachments = None
        self.revision = revision
        self.unmasked_password = None
        self.totp = None
        self.version = 2

    def load(self, data, **kwargs):
        self.version = kwargs.get('version', 2)
        if 'title' in data:
            self.title = Record.xstr(data['title']).strip()
        if 'notes' in data:
            self.notes = Record.xstr(data['notes'])

        if self.version == 2:
            if 'secret1' in data:
                self.login = Record.xstr(data['secret1'])
            if 'secret2' in data:
                self.password = Record.xstr(data['secret2'])
            if 'link' in data:
                self.login_url = Record.xstr(data['link'])
            if 'custom' in data:
                self.custom_fields = data['custom'] or []
            if 'extra' in kwargs and kwargs['extra']:
                extra = kwargs['extra']
                self.attachments = extra.get('files')
                if 'fields' in extra:
                    for field in extra['fields']:
                        if field['field_type'] == 'totp':
                            self.totp = field['data']
        elif self.version == 3:
            self.record_type = data.get('type', 'login')
            for field in itertools.chain(data['fields'], data.get('custom') or []):
                field_label = field.get('label', '')
                field_type = field.get('type', '')
                field_value = field.get('value', '')
                if isinstance(field_value, list):
                    if len(field_value) == 1:
                        field_value = field_value[0]
                    elif len(field_value) == 0:
                        field_value = None
                if field_value:
                    if isinstance(field_value, str):
                        if field_type == 'login' and not self.login:
                            self.login = field_value
                            continue
                        if field_type == 'password' and not self.password:
                            self.password = field_value
                            continue
                        if field_type == 'url' and not self.login_url:
                            self.login_url = field_value
                            continue
                        if field_type == 'oneTimeCode' and not self.totp:
                            self.totp = field_value
                            continue

                    if field_type:
                        field_name = f'{field_type}:{field_label}'
                    elif field_label:
                        field_name = field_label
                    else:
                        field_name = 'text'
                    self.append_field_value(field_name, field_value)

        elif self.version == 4:
            self.record_type = 'file'
            for field in ['size', 'name', 'type']:
                if field in data:
                    self.append_field_value(field, data[field])
        else:
            pass
        if 'revision' in kwargs:
            self.revision = kwargs['revision']

    def get(self, field):
        result = ''
        for c in self.custom_fields:
            if (c['name'] == field):
                result = c['value']
                break
        return result

    def append_field_value(self, name, value):
        if not value:
            return
        field = next((x for x in self.custom_fields if x.get('name', '') == name), None)
        if not field:
            field = {'type': 'text', 'name': name}
            self.custom_fields.append(field)
        field_value = field.get('value', None)
        if field_value:
            if not isinstance(field_value, list):
                field_value = [field_value]
            if isinstance(value, list):
                field_value.extend(value)
            else:
                field_value.append(value)
        else:
            field_value = value
        field['value'] = field_value

    def set_field(self, name, value):
        found = False
        for field in self.custom_fields:
            if field['name'] == name:
                field['value'] = value
                found = True
                break
        if not found:
            self.custom_fields.append({'type': 'text', 'name': name, 'value': value})

    def remove_field(self, name):
        if self.custom_fields:
            idxs = [i for i, x in enumerate(self.custom_fields) if x['name'] == name]
            if len(idxs) == 1:
                return self.custom_fields.pop(idxs[0])

    def display(self, unmask=False):
        print('')
        print('{0:>20s}: {1:<20s}'.format('UID', self.record_uid))
        print('{0:>20s}: {1:<20s}'.format('Type', ''))
        if self.title: print('{0:>20s}: {1:<20s}'.format('Title', self.title))
        if self.login: print('{0:>20s}: {1:<20s}'.format('Login', self.login))
        if self.password: print('{0:>20s}: {1:<20s}'.format('Password', self.password if unmask else '********'))
        if self.login_url: print('{0:>20s}: {1:<20s}'.format('URL', self.login_url))
        # print('{0:>20s}: https://keepersecurity.com/vault#detail/{1}'.format('Link',self.record_uid))

        if len(self.custom_fields) > 0:
            for c in self.custom_fields:
                if not 'value' in c: c['value'] = ''
                if not 'name' in c: c['name'] = c['type'] if 'type' in c else ''
                print('{0:>20s}: {1:<s}'.format(str(c['name']), str(c['value'])))

        if self.notes:
            lines = self.notes.split('\n')
            for i in range(len(lines)):
                print('{0:>21s} {1}'.format('Notes:' if i == 0 else '', lines[i].strip()))

        if self.attachments:
            for i in range(len(self.attachments)):
                atta = self.attachments[i]
                size = atta.get('size') or 0
                scale = 'b'
                if size > 0:
                    if size > 1000:
                        size = size / 1024
                        scale = 'Kb'
                    if size > 1000:
                        size = size / 1024
                        scale = 'Mb'
                    if size > 1000:
                        size = size / 1024
                        scale = 'Gb'
                sz = '{0:.2f}'.format(size).rstrip('0').rstrip('.')
                print('{0:>21s} {1:<20s} {2:>6s}{3:<2s} {4:>6s}: {5}'.format(
                    'Attachments:' if i == 0 else '', atta.get('title') or atta.get('name'), sz, scale, 'ID', atta.get('id')))

        if self.totp:
            print('{0:>20s}: {1}'.format('TOTP URL', self.totp if unmask else '********'))
            code, remain, _ = get_totp_code(self.totp)
            if code:
                print('{0:>20s}: {1:<20s} valid for {2} sec'.format('Two Factor Code', code, remain))

    def mask_password(self):
        if self.password != '******':
            self.unmasked_password = self.password
        self.password = '******'

    def to_string(self):
        target = self.record_uid + self.folder + self.title + \
                 self.login + self.password + self.notes + \
                 self.login_url + str(self.custom_fields)
        return target

    def to_lowerstring(self):
        return self.to_string().lower()

    def to_tab_delimited(self):

        def tabulate(*args):
            return '\t'.join(args)

        custom_fields = ''
        if self.custom_fields:
            for field in self.custom_fields:
                if ('name' in field) and ('value' in field):
                    custom_fields = '\t'.join([field['name'] + '\t' + \
                                               field['value'] for field in self.custom_fields])

        return tabulate(self.folder, self.title, self.login,
                        self.password, self.login_url, self.notes.replace('\n', '\\\\n'),
                        custom_fields)

    def to_dictionary(self):
        return {
            'uid': self.record_uid,
            'folder': self.folder,
            'title': self.title,
            'login': self.login,
            'password': self.password,
            'login_url': self.login_url,
            'notes': self.notes,
            'custom_fields': self.custom_fields,
        }

    @classmethod
    def validate_record_data(cls, data, extra, udata):
        # data - always present (UID, Title, ...)
        if data:
            data_types = {
                'folder': {'field': 'folder', 'name': 'folder', 'type': ''},
                'title': {'field': 'title', 'name': 'title', 'type': ''},
                'secret1': {'field': 'secret1', 'name': 'login', 'type': ''},
                'secret2': {'field': 'secret2', 'name': 'password', 'type': ''},
                'link': {'field': 'link', 'name': 'url', 'type': ''},
                'notes': {'field': 'notes', 'name': 'notes', 'type': ''},
                'custom': {'field': 'custom', 'name': 'custom', 'type': []}
            }

            for item in data_types:
                if item in data and type(data.get(item)) != type(data_types[item].get('type')):
                    raise ValueError('Error validating record data - "' + data_types[item].get('name') + '" is invalid!')

            if 'custom' in data and isinstance(data['custom'], list):
                invalid = [x for x in data['custom'] if not(x)]
                if invalid:
                    raise ValueError('Error validating record data - Invalid custom fields! ' + str(invalid))
        else:
            raise Exception('Record is empty!')

        # extra and udata sections are optional
        if extra:
            fields = extra.get('fields') or []
            invalid = [x for x in fields if not(x)]
            if invalid:
                raise ValueError('Error validating record extra data - Invalid extra fields! ' + str(invalid))
