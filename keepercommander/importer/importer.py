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
import abc
import collections
import importlib
import io
import json
import logging
import os.path
from contextlib import contextmanager
from typing import List, Optional, Union

from ..error import CommandError
from ..recordv3 import RecordV3

PathDelimiter = '\\'
TWO_FACTOR_CODE = 'TFC:Keeper'
FIELD_TYPE_ONE_TIME_CODE = 'oneTimeCode'


def replace_email_domain(email, old_domain, new_domain):
    # type: (str, Optional[str], Optional[str]) -> str
    if old_domain and new_domain and email.endswith(f'@{old_domain}'):
        email_user, domain = email.split('@')
        return f'{email_user}@{new_domain}'
    else:
        return email


def importer_for_format(input_format):
    full_name = 'keepercommander.importer.' + input_format
    module = importlib.import_module(full_name)
    if hasattr(module, 'Importer'):
        return module.Importer
    raise Exception('Cannot resolve importer for format {}'.format(input_format))


def exporter_for_format(output_format):
    full_name = 'keepercommander.importer.' + output_format
    module = importlib.import_module(full_name)
    if hasattr(module, 'Exporter'):
        return module.Exporter
    raise Exception('Cannot resolve exporter for format {}'.format(output_format))


def strip_path_delimiter(name, delimiter=PathDelimiter):
    folder = name.strip()
    if folder == delimiter:
        return ''
    if len(folder) > 1:
        if folder[:1] == delimiter and folder[:2] != delimiter*2:
            folder = folder[1:].strip()
    if len(folder) > 1:
        if folder[-1:] == delimiter and folder[-2:] != delimiter*2:
            folder = folder[:-1].strip()
    return folder


def path_components(path, delimiter=PathDelimiter):
    # type: (str, str) -> collections.Iterable[str]
    p = path.strip()
    pos = 0
    while pos < len(p):
        idx = p.find(delimiter, pos)
        if idx >= 0:
            if idx+1 < len(p):
                if p[idx+1] == delimiter:
                    pos = idx + 2
                    continue
            comp = p[:idx].strip()
            p = p[idx+1:].strip()
            pos = 0
            if len(comp) > 0:
                yield comp.replace(2*delimiter, delimiter)
        else:
            p = strip_path_delimiter(p, delimiter=delimiter)
            if len(p) > 0:
                yield p.replace(2*delimiter, delimiter)
                p = ''


def check_if_bool(value):
    return value is None or type(value) == bool


class Permission:
    def __init__(self):
        self.uid = None
        self.name = None
        self.manage_users = None
        self.manage_records = None


class SharedFolder:
    def __init__(self):
        self.uid = None
        self.path = None
        self.manage_users = None
        self.manage_records = None
        self.can_edit = None
        self.can_share = None
        self.permissions = None  # type: [Permission]

    def validate(self):
        if not self.path:
            raise CommandError('import', 'shared folder. path cannot be empty')
        for attr in ['manage_users', 'manage_records', 'can_edit', 'can_share']:
            if hasattr(self, attr):
                if not check_if_bool(getattr(self, attr)):
                    raise CommandError('import', 'shared folder. property \'{0}\' should be a boolean'.format(attr))
        if self.permissions:
            for p in self.permissions:
                if not p.name and not p.uid:
                    raise CommandError('import', 'shared folder permission. property \'name\' cannot be empty'.format(attr))
                for attr in ['manage_users', 'manage_records']:
                    if hasattr(p, attr):
                        if not check_if_bool(getattr(p, attr)):
                            raise CommandError('import', 'shared folder permission. property \'{0}\' should be a boolean'.format(attr))


class Attachment(abc.ABC):
    def __init__(self):
        self.name = None
        self.size = None
        self.mime = None

    @abc.abstractmethod
    def open(self):  # type: () -> io.BufferedIOBase
        raise NotImplementedError()


class Folder:
    def __init__(self):
        self.uid = None        # type: Optional[str]
        self.domain = None     # type: Optional[str]
        self.path = None       # type: Optional[str]
        self.can_edit = None   # type: Optional[str]
        self.can_share = None  # type: Optional[str]

    def get_folder_path(self):
        path = self.domain or ''
        if self.path:
            if path:
                path = path + PathDelimiter
            path = path + self.path
        return path


class RecordField:
    def __init__(self, type=None, label=None, value=None):
        self.type = type    # type: Optional[str]
        self.label = label   # type: Optional[str]
        self.value = value   # type: any

    def name_key(self):
        if self.type and self.label:
            return f'${self.type.lower()}.{self.label.lower()}'
        elif self.type:
            return f'${self.type.lower()}'
        else:
            return (self.label or '').lower()

    @staticmethod
    def hash_value(value):  # type: (any) -> str
        if not value:
            return ''
        if isinstance(value, str):
            value = value.strip()
        elif isinstance(value, list):
            value = [RecordField.hash_value(x) for x in value]
            value = '|'.join((x for x in value if x))
        elif isinstance(value, dict):
            keys = [x for x in value]
            if 'privateKey' in keys:
                if value['privateKey']:
                    try:
                        keys.remove('publicKey')
                    except:
                        pass
            keys.sort()
            kvp = [(x, RecordField.hash_value(value[x])) for x in keys]
            kvp = [x for x in kvp if x[1]]
            value = ';'.join((f'{x[0]}:{x[1]}' for x in kvp))
        else:
            value = str(value)
        return value

    def hash_key(self):  # type: () -> Optional[str]
        value = RecordField.hash_value(self.value)
        if value:
            name = self.name_key()
            return f'{name}:{value}'


class RecordReferences:
    def __init__(self, type='', label=None):
        self.type = type
        self.label = label
        self.uids = []   # type: List[any]


class Record:
    def __init__(self):
        self.uid = None
        self.type = None         # type: Optional[str]
        self.title = None
        self.login = None
        self.password = None
        self.login_url = None
        self.notes = None
        self.fields = []         # type: List[RecordField]
        self.folders = None      # type: Optional[List[Folder]]
        self.attachments = None  # type: Optional[List[Attachment]]
        self.references = None   # type: Optional[List[RecordReferences]]
        self.schema = None       # type: Optional[List[RecordSchemaField]]

    def validate(self):
        if not self.title:
            raise CommandError('import', 'Record: title cannot be empty')
        if self.folders:
            for f in self.folders:
                for attr in ['can_edit', 'can_share']:
                    if hasattr(f, attr):
                        if not check_if_bool(getattr(f, attr)):
                            raise CommandError('import', f'Record \'{self.title}\': folder property \'{attr}\' should be boolean')


class RecordSchemaField:
    def __init__(self):
        self.ref = ''
        self.label = ''


class File:
    def __init__(self):
        self.file_id = None
        self.title = None
        self.name = None
        self.size = None
        self.key = None
        self.mime = None

    def open(self):
        raise NotImplementedError()

    def validate(self):
        pass


class BaseImporter(abc.ABC):
    def execute(self, name, **kwargs):
        # type: (BaseImporter, str, dict) -> collections.Iterable[Union[Record, SharedFolder, File]]
        yield from self.do_import(name, **kwargs)

    @abc.abstractmethod
    def do_import(self, filename, **kwargs):
        # type: (BaseImporter, str, dict) -> collections.Iterable[Union[Record, SharedFolder, File]]
        pass

    def extension(self):
        return ''

    @staticmethod
    def import_host_field(value):    # type: (str) -> Optional[dict]
        if isinstance(value, str):
            host, _, port = value.partition(':')
            return {
                'hostName': host.strip(),
                'port': port.strip()
            }

    @staticmethod
    def import_phone_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            region = ''
            number = ''
            ext = ''
            phone_type, _, rest = value.partition(':')
            if not rest:
                rest = phone_type
                phone_type = ''
            comps = rest.strip().split(' ')
            for comp in comps:
                comp = comp.strip()
                if comp.isalpha():
                    if len(comp) == 2:
                        if not region:
                            region = comp
                    elif not phone_type:
                        phone_type = comp
                elif len(comp) >= 6:
                    if not number:
                        number = comp
                elif not ext:
                    ext = comp
            result = {
                'type': '',
                'region': '',
                'number': number.strip(),
                'ext': ext.strip()
            }
            phone_type = phone_type.strip()
            region = region.strip()
            if phone_type:
                result['type'] = phone_type
            if region:
                result['region'] = region
            return result

    @staticmethod
    def import_name_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            first = ''
            middle = ''
            last = ''
            comma_pos = value.find(',')
            if comma_pos >= 0:
                last = value[:comma_pos]
                rest = value[comma_pos+1:]
            else:
                space_pos = value.rfind(' ')
                if space_pos >= 0:
                    last = value[space_pos+1:]
                    rest = value[:space_pos]
                else:
                    last = value
                    rest = ''
            rest = rest.strip()
            if rest:
                space_pos = rest.rfind(' ')
                if space_pos >= 0:
                    middle = rest[space_pos+1:]
                    first = rest[:space_pos]
                else:
                    middle = ''
                    first = rest

            return {
                'first': first.strip(),
                'middle': middle.strip(),
                'last': last.strip(),
            }

    @staticmethod
    def import_address_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            comps = value.split(',')
            street1 = comps[0].strip() if len(comps) > 0 else ''
            city = comps[1].strip() if len(comps) > 1 else ''
            state, _, zip_code = comps[2].strip().partition(' ') if len(comps) > 2 else ('', '', '')
            country = comps[3].strip() if len(comps) > 3 else ''

            return {
                'street1': street1,
                'street2': '',
                'city': city,
                'state': state,
                'zip': zip_code,
                'country': country
            }

    @staticmethod
    def import_q_and_a_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            q, sign, a = value.partition('?')
            return {
                'question': q.strip() + '?',
                'answer': a.strip(),
            }

    @staticmethod
    def import_card_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            comps = value.split(' ')
            number = ''
            expiration = ''
            cvv = ''
            for comp in comps:
                comp = comp.strip()
                if comp:
                    if len(comp) > 10:
                        number = comp
                    elif comp.find('/') >= 0:
                        expiration = comp
                    elif len(comp) <= 6:
                        cvv = comp
            if number or expiration or cvv:
                return {
                    'cardNumber': number,
                    'cardExpirationDate': expiration,
                    'cardSecurityCode':  cvv,
                }

    @staticmethod
    def import_account_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            account_type = ''
            routing = ''
            account_number = ''
            comps = value.split()
            for comp in comps:
                comp = comp.strip()
                if comp.isnumeric():
                    if not routing:
                        routing = comp
                    elif not account_number:
                        account_number = comp
                else:
                    if not account_type:
                        account_type = comp
            if routing or account_number:
                return {
                    'accountType': account_type,
                    'routingNumber': routing,
                    'accountNumber': account_number
                }

    @staticmethod
    def import_ssh_key_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            return {
                'privateKey': value,
                'publicKey': ''
            }

    @staticmethod
    def import_field(field_type, field_value):  # type: (str, str) -> any
        if not field_value:
            return None
        if not field_type:
            return field_value
        if field_type in {'text', 'multiline', 'secret', 'note'}:
            return field_value
        if field_type == 'date':
            try:
                return int(field_value)
            except:
                return None
        if field_type == 'keyPair':
            return BaseImporter.import_ssh_key_field(field_value)

        str_values = field_value.split('\n')
        values = []
        for str_value in str_values:
            if field_type == 'host':
                v = BaseImporter.import_host_field(str_value)
            elif field_type == 'phone':
                v = BaseImporter.import_phone_field(str_value)
            elif field_type == 'name':
                v = BaseImporter.import_name_field(str_value)
            elif field_type == 'address':
                v = BaseImporter.import_address_field(str_value)
            elif field_type == 'securityQuestion':
                v = BaseImporter.import_q_and_a_field(str_value)
            elif field_type == 'paymentCard':
                v = BaseImporter.import_card_field(str_value)
            elif field_type == 'bankAccount':
                v = BaseImporter.import_account_field(str_value)
            else:
                v = str_value
                if field_type in RecordV3.field_values:
                    fv = RecordV3.field_values[field_type]
                    if isinstance(fv.get('value'), dict):
                        try:
                            v = json.loads(str_value)
                        except:
                            pass
                    elif isinstance(fv.get('value'), int):
                        try:
                            v = int(str_value)
                        except:
                            pass
            if v:
                values.append(v)
        if values:
            if len(values) == 1:
                return values[0]
            return values


class BaseFileImporter(BaseImporter, abc.ABC):
    def __init__(self):
        super(BaseFileImporter, self).__init__()

    def execute(self, name, **kwargs):
        # type: (str, ...) -> collections.Iterable[Union[Record, SharedFolder, File]]

        path = os.path.expanduser(name)
        if not os.path.isfile(path):
            ext = self.extension()
            if ext:
                path = path + '.' + ext

        if not os.path.isfile(path):
            raise CommandError('import', 'File \'{0}\' does not exist'.format(name))

        yield from self.do_import(path, **kwargs)


class BaseExporter(abc.ABC):
    def __init__(self):
        self.max_size = 10 * 1024 * 1024

    def execute(self, filename, items, file_password=None):
        # type: (str, List[Union[Record, SharedFolder, File]], Optional[str]) -> None
        if filename:
            filename = os.path.expanduser(filename)
            if filename.find('.') < 0:
                ext = self.extension()
                if ext:
                    filename = filename + '.' + ext
        elif not self.supports_stdout():
            raise CommandError('export', 'File name parameter is required.')

        self.do_export(filename, items, file_password)
        if filename and os.path.isfile(filename):
            logging.info('Vault has been exported to: %s', os.path.abspath(filename))

    @abc.abstractmethod
    def do_export(self, filename, records, file_password=None):
        # type: (str, List[Record, File], Optional[str]) -> None
        pass

    def has_shared_folders(self):
        return False

    def has_attachments(self):
        return False

    def extension(self):
        return ''

    def supports_stdout(self):
        return False

    def supports_v3_record(self):
        return True

    @staticmethod
    def export_host_field(value):    # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            host = value.get('hostName') or ''
            port = value.get('port') or ''
            if host or port:
                if port:
                    host += ':' + port
            return host

    @staticmethod
    def export_phone_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            phone = value.get('type') or ''
            if phone:
                phone += ':'
            region = value.get('region') or ''
            if region:
                if len(region) == 2 and region.isalpha():
                    pass
                elif region.isnumeric():
                    region = '+' + region
                else:
                    region = ''
                if region:
                    phone += '  ' + region
            number = (value.get('number') or '').replace(' ', '-')
            if number:
                phone += ' ' + number
            ext = (value.get('ext') or '').replace(' ', '-')
            if ext:
                phone += ' ' + ext
            return phone

    @staticmethod
    def export_name_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            first_name = value.get('first') or ''
            middle_name = value.get('middle') or ''
            name = value.get('last') or ''
            if first_name or middle_name or name:
                name = f'{name}, {first_name}'
                if middle_name:
                    name += ' ' + middle_name
            return name

    @staticmethod
    def export_address_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            address = value.get('street1', '').replace(',', '.')
            street2 = value.get('street2', '').replace(',', '.')
            if street2:
                address += ' ' + street2
            city = value.get('city', '').replace(',', '.')
            if city:
                address += ', ' + city
                state = value.get('state', '').replace(',', '.')
                zip_code = value.get('zip', '').replace(',', '.')
                if state or zip_code:
                    address += ', ' + state + ' ' + zip_code
                    country = value.get('country', '').replace(',', '.')
                    if country:
                        address += ', ' + country
            return address

    @staticmethod
    def export_q_and_a_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            q = value.get('question', '').replace('?', '')
            a = value.get('answer', '')
            if q or a:
                return f'{q}? {a}'
            return q

    @staticmethod
    def export_card_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            comps = []
            number = value.get('cardNumber')
            if number:
                comps.append(number)
            expiration = value.get('cardExpirationDate')
            if expiration:
                comps.append(expiration)
            cvv = value.get('cardSecurityCode')
            if cvv:
                comps.append(cvv)
            if comps:
                return ' '.join(comps)

    @staticmethod
    def export_account_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            account_type = value.get('accountType', '').replace(' ', '')
            routing = value.get('routingNumber', '').replace(' ', '')
            account_number = value.get('accountNumber', '').replace(' ', '')
            if routing or account_number:
                comps = []
                if account_type:
                    comps.append(account_type)
                if routing:
                    comps.append(routing)
                if account_number:
                    comps.append(account_number)
                if comps:
                    return ' '.join(comps)

    @staticmethod
    def export_ssh_key_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            return value.get('privateKey', '')

    @staticmethod
    def export_field(field_type, field_value):  # type: (str, any) -> str
        if not field_value:
            return ''

        if isinstance(field_value, str):
            return field_value
        if isinstance(field_value, list):
            values = []
            for value in field_value:
                v = BaseExporter.export_field(field_type, value)
                if v:
                    values.append(v)
            return '\n'.join((x.replace('\n', ' ') for x in values))
        if isinstance(field_value, dict):
            if field_type == 'host':
                return BaseExporter.export_host_field(field_value)
            if field_type == 'phone':
                return BaseExporter.export_phone_field(field_value)
            if field_type == 'name':
                return BaseExporter.export_name_field(field_value)
            if field_type == 'address':
                return BaseExporter.export_address_field(field_value)
            if field_type == 'securityQuestion':
                return BaseExporter.export_q_and_a_field(field_value)
            if field_type == 'paymentCard':
                return BaseExporter.export_card_field(field_value)
            if field_type == 'bankAccount':
                return BaseExporter.export_account_field(field_value)
            if field_type == 'keyPair':
                return BaseExporter.export_ssh_key_field(field_value)
            return json.dumps(field_value)

        return str(field_value)


class BytesAttachment(Attachment):
    def __init__(self, name, buffer):  # type: (str, bytes) -> None
        Attachment.__init__(self)
        self.name = name
        self.data = buffer
        self.size = len(buffer)

    @contextmanager
    def open(self):
        out = io.BytesIO()
        out.write(self.data)
        out.seek(0)
        yield out
