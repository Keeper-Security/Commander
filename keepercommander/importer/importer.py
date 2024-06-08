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
import importlib
import io
import json
import logging
import os.path
from contextlib import contextmanager
from typing import List, Optional, Union, Dict, Iterable, Type, Any

from .. import vault, record_types
from ..error import CommandError
from ..params import KeeperParams

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
    try:
        module = importlib.import_module(full_name)
        if hasattr(module, 'Importer'):
            return module.Importer
        raise Exception('Cannot resolve importer for format {}'.format(input_format))
    except ModuleNotFoundError as e:
        raise CommandError('', f'The required module is not installed:\n\tpip install {e.name}')


def exporter_for_format(output_format):
    full_name = 'keepercommander.importer.' + output_format
    try:
        module = importlib.import_module(full_name)
        if hasattr(module, 'Exporter'):
            return module.Exporter
        raise Exception('Cannot resolve exporter for format {}'.format(output_format))
    except ModuleNotFoundError as e:
        raise CommandError('', f'The required module is not installed:\n\tpip install {e.name}')


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


def path_components(path, delimiter=PathDelimiter):    # type: (str, str) -> Iterable[str]
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
        self.permissions = None  # type: Optional[List[Permission]]

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


class Team:
    def __init__(self):
        self.uid = None
        self.name = None
        self.members = None   # type: Optional[List[str]]

    def validate(self):
        if not self.name:
            raise CommandError('', 'Team name cannot be empty')


class Attachment(abc.ABC):
    def __init__(self):
        self.file_uid = None
        self.name = None
        self.size = None
        self.mime = None

    @abc.abstractmethod
    def open(self):  # type: () -> io.BufferedIOBase
        pass

    def prepare(self):   # type: () -> None
        """ populate size if empty """
        pass


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
            value = json.dumps(value, sort_keys=True, separators=(',', ':'))
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
        self.label = label  # type: Optional[str]
        self.uids = []      # type: List[Any]


class Record:
    def __init__(self):
        self.uid = None          # type: Optional[Any]
        self.type = None         # type: Optional[str]
        self.title = None        # type: Optional[str]
        self.login = None        # type: Optional[str]
        self.password = None     # type: Optional[str]
        self.login_url = None    # type: Optional[str]
        self.notes = None        # type: Optional[str]
        self.last_modified = 0
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
        self.required = None   # type: Optional[bool]


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


class RecordTypeField:
    def __init__(self):
        self.type = ''
        self.label = ''
        self.required = None   # type Optional[bool]

    @classmethod
    def create(cls, field_type, field_label):  # type: (str, str) -> 'RecordTypeField'
        f = cls()
        f.type = field_type
        f.label = field_label
        return f


class RecordType:
    def __init__(self):
        self.name = ''
        self.description = ''
        self.fields = []  # type: List[RecordTypeField]


class BaseImporter(abc.ABC):
    def execute(self, name, **kwargs):
        # type: (BaseImporter, str, ...) -> Iterable[Union[Record, SharedFolder, File]]
        yield from self.do_import(name, **kwargs)

    @abc.abstractmethod
    def do_import(self, filename, **kwargs):
        # type: (BaseImporter, str, ...) -> Iterable[Union[Record, SharedFolder, File]]
        pass

    def extension(self):
        return ''

    def support_folder_filter(self):
        return False

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
        if field_type == 'privateKey':
            return vault.TypedField.import_ssh_key_field(field_value)
        if field_type == 'checkbox':
            return field_value.lower() in ('1', 't', 'true')

        str_values = field_value.split('\n')
        values = []
        value_type = None     # type: Optional[Type]
        if field_type in record_types.RecordFields:
            rf = record_types.RecordFields[field_type]
            if rf.type in record_types.FieldTypes:
                ft = record_types.FieldTypes[rf.type]
                value_type = type(ft.value)
        for str_value in str_values:
            v = None
            if value_type == dict:
                if len(str_value) >= 2:
                    if str_value[0] == '{' and str_value[-1] == '}':
                        try:
                            v = json.loads(str_value)
                        except:
                            pass
            if not v:
                if field_type == 'host':
                    v = vault.TypedField.import_host_field(str_value)
                elif field_type == 'phone':
                    v = vault.TypedField.import_phone_field(str_value)
                elif field_type == 'name':
                    v = vault.TypedField.import_name_field(str_value)
                elif field_type == 'address':
                    v = vault.TypedField.import_address_field(str_value)
                elif field_type == 'securityQuestion':
                    v = vault.TypedField.import_q_and_a_field(str_value)
                elif field_type == 'paymentCard':
                    v = vault.TypedField.import_card_field(str_value)
                elif field_type == 'bankAccount':
                    v = vault.TypedField.import_account_field(str_value)
                elif field_type == 'schedule':
                    v = vault.TypedField.import_schedule_field(str_value)
                else:
                    if value_type == int:
                        try:
                            v = int(str_value)
                        except:
                            pass
                    elif value_type == bool:
                        v = str_value.lower() in ('1', 't', 'true')
                    else:
                        v = str_value
            if v:
                values.append(v)
        if values:
            if len(values) == 1:
                return values[0]
            return values

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


class BaseFileImporter(BaseImporter, abc.ABC):
    def __init__(self):
        super(BaseFileImporter, self).__init__()

    def execute(self, name, **kwargs):
        # type: (str, ...) -> Iterable[Union[Record, SharedFolder, File]]

        path = os.path.expanduser(name)
        if not os.path.isfile(path):
            ext = self.extension()
            if ext:
                path = path + '.' + ext

        if not os.path.isfile(path):
            raise CommandError('import', f'File \'{name}\' does not exist')

        yield from self.do_import(path, **kwargs)


class BaseExporter(abc.ABC):
    def __init__(self):
        self.max_size = 10 * 1024 * 1024

    def execute(self, filename, items, **kwargs):
        # type: (str, List[Union[Record, SharedFolder, File, Team]], ...) -> None
        if filename:
            filename = os.path.expanduser(filename)
            if filename.find('.') < 0:
                ext = self.extension()
                if ext:
                    filename = filename + '.' + ext
        elif not self.supports_stdout():
            raise CommandError('export', 'File name parameter is required.')

        self.do_export(filename, items, **kwargs)

    @abc.abstractmethod
    def do_export(self, filename, records, **kwargs):
        # type: (str, List[Union[Record, SharedFolder, File, Team]], ...) -> None
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
                return vault.TypedField.export_host_field(field_value)
            if field_type == 'phone':
                return vault.TypedField.export_phone_field(field_value)
            if field_type == 'name':
                return vault.TypedField.export_name_field(field_value)
            if field_type == 'address':
                return vault.TypedField.export_address_field(field_value)
            if field_type == 'securityQuestion':
                return vault.TypedField.export_q_and_a_field(field_value)
            if field_type == 'paymentCard':
                return vault.TypedField.export_card_field(field_value)
            if field_type == 'bankAccount':
                return vault.TypedField.export_account_field(field_value)
            if field_type in ('keyPair', 'privateKey'):
                return vault.TypedField.export_ssh_key_field(field_value)
            if field_type == 'schedule':
                return vault.TypedField.export_schedule_field(field_value)
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
        yield io.BytesIO(self.data)


class BaseDownloadMembership(abc.ABC):
    @abc.abstractmethod
    def download_membership(self, params, **kwargs):    # type: (KeeperParams, ...) -> Iterable[Union[SharedFolder, Team]]
        pass


class BaseDownloadRecordType(abc.ABC):
    @abc.abstractmethod
    def download_record_type(self, params, **kwargs):   # type: (KeeperParams, ...) -> Iterable[RecordType]
        pass
