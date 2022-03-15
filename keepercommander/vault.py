#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

import abc
import json
from typing import Optional, List, Tuple, Iterable, Type

import itertools

from .params import KeeperParams


class KeeperRecord(abc.ABC):
    def __init__(self):
        self.record_uid = ''
        self.title = ''
        self.client_time_modified = 0
        self.record_key = b''
        self.revision = 0

    @abc.abstractmethod
    def get_version(self):  # type: () -> int
        pass

    @property
    def version(self):
        return self.get_version()

    @abc.abstractmethod
    def get_record_type(self):  # type: () -> str
        pass

    @property
    def record_type(self):
        return self.get_record_type()

    @abc.abstractmethod
    def load_record_data(self, data, extra=None):   # type: (dict, Optional[dict]) -> None
        pass

    @staticmethod
    def create(params, record_type):  # type: (KeeperParams, str) -> Optional['KeeperRecord']
        if not record_type:
            record_type = 'login'
        if record_type in {'legacy', 'general'}:
            record = PasswordRecord()
        elif record_type == 'file':
            record = FileRecord()
        else:
            record = TypedRecord()
            meta_data = next((x for x in params.record_type_cache.values()
                              if x.get('$id', '') == record_type.lower()), None)
            if meta_data and 'fields' in meta_data:
                for field in meta_data['fields']:
                    typed_field = TypedField()
                    typed_field.type = field.get('$ref', 'text')
                    typed_field.label = field.get('label', None)
                    record.fields.append(typed_field)
        return record

    @staticmethod
    def load(params, record_uid):  # type: (KeeperParams, str) -> Optional['KeeperRecord']
        if record_uid not in params.record_cache:
            return
        record = params.record_cache[record_uid]
        if 'data_unencrypted' not in record:
            return
        version = record.get('version', 0)

        if version == 2:
            keeper_record = PasswordRecord()
        elif version == 3:
            keeper_record = TypedRecord()
        elif version == 4:
            keeper_record = FileRecord()
            keeper_record.storage_size = record.get('file_size')
        elif version == 5:
            keeper_record = ApplicationRecord()
        else:
            return
        keeper_record.record_uid = record['record_uid']
        keeper_record.revision = record.get('revision', 0)
        keeper_record.record_key = record['record_key_unencrypted']
        keeper_record.client_time_modified = record.get('client_modified_time', 0)

        data = json.loads(record['data_unencrypted'])
        extra = json.loads(record['extra_unencrypted']) if 'extra_unencrypted' in record else None
        keeper_record.load_record_data(data, extra)

        return keeper_record

    def enumerate_fields(self):    # type: () -> Iterable[Tuple[str, any]]
        yield '(title)', self.title


class CustomField(object):
    def __init__(self, custom_field=None):  # type: (Optional[dict]) -> None
        if custom_field is None:
            custom_field = {}
        self.name = custom_field.get('name', '')
        self.value = custom_field.get('value', '')
        self.type = custom_field.get('type', '')


class AttachmentFile(object):
    def __init__(self, file_field=None):  # type: (Optional[dict]) -> None
        self.id = file_field.get('id', '')
        self.key = file_field.get('key', '')
        self.name = file_field.get('name', '')
        self.title = file_field.get('title', '')
        self.mime_type = file_field.get('type', '')
        self.size = file_field.get('size', 0)


class ExtraField(object):
    def __init__(self, extra_field=None):  # type: (Optional[dict]) -> None
        if extra_field is None:
            extra_field = {}
        self.id = extra_field.get('id', '')
        self.field_type = extra_field.get('field_type', '')
        self.field_title = extra_field.get('field_title', '')
        self.data = extra_field.get('data', '')


class PasswordRecord(KeeperRecord):
    def __init__(self):
        super(PasswordRecord, self).__init__()
        self.login = ''
        self.password = ''
        self.link = ''
        self.notes = ''
        self.custom = []  # type: List[CustomField]
        self.attachments = None  # type: Optional[List[AttachmentFile]]
        self.fields = None  # type: Optional[List[ExtraField]]

    def get_version(self):  # type: () -> int
        return 2

    def get_record_type(self):
        return ''

    def load_record_data(self, data, extra=None):
        self.title = data.get('title', '')
        self.login = data.get('secret1', '')
        self.password = data.get('secret2', '')
        self.link = data.get('link', '')
        self.notes = data.get('notes', '')
        custom = data.get('custom')
        if isinstance(custom, list):
            self.custom.extend((CustomField(x) for x in custom if isinstance(x, dict) and 'name' in x))
        if isinstance(extra, dict):
            if 'files' in extra:
                self.attachments = [AttachmentFile(x) for x in extra['files']]

            if 'fields' in extra:
                self.fields = [ExtraField(x) for x in extra['fields']]

    def enumerate_fields(self):  # type: () -> Iterable[Tuple[str, any]]
        for pair in super(PasswordRecord, self).enumerate_fields():
            yield pair
        yield '(login)', self.login
        yield '(password)', self.password
        yield '(url)', self.link
        yield '(notes)', self.notes
        for cf in self.custom:
            yield cf.name, cf.value
        if self.fields:
            for f in self.fields:
                field_type = f.field_type
                if field_type == 'totp':
                    field_type = '(oneTimeCode)'
                field_title = f.field_title
                field_name = f'{field_type}.{field_title}' \
                    if (field_type and field_title) else (field_type or field_title)
                yield field_name, f.data


class TypedField(object):
    def __init__(self, typed_field=None):
        if typed_field is None:
            typed_field = {}
        self.type = typed_field.get('type', '')
        self.label = typed_field.get('label', '')
        self.value = typed_field.get('value', [])

    def get_default_value(self, value_type=None):  # type: (Optional[Type]) -> any
        value = None
        if isinstance(self.value, list):
            if len(self.value) > 0:
                value = self.value[0]
        else:
            value = self.value
        if isinstance(value_type, type):
            if not isinstance(value, value_type):
                return
        return value

    def get_field_name(self):
        return f'({self.type}.{self.label})' if self.type and self.label else \
               f'({self.type})' if self.type else \
               f'{self.label}'

    def get_external_value(self):
        if isinstance(self.value, list):
            if len(self.value) == 0:
                return None
            if len(self.value) == 1:
                return self.value[0]
        return self.value


class TypedRecord(KeeperRecord):
    def __init__(self):
        super(TypedRecord, self).__init__()
        self.type_name = ''
        self.notes = ''
        self.fields = []     # type: List[TypedField]
        self.custom = []     # type: List[TypedField]

    def get_version(self):  # type: () -> int
        return 3

    def get_record_type(self):
        return self.type_name

    def get_typed_field(self, field_type, label=None):    # type: (str, Optional[str]) -> Optional['TypedField']
        return next((x for x in itertools.chain(self.fields, self.custom)
                     if field_type == x.type and (not label or (x.label and label.casefold() == x.label.casefold()))),
                    None)

    def load_record_data(self, data, extra=None):
        self.type_name = data.get('type', '')
        self.title = data.get('title', '')
        self.notes = data.get('notes', '')
        self.fields.extend((TypedField(x) for x in data.get('fields', [])))
        self.custom.extend((TypedField(x) for x in data.get('custom', [])))

    def enumerate_fields(self):  # type: () -> Iterable[Tuple[str, any]]
        for pair in super(TypedRecord, self).enumerate_fields():
            yield pair
        yield '(notes)', self.notes
        for field in itertools.chain(self.fields, self.custom):
            yield field.get_field_name(), field.get_external_value()


class FileRecord(KeeperRecord):
    def __init__(self):
        super(FileRecord, self).__init__()
        self.name = ''
        self.size = None   # type: Optional[int]
        self.mime_type = ''
        self.last_modified = None   # type: Optional[int]
        self.storage_size = None   # type: Optional[int]

    def get_version(self):  # type: () -> int
        return 4

    def get_record_type(self):
        return 'file'

    def load_record_data(self, data, extra=None):
        self.title = data.get('title', '')
        self.name = data.get('name', '')
        self.size = data.get('size')
        self.mime_type = data.get('type', '')
        self.last_modified = data.get('lastModified')

    def enumerate_fields(self):  # type: () -> Iterable[Tuple[str, any]]
        for pair in super(FileRecord, self).enumerate_fields():
            yield pair
        yield 'File Name', self.name
        yield 'Mime Type', self.mime_type


class ApplicationRecord(KeeperRecord):
    def __init__(self):
        super(ApplicationRecord, self).__init__()
        self.type_name = ''

    def get_version(self):
        return 5

    def get_record_type(self):
        return self.type_name

    def load_record_data(self, data, extra=None):
        self.title = data.get('title', '')
        self.type_name = data.get('type', 'app')


def tokenize_typed_value(value):  # type: (any) -> Iterable[str]
    if isinstance(value, list):
        for v in value:
            for token in tokenize_typed_value(v):
                yield token
    elif isinstance(value, dict):
        for key in value:
            v = value[key]
            if v and isinstance(v, str):
                yield v
    elif isinstance(value, str):
        if value:
            yield value
