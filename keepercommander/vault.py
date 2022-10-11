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
import datetime
import json
from typing import Optional, List, Tuple, Iterable, Type, Union, Dict, Any

import itertools

from .params import KeeperParams
from . import record_types


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
    def load(params, rec):
        # type: (KeeperParams, Union[str, Dict[str, Any]]) -> Optional['KeeperRecord']
        if isinstance(rec, str):
            if rec not in params.record_cache:
                return
            record = params.record_cache[rec]
        elif isinstance(rec, dict):
            record = rec
        else:
            return

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

    def enumerate_fields(self):    # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        yield '(title)', self.title

    @staticmethod
    def size_to_str(size):    # type: (Union[int, float]) -> str
        scale = 'Bytes'
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
        return f'{size:.2f}'.rstrip('0').rstrip('.') + f' {scale}'


class CustomField(object):
    def __init__(self, custom_field=None):  # type: (Optional[dict]) -> None
        if custom_field is None:
            custom_field = {}
        self.name = custom_field.get('name', '').strip()
        self.value = custom_field.get('value', '').strip()
        self.type = custom_field.get('type', '').strip()

    @classmethod
    def new_field(cls, name, value):
        cf = CustomField()
        cf.type = 'text'
        cf.name = name
        cf.value = value
        return cf


class AttachmentFileThumb:
    def __init__(self, thumb_field=None):      # type: (Optional[dict]) -> None
        self.id = thumb_field.get('id', '') if thumb_field else ''
        self.type = thumb_field.get('type', '') if thumb_field else ''
        self.size = thumb_field.get('size', 0) if thumb_field else 0


class AttachmentFile(object):
    def __init__(self, file_field=None):  # type: (Optional[dict]) -> None
        self.id = file_field.get('id', '')
        self.key = file_field.get('key', '')
        self.name = file_field.get('name', '')
        self.title = file_field.get('title', '')
        self.mime_type = file_field.get('type', '')
        self.size = file_field.get('size', 0)
        self.last_modified = file_field.get('lastModified', 0) if file_field else 0  # type: int
        self.thumbnails = []                                                         # type: List[AttachmentFileThumb]
        if file_field and 'thumbnails' in file_field:
            thumbs = file_field.get('thumbnails')
            if isinstance(thumbs, list):
                for thumb in thumbs:
                    self.thumbnails.append(AttachmentFileThumb(thumb))


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
        self.totp = ''           # type: str

    def get_version(self):  # type: () -> int
        return 2

    def get_record_type(self):
        return ''

    def load_record_data(self, data, extra=None):
        self.title = (data.get('title') or '').strip()
        self.login = (data.get('secret1') or '').strip()
        self.password = data.get('secret2') or ''
        self.link = data.get('link') or ''
        self.notes = data.get('notes') or ''
        custom = data.get('custom')
        if isinstance(custom, list):
            self.custom.extend((CustomField(x) for x in custom if isinstance(x, dict) and 'name' in x))
        if isinstance(extra, dict):
            if 'files' in extra:
                self.attachments = [AttachmentFile(x) for x in extra['files']]

            if 'fields' in extra and isinstance(extra['fields'], list):
                self.totp = next((x.get('data', '') for x in extra['fields'] if x.get('field_type') == 'totp'), '')

    def enumerate_fields(self):
        # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        for pair in super(PasswordRecord, self).enumerate_fields():
            yield pair
        yield '(login)', self.login
        yield '(password)', self.password
        yield '(url)', self.link
        yield '(notes)', self.notes
        if self.totp:
            yield '(oneTimeCode)', self.totp
        for cf in self.custom:
            yield cf.name, cf.value
        if self.attachments:
            for atta in self.attachments:
                yield atta.title or atta.name, f'File ID: {atta.id}; Size: {KeeperRecord.size_to_str(atta.size)}'


class TypedField(object):
    def __init__(self, typed_field=None):
        if typed_field is None:
            typed_field = {}
        self.type = (typed_field.get('type') or '').strip()
        self.label = (typed_field.get('label') or '').strip()
        self.value = typed_field.get('value', [])

    @classmethod
    def new_field(cls, field_type, field_value, field_label=None):
        # type: (str, Any, Optional[str]) -> 'TypedField'
        f_type = field_type or 'text'
        if f_type not in record_types.RecordFields:
            f_type = 'text'
        if not isinstance(field_value, list):
            field_value = [field_value]
        tf = TypedField()
        tf.type = f_type
        tf.value = field_value
        tf.label = field_label or ''
        return tf

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
        return f'({self.type}).{self.label}' if self.type and self.label else \
               f'({self.type})' if self.type else \
               f'{self.label}'

    @staticmethod
    def get_exported_value(field_type, field_value):
        # type: (str, Any) -> Iterable[str]
        if not field_value:
            return

        if isinstance(field_value, str):
            yield field_value
            return

        rf = record_types.RecordFields.get(field_type)
        ft = record_types.FieldTypes.get(rf.type) if rf else None
        if isinstance(field_value, int):
            if ft and ft.name == 'date':
                if field_value != 0:
                    dt = datetime.datetime.fromtimestamp(int(field_value // 1000)).date()
                    yield str(dt)
            else:
                yield str(field_value)
        elif isinstance(field_value, list):
            for elem in field_value:
                for ev in TypedField.get_exported_value(field_type, elem):
                    yield ev
        elif isinstance(field_value, dict):
            if ft:
                if ft.name == 'host':
                    hostname = field_value.get('hostname') or ''
                    port = field_value.get('port') or ''
                    if hostname or port:
                        if port:
                            hostname = f'{hostname}:{port}'
                    yield hostname
                elif ft.name == 'phone':
                    phone = field_value.get('type') or ''
                    if phone:
                        phone += ':'
                    for key in ('region', 'number', 'ext'):
                        if key in field_value:
                            value = field_value[key]
                            if value:
                                phone += f' {value}'
                    yield phone
                elif ft.name == 'name':
                    last = field_value.get('last') or ''
                    first = field_value.get('first') or ''
                    middle = field_value.get('middle') or ''
                    if last or first or middle:
                        name = f'{last},'
                        if first:
                            name += f' {first}'
                        if middle:
                            name += f' {middle}'
                        yield name
                elif ft.name == 'address':
                    street = ' '.join(x for x in (field_value.get('street1'), field_value.get('street1')) if x)
                    city = field_value.get('city') or ''
                    state = ' '.join(x for x in (field_value.get('state'), field_value.get('zip')) if x)
                    country = field_value.get('country') or ''
                    if street or city or state or country:
                        address = ', '.join((street, city, state, country))
                        while address.endswith(', '):
                            address = address.rstrip(', ')
                        yield address
                elif ft.name == 'securityQuestion':
                    q = (field_value.get('question') or '').rstrip('?')
                    a = field_value.get('answer') or ''
                    if q or a:
                        yield f'{q}? {a}'
                elif ft.name == 'paymentCard':
                    number = field_value.get('cardNumber') or ''
                    expiration = field_value.get('cardExpirationDate') or ''
                    cvv = field_value.get('cardSecurityCode') or ''
                    if number or expiration or cvv:
                        if expiration:
                            number += f' EXP:{expiration}'
                        if cvv:
                            number += f' {cvv}'
                        yield cvv
                elif ft.name == 'bankAccount':
                    account = field_value.get('accountType') or ''
                    if account:
                        account += ':'
                    for key in ('routingNumber', 'accountNumber'):
                        if key in field_value:
                            value = field_value[key]
                            if value:
                                account += f' {value}'
                    if account:
                        yield account
                elif ft.name == 'privateKey':
                    private_key = field_value.get('privateKey') or ''
                    if private_key:
                        yield private_key

    def get_external_value(self):   # type: () -> Iterable[str]
        for value in self.get_exported_value(self.type, self.value):
            yield value


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

    def get_typed_field(self, field_type, label=None):    # type: (str, Optional[str]) -> Optional[TypedField]
        return next((x for x in itertools.chain(self.fields, self.custom)
                     if field_type == x.type and (not label or (x.label and label.casefold() == x.label.casefold()))),
                    None)

    def load_record_data(self, data, extra=None):
        self.type_name = data.get('type', '').strip()
        self.title = data.get('title', '').strip()
        self.notes = data.get('notes', '')
        self.fields.extend((TypedField(x) for x in data.get('fields', [])))
        self.custom.extend((TypedField(x) for x in data.get('custom', [])))

    def enumerate_fields(self):
        # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        for pair in super(TypedRecord, self).enumerate_fields():
            yield pair
        yield '(type)', self.record_type
        yield '(notes)', self.notes
        for field in itertools.chain(self.fields, self.custom):
            values = list(field.get_external_value())
            yield field.get_field_name(), '' if len(values) == 0 else values[0] if len(values) == 1 else values


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
        self.title = data.get('title', '').strip()
        self.name = data.get('name', '').strip()
        self.size = data.get('size')
        self.mime_type = data.get('type', '')
        self.last_modified = data.get('lastModified')

    def enumerate_fields(self):  # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        for pair in super(FileRecord, self).enumerate_fields():
            yield pair
        yield '(type)', self.get_record_type()
        yield '(name)', self.name
        if self.mime_type:
            yield '(mime-type)', self.mime_type
        yield '(size)', KeeperRecord.size_to_str(self.size)


class ApplicationRecord(KeeperRecord):
    def __init__(self):
        super(ApplicationRecord, self).__init__()

    def get_version(self):
        return 5

    def get_record_type(self):
        return 'app'

    def load_record_data(self, data, extra=None):
        self.title = data.get('title', '')

    def enumerate_fields(self):  # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        for pair in super(ApplicationRecord, self).enumerate_fields():
            yield pair
        yield '(type)', self.get_record_type()
