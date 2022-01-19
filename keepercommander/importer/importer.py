#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import abc
import io
import os.path
import importlib
import logging
import collections

from typing import List, Optional, Union

from contextlib import contextmanager

from ..error import CommandError

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
            logging.error("stdout is not supported for this file format")
            return

        self.do_export(filename, items, file_password)

    @abc.abstractmethod
    def do_export(self, filename, records, file_password=None):  # type: (str, List[Record, File], Optional[str]) -> None
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
