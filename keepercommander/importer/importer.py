#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import os.path
import importlib


PathDelimiter = '\\'


def importer_for_format(format):
    full_name = 'keepercommander.importer.' + format
    module = importlib.import_module(full_name)
    if hasattr(module, 'Importer'):
        return module.Importer
    raise Exception('Cannot resolve importer for format {}'.format(format))


def exporter_for_format(format):
    full_name = 'keepercommander.importer.' + format
    module = importlib.import_module(full_name)
    if hasattr(module, 'Exporter'):
        return module.Exporter
    raise Exception('Cannot resolve exporter for format {}'.format(format))


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
    '''
    :type path: str
    :rtype: collections.Iterable[str]
    '''
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


class Folder:
    def __init__(self):
        self.uid = None
        self.domain = None # type: str
        self.path = None # type: str
        self.can_edit = False
        self.can_share = False


class Record:
    def __init__(self):
        self.record_uid = None
        self.title = None
        self.login = None
        self.password = None
        self.login_url = None
        self.notes = None
        self.custom_fields = []
        self.folders = None     # type: [Folder]


class BaseImporter:
    def execute(self, filename):
        '''
        :type filename: str
        :rtype: collections.Iterable[Record]
        '''
        path = os.path.expanduser(filename)
        if not os.path.isfile(path):
            raise Exception('File \'{0}\' does not exist'.format(filename))

        yield from self.do_import(path)

    def do_import(self, filename):
        '''
        :type filename: str
        :rtype: collections.Iterable[Record]
        '''
        raise NotImplemented()


class BaseExporter:
    def execute(self, filename, records):
        '''
        :type filename: str
        :type records: collections.Iterable[Record]
        :rtype: None
        '''
        path = os.path.expanduser(filename)
        self.do_export(path, records)

    def do_export(self, filename, records):
        '''
        :type filename: str
        :type records: collections.Iterable[Record]
        :rtype: None
        '''
        raise NotImplemented()

