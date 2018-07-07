#_  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse

from .. import api, display, imp_exp
from .base import raise_parse_exception, suppress_exit, user_choice, Command


def register_commands(commands, aliases, command_info):
    commands['rotate'] = RecordRotateCommand()
    commands['import'] = RecordImportCommand()
    commands['export'] = RecordExportCommand()
    commands['delete_all'] = RecordDeleteAllCommand()
    commands['test'] = TestCommand()
    aliases['r'] = 'rotate'
    for p in [rotate_parser, import_parser, export_parser]:
        command_info[p.prog] = p.description


rotate_parser = argparse.ArgumentParser(prog='rotate|r', description='Rotate Keeper record')
rotate_parser.add_argument('--print', dest='print', action='store_true', help='display the record content after rotation')
rotate_parser.add_argument('--match', dest='match', action='store', help='regular expression to select records for password rotation')
rotate_parser.add_argument('uid', nargs='?', type=str, action='store', help='record UID')
rotate_parser.error = raise_parse_exception
rotate_parser.exit = suppress_exit


import_parser = argparse.ArgumentParser(prog='import', description='Import data from local file to Keeper')
import_parser.add_argument('--format', dest='format', choices=['json', 'csv', 'keepass'], required=True, help='file format')
import_parser.add_argument('filename', type=str, help='file name')
import_parser.error = raise_parse_exception
import_parser.exit = suppress_exit


export_parser = argparse.ArgumentParser(prog='export', description='Export data from Keeper to local file')
export_parser.add_argument('--format', dest='format', choices=['json', 'csv'], required=True, help='file format')
export_parser.add_argument('filename', type=str, help='file name')
export_parser.error = raise_parse_exception
export_parser.exit = suppress_exit


test_parser = argparse.ArgumentParser(prog='test', description='Test KeeperCommander environment')
test_parser.add_argument('area', type=str, choices=['aes', 'rsa'], help='test area')
test_parser.error = raise_parse_exception
test_parser.exit = suppress_exit


class RecordRotateCommand(Command):
    def get_parser(self):
        return rotate_parser

    def execute(self, params, **kwargs):
        print_result = kwargs['print'] if 'print' in kwargs else None
        uid = kwargs['uid'] if 'uid' in kwargs else None
        match = kwargs['match'] if 'match' in kwargs else None
        if uid:
            api.rotate_password(params, uid)
            if print_result:
                display.print_record(params, uid)
        elif match:
            results = api.search_records(params, match)
            for r in results:
                api.rotate_password(params, r.record_uid)
                if print_result:
                    display.print_record(params, r.record_uid)


class RecordImportCommand(Command):
    def get_parser(self):
        return import_parser

    def execute(self, params, **kwargs):
        format = kwargs['format'] if 'format' in kwargs else None
        filename = kwargs['filename'] if 'filename' in kwargs else None
        if format and filename:
            imp_exp._import(params, format, filename)
        else:
            print('Missing argument')


class RecordExportCommand(Command):
    def get_parser(self):
        return export_parser

    def execute(self, params, **kwargs):
        format = kwargs['format'] if 'format' in kwargs else None
        filename = kwargs['filename'] if 'filename' in kwargs else None
        if format and filename:
            imp_exp.export(params, format, filename)
        else:
            print('Missing argument')


class RecordDeleteAllCommand(Command):
    def execute(self, params, **kwargs):
        uc = user_choice('Are you sure you want to delete all Keeper records on the server?', 'yn', default='n')
        if uc.lower() == 'y':
            imp_exp.delete_all(params)


class TestCommand(Command):
    def get_parser(self):
        return test_parser

    def execute(self, params, **kwargs):
        area = kwargs['area'] if 'area' in kwargs else None
        if area == 'rsa':
            api.test_rsa(params)
        elif area == 'aes':
            api.test_aes(params)
