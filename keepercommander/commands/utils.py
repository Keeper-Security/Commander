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
import shlex

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
import_parser.add_argument('--format', dest='format', choices=['json', 'csv', 'keepass'], help='file format')
import_parser.add_argument('filename', type=str, help='file name')
import_parser.error = raise_parse_exception
import_parser.exit = suppress_exit


export_parser = argparse.ArgumentParser(prog='export', description='Export data from Keeper to local file')
export_parser.add_argument('--format', dest='format', choices=['json', 'csv'], help='file format')
export_parser.add_argument('filename', type=str, help='file name')
export_parser.error = raise_parse_exception
export_parser.exit = suppress_exit


test_parser = argparse.ArgumentParser(prog='test', description='Test KeeperCommander environment')
test_parser.add_argument('area', type=str, choices=['aes', 'rsa'], help='test area')
test_parser.error = raise_parse_exception
test_parser.exit = suppress_exit


class RecordRotateCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts = rotate_parser.parse_args(shlex.split(args))
            if opts.uid:
                api.rotate_password(params, opts.uid)
                if print:
                    display.print_record(params, opts.uid)
            elif opts.match:
                results = api.search_records(params, opts.match)
                for r in results:
                    api.rotate_password(params, r.record_uid)
                    if print:
                        display.print_record(params, r.record_uid)

        except Exception as e:
            print(e)


class RecordImportCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts = import_parser.parse_args(shlex.split(args))
            imp_exp._import(params, opts.format, opts.filename)

        except Exception as e:
            print(e)


class RecordExportCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts = export_parser.parse_args(shlex.split(args))
            imp_exp.export(params, opts.format, opts.filename)

        except Exception as e:
            print(e)


class RecordDeleteAllCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            uc = user_choice('Are you sure you want to delete all Keeper records on the server?', 'yn', default='n')
            if uc.lower() == 'y':
                imp_exp.delete_all(params)

        except Exception as e:
            print(e)


class TestCommand(Command):

    def execute(self, params, args, **kwargs):
        try:
            opts = test_parser.parse_args(shlex.split(args))
            if opts.area == 'rsa':
                api.test_rsa(params)
            elif opts.area == 'aes':
                api.test_aes(params)

        except Exception as e:
            print(e)


