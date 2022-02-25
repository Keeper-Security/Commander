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

import abc
import argparse
import collections
import csv
import datetime
import io
import json
import logging
import os
import re
import shlex
from collections import OrderedDict
from typing import Optional, Sequence

from tabulate import tabulate

from .. import api
from ..params import KeeperParams
from ..subfolder import try_resolve_path

aliases = {}        # type: {str, str}
commands = {}       # type: {str, Command}
enterprise_commands = {}     # type: {str, Command}
msp_commands = {}   # type: {str, Command}
command_info = OrderedDict()


class ParseError(Exception):
    pass


def register_commands(commands, aliases, command_info):
    from .record import register_commands as record_commands, register_command_info as record_command_info
    record_commands(commands)
    record_command_info(aliases, command_info)

    from .recordv3 import register_commands as recordv3_commands, register_command_info as recordv3_command_info
    recordv3_commands(commands)
    recordv3_command_info(aliases, command_info)

    from .folder import register_commands as folder_commands, register_command_info as folder_command_info
    folder_commands(commands)
    folder_command_info(aliases, command_info)

    from .register import register_commands as register_commands, register_command_info as register_command_info
    register_commands(commands)
    register_command_info(aliases, command_info)

    from . import connect
    connect.connect_commands(commands)
    connect.connect_command_info(aliases, command_info)

    from . import breachwatch
    breachwatch.register_commands(commands)
    breachwatch.register_command_info(aliases, command_info)

    from . import convert
    convert.register_commands(commands)
    convert.register_command_info(aliases, command_info)

    from . import scripting
    scripting.register_commands(commands)
    scripting.register_command_info(aliases, command_info)

    from .utils import register_commands as misc_commands, register_command_info as misc_command_info
    misc_commands(commands)
    misc_command_info(aliases, command_info)

    from .. import importer
    importer.register_commands(commands)
    importer.register_command_info(aliases, command_info)

    from .. import plugins
    plugins.register_commands(commands)
    plugins.register_command_info(aliases, command_info)


def register_enterprise_commands(commands, aliases, command_info):
    from . import enterprise
    enterprise.register_commands(commands)
    enterprise.register_command_info(aliases, command_info)
    from . import automator
    automator.register_commands(commands)
    automator.register_command_info(aliases, command_info)
    from . import enterprise_create_user
    enterprise_create_user.register_commands(commands)
    enterprise_create_user.register_command_info(aliases, command_info)


def register_msp_commands(commands, aliases, command_info):
    from .msp import register_commands as msp_commands, register_command_info as msp_command_info
    msp_commands(commands)
    msp_command_info(aliases, command_info)


def user_choice(question, choice, default='', show_choice=True, multi_choice=False):
    choices = [ch.lower() if ch.upper() == default.upper() else ch.lower() for ch in choice]

    result = ''
    while True:
        pr = question
        if show_choice:
            pr = pr + ' [' + '/'.join(choices) + ']'

        pr = pr + ': '
        result = input(pr)

        if len(result) == 0:
            return default

        if multi_choice:
            s1 = set([x.lower() for x in choices])
            s2 = set([x.lower() for x in result])
            if s2 < s1:
                return ''.join(s2)
            pass
        elif any(map(lambda x: x.upper() == result.upper(), choices)):
            return result

        logging.error('Error: invalid input')


def raise_parse_exception(m):
    raise ParseError(m)


def suppress_exit(*args):
    raise ParseError()


def json_serialized(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    return str(obj)


def is_json_value_field(obj):
    if obj is None:
        return False
    if isinstance(obj, str):
        return len(obj) > 0
    return True


def dump_report_data(data, headers, title=None, fmt='', filename=None, append=False, **kwargs):
    # type: (Sequence[Sequence], Sequence[str], Optional[str], Optional[str], Optional[str], bool, ...) -> Optional[str]
    # kwargs:
    #           row_number: boolean     - Add row number. table only
    #           column_width: int       - Truncate long columns. table only
    if fmt == 'csv':
        if filename:
            _, ext = os.path.splitext(filename)
            if not ext:
                filename += '.csv'

        with open(filename, 'a' if append else 'w', newline='') if filename else io.StringIO() as fd:
            csv_writer = csv.writer(fd)
            if title:
                csv_writer.writerow([])
                csv_writer.writerow([title])
                csv_writer.writerow([])
            elif append:
                csv_writer.writerow([])

            starting_column = 0
            if headers:
                if headers[0] == '#':
                    starting_column = 1
                csv_writer.writerow(headers[starting_column:])
            for row in data:
                for i in range(len(row)):
                    if type(row[i]) == list:
                        row[i] = '\n'.join(row[i])
                csv_writer.writerow(row[starting_column:])
            if isinstance(fd, io.StringIO):
                report = fd.getvalue()
                if append:
                    logging.info(report)
                else:
                    return report
    elif fmt == 'json':
        data_list = []
        for row in data:
            obj = {}
            for index, column in filter(lambda x: is_json_value_field(x[1]), enumerate(row)):
                name = headers[index] if headers and index < len(headers) else "#{:0>2}".format(index)
                if name != '#':
                    obj[name] = column
            data_list.append(obj)
        if filename:
            _, ext = os.path.splitext(filename)
            if not ext:
                filename += '.json'
            with open(filename, 'a' if append else 'w') as fd:
                json.dump(data_list, fd, indent=2, default=json_serialized)
        else:
            report = json.dumps(data_list, indent=2, default=json_serialized)
            if append:
                logging.info(report)
            else:
                return report
    else:
        if title:
            print('\n{0}\n'.format(title))
        elif append:
            print('\n')
        row_number = kwargs.get('row_number')
        if not isinstance(row_number, bool):
            row_number = False
        column_width = kwargs.get('column_width')
        if not isinstance(column_width, int):
            column_width = 0
        if 0 < column_width < 32:
            column_width = 32

        if row_number and headers:
            headers = list(headers)
            headers.insert(0, '#')

        expanded_data = []
        for row_no in range(len(data)):
            row = data[row_no]
            if row_number:
                if not isinstance(row, list):
                    row = list(row)
                row.insert(0, row_no + 1)
            expanded_rows = 1
            for column in row:
                if type(column) == list:
                    if len(column) > expanded_rows:
                        expanded_rows = len(column)
            for i in range(expanded_rows):
                rowi = []
                for column in row:
                    value = ''
                    if type(column) == list:
                        if i < len(column):
                            value = column[i]
                    elif i == 0:
                        value = column
                    if column_width > 0:
                        if isinstance(value, str) and len(value) > column_width:
                            value = value[:column_width-2] + '...'
                    rowi.append(value)
                expanded_data.append(rowi)
        print(tabulate(expanded_data, headers=headers))


parameter_pattern = re.compile(r'\${(\w+)}')


class CliCommand(abc.ABC):
    @abc.abstractmethod
    def execute_args(self, params, args, **kwargs):   # type: (Command, KeeperParams, str, dict) -> any
        pass

    def is_authorised(self):
        return True


class Command(CliCommand):
    def execute(self, params, **kwargs):     # type: (KeeperParams, any) -> any
        raise NotImplemented()

    def execute_args(self, params, args, **kwargs):
        # type: (Command, KeeperParams, str, dict) -> any

        global parameter_pattern
        try:
            d = {}
            d.update(kwargs)
            parser = self._get_parser_safe()
            if parser is not None:
                if args:
                    pos = 0
                    value = args
                    while True:
                        m = parameter_pattern.search(value, pos)
                        if not m:
                            break
                        p = m.group(1)
                        if p in params.environment_variables:
                            pv = params.environment_variables[p]
                            value = value[:m.start()] + pv + value[m.end():]
                            pos = m.start() + len(pv)
                        else:
                            pos = m.end() + 1
                    args = value

                opts = parser.parse_args(shlex.split(args))
                d.update(opts.__dict__)
            return self.execute(params, **d)
        except ParseError as e:
            logging.error(e)

    def get_parser(self):   # type: () -> Optional[argparse.ArgumentParser]
        return None

    def _ensure_parser(func):
        def _wrapper(self):
            parser = func(self)
            if parser:
                if parser.exit != suppress_exit:
                    parser.exit = suppress_exit
                if parser.error != raise_parse_exception:
                    parser.error = raise_parse_exception
            return parser
        return _wrapper

    @_ensure_parser
    def _get_parser_safe(self):
        return self.get_parser()
    _ensure_parser = staticmethod(_ensure_parser)


class GroupCommand(CliCommand):
    def __init__(self):
        self._commands = collections.OrderedDict()     # type: dict[str, Command]
        self._command_info = {}    # type: dict[str, str]
        self.default_verb = ''

    def register_command(self, verb, command, description=None):   # type: (any, Command, str) -> None
        verb = verb.lower()
        self._commands[verb] = command
        if not description:
            parser = command.get_parser()
            if parser:
                description = parser.description
        if description:
            self._command_info[verb] = description

    def execute_args(self, params, args, **kwargs):  # type: (KeeperParams, str, dict) -> any
        if args.startswith('-- '):
            args = args[3:].strip()
        self.validate(params)
        pos = args.find(' ')
        if pos > 0:
            verb = args[:pos].strip()
            args = args[pos + 1:].strip()
        else:
            verb = args.strip()
            args = ''

        print_help = False
        if not verb:
            verb = self.default_verb
            print_help = True
        if verb:
            verb = verb.lower()

        command = self._commands.get(verb)
        if not command:
            print_help = True
            if verb not in ['--help', '-h', 'help', '']:
                logging.warning('Invalid command: %s', verb)

        if print_help:
            logging.info('%s command [--options]', kwargs.get('command'))
            table = []
            headers = ['Command', 'Description']
            for verb in self._commands.keys():
                row = [verb, self._command_info.get(verb) or '']
                table.append(row)
            print('')
            dump_report_data(table, headers=headers)
            print('')

        if command:
            kwargs['action'] = verb
            command.execute_args(params, args, **kwargs)

    def validate(self, params):  # type: (KeeperParams) -> None
        pass


class RecordMixin:
    @staticmethod
    def resolve_records(params, record_name):  # type: (KeeperParams, str) -> collections.Iterator[str]
        if not record_name:
            return

        if record_name in params.record_cache:
            yield record_name
        else:
            rs = try_resolve_path(params, record_name)
            if rs is not None:
                folder, record_name = rs
                if folder is not None and record_name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.casefold() == record_name.casefold():
                                yield uid
