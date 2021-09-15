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

import argparse
import collections
import shlex
import logging
import json
import os
import re
import csv
import sys
import abc

from tabulate import tabulate
from collections import OrderedDict

from ..params import KeeperParams


aliases = {}        # type: {str, str}
commands = {}       # type: {str, Command}
enterprise_commands = {}     # type: {str, Command}
msp_commands = {}   # type: {str, Command}
command_info = OrderedDict()


class ParseError(Exception):
    pass


def register_commands(commands, aliases, command_info):
    from .recordv3 import register_commands as record_commands, register_command_info as record_command_info
    record_commands(commands)
    record_command_info(aliases, command_info)

    from .folder import register_commands as folder_commands, register_command_info as folder_command_info
    folder_commands(commands)
    folder_command_info(aliases, command_info)

    from .register import register_commands as register_commands, register_command_info as register_command_info
    register_commands(commands)
    register_command_info(aliases, command_info)

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


def suppress_exit():
    raise ParseError()


def dump_report_data(data, headers, title=None, fmt='', filename=None, append=False):
    # type: (list, list, str, str, str, bool) -> None
    if fmt == 'csv':
        if filename:
            _, ext = os.path.splitext(filename)
            if not ext:
                filename += '.csv'
        fd = open(filename, 'a' if append else 'w', newline='') if filename else sys.stdout
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
        if filename:
            fd.flush()
            fd.close()
    elif fmt == 'json':
        data_list = []
        for row in data:
            obj = {}
            for index, column in filter(lambda x: x[1], enumerate(row)):
                name = headers[index] if headers and index < len(headers) else "#{:0>2}".format(index)
                if name != '#':
                    obj[name] = column
            data_list.append(obj)
        if filename:
            _, ext = os.path.splitext(filename)
            if not ext:
                filename += '.json'
        fd = open(filename, 'a' if append else 'w') if filename else sys.stdout
        json.dump(data_list, fd, indent=2)
        if filename:
            fd.flush()
            fd.close()
    else:
        if title:
            print('\n{0}\n'.format(title))
        elif append:
            print('\n')
        expanded_data = []
        for row in data:
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
    def execute(self, params, **kwargs):     # type: (KeeperParams, **any) -> any
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

    def get_parser(self):   # type: () -> argparse.ArgumentParser | None
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
