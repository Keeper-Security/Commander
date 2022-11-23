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
from typing import Optional, Sequence, Callable, List, Any

import sys
from tabulate import tabulate

from .. import api, crypto, utils, vault
from ..params import KeeperParams
from ..subfolder import try_resolve_path, BaseFolderNode

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

    from .verify_records import VerifyRecordsCommand, VerifySharedFoldersCommand
    commands['verify-records'] = VerifyRecordsCommand()
    commands['verify-shared-folders'] = VerifySharedFoldersCommand()

    from .. import importer
    importer.register_commands(commands)
    importer.register_command_info(aliases, command_info)

    from .. import plugins
    plugins.register_commands(commands)
    plugins.register_command_info(aliases, command_info)

    from .. import rsync
    rsync.register_commands(commands)
    rsync.register_command_info(aliases, command_info)


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
    from . import distributor
    commands['distributor'] = distributor.DistributorCommand()
    command_info['distributor'] = 'Manage distributors'
    aliases['ds'] = 'distributor'


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


WORDS_TO_CAPITALIZE = {'Id', 'Uid', 'Ip', 'Url'}


def field_to_title(field):   # type: (str) -> str
    words = field.split('_')
    words = [x.capitalize() for x in words if x]
    words = [x.upper() if x in WORDS_TO_CAPITALIZE else x for x in words]
    return ' '.join(words)


def dump_report_data(data, headers, title=None, fmt='', filename=None, append=False, **kwargs):
    # type: (List[List], Sequence[str], Optional[str], Optional[str], Optional[str], bool, ...) -> Optional[str]
    # kwargs:
    #           row_number: boolean        - Add row number. table only
    #           column_width: int          - Truncate long columns. table only
    #           no_header: boolean         - Do not print header
    #           group_by: int           - Sort and Group by columnNo
    #           sort_by: int            - Sort by columnNo
    #           align_right: Sequence[int] - Force right align

    sort_by = kwargs.get('sort_by')
    group_by = kwargs.get('group_by')
    if group_by is not None:
        group_by = int(group_by)
        sort_by = group_by

    if isinstance(sort_by, int):
        data.sort(key=lambda x: x[sort_by] if 0 <= sort_by < len(x) else None)

    if fmt == 'csv':
        if filename:
            _, ext = os.path.splitext(filename)
            if not ext:
                filename += '.csv'

        with open(filename, 'a' if append else 'w', newline='', encoding='utf-8') if filename else io.StringIO() as fd:
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
        last_group_by_value = None
        for row_no in range(len(data)):
            row = data[row_no]
            if isinstance(group_by, int):
                if 0 <= group_by < len(row):
                    group_by_value = row[group_by]
                    if group_by_value == last_group_by_value:
                        row[group_by] = None
                    else:
                        last_group_by_value = group_by_value
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
        tablefmt = 'simple'
        right_align = kwargs.get('right_align')
        if isinstance(right_align, int):
            right_align = [right_align]
        if isinstance(right_align, (list, tuple)) and isinstance(headers, (list, tuple)):
            colalign = ['left'] * len(headers)  # type: Optional[List]
            if row_number:
                colalign[0] = 'decimal'
            for i in range(len(right_align)):
                pos = right_align[i]
                if row_number:
                    pos += 1
                if isinstance(pos, int) and pos < len(colalign):
                    colalign[pos] = 'decimal'
        else:
            colalign = None

        if kwargs.get('no_header'):
            headers = ()
            tablefmt = 'plain'

        print(tabulate(expanded_data, headers=headers, tablefmt=tablefmt, colalign=colalign if expanded_data else None))


parameter_pattern = re.compile(r'\${(\w+)}')


def expand_cmd_args(args, envvars, pattern=parameter_pattern):
    pos = 0
    while True:
        m = pattern.search(args, pos)
        if not m:
            break
        p = m.group(1)
        if p in envvars:
            pv = envvars[p]
            args = args[:m.start()] + pv + args[m.end():]
            pos = m.start() + len(pv)
        else:
            pos = m.end() + 1
    return args


def normalize_output_param(args: str) -> str:
    if sys.platform.startswith('win'):
        # Replace backslashes in output param only if in windows
        args_list = re.split(r'\s+--', args)
        for i, args_grp in enumerate(args_list):
            if re.match(r'(--)*output', args_grp):
                args_list[i] = re.sub(r'\\(\w+)', r'/\1', args_grp)
        args = ' --'.join(args_list)
    return args


def as_boolean(value, default=None):  # type: (Any, Optional[bool]) -> bool
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value > 0

    if isinstance(value, str) and len(value) > 0:
        value = value.lower()
        if value in ('yes', 'y', 'on', '1', 'true', 't'):
            return True
        if value in ('no', 'n', 'off', '0', 'false', 'f'):
            return False

    if default is not None and isinstance(default, bool):
        return default

    raise Exception("Unknown value. Available values 'yes'/'no', 'y'/'n', 'on'/'off', '1'/'0', 'true'/'false'")


class CliCommand(abc.ABC):
    @abc.abstractmethod
    def execute_args(self, params, args, **kwargs):   # type: (Command, KeeperParams, str, dict) -> any
        pass

    def is_authorised(self):
        return True


class Command(CliCommand):
    def __init__(self):
        super(Command, self).__init__()
        self.extra_parameters = ''

    def execute(self, params, **kwargs):     # type: (KeeperParams, any) -> any
        raise NotImplementedError()

    def execute_args(self, params, args, **kwargs):
        # type: (Command, KeeperParams, str, dict) -> any

        global parameter_pattern
        try:
            d = {}
            d.update(kwargs)
            self.extra_parameters = ''
            parser = self._get_parser_safe()
            envvars = params.environment_variables
            args = '' if args is None else args
            if parser:
                args = expand_cmd_args(args, envvars)
                args = normalize_output_param(args)
                if self.support_extra_parameters():
                    opts, extra_args = parser.parse_known_args(shlex.split(args))
                    if extra_args:
                        self.extra_parameters = ' '.join(extra_args)
                else:
                    opts = parser.parse_args(shlex.split(args))
                d.update(opts.__dict__)

            return self.execute(params, **d)
        except ParseError as e:
            logging.error(e)

    def support_extra_parameters(self):   # type: () -> bool
        return False

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
        self._aliases = {}         # type: dict[str, str]
        self.default_verb = ''

    def register_command(self, verb, command, description=None, alias=None):   # type: (any, Command, str) -> None
        verb = verb.lower()
        self._commands[verb] = command
        if not description:
            parser = command.get_parser()
            if parser:
                description = parser.description
        if description:
            self._command_info[verb] = description
        if alias:
            self._aliases[alias] = verb

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

        if verb in self._aliases:
            verb = self._aliases[verb]

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
            if command.is_authorised() and not params.session_token:
                from .utils import LoginCommand
                login_cmd = LoginCommand()
                login_cmd.execute(params)
                if not params.session_token:
                    return

            return command.execute_args(params, args, **kwargs)

    def validate(self, params):  # type: (KeeperParams) -> None
        pass

    @property
    def subcommands(self):
        return self._commands


class RecordMixin:
    CUSTOM_FIELD_TYPES = {'text', 'secret', 'email', 'url', 'multiline', 'pinCode'}

    @staticmethod
    def resolve_single_record(params, record_name):  # type: (KeeperParams, str) -> Optional[vault.KeeperRecord]
        if not record_name:
            return

        if record_name in params.record_cache:
            return vault.KeeperRecord.load(params, record_name)

        rs = try_resolve_path(params, record_name)
        if rs is None:
            return
        folder, record_name = rs
        if folder is None or record_name is None:
            return

        folder_uid = folder.uid or ''
        if folder_uid in params.subfolder_record_cache:
            for uid in params.subfolder_record_cache[folder_uid]:
                record = vault.KeeperRecord.load(params, uid)
                if record and record.title.casefold() == record_name.casefold():
                    return record

    @staticmethod
    def get_custom_field(record, field_name):     # type: (vault.KeeperRecord, str) -> str
        if isinstance(record, vault.PasswordRecord):
            return next((x.value for x in record.custom if field_name.lower() == x.name.lower()), None)

        if isinstance(record, vault.TypedRecord):
            return next((x.get_default_value(str) for x in record.custom
                         if (x.type or 'text') in RecordMixin.CUSTOM_FIELD_TYPES and field_name.lower() == (x.label or '').lower()), None)

    @staticmethod
    def get_record_field(record, field_name):     # type: (vault.KeeperRecord, str) -> str
        if isinstance(record, vault.PasswordRecord):
            if field_name == 'login':
                return record.login
            if field_name == 'password':
                return record.password
            if field_name == 'url':
                return record.link

        elif isinstance(record, vault.TypedRecord):
            if field_name in {'hostname', 'port'}:
                field = record.get_typed_field('host')
            else:
                field = record.get_typed_field(field_name)
            if field:
                value = field.get_default_value()
                if isinstance(value, str):
                    return value
                if isinstance(value, dict):
                    if field_name in {'host', 'hostname', 'port'}:
                        host_name = value.get('hostName') or ''
                        port = value.get('port') or ''
                        if field_name == 'hostname':
                            return host_name
                        if field_name == 'port':
                            return port
                        if port:
                            return f'{host_name}:{port}'
                        return host_name
                    return ''

        return RecordMixin.get_custom_field(record, field_name)

    @staticmethod
    def load_record_history(params, record_uid):  # type: (KeeperParams, str) -> Optional[list]
        current_rec = params.record_cache[record_uid]
        if record_uid in params.record_history:
            history = params.record_history[record_uid]
            if history[0].get('revision') < current_rec['revision']:
                del params.record_history[record_uid]

        record_key = current_rec['record_key_unencrypted']

        if record_uid not in params.record_history:
            rq = {
                'command': 'get_record_history',
                'record_uid': record_uid,
                'client_time': utils.current_milli_time()
            }
            rs = api.communicate(params, rq)
            history = rs['history']   # type: list
            history.sort(key=lambda x: x.get('revision', 0), reverse=True)
            for rec in history:
                rec['record_key_unencrypted'] = record_key
                if 'data' in rec:
                    data = utils.base64_url_decode(rec['data'])
                    version = rec.get('version') or 0
                    try:
                        if version <= 2:
                            rec['data_unencrypted'] = crypto.decrypt_aes_v1(data, record_key)
                        else:
                            rec['data_unencrypted'] = crypto.decrypt_aes_v2(data, record_key)
                        if 'extra' in rec:
                            extra = utils.base64_url_decode(rec['extra'])
                            if version <= 2:
                                rec['extra_unencrypted'] = crypto.decrypt_aes_v1(extra, record_key)
                            else:
                                rec['extra_unencrypted'] = crypto.decrypt_aes_v2(extra, record_key)
                    except Exception as e:
                        logging.warning('Cannot decrypt record history revision: %s', e)

            params.record_history[record_uid] = history

        return params.record_history.get(record_uid)


class FolderMixin:
    @staticmethod
    def traverse_folder_tree(params, folder_uid, callback):
        # type: (KeeperParams, str, Callable[[BaseFolderNode], None]) -> None
        folders = []
        if folder_uid:
            folders.append(folder_uid)
        else:
            folders.extend(params.root_folder.subfolders)
            callback(params.root_folder)
        pos = 0
        while pos < len(folders):
            f_uid = folders[pos]
            pos += 1
            if f_uid in params.folder_cache:
                folder = params.folder_cache[f_uid]   # type: BaseFolderNode
                if folder.subfolders:
                    folders.extend(folder.subfolders)
                callback(folder)
