# -*- coding: utf-8 -*-
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

from typing import Optional, Callable, Iterator, List, Iterable, Tuple

import argparse
import logging
import io
import os
import re
import shutil
import sys
import tempfile

from .base import Command, RecordMixin, dump_report_data
from .ssh_agent import add_ssh_key, SshAgentCommand
from .record import find_record, RecordListCommand
from ..attachment import prepare_attachment_download
from ..params import KeeperParams
from ..subfolder import find_folders, get_folder_path, try_resolve_path
from ..vault import TypedRecord, KeeperRecord, PasswordRecord
from ..vault_extensions import SshKeysFacade

ssh_parser = argparse.ArgumentParser(prog='ssh',
                                     description='Establishes connection to external server using SSH. ')
ssh_parser.add_argument('record', nargs='?', type=str, action='store',
                        help='record path or UID. Record types: "SSH Key", "Server"')
ssh_parser.add_argument('destination', nargs='?', type=str, action='store',
                        metavar='LOGIN@HOST[:PORT]', help='Optional. SSH endpoint')

mysql_parser = argparse.ArgumentParser(prog='mysql', description='Establishes connection to MySQL server.')
mysql_parser.add_argument('record', nargs='?', type=str, action='store',
                          help='record path or UID. Record types: "Database"')

postgres_parser = argparse.ArgumentParser(prog='postgresql',
                                          description='Establishes connection to Postgres/Redshift servers.')
postgres_parser.add_argument('record', nargs='?', type=str, action='store',
                             help='record path or UID. Record types: "Database"')
postgres_parser.add_argument('database', nargs='?', type=str, action='store',
                             help='Postgres database name.')

rdp_parser = argparse.ArgumentParser(prog='rdp',
                                     description='Establishes RDP connection to remote Windows servers.')
rdp_parser.add_argument('record', nargs='?', type=str, action='store',
                        help='record path or UID. Record types: "Server"')


connect_parser = argparse.ArgumentParser(prog='connect', description='Establishes connection to external server')
connect_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                            help='display help on command format and template parameters')
connect_parser.add_argument('-n', '--new', dest='new_data', action='store_true', help='request per-user data')
connect_parser.add_argument('-s', '--sort', dest='sort_by', action='store', choices=['endpoint', 'title', 'folder'],
                            help='sort output')
connect_parser.add_argument('-f', '--filter', dest='filter_by', action='store', help='filter output')
connect_parser.add_argument('endpoint', nargs='?', action='store', type=str,
                            help='endpoint name or full record path to endpoint')

mysql = ''
postgresql = ''

endpoint_parameter_pattern = re.compile(r'\${(.+?)}')


def detect_clients():
    global mysql, postgresql
    if shutil.which('mysql'):
        mysql = 'mysql'
    if shutil.which('pgcli'):
        postgresql = 'pgcli'
    elif shutil.which('psql'):
        postgresql = 'psql'


detect_clients()


def connect_commands(commands):
    commands['ssh-agent'] = SshAgentCommand()
    commands['connect'] = ConnectCommand()
    commands['ssh'] = ConnectSshCommand()
    if mysql:
        commands['mysql'] = ConnectMysqlCommand()
    if postgresql:
        commands['postgresql'] = ConnectPostgresCommand()
    if sys.platform == 'win32':
        commands['rdp'] = ConnectRdpCommand()


def connect_command_info(aliases, command_info):
    command_info[connect_parser.prog] = connect_parser.description
    command_info[ssh_parser.prog] = ssh_parser.description
    if mysql:
        command_info['mysql'] = mysql_parser.description
    if postgresql:
        command_info['postgresql'] = postgres_parser.description
        aliases['pg'] = 'postgresql'
    if sys.platform == 'win32':
        command_info['rdp'] = rdp_parser.description


class BaseConnectCommand(Command, RecordMixin):
    def __init__(self):
        super(BaseConnectCommand, self).__init__()
        self.command = ''
        self.run_at_the_end = []

    def support_extra_parameters(self):
        return True

    SHELL_SUBSTITUTION = {
        '`': r'\`',
        '$': r'\$',
        '?': r'\?',
        '*': r'\*',
        '^': r'\^',
        '(': r'\(',
        ')': r'\)'
    }

    def execute_shell(self):
        logging.debug('Executing "%s" ...', self.command)
        try:
            command = self.command.translate(str.maketrans(BaseConnectCommand.SHELL_SUBSTITUTION))
            os.system(command)
        finally:
            self.command = ''
            for cb in self.run_at_the_end:
                try:
                    cb()
                except Exception as e:
                    logging.debug(e)
            self.run_at_the_end.clear()

    def get_extra_options(self, params, record, application):
        # type: (KeeperParams, KeeperRecord, str) -> str
        record_options = BaseConnectCommand.get_custom_field(record, f'{application}:option')
        if record_options:
            temp_files = []
            record_options = BaseConnectCommand.get_command_string(params, record, record_options, temp_files)
            if temp_files:
                def remove_files():
                    for file in temp_files:
                        os.remove(file)
                self.run_at_the_end.append(remove_files)

        options = ''
        if record_options:
            options += f' {record_options}'
        if self.extra_parameters:
            options += f' {self.extra_parameters}'
        return options

    @staticmethod
    def get_record(params, record, types):  # type: (KeeperParams, str, Iterator[str]) -> Optional[TypedRecord]
        if not record:
            ls = RecordListCommand()
            ls.execute(params, record_type=types, verbose=True)
            return

        try:
            record = find_record(params, record)
        except Exception as e:
            logging.warning(e)
            return

        if not isinstance(record, TypedRecord):
            logging.warning('Only typed records are supported')
            return

        if record.record_type not in types:
            logging.warning('Command supports %s records only', ' and '.join(types))
            return
        return record

    @staticmethod
    def get_parameter_value(params, record, parameter, temp_files, **kwargs):
        # type: (KeeperParams, KeeperRecord, str, list, ...) -> Optional[str]
        if parameter.startswith('file:') or parameter.startswith('body:'):
            file_name = parameter[5:]
            attachments = list(prepare_attachment_download(params, record.record_uid, file_name))
            if len(attachments) == 0:
                logging.warning('Attachment file \"%s\" not found', file_name)
                return None
            if len(attachments) > 1:
                logging.warning('More than one attachment file \"%s\" found', file_name)
                return None

            if parameter.startswith('file:'):
                prefix = (kwargs.get('endpoint') or file_name) + '.'
                with tempfile.NamedTemporaryFile(delete=False, prefix=prefix) as tf:
                    attachments[0].download_to_stream(params, tf)
                    temp_files.append(tf.name)
                    return tf.name
            else:
                with io.BytesIO() as mem:
                    attachments[0].download_to_stream(params, mem)
                    return mem.getvalue().decode('utf-8')
        else:
            return BaseConnectCommand.get_record_field(record, parameter)

    @staticmethod
    def get_command_string(params, record, template, temp_files, **kwargs):
        # type: (KeeperParams, KeeperRecord, str, list, ...) -> str or None
        command = template
        while True:
            m = endpoint_parameter_pattern.search(command)
            if not m:
                break
            p = m.group(1)
            pv = BaseConnectCommand.get_parameter_value(params, record, p, temp_files, **kwargs)
            command = command[:m.start()] + (pv or '') + command[m.end():]
        return command


class ConnectSshCommand(BaseConnectCommand):
    def get_parser(self):
        return ssh_parser

    def execute(self, params, **kwargs):
        name = kwargs['record'] if 'record' in kwargs else None
        record = self.get_record(params, name, ['sshKeys', 'serverCredentials'])
        if not record:
            return

        dst = kwargs.get('destination', '')
        if dst:
            login, at, host = dst.partition('@')
            if at != '@':
                logging.warning('Destination parameter should be LOGIN@HOST[:PORT]')
                return
        else:
            login = BaseConnectCommand.get_record_field(record, 'login')
            host = BaseConnectCommand.get_record_field(record, 'host')

        if not login:
            logging.warning('Record "%s" does not have login.', record.title)
            return
        if not host:
            logging.warning('Record "%s" does not have host.', record.title)
            return

        host_name, _, port = host.partition(':')

        self.run_at_the_end.clear()

        options = self.get_extra_options(params, record, 'ssh')
        self.command = f'ssh{options} {login}@{host_name}'
        if port:
            self.command += f' -p {port}'

        if record.record_type == 'sshKeys':
            facade = SshKeysFacade()
            facade.assign_record(record)
            private_key = facade.private_key
            if not facade.private_key:
                logging.warning('Record "%s" does not have private key.', record.title)
                return
            passphrase = facade.passphrase
            if not passphrase:
                passphrase = None
            to_remove = add_ssh_key(private_key=private_key, passphrase=passphrase, key_name=record.title)
            if to_remove:
                self.run_at_the_end.append(to_remove)
        else:
            password = BaseConnectCommand.get_record_field(record, 'password')
            if password:
                if shutil.which('sshpass'):
                    self.command = 'sshpass -e ' + self.command
                    os.putenv('SSHPASS', password)

                    def clear_env():
                        os.putenv('SSHPASS', '')
                    self.run_at_the_end.append(clear_env)
                else:
                    self.command += ' -o PubkeyAuthentication=no'
                    try:
                        import pyperclip
                        pyperclip.copy(password)
                        logging.info('\nPassword is copied to clipboard\n')

                        def clear_clipboard():
                            txt = pyperclip.paste()
                            if txt == password:
                                pyperclip.copy('')
                        self.run_at_the_end.append(clear_clipboard)
                    except Exception as e:
                        logging.debug(e)
                        logging.info('Failed to copy password to clipboard')

        logging.info('Connecting to "%s" ...', record.title)
        self.execute_shell()


class ConnectMysqlCommand(BaseConnectCommand):
    def get_parser(self):
        return mysql_parser

    def execute(self, params, **kwargs):
        name = kwargs['record'] if 'record' in kwargs else None
        record = self.get_record(params, name, ['databaseCredentials', 'serverCredentials'])
        if not record:
            return

        login = BaseConnectCommand.get_record_field(record, 'login')
        if not login:
            logging.warning('Record "%s" does not have login.', record.title)
            return

        host = BaseConnectCommand.get_record_field(record, 'host')
        if not host:
            logging.warning('Record "%s" does not have host.', record.title)
            return
        host_name, _, port = host.partition(':')

        self.run_at_the_end.clear()

        options = self.get_extra_options(params, record, 'mysql')
        self.command = f'mysql{options}'
        self.command += f' --host {host_name} --user {login}'
        if port:
            self.command += f' --port {port}'

        password = BaseConnectCommand.get_record_field(record, 'password')
        if password:
            os.putenv('MYSQL_PWD', password)

            def clear_env():
                os.putenv('MYSQL_PWD', '')
            self.run_at_the_end.append(clear_env)

        logging.info('Connecting to "%s" ...', record.title)
        self.execute_shell()


class ConnectPostgresCommand(BaseConnectCommand):
    def get_parser(self):
        return postgres_parser

    def execute(self, params, **kwargs):
        name = kwargs['record'] if 'record' in kwargs else None
        record = self.get_record(params, name, ['databaseCredentials', 'serverCredentials'])
        if not record:
            return

        login = BaseConnectCommand.get_record_field(record, 'login')
        if not login:
            logging.warning('Record "%s" does not have user name.', record.title)
            return
        host = BaseConnectCommand.get_record_field(record, 'host')
        if not host:
            logging.warning('Record "%s" does not have host.', record.title)
            return
        host_name, _, port = host.partition(':')

        database = kwargs.get('database')
        if not database:
            database = BaseConnectCommand.get_custom_field(record, 'database')
        if not database:
            database = 'template1'
            logging.info(f'\nConnecting to the default database: {database}\n')

        self.command = f'{postgresql} {self.extra_parameters} -h {host_name}'
        if port:
            self.command += f' -p {port}'
        self.command += f' -U {login} -w {database}'
        self.run_at_the_end.clear()

        password = BaseConnectCommand.get_record_field(record, 'password')
        if password:
            os.putenv('PGPASSWORD', password)

            def clear_env():
                os.putenv('PGPASSWORD', '')
            self.run_at_the_end.append(clear_env)

        logging.info('Connecting to "%s" ...', record.title)
        self.execute_shell()


class ConnectRdpCommand(BaseConnectCommand):
    def get_parser(self):
        return rdp_parser

    def execute(self, params, **kwargs):
        name = kwargs['record'] if 'record' in kwargs else None
        record = self.get_record(params, name, ['serverCredentials'])
        if not record:
            return

        login = BaseConnectCommand.get_record_field(record, 'login')
        if not login:
            logging.warning('Record "%s" does not have user name.', record.title)
            return

        host = BaseConnectCommand.get_record_field(record, 'host')
        if not host:
            logging.warning('Record "%s" does not have host.', record.title)
            return
        host_name, _, port = host.partition(':')

        password = BaseConnectCommand.get_record_field(record, 'password')
        if password:
            os.system(f'cmdkey /generic:{host_name} /user:{login} /pass:{password} > NUL')

            def clear_password():
                os.system(f'cmdkey /delete:{host_name} > NUL')
            self.run_at_the_end.append(clear_password)

        self.command = f'mstsc /v:{host_name}'
        if port:
            self.command += ':' + port

        logging.info('Connecting to "%s" ...', record.title)
        self.execute_shell()


connect_command_description = '''
Connect Command Syntax Description:
This command reads the custom fields for names starting with "connect:"
  connect:<name>                                    command 
  connect:<name>:description                        command description
  connect:<name>:ssh-key:<key-comment>              ssh private key to add to ssh-agent
  connect:<name>:env:<Environment Variable To Set>  sets environment variable
Connection command may contain template parameters.
Parameter syntax is ${<parameter_name>}
Supported parameters:
    ${user_email}                   Keeper user email address
    ${login}                        Record login
    ${password}                     Record password
    ${file:<attachment_name>}       stores attachment into temporary file. parameter is replaced with temp file name
    ${body:<attachment_name>}       content of the attachment file.
    ${<custom_field_name>}          custom field value
SSH Example:
Title: SSH to my Server via Gateway
Custom Field 1 Name: connect:my_server:description
Custom Field 1 Value: Production Server Inside Gateway
Custom Field 2 Name: connect:my_server
Custom Field 2 Value: ssh -o "ProxyCommand ssh -i ${file:gateway.pem} ec2-user@gateway.mycompany.com -W %h:%p" -i ${file:server.pem} ec2-user@server.company.com
File Attachments:
gateway.pem
server.pem
To initiate connection: "connect my_server"
Connect to Postgres Example:
Title:    Postgres
Login:    PGuser
Password: **************
Custom Field 1 Name:  connect:postgres
Custom Field 1 Value: psql --host=11.22.33.44 --port=3306 --username=${login} --dbname=postgres --no-password
Custom Field 2 Name:  connect:postgres:env:PGPASSWORD
Custom Field 2 Value: ${password}
To initiate connection: "connect postgres"
'''


endpoint_pattern = re.compile(r'^connect:([^:]+)$')
endpoint_desc_pattern = re.compile(r'^connect:([^:]+):description$')


class ConnectEndpoint:
    def __init__(self, name, description, record_uid, record_title, paths):
        self.name = name                    # type: str
        self.description = description      # type: str
        self.record_uid = record_uid        # type: str
        self.record_title = record_title    # type: str
        self.paths = paths                  # type: list


class ConnectCommand(BaseConnectCommand):
    LastRevision = 0        # int
    Endpoints = []          # type: [ConnectEndpoint]

    def get_parser(self):
        return connect_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(connect_command_description)
            return

        ConnectCommand.find_endpoints(params)

        endpoint = kwargs.get('endpoint')
        if endpoint:
            endpoints = [x for x in ConnectCommand.Endpoints if x.name == endpoint]
            if not endpoints:
                rpos = endpoint.rfind(':')
                if rpos > 0:
                    try_path = endpoint[:rpos]
                    endpoint_name = endpoint[rpos+1:]
                else:
                    try_path = endpoint
                    endpoint_name = ''
                record_uid = ''
                if try_path in params.record_cache:
                    record_uid = try_path
                else:
                    rs = try_resolve_path(params, try_path)
                    if rs is not None:
                        folder, title = rs
                        if folder is not None and title is not None:
                            folder_uid = folder.uid or ''
                            if folder_uid in params.subfolder_record_cache:
                                for uid in params.subfolder_record_cache[folder_uid]:
                                    r = KeeperRecord.load(params, uid)
                                    if r.title.lower() == title.lower():
                                        record_uid = uid
                                        break
                if record_uid:
                    endpoints = [x for x in ConnectCommand.Endpoints
                                 if x.record_uid == record_uid and endpoint_name in {'', x.name}]

            if len(endpoints) > 0:
                if len(endpoints) == 1:
                    record = KeeperRecord.load(params, endpoints[0].record_uid)
                    self.connect_endpoint(params, endpoints[0].name, record)
                else:
                    logging.warning("Connect endpoint '%s' is not unique", endpoint)
                    ConnectCommand.dump_endpoints(endpoints)
                    logging.info("Use full endpoint path: /<Folder>/<Title>[:<Endpoint>]")
                    folder = endpoints[0].paths[0] if len(endpoints[0].paths) > 0 else '/'
                    logging.info('Example: connect "%s/%s:%s"', folder, endpoints[0].record_title, endpoints[0].name)
            else:
                logging.info("Connect endpoint '%s' not found", endpoint)
        else:
            if ConnectCommand.Endpoints:
                sorted_by = kwargs.get('sort_by') or 'endpoint'
                filter_by = kwargs.get('filter_by') or ''
                logging.info("Available connect endpoints")
                if filter_by:
                    logging.info('Filtered by "%s"', filter_by)
                    filter_by = filter_by.lower()
                ConnectCommand.dump_endpoints(ConnectCommand.Endpoints, filter_by, sorted_by)
            else:
                logging.info("No connect endpoints found")
            return

    @staticmethod
    def dump_endpoints(endpoints, filter_by='', sorted_by=''):
        logging.info('')
        headers = ['Endpoint', 'Description', 'Record Title', 'Folder(s)']
        table = []
        for endpoint in endpoints:
            title = endpoint.record_title
            folder = endpoint.paths[0] if len(endpoint.paths) > 0 else '/'
            if filter_by:
                if not any([x for x in [endpoint.name.lower(), title.lower(), folder.lower()] if x.find(filter_by) >= 0]):
                    continue
            if len(title) > 23:
                title = title[:20] + '...'
            table.append([endpoint.name, endpoint.description or '', title, folder])
        table.sort(key=lambda x: x[3] if sorted_by == 'folder' else x[2] if sorted_by == 'title' else x[0])
        dump_report_data(table, headers, row_number=True)

    @staticmethod
    def find_endpoints(params):   # type: (KeeperParams) -> None
        if ConnectCommand.LastRevision < params.revision:
            ConnectCommand.LastRevision = params.revision
            ConnectCommand.Endpoints.clear()
            for record_uid in params.record_cache:
                record = KeeperRecord.load(params, record_uid)
                endpoints = []
                endpoints_desc = {}
                if isinstance(record, PasswordRecord):
                    for field in record.custom:
                        m = endpoint_pattern.match(field.name)
                        if m:
                            endpoints.append(m[1])
                        else:
                            m = endpoint_desc_pattern.match(field.name)
                            if m:
                                endpoints_desc[m[1]] = field.value or ''
                elif isinstance(record, TypedRecord):
                    for field in record.custom:
                        if field.type and field.type != 'text':
                            continue
                        m = endpoint_pattern.match(field.label)
                        if m:
                            endpoints.append(m[1])
                        else:
                            m = endpoint_desc_pattern.match(field.label)
                            if m:
                                endpoints_desc[m[1]] = field.get_default_value(str) or ''
                if endpoints:
                    paths = []
                    for folder_uid in find_folders(params, record_uid):
                        path = '/' + get_folder_path(params, folder_uid, '/')
                        paths.append(path)
                    for endpoint in endpoints:
                        epoint = ConnectEndpoint(endpoint, endpoints_desc.get(endpoint) or '', record_uid, record.title, paths)
                        ConnectCommand.Endpoints.append(epoint)
            ConnectCommand.Endpoints.sort(key=lambda x: x.name)

    @staticmethod
    def get_fields_by_patters(record, pattern):   # type: (KeeperRecord, str) -> Iterable[Tuple[str, str]]
        if isinstance(record, PasswordRecord):
            return ((x.name, x.value) for x in record.custom if x.name.lower().startswith(pattern))

        if isinstance(record, TypedRecord):
            return ((x.label, x.get_default_value()) for x in record.custom
                    if (x.type or 'text') == 'text' and (x.label or '').lower().startswith(pattern))

    @staticmethod
    def add_ssh_keys(params, endpoint, record, temp_files):
        # type: (KeeperParams, str, KeeperRecord, List[str]) -> Iterable[Callable]
        key_prefix = f'connect:{endpoint}:ssh-key'

        for cf_name, cf_value in ConnectCommand.get_fields_by_patters(record, key_prefix):
            key_name = cf_name[len(key_prefix)+1:] or 'Commander'
            parsed_values = []
            while True:
                m = endpoint_parameter_pattern.search(cf_value)
                if not m:
                    break
                p = m.group(1)
                val = ConnectCommand.get_parameter_value(params, record, p, temp_files)
                if not val:
                    raise Exception(f'Add ssh-key. Failed to resolve key parameter: {p}')
                parsed_values.append(val)
                cf_value = cf_value[m.end():]
            if len(parsed_values) > 0:
                cf_value = cf_value.strip()
                if cf_value:
                    parsed_values.append(cf_value)
                to_delete = add_ssh_key(parsed_values[0], parsed_values[1] if len(parsed_values) > 1 else None, key_name)
                if to_delete:
                    yield to_delete

    @staticmethod
    def add_environment_variables(params, endpoint, record, temp_files):
        # type: (KeeperParams, str, KeeperRecord, List[str]) -> Iterable[Callable]
        key_prefix = f'connect:{endpoint}:env:'
        for cf_name, cf_value in ConnectCommand.get_fields_by_patters(record, key_prefix):
            key_name = cf_name[len(key_prefix):]
            if not key_name:
                continue
            while True:
                m = endpoint_parameter_pattern.search(cf_value)
                if not m:
                    break
                p = m.group(1)
                val = ConnectCommand.get_parameter_value(params, record, p, temp_files)
                if not val:
                    raise Exception('Add environment variable. Failed to resolve key parameter: {0}'.format(p))
                cf_value = cf_value[:m.start()] + val + cf_value[m.end():]
            if cf_value:
                os.putenv(key_name, cf_value)

                def clear_env():
                    os.putenv(key_name, '')
                yield clear_env

    def connect_endpoint(self, params, endpoint, record):
        # type: (KeeperParams, str, KeeperRecord) -> None
        temp_files = []
        try:
            command = BaseConnectCommand.get_custom_field(record, f'connect:{endpoint}:pre')
            if command:
                command = BaseConnectCommand.get_command_string(params, record, command, temp_files, endpoint=endpoint)
                if command:
                    os.system(command)

            command = ConnectCommand.get_custom_field(record, f'connect:{endpoint}')
            if command:
                self.command = ConnectCommand.get_command_string(params, record, command, temp_files, endpoint=endpoint)
                if self.command:
                    self.run_at_the_end.extend(
                        ConnectCommand.add_ssh_keys(params, endpoint, record, temp_files))
                    self.run_at_the_end.extend(
                        ConnectCommand.add_environment_variables(params, endpoint, record, temp_files))

                    logging.info('Connecting to "%s" ...', record.title)
                    self.execute_shell()

            command = BaseConnectCommand.get_custom_field(record, f'connect:{endpoint}:post')
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, endpoint=endpoint)
                if command:
                    os.system(command)
        finally:
            for file in temp_files:
                os.remove(file)
