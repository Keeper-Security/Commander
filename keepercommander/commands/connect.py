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

import argparse
import io
import logging
import os
import re
import tempfile
from typing import Optional, Iterable, Tuple

import itertools

from cryptography.hazmat.primitives.asymmetric import rsa  # , dsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from tabulate import tabulate

from .base import raise_parse_exception, suppress_exit, Command
from .. import api
from ..attachment import prepare_attachment_download, KeeperRecord, TypedRecord, PasswordRecord, FileRecord
from ..params import KeeperParams
from ..subfolder import try_resolve_path, find_folders, get_folder_path

connect_parser = argparse.ArgumentParser(prog='connect', description='Establishes connection to external server')
connect_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                            help='display help on command format and template parameters')
connect_parser.add_argument('-s', '--sort', dest='sort_by', action='store', choices=['endpoint', 'title', 'folder'],
                            help='sort output')
connect_parser.add_argument('-f', '--filter', dest='filter_by', action='store', help='filter output')
connect_parser.add_argument('endpoint', nargs='?', action='store', type=str,
                            help='endpoint name or full record path to endpoint')
connect_parser.error = raise_parse_exception
connect_parser.exit = suppress_exit


SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH2_AGENTC_ADD_IDENTITY = 17
SSH2_AGENTC_REMOVE_IDENTITY = 18
SSH2_AGENTC_ADD_ID_CONSTRAINED = 25
SSH_AGENT_CONSTRAIN_LIFETIME = 1


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
    ${host}                         The content of the Hostname field. "hostname[:port]"
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
endpoint_parameter_pattern = re.compile(r'\${(.+?)}')


class ConnectSshAgent:
    def __init__(self, path):
        self.path = path
        self._fd = None

    def __enter__(self):
        if os.name == 'posix':
            if not self.path:
                raise Exception('Add ssh-key. \'SSH_AUTH_SOCK\' environment variable is not set')
            from socket import AF_UNIX, SOCK_STREAM, socket
            self._fd = socket(AF_UNIX, SOCK_STREAM, 0)
            self._fd.settimeout(1)
            self._fd.connect(self.path)
        elif os.name == 'nt':
            path = self.path or r'\\.\pipe\openssh-ssh-agent'
            self._fd = open(path, 'rb+', buffering=0)
        else:
            raise Exception('SSH Agent Connect: Unsupported platform')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd:
            self._fd.close()

    def send(self, rq):     # type: (bytes) -> bytes
        if self._fd:
            rq_len = len(rq)
            to_send = rq_len.to_bytes(4, byteorder='big') + rq

            if os.name == 'posix':
                self._fd.send(to_send)
                lb = self._fd.recv(4)
                rs_len = int.from_bytes(lb, byteorder='big')
                return self._fd.recv(rs_len)
            elif os.name == 'nt':
                self._fd.write(to_send)
                self._fd.flush()
                lb = self._fd.read(4)
                rs_len = int.from_bytes(lb, byteorder='big')
                return self._fd.read(rs_len)
        raise Exception('SSH Agent Connect: Unsupported platform')


class ConnectEndpoint:
    def __init__(self, name, description, record_uid, record_title, paths):
        # type: (str, str, str, str, list) -> None
        self.name = name                    # type: str
        self.description = description      # type: str
        self.record_uid = record_uid        # type: str
        self.record_title = record_title    # type: str
        self.paths = paths                  # type: list


class ConnectRecord(object):
    def __init__(self, record):   # type: (KeeperRecord) -> None
        self.record = record

    @property
    def record_uid(self):
        return self.record.record_uid

    def get_value_by_name(self, name):  # type: (str) -> Optional[str]
        if isinstance(self.record, PasswordRecord):
            if name == 'login':
                return self.record.login
            if name == 'password':
                return self.record.password
            return next((x.value for x in self.record.custom
                         if x.name.casefold() == name.casefold()), None)
        if isinstance(self.record, TypedRecord):
            field_type, sep, value_name = name.partition('.')
            field = next((x for x in itertools.chain(self.record.fields, self.record.custom)
                          if field_type == x.type), None)
            if field:
                value = field.get_default_value()
                if isinstance(value, dict):
                    if sep == '.':
                        if value_name in value:
                            return value[value_name]
                    elif name == 'host':
                        host_name = value.get('hostName', None)
                        if host_name:
                            port = value.get('port', None)
                            if port:
                                return f'{host_name}:{[port]}'
                            return host_name
                if isinstance(value, str):
                    return value

            return next((x.get_default_value() for x in self.record.custom
                         if x.label and x.label.casefold() == name.casefold()), None)

    def get_attachment_id(self, params, name):  # type: (KeeperParams, str) -> Optional[str]
        attachment_id = None
        if isinstance(self.record, PasswordRecord):
            attachment_id = next((x.id for x in self.record.attachments if x.id == name), None)
            if not attachment_id:
                attachment_id = next((x.id for x in self.record.attachments
                                      if x.title.casefold() == name.casefold()), None)
            if not attachment_id:
                attachment_id = next((x.id for x in self.record.attachments
                                      if x.name.casefold() == name.casefold()), None)
        if isinstance(self.record, TypedRecord):
            file_ref = self.record.get_typed_field('fileRef')
            if file_ref:
                file_uids = file_ref.value
                if isinstance(file_uids, list):
                    attachment_id = next((x for x in file_uids if x == name), None)
                    if not attachment_id:
                        files = [KeeperRecord.load(params, x) for x in file_uids]
                        files = [x for x in files if isinstance(x, FileRecord)]
                        attachment_id = next((x.record_uid for x in files
                                              if x.title.casefold() == name.casefold()), None)
                        if not attachment_id:
                            attachment_id = next((x.record_uid for x in files
                                                  if x.name.casefold() == name.casefold()), None)
        return attachment_id

    def get_custom_value_by_name_prefix(self, name_prefix):   # type: (str) -> Iterable[Tuple[str, str]]
        if isinstance(self.record, PasswordRecord):
            for cf in (x for x in self.record.custom if x.name.startswith(name_prefix)):
                value = cf.value
                if value:
                    yield cf.name[len(name_prefix)+1:], value

        if isinstance(self.record, TypedRecord):
            for cf in (x for x in self.record.custom
                       if x.type in {None, '', 'text'} and x.label and x.label.startswith(name_prefix)):
                value = cf.get_default_value()
                if value:
                    yield cf.label[len(name_prefix)+1:], value


class ConnectCommand(Command):
    LastRevision = 0        # type: int
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
                                    r = api.get_record(params, uid)
                                    if r.title.lower() == title.lower():
                                        record_uid = uid
                                        break
                if record_uid:
                    endpoints = [x for x in ConnectCommand.Endpoints
                                 if x.record_uid == record_uid and endpoint_name in {'', x.name}]

            if len(endpoints) > 0:
                if len(endpoints) == 1:
                    keeper_record = KeeperRecord.load(params, endpoints[0].record_uid)
                    if keeper_record:
                        record = ConnectRecord(keeper_record)
                        ConnectCommand.connect_endpoint(params, endpoints[0].name, record)
                else:
                    logging.warning(f"Connect endpoint '{endpoint}' is not unique")
                    ConnectCommand.dump_endpoints(endpoints)
                    logging.info("Use full endpoint path: /<Folder>/<Title>[:<Endpoint>]")
                    folder = endpoints[0].paths[0] if len(endpoints[0].paths) > 0 else '/'
                    logging.info(f'Example: connect "{folder}/{endpoints[0].record_title}:{endpoints[0].name}"')
            else:
                logging.info(f"Connect endpoint '{endpoint}' not found")
        else:
            if ConnectCommand.Endpoints:
                sorted_by = kwargs['sort_by'] or 'endpoint'
                filter_by = kwargs['filter_by'] or ''
                logging.info("Available connect endpoints")
                if filter_by:
                    logging.info('Filtered by \"%s\"', filter_by)
                    filter_by = filter_by.lower()
                ConnectCommand.dump_endpoints(ConnectCommand.Endpoints, filter_by, sorted_by)
            else:
                logging.info("No connect endpoints found")
            return

    @staticmethod
    def dump_endpoints(endpoints, filter_by='', sorted_by=''):
        logging.info('')
        headers = ["#", 'Endpoint', 'Description', 'Record Title', 'Folder(s)']
        table = []
        for endpoint in endpoints:
            title = endpoint.record_title
            folder = endpoint.paths[0] if len(endpoint.paths) > 0 else '/'
            if filter_by:
                if not any([x for x in [endpoint.name.lower(), title.lower(), folder.lower()] if x.find(filter_by) >= 0]):
                    continue
            if len(title) > 23:
                title = title[:20] + '...'
            table.append([0, endpoint.name, endpoint.description or '', title, folder])
        table.sort(key=lambda x: x[4] if sorted_by == 'folder' else x[3] if sorted_by == 'title' else x[1])
        for i in range(len(table)):
            table[i][0] = i + 1
        print(tabulate(table, headers=headers))
        print('')

    @staticmethod
    def delete_ssh_keys(delete_requests):
        try:
            ssh_socket_path = os.environ.get('SSH_AUTH_SOCK')
            with ConnectSshAgent(ssh_socket_path) as fd:
                for rq in delete_requests:
                    recv_payload = fd.send(rq)
                    if recv_payload and recv_payload[0] == SSH_AGENT_FAILURE:
                        logging.info('Failed to delete added ssh key')
        except Exception as e:
            logging.error(e)

    @staticmethod
    def add_environment_variables(params, endpoint, record, temp_files):
        # type: (KeeperParams, str, ConnectRecord, [str]) -> [str]
        rs = []         # type: [str]
        key_prefix = f'connect:{endpoint}:env'
        for key_name, value in record.get_custom_value_by_name_prefix(key_prefix):
            if not key_name:
                continue
            while True:
                m = endpoint_parameter_pattern.search(value)
                if not m:
                    break
                p = m.group(1)
                val = ConnectCommand.get_parameter_value(params, record, p, temp_files)
                if not val:
                    raise Exception(f'Add environment variable. Failed to resolve key parameter: {p}')
                value = value[:m.start()] + val + value[m.end():]
            if value:
                rs.append(key_name)
                os.putenv(key_name, value)
        return rs

    @staticmethod
    def get_private_key(record):   # type: (KeeperRecord) -> Optional[Tuple[str, str]]
        if isinstance(record, TypedRecord):
            field = record.get_typed_field('keyPair')
            if field:
                key_pair = field.get_default_value()
                if isinstance(key_pair, dict) and 'privateKey' in key_pair:
                    private_key = key_pair['privateKey']
                    if private_key:
                        passphrase = record.get_typed_field('password', 'passphrase')
                        if not passphrase:
                            passphrase = record.get_typed_field('password')
                        return private_key, passphrase.get_default_value() if passphrase else None

    @staticmethod
    def add_ssh_keys(params, endpoint, record, temp_files):
        # type: (KeeperParams, str, ConnectRecord, [str]) -> [bytes]
        rs = []
        ssh_socket_path = os.environ.get('SSH_AUTH_SOCK')
        key_prefix = f'connect:{endpoint}:ssh-key'
        for key_name, value in record.get_custom_value_by_name_prefix(key_prefix):
            key_data = None
            passphrase = None
            if value in params.record_cache:
                ssh_key_record = KeeperRecord.load(params, value)
                if ssh_key_record:
                    if not key_name:
                        key_name = ssh_key_record.title
                    key_data, passphrase = ConnectCommand.get_private_key(ssh_key_record)
            else:
                parsed_values = []
                while True:
                    m = endpoint_parameter_pattern.search(value)
                    if not m:
                        break
                    p = m.group(1)
                    val = ConnectCommand.get_parameter_value(params, record, p, temp_files)
                    if not val:
                        raise Exception(f'Add ssh-key. Failed to resolve key parameter: {p}')
                    parsed_values.append(val.strip())
                    value = value[m.end():]
                if len(parsed_values) > 0:
                    value = value.strip()
                    if value:
                        parsed_values.append(value)
                if len(parsed_values) > 0:
                    key_data = parsed_values[0]
                if len(parsed_values) > 1 and parsed_values[1]:
                    passphrase = parsed_values[1]
            if not key_data:
                continue
            if not key_name:
                key_name = 'Commander'

            """
            private_key = RSA.importKey(key_data, passphrase)
            """
            private_key = load_pem_private_key(key_data.encode(), password=passphrase.encode() if passphrase else None)
            if isinstance(private_key, rsa.RSAPrivateKey):
                private_numbers = private_key.private_numbers()
                public_numbers = private_key.public_key().public_numbers()

                store_payload = SSH2_AGENTC_ADD_IDENTITY.to_bytes(1, byteorder='big')
                store_payload += ConnectCommand.ssh_agent_encode_str('ssh-rsa')
                store_payload += ConnectCommand.ssh_agent_encode_long(public_numbers.n)
                store_payload += ConnectCommand.ssh_agent_encode_long(public_numbers.e)
                store_payload += ConnectCommand.ssh_agent_encode_long(private_numbers.d)
                store_payload += ConnectCommand.ssh_agent_encode_long(private_numbers.iqmp)
                store_payload += ConnectCommand.ssh_agent_encode_long(private_numbers.p)
                store_payload += ConnectCommand.ssh_agent_encode_long(private_numbers.q)
                store_payload += ConnectCommand.ssh_agent_encode_str(key_name)
                # windows ssh implementation does not support constrained identity
                # store_payload += SSH_AGENT_CONSTRAIN_LIFETIME.to_bytes(1, byteorder='big')
                # store_payload += int(10).to_bytes(4, byteorder='big')

                remove_payload = ConnectCommand.ssh_agent_encode_str('ssh-rsa')
                remove_payload += ConnectCommand.ssh_agent_encode_long(public_numbers.e)
                remove_payload += ConnectCommand.ssh_agent_encode_long(public_numbers.n)
                remove_payload = SSH2_AGENTC_REMOVE_IDENTITY.to_bytes(1, byteorder='big') + ConnectCommand.ssh_agent_encode_bytes(remove_payload)
            else:
                raise Exception(f'Add ssh-key. Key \"{key_name}\" is not supported yet.')

            if store_payload:
                with ConnectSshAgent(ssh_socket_path) as fd:
                    recv_payload = fd.send(store_payload)
                    if recv_payload and recv_payload[0] == SSH_AGENT_FAILURE:
                        raise Exception(f'Add ssh-key. Failed to add ssh key \"{key_name}\" to ssh-agent')
                if remove_payload:
                    rs.append(remove_payload)
        return rs

    @staticmethod
    def ssh_agent_encode_bytes(b):      # type: (bytes) -> bytes
        return len(b).to_bytes(4, byteorder='big') + b

    @staticmethod
    def ssh_agent_encode_long(long_value):       # type: (int) -> bytes
        length = (long_value.bit_length() + 7) // 8
        b = long_value.to_bytes(length=length, byteorder='big')
        if b[0] >= 0x80:
            b = b'\x00' + b
        return ConnectCommand.ssh_agent_encode_bytes(b)

    @staticmethod
    def ssh_agent_encode_str(s):        # type: (str) -> bytes
        return ConnectCommand.ssh_agent_encode_bytes(s.encode('utf-8'))

    @staticmethod
    def find_endpoints(params):
        # type: (KeeperParams) -> None
        if ConnectCommand.LastRevision < params.revision:
            ConnectCommand.LastRevision = params.revision
            ConnectCommand.Endpoints.clear()
            for record_uid in params.record_cache:
                record = KeeperRecord.load(params, record_uid)  # type: Optional[KeeperRecord]
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
                        if field.label and field.type in {None, '', 'text'}:
                            m = endpoint_pattern.match(field.label)
                            if m:
                                endpoints.append(m[1])
                            else:
                                m = endpoint_desc_pattern.match(field.label)
                                if m:
                                    endpoints_desc[m[1]] = field.get_default_value() or ''
                if endpoints:
                    paths = []
                    for folder_uid in find_folders(params, record_uid):
                        path = '/' + get_folder_path(params, folder_uid, '/')
                        paths.append(path)
                    for endpoint in endpoints:
                        epoint = ConnectEndpoint(endpoint, endpoints_desc.get(endpoint) or '',
                                                 record_uid, record.title, paths)
                        ConnectCommand.Endpoints.append(epoint)
            ConnectCommand.Endpoints.sort(key=lambda x: x.name)

    attachment_cache = {}

    @staticmethod
    def get_command_string(params, record, template, temp_files, **kwargs):
        # type: (KeeperParams, ConnectRecord, str, list, ...) -> str or None
        command = template
        while True:
            m = endpoint_parameter_pattern.search(command)
            if not m:
                break
            p = m.group(1)
            pv = ConnectCommand.get_parameter_value(params, record, p, temp_files, **kwargs)
            command = command[:m.start()] + (pv or '') + command[m.end():]
        logging.debug(command)
        return command

    @staticmethod
    def get_parameter_value(params, record, parameter, temp_files, **kwargs):
        # type: (KeeperParams, ConnectRecord, str, list, ...) -> str or None
        if parameter.startswith('file:') or parameter.startswith('body:'):
            file_name = parameter[5:]
            if file_name not in ConnectCommand.attachment_cache:
                attachment_id = record.get_attachment_id(params, file_name)
                if not attachment_id:
                    logging.error('Attachment file \"%s\" not found', file_name)
                    return None
                download = next(prepare_attachment_download(params, record.record_uid, attachment_id), None)
                if not download:
                    logging.error('Attachment file \"%s\" can not be downloaded', file_name)
                    return None
                with io.BytesIO() as stream:
                    download.download_to_stream(params, stream)
                    stream.flush()
                    body = stream.getvalue()
                if body:
                    ConnectCommand.attachment_cache[file_name] = body
            if file_name not in ConnectCommand.attachment_cache:
                logging.error('Attachment file \"%s\" not found', file_name)
                return None
            body = ConnectCommand.attachment_cache[file_name]      # type: bytes
            prefix = (kwargs.get('endpoint') or file_name) + '.'
            if parameter.startswith('file:'):
                tf = tempfile.NamedTemporaryFile(delete=False, prefix=prefix)
                tf.write(body)
                tf.flush()
                temp_files.append(tf.name)
                tf.close()
                return tf.name
            else:
                return body.decode('utf-8')
        elif parameter == 'user_email':
            return params.user
        else:
            value = record.get_value_by_name(parameter)
            if value:
                return value
        logging.error('Parameter \"%s\" cannot be resolved', parameter)

    @staticmethod
    def connect_endpoint(params, endpoint, record):
        # type: (KeeperParams, str, ConnectRecord) -> None
        temp_files = []

        try:
            command = record.get_value_by_name(f'connect:{endpoint}:pre')
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, endpoint=endpoint)
                if command:
                    os.system(command)

            command = record.get_value_by_name(f'connect:{endpoint}')
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, endpoint=endpoint)
                if command:
                    added_keys = ConnectCommand.add_ssh_keys(params, endpoint, record, temp_files)
                    added_envs = ConnectCommand.add_environment_variables(params, endpoint, record, temp_files)
                    logging.info('Connecting to %s...', endpoint)
                    os.system(command)
                    if added_keys:
                        ConnectCommand.delete_ssh_keys(added_keys)
                    if added_envs:
                        for name in added_envs:
                            os.putenv(name, '')

            command = record.get_value_by_name(f'connect:{endpoint}:post')
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, endpoint=endpoint)
                if command:
                    os.system(command)

        finally:
            for file in temp_files:
                os.remove(file)
