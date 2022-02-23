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
import logging
import os
import shutil
from typing import Optional, Callable, Iterator

import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from .base import Command
from .record import find_record, RecordListCommand
from ..attachment import TypedRecord
from ..params import KeeperParams
from ..vault_extensions import SshKeysFacade, ServerCredentialsFacade, DatabaseCredentialsFacade

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


mysql = ''
postgresql = ''


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
    commands['ssh'] = ConnectSshCommand()
    if mysql:
        commands['mysql'] = ConnectMysqlCommand()
    if postgresql:
        commands['postgresql'] = ConnectPostgresCommand()
    if sys.platform == 'win32':
        commands['rdp'] = ConnectRdpCommand()


def connect_command_info(aliases, command_info):
    command_info[ssh_parser.prog] = ssh_parser.description
    if mysql:
        command_info['mysql'] = mysql_parser.description
    if postgresql:
        command_info['postgresql'] = postgres_parser.description
        aliases['pg'] = 'postgresql'
    if sys.platform == 'win32':
        command_info['rdp'] = rdp_parser.description


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


SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH2_AGENTC_ADD_IDENTITY = 17
SSH2_AGENTC_REMOVE_IDENTITY = 18
SSH2_AGENTC_ADD_ID_CONSTRAINED = 25
SSH_AGENT_CONSTRAIN_LIFETIME = 1


def delete_ssh_key(delete_request):
    try:
        ssh_socket_path = os.environ.get('SSH_AUTH_SOCK')
        with ConnectSshAgent(ssh_socket_path) as fd:
            recv_payload = fd.send(delete_request)
            if recv_payload and recv_payload[0] == SSH_AGENT_FAILURE:
                logging.info('Failed to delete added ssh key')
    except Exception as e:
        logging.error(e)


def ssh_agent_encode_bytes(b):      # type: (bytes) -> bytes
    return len(b).to_bytes(4, byteorder='big') + b


def ssh_agent_encode_str(s):        # type: (str) -> bytes
    return ssh_agent_encode_bytes(s.encode('utf-8'))


def ssh_agent_encode_long(long_value):       # type: (int) -> bytes
    length = (long_value.bit_length() + 7) // 8
    b = long_value.to_bytes(length=length, byteorder='big')
    if b[0] >= 0x80:
        b = b'\x00' + b
    return ssh_agent_encode_bytes(b)


def add_ssh_key(private_key, passphrase, key_name):   # type: (str, str, str) -> Optional[Callable]
    ssh_socket_path = os.environ.get('SSH_AUTH_SOCK')
    header, _, _ = private_key.partition('\n')
    if 'BEGIN OPENSSH PRIVATE KEY' in header:
        private_key = serialization.load_ssh_private_key(
            private_key.encode(), password=passphrase.encode() if passphrase else None)
    else:
        private_key = serialization.load_pem_private_key(
            private_key.encode(), password=passphrase.encode() if passphrase else None)
    if isinstance(private_key, rsa.RSAPrivateKey):
        private_numbers = private_key.private_numbers()
        public_numbers = private_key.public_key().public_numbers()

        store_payload = SSH2_AGENTC_ADD_IDENTITY.to_bytes(1, byteorder='big')
        store_payload += ssh_agent_encode_str('ssh-rsa')
        store_payload += ssh_agent_encode_long(public_numbers.n)
        store_payload += ssh_agent_encode_long(public_numbers.e)
        store_payload += ssh_agent_encode_long(private_numbers.d)
        store_payload += ssh_agent_encode_long(private_numbers.iqmp)
        store_payload += ssh_agent_encode_long(private_numbers.p)
        store_payload += ssh_agent_encode_long(private_numbers.q)
        store_payload += ssh_agent_encode_str(key_name)
        # windows ssh implementation does not support constrained identity
        # store_payload += SSH_AGENT_CONSTRAIN_LIFETIME.to_bytes(1, byteorder='big')
        # store_payload += int(10).to_bytes(4, byteorder='big')

        remove_payload = ssh_agent_encode_str('ssh-rsa')
        remove_payload += ssh_agent_encode_long(public_numbers.e)
        remove_payload += ssh_agent_encode_long(public_numbers.n)
        remove_payload = SSH2_AGENTC_REMOVE_IDENTITY.to_bytes(1, byteorder='big') + ssh_agent_encode_bytes(remove_payload)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        private_numbers = private_key.private_numbers()
        curve_name = 'nistp256'
        store_payload = SSH2_AGENTC_ADD_IDENTITY.to_bytes(1, byteorder='big')
        store_payload += ssh_agent_encode_str(f'ecdsa-sha2-{curve_name}')
        store_payload += ssh_agent_encode_str(curve_name)
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
        store_payload += ssh_agent_encode_bytes(public_key_bytes)
        store_payload += ssh_agent_encode_long(private_numbers.private_value)
        store_payload += ssh_agent_encode_str(key_name)

        remove_payload = ssh_agent_encode_str(f'ecdsa-sha2-{curve_name}')
        remove_payload += ssh_agent_encode_str(curve_name)
        remove_payload += ssh_agent_encode_bytes(public_key_bytes)
        remove_payload = SSH2_AGENTC_REMOVE_IDENTITY.to_bytes(1, byteorder='big') + ssh_agent_encode_bytes(remove_payload)

    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())

        store_payload = SSH2_AGENTC_ADD_IDENTITY.to_bytes(1, byteorder='big')
        store_payload += ssh_agent_encode_str('ssh-ed25519')
        store_payload += ssh_agent_encode_bytes(public_key_bytes)
        store_payload += ssh_agent_encode_bytes(private_key_bytes + public_key_bytes)
        store_payload += ssh_agent_encode_str(key_name)

        remove_payload = ssh_agent_encode_str('ssh-ed25519')
        remove_payload += ssh_agent_encode_bytes(public_key_bytes)
        remove_payload = SSH2_AGENTC_REMOVE_IDENTITY.to_bytes(1, byteorder='big') + ssh_agent_encode_bytes(remove_payload)
    else:
        if private_key:
            key_type = type(private_key)
            raise Exception(f'Add ssh-key. Key type \"{key_type.__name__}\" is not supported yet.')
        else:
            raise Exception('Cannot load SSH private key.')

    if store_payload:
        with ConnectSshAgent(ssh_socket_path) as fd:
            recv_payload = fd.send(store_payload)
            if recv_payload and recv_payload[0] == SSH_AGENT_FAILURE:
                raise Exception(f'Add ssh-key. Failed to add ssh key \"{key_name}\" to ssh-agent')
        if remove_payload:
            def remove_key():
                delete_ssh_key(remove_payload)
            return remove_key


class BaseConnectCommand(Command):
    def __init__(self):
        super(BaseConnectCommand, self).__init__()
        self.command = ''
        self.run_at_the_end = []

    def execute_shell(self):
        logging.debug('Executing "%s" ...', self.command)
        try:
            os.system(self.command)
        finally:
            self.command = ''
            for cb in self.run_at_the_end:
                try:
                    cb()
                except Exception as e:
                    logging.debug(e)
            self.run_at_the_end.clear()

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


class ConnectSshCommand(BaseConnectCommand):
    def get_parser(self):
        return ssh_parser

    def execute(self, params, **kwargs):
        name = kwargs['record'] if 'record' in kwargs else None
        record = self.get_record(params, name, ['sshKeys', 'serverCredentials'])
        if not record:
            return

        facade = SshKeysFacade() if record.record_type == 'sshKeys' else ServerCredentialsFacade()
        facade.assign_record(record)

        self.command = ''
        self.run_at_the_end.clear()

        dst = kwargs.get('destination', '')
        if dst:
            l, at, d = dst.partition('@')
            if at == '@':
                login = l
                host_name, _, port = d.partition(':')
            else:
                logging.warning('Destination parameter should be LOGIN@HOST[:PORT]')
                return
        else:
            login = facade.login
            if not login:
                logging.warning('Record "%s" does not have user name.', record.title)
                return
            host_name = facade.host_name
            if not host_name:
                logging.warning('Record "%s" does not have host name.', record.title)
                return
            port = facade.port

        self.command = f'ssh {login}@{host_name}'
        if port:
            self.command += f' -p {port}'

        if isinstance(facade, SshKeysFacade):
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
        elif isinstance(facade, ServerCredentialsFacade):
            password = facade.password
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

        facade = DatabaseCredentialsFacade()
        facade.assign_record(record)

        login = facade.login
        if not login:
            logging.warning('Record "%s" does not have user name.', record.title)
            return
        host_name = facade.host_name
        if not host_name:
            logging.warning('Record "%s" does not have host name.', record.title)
            return
        port = facade.port

        self.command = f'mysql -h {host_name} -u {login}'
        if port:
            self.command += f' -P {port}'
        self.run_at_the_end.clear()

        password = facade.password
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

        facade = DatabaseCredentialsFacade()
        facade.assign_record(record)

        login = facade.login
        if not login:
            logging.warning('Record "%s" does not have user name.', record.title)
            return
        host_name = facade.host_name
        if not host_name:
            logging.warning('Record "%s" does not have host name.', record.title)
            return
        port = facade.port

        database = kwargs.get('database')
        if not database:
            db_field = record.get_typed_field('text', 'database')
            if db_field:
                database = db_field.get_default_value()
        if not database:
            database = 'template1'
            logging.info(f'\nConnecting to the default database: {database}\n')

        self.command = f'{postgresql} -h {host_name}'
        if port:
            self.command += f' -p {port}'
        self.command += f' -U {login} -w {database}'
        self.run_at_the_end.clear()

        password = facade.password
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

        facade = ServerCredentialsFacade()
        facade.assign_record(record)

        login = facade.login
        if not login:
            logging.warning('Record "%s" does not have user name.', record.title)
            return
        host_name = facade.host_name
        if not host_name:
            logging.warning('Record "%s" does not have host name.', record.title)
            return
        port = facade.port
        password = facade.password

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
