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
import socket
import datetime
import threading
from typing import Optional, List, Callable, Tuple, Any

import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding, utils

from .base import GroupCommand, Command, dump_report_data
from .. import vault
from ..params import KeeperParams

ssh_agent_info_parser = argparse.ArgumentParser(prog='ssh-agent info', description='Display ssh agent status')
ssh_agent_start_parser = argparse.ArgumentParser(prog='ssh-agent start', description='Start ssh agent')
ssh_agent_stop_parser = argparse.ArgumentParser(prog='ssh-agent stop', description='Stop ssh agent')

ssh_agent_log_parser = argparse.ArgumentParser(prog='ssh-agent log', description='Display ssh agent logs')
ssh_agent_log_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'], default='table', help='output format.')
ssh_agent_log_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')


class ConnectSshAgent:
    def __init__(self, path=None):
        self._fd = None
        self._path = path

    def __enter__(self):
        if os.name == 'posix':
            path = self._path or os.environ.get('SSH_AUTH_SOCK')
            if not path:
                raise Exception('Add ssh-key. \'SSH_AUTH_SOCK\' environment variable is not set')
            from socket import AF_UNIX, SOCK_STREAM, socket
            self._fd = socket(AF_UNIX, SOCK_STREAM, 0)
            self._fd.settimeout(1)
            self._fd.connect(path)
        elif os.name == 'nt':
            path = r'\\.\pipe\openssh-ssh-agent'
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


SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENTC_ADD_IDENTITY = 17
SSH_AGENTC_REMOVE_IDENTITY = 18
SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
SSH_AGENTC_LOCK = 22
SSH_AGENTC_UNLOCK = 23
SSH_AGENTC_ADD_ID_CONSTRAINED = 25

SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENT_SIGN_RESPONSE = 14

SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4

SSH_AGENT_CONSTRAIN_LIFETIME = 1


def delete_ssh_key(delete_request):
    try:
        with ConnectSshAgent() as fd:
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


def ssh_agent_get_next_value(buffer, position):   # type: (bytes, int) -> Tuple[bytes, int]
    size = len(buffer)
    if position + 4 > size:
        raise ValueError('ssh-agent: invalid buffer')
    length = int.from_bytes(buffer[position: position+4], byteorder='big')
    position += 4
    if position + length > size:
        raise ValueError('ssh-agent: invalid buffer')
    return buffer[position:position + length], position + length


def load_private_key(private_key_pem, passphrase):    # type: (str, str) -> Any
    password = passphrase.encode() if passphrase else None
    header, _, _ = private_key_pem.partition('\n')
    if 'BEGIN OPENSSH PRIVATE KEY' in header:
        return serialization.load_ssh_private_key(private_key_pem.encode(), password=password)
    else:
        return serialization.load_pem_private_key(private_key_pem.encode(), password=password)


def add_ssh_key(private_key_pem, passphrase, key_name):   # type: (str, str, str) -> Optional[Callable]
    private_key = load_private_key(private_key_pem, passphrase)
    if isinstance(private_key, rsa.RSAPrivateKey):
        private_numbers = private_key.private_numbers()
        public_numbers = private_key.public_key().public_numbers()

        store_payload = SSH_AGENTC_ADD_IDENTITY.to_bytes(1, byteorder='big')
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
        remove_payload = SSH_AGENTC_REMOVE_IDENTITY.to_bytes(1, byteorder='big') + ssh_agent_encode_bytes(remove_payload)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve_name = 'nistp381' if private_key.curve.name == 'secp384r1' else \
            'nistp521' if private_key.curve.name == 'secp521r1' else \
                'nistp256' if private_key.curve.name == 'secp256r1' else ''
        if not curve_name:
            raise ValueError(f'EC curve is not supported {private_key.curve.name}')

        private_numbers = private_key.private_numbers()
        store_payload = SSH_AGENTC_ADD_IDENTITY.to_bytes(1, byteorder='big')
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
        remove_payload = SSH_AGENTC_REMOVE_IDENTITY.to_bytes(1, byteorder='big') + ssh_agent_encode_bytes(remove_payload)

    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())

        store_payload = SSH_AGENTC_ADD_IDENTITY.to_bytes(1, byteorder='big')
        store_payload += ssh_agent_encode_str('ssh-ed25519')
        store_payload += ssh_agent_encode_bytes(public_key_bytes)
        store_payload += ssh_agent_encode_bytes(private_key_bytes + public_key_bytes)
        store_payload += ssh_agent_encode_str(key_name)

        remove_payload = ssh_agent_encode_str('ssh-ed25519')
        remove_payload += ssh_agent_encode_bytes(public_key_bytes)
        remove_payload = SSH_AGENTC_REMOVE_IDENTITY.to_bytes(1, byteorder='big') + ssh_agent_encode_bytes(remove_payload)
    else:
        if private_key:
            key_type = type(private_key)
            raise Exception(f'Add ssh-key. Key type \"{key_type.__name__}\" is not supported yet.')
        else:
            raise Exception('Cannot load SSH private key.')

    if store_payload:
        with ConnectSshAgent() as fd:
            recv_payload = fd.send(store_payload)
            if recv_payload and recv_payload[0] == SSH_AGENT_FAILURE:
                raise Exception(f'Add ssh-key. Failed to add ssh key \"{key_name}\" to ssh-agent')
        if remove_payload:
            def remove_key():
                delete_ssh_key(remove_payload)
            return remove_key


class SshAgentKey:
    def __init__(self):
        self.key_type = ''
        self.key_blob = None
        self.private_key = None
        self.comment = ''
        self.constraints = []
        self.record_uid = ''


class SshAgentContext(logging.Handler):
    def __init__(self):
        super(SshAgentContext, self).__init__()

        self._thread = None            # type: Optional[threading.Thread]
        self.keys = []                 # type: List[SshAgentKey]
        self.path = None               # type: Optional[str]
        self._server = None            # type: Optional[socket.socket]
        self._lock_passphrase = None   # type: Optional[bytes]
        self._backend = default_backend()
        self._logger = logging.getLogger('ssh-agent')
        self._logger.propagate = False
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()
        self._logger.addHandler(self)
        self.log_messages = []   # type: List[logging.LogRecord]

    @property
    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def emit(self, record):     # type: (logging.LogRecord) -> None
        logging.info(record.msg % record.args)
        self.log_messages.append(record)

    def _process_ssh_agent_request(self, request):    # type: (bytes) -> bytes
        command = request[0]
        pos = 1
        if self._lock_passphrase:
            if command == SSH_AGENTC_UNLOCK:
                passphrase, pos = ssh_agent_get_next_value(request, pos)
                if passphrase == self._lock_passphrase:
                    self._lock_passphrase = None
                    self._logger.info('SSH Agent has been unlocked')
                    return SSH_AGENT_SUCCESS.to_bytes(1, byteorder='big')
            elif command == SSH_AGENTC_REQUEST_IDENTITIES:
                payload = SSH_AGENT_IDENTITIES_ANSWER.to_bytes(1, byteorder='big')
                payload += int(0).to_bytes(4, byteorder='big')
                return payload
        else:
            if command in {SSH_AGENTC_ADD_IDENTITY, SSH_AGENTC_ADD_ID_CONSTRAINED}:
                key = SshAgentKey()
                key_type, pos = ssh_agent_get_next_value(request, pos)
                key.key_type = key_type.decode()
                if key.key_type == 'ssh-rsa':
                    rsa_n, pos = ssh_agent_get_next_value(request, pos)
                    rsa_e, pos = ssh_agent_get_next_value(request, pos)
                    e = int.from_bytes(rsa_e, byteorder='big')
                    n = int.from_bytes(rsa_n, byteorder='big')
                    key.key_blob = \
                        ssh_agent_encode_bytes(key_type) + ssh_agent_encode_bytes(rsa_e) + ssh_agent_encode_bytes(rsa_n)
                    public_key_numbers = rsa.RSAPublicNumbers(e, n)

                    rsa_d, pos = ssh_agent_get_next_value(request, pos)
                    rsa_iqmp, pos = ssh_agent_get_next_value(request, pos)
                    rsa_p, pos = ssh_agent_get_next_value(request, pos)
                    rsa_q, pos = ssh_agent_get_next_value(request, pos)
                    d = int.from_bytes(rsa_d, byteorder='big')
                    iqmp = int.from_bytes(rsa_iqmp, byteorder='big')
                    p = int.from_bytes(rsa_p, byteorder='big')
                    q = int.from_bytes(rsa_q, byteorder='big')
                    dmp1 = rsa.rsa_crt_dmp1(d, p)
                    dmq1 = rsa.rsa_crt_dmq1(d, q)
                    private_key_numbers = rsa.RSAPrivateNumbers(
                        p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, public_numbers=public_key_numbers)
                    key.private_key = private_key_numbers.private_key(backend=self._backend)
                elif key.key_type.startswith('ecdsa-sha2'):
                    curve_name, pos = ssh_agent_get_next_value(request, pos)
                    if curve_name == b'nistp256':
                        curve = ec.SECP256R1()
                    elif curve_name == b'nistp384':
                        curve = ec.SECP384R1()
                    elif curve_name == b'nistp521':
                        curve = ec.SECP521R1()
                    else:
                        raise ValueError(f'Unsupported EC key: {curve_name.decode()}')

                    public_key_bytes, pos = ssh_agent_get_next_value(request, pos)
                    key.key_blob = ssh_agent_encode_bytes(key_type) + ssh_agent_encode_bytes(public_key_bytes)
                    public_numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(curve, public_key_bytes)

                    priv_key, pos = ssh_agent_get_next_value(request, pos)
                    private_int = int.from_bytes(priv_key, byteorder='big')
                    private_numbers = ec.EllipticCurvePrivateNumbers(private_int, public_numbers)
                    key.private_key = private_numbers.private_key(backend=self._backend)
                elif key.key_type == 'ssh-ed25519':
                    public_key_bytes, pos = ssh_agent_get_next_value(request, pos)
                    key.key_blob = ssh_agent_encode_bytes(key_type) + ssh_agent_encode_bytes(public_key_bytes)

                    private_key_bytes, pos = ssh_agent_get_next_value(request, pos)
                    key.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes[0:32])
                else:
                    raise ValueError(f'Unsupported private key type: {key.key_type}')
                comment, pos = ssh_agent_get_next_value(request, pos)
                key.comment = comment.decode()
                if command == SSH_AGENTC_ADD_ID_CONSTRAINED:
                    pass
                self.keys.append(key)
                self._logger.info('Identity \"%s\" has been added', key.comment)

                return SSH_AGENT_SUCCESS.to_bytes(1, byteorder='big')

            elif command == SSH_AGENTC_REMOVE_IDENTITY:
                key_blob, pos = ssh_agent_get_next_value(request, pos)
                key = next((x for x in self.keys if x.key_blob == key_blob), None)
                if key:
                    self.keys.remove(key)
                    self._logger.info('Identity \"%s\" has been removed', key.comment)
                return SSH_AGENT_SUCCESS.to_bytes(1, byteorder='big')

            elif command == SSH_AGENTC_REMOVE_ALL_IDENTITIES:
                num = len(self.keys)
                self.keys.clear()

                self._logger.info('%d identites have been removed', num)
                return SSH_AGENT_SUCCESS.to_bytes(1, byteorder='big')

            elif command == SSH_AGENTC_SIGN_REQUEST:
                key_blob, pos = ssh_agent_get_next_value(request, pos)
                key = next((x for x in self.keys if x.key_blob == key_blob), None)
                if key:
                    data, pos = ssh_agent_get_next_value(request, pos)
                    flags = int.from_bytes(request[pos:pos+4], byteorder='big')
                    signature = b''
                    signature_method = key.key_type
                    if key.key_type == 'ssh-rsa':
                        rsa_pk = key.private_key   # type: rsa.RSAPrivateKey
                        if flags & SSH_AGENT_RSA_SHA2_512:
                            hash_algorithm = hashes.SHA512()
                            signature_method = 'rsa-sha2-512'
                        elif flags & SSH_AGENT_RSA_SHA2_256:
                            hash_algorithm = hashes.SHA512()
                            signature_method = 'rsa-sha2-256'
                        else:
                            hash_algorithm = hashes.SHA1()
                        signature = rsa_pk.sign(data, padding.PKCS1v15(), hash_algorithm)
                    elif key.key_type.startswith('ecdsa-sha2'):
                        ec_pk = key.private_key     # type: ec.EllipticCurvePrivateKey
                        hash_algorithm = \
                            hashes.SHA256() if ec_pk.curve.key_size <= 256 else \
                                hashes.SHA384() if ec_pk.curve.key_size <= 384 else \
                                    hashes.SHA512()
                        sig = ec_pk.sign(data, ec.ECDSA(hash_algorithm))
                        r, s = utils.decode_dss_signature(sig)
                        signature += ssh_agent_encode_long(r)
                        signature += ssh_agent_encode_long(s)
                    elif key.key_type == 'ssh-ed25519':
                        ed_pk = key.private_key     # type: ed25519.Ed25519PrivateKey
                        signature = ed_pk.sign(data)
                    if signature:
                        self._logger.info('Request has been signed with key \"%s\"', key.comment)
                        payload = ssh_agent_encode_str(signature_method)
                        payload += ssh_agent_encode_bytes(signature)
                        return SSH_AGENT_SIGN_RESPONSE.to_bytes(1, byteorder='big') + ssh_agent_encode_bytes(payload)

            elif command == SSH_AGENTC_REQUEST_IDENTITIES:
                payload = SSH_AGENT_IDENTITIES_ANSWER.to_bytes(1, byteorder='big')
                if self._lock_passphrase:
                    payload += int(0).to_bytes(4, byteorder='big')
                else:
                    payload += len(self.keys).to_bytes(4, byteorder='big')
                    for key in self.keys:
                        payload += ssh_agent_encode_bytes(key.key_blob)
                        payload += ssh_agent_encode_str(key.comment)

                return payload

            if command == SSH_AGENTC_LOCK:
                passphrase, pos = ssh_agent_get_next_value(request, pos)
                self._lock_passphrase = passphrase
                self._logger.info('SSH Agent has been locked')
                return SSH_AGENT_SUCCESS.to_bytes(1, byteorder='big')

        self._logger.info('SSH Agent has been unlocked')
        return SSH_AGENT_FAILURE.to_bytes(1, byteorder='big')

    def _unix_connection_proc(self, connection):
        while True:
            try:
                length_bytes = connection.recv(4)
                if len(length_bytes) != 4:
                    break
                length = int.from_bytes(length_bytes, byteorder='big')
                if length == 0:
                    break
                request = connection.recv(length)
                if len(request) != length:
                    break
                response = self._process_ssh_agent_request(request)
                connection.send(len(response).to_bytes(4, byteorder='big'))
                connection.send(response)
            except Exception as e:
                self._logger.error('SSH request process error: %s', e)
                payload = SSH_AGENT_FAILURE.to_bytes(1, byteorder='big')
                connection.send(len(payload).to_bytes(4, byteorder='big') + payload)
                break
        connection.close()

    def _windows_connection_proc(self, connection):
        import win32file
        import win32pipe
        while True:
            try:
                try:
                    _, length_bytes = win32file.ReadFile(connection, 4)
                    if len(length_bytes) != 4:
                        break
                    length = int.from_bytes(length_bytes, byteorder='big')
                    if length == 0:
                        break
                    _, request = win32file.ReadFile(connection, length)
                    if len(request) != length:
                        break

                    response = self._process_ssh_agent_request(request)
                    win32file.WriteFile(connection, len(response).to_bytes(4, byteorder='big'))
                    win32file.WriteFile(connection, response)
                except win32file.error as we:
                    if we.winerror != 109:
                        self._logger.error('SSH request process error: %s', we)
                    break
            except Exception as e:
                self._logger.error('SSH request process error: %s', e)
                payload = SSH_AGENT_FAILURE.to_bytes(1, byteorder='big')
                win32file.WriteFile(connection, len(payload).to_bytes(4, byteorder='big'))
                win32file.WriteFile(connection, payload)
                win32file.FlushFileBuffers(connection)
                break
        win32file.FlushFileBuffers(connection)
        win32pipe.DisconnectNamedPipe(connection)
        win32file.CloseHandle(connection)

    def _unix_server_proc(self, username):
        path = os.path.expanduser('~')
        path = os.path.join(path, '.keeper')
        if not os.path.isdir(path):
            os.mkdir(path)
        self.path = os.path.join(path, f'{username or "commander"}.ssh_agent')
        if os.path.exists(self.path):
            os.remove(self.path)

        logging.info('SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;', self.path)

        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        while True:
            if not self._server:
                break
            self._server.listen(1)
            if not self._server:
                break
            conn, _ = self._server.accept()
            if not self._server:
                break
            threading.Thread(daemon=True, target=self._unix_connection_proc, args=(conn,)).start()

    def _windows_server_proc(self):
        import win32pipe
        self.path = r'\\.\pipe\openssh-ssh-agent'

        while True:
            self._server = win32pipe.CreateNamedPipe(
                self.path, win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, None)
            try:
                win32pipe.ConnectNamedPipe(self._server, None)
                if self._server:
                    threading.Thread(daemon=True, target=self._windows_connection_proc, args=(self._server,)).start()
                else:
                    break
            except Exception as e:
                self._logger.warning('SSH Agent connect named pipe error: %s', e)
                break

    def _server_proc(self, username=None):    # type: (Optional[str]) -> None
        try:
            if os.name == 'posix':
                self._unix_server_proc(username)
            elif os.name == 'nt':
                try:
                    import win32pipe
                    self._windows_server_proc()
                except ModuleNotFoundError as me:
                    pywin32_description = "SSH Agent requires Windows integration module to be installed.\n" +\
                                          "To install:\n\npip install pywin32"
                    logging.warning(pywin32_description)
            else:
                logging.warning('SSH Agent Connect: Unsupported platform')
        except Exception as e:
            self._logger.warning('SSH Agent error: %s', e)

    def start(self, username=None):
        if self.is_running:
            logging.info('ssh-agent already started')
            return

        self._thread = threading.Thread(target=self._server_proc, args=(username,), daemon=True)
        self._thread.start()
        time.sleep(1)
        if self.is_running:
            logging.info('ssh-agent has been started')

    def stop(self):
        if not self.is_running:
            logging.info('ssh-agent is not running')
            return
        try:
            self._server = None
            thread = self._thread
            self._thread = None
            with ConnectSshAgent(self.path):
                pass
            if thread:
                thread.join(1)
            logging.info('ssh-agent has been stopped')
        except Exception as e:
            logging.info('ssh-agent stop error: %s', e)

    def load_private_keys(self, params):    # type: (KeeperParams) -> None
        for record_uid in params.record_cache:
            record = vault.KeeperRecord.load(params, record_uid)
            if isinstance(record, vault.TypedRecord):
                key_field = record.get_typed_field('keyPair')
                if not key_field:
                    continue
                key_pair = key_field.get_default_value(value_type=dict)
                if not key_pair:
                    continue
                private_key = key_pair.get('privateKey')
                if not private_key:
                    continue
                passphrase = None
                password_field = record.get_typed_field('password', label='passphrase')
                if password_field:
                    passphrase = password_field.get_default_value(str)
                try:
                    private_key = load_private_key(private_key, passphrase)
                    key = SshAgentKey()
                    key.private_key = private_key
                    key.comment = record.title
                    key.record_uid = record.record_uid
                    if isinstance(private_key, rsa.RSAPrivateKey):
                        key.key_type = 'ssh-rsa'
                        public_numbers = private_key.public_key().public_numbers()
                        key_blob = ssh_agent_encode_str(key.key_type)
                        key_blob += ssh_agent_encode_long(public_numbers.e)
                        key_blob += ssh_agent_encode_long(public_numbers.n)
                        key.key_blob = key_blob
                        self._logger.info('Record \"%s\" [%s]. RSA key loaded', record.title, record.record_uid)
                        self.keys.append(key)

                    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                        curve_name = 'nistp381' if private_key.curve.name == 'secp384r1' else \
                            'nistp521' if private_key.curve.name == 'secp521r1' else \
                                'nistp256' if private_key.curve.name == 'secp256r1' else ''
                        if not curve_name:
                            raise ValueError(f'EC curve is not supported {private_key.curve.name}')
                        key.key_type = f'ecdsa-sha2-{curve_name}'
                        public_key_bytes = private_key.public_key().public_bytes(
                            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
                        key_blob = ssh_agent_encode_str(key.key_type)
                        key_blob += ssh_agent_encode_str(curve_name)
                        key_blob += ssh_agent_encode_bytes(public_key_bytes)
                        key.key_blob = key_blob
                        self._logger.info('Record \"%s\" [%s]. EC key loaded', record.title, record.record_uid)
                        self.keys.append(key)

                    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                        key.key_type = 'ssh-ed25519'
                        public_key_bytes = private_key.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                        key_blob = ssh_agent_encode_str(key.key_type)
                        key_blob += ssh_agent_encode_bytes(public_key_bytes)
                        key.key_blob = key_blob
                        self._logger.info('Record \"%s\" [%s]. ED25519 key loaded', record.title, record.record_uid)
                        self.keys.append(key)

                    else:
                        self._logger.warning('Record \"%s\" [%s]. Not supported private key', record.title, record.record_uid)

                except Exception as e:
                    self._logger.error('Record \"%s\" [%s]. Load private key error: %s', record.title, record.record_uid, e)


class SshAgentCommand(GroupCommand):
    def __init__(self):
        super(SshAgentCommand, self).__init__()
        self.register_command('info', SshAgentInfoCommand())
        self.register_command('start', SshAgentStartCommand())
        self.register_command('stop', SshAgentStopCommand())
        self.register_command('log', SshAgentLogCommand())
        self.default_verb = 'info'


class SshAgentInfoCommand(Command):
    def get_parser(self):
        return ssh_agent_info_parser

    def execute(self, params, **kwargs):
        if isinstance(params.ssh_agent, SshAgentContext):
            print('{0:>20s}: {1}'.format('Status', 'Running' if params.ssh_agent.is_running else 'Stopped'))
            if params.ssh_agent.is_running:
                print('{0:>20s}: {1}'.format('Loaded Keys', len(params.ssh_agent.keys)))
            print(f'\nSSH_AUTH_SOCK={params.ssh_agent.path}; export SSH_AUTH_SOCK;')
        else:
            print('{0:>20s}: {1}'.format('Status', 'Stopped'))


class SshAgentStartCommand(Command):
    def get_parser(self):
        return ssh_agent_start_parser

    def execute(self, params, **kwargs):
        if params.ssh_agent is None:
            params.ssh_agent = SshAgentContext()
        params.ssh_agent.keys = [x for x in params.ssh_agent.keys if x.record_uid]
        params.ssh_agent.load_private_keys(params)
        params.ssh_agent.start(params.user)


class SshAgentStopCommand(Command):
    def get_parser(self):
        return ssh_agent_stop_parser

    def execute(self, params, **kwargs):
        if isinstance(params.ssh_agent, SshAgentContext):
            params.ssh_agent.stop()
            params.ssh_agent = None


class SshAgentLogCommand(Command):
    def get_parser(self):
        return ssh_agent_log_parser

    def execute(self, params, **kwargs):
        if not isinstance(params.ssh_agent, SshAgentContext):
            pass
        table = []
        headers = ['Time', 'Level', 'Message']
        for record in params.ssh_agent.log_messages:
            if record.levelno <= logging.DEBUG:
                severity = 'DEBUG'
            elif record.levelno <= logging.INFO:
                severity = 'INFO'
            elif record.levelno <= logging.WARNING:
                severity = 'WARN'
            else:
                severity = 'ERROR'
            message = record.msg % record.args
            table.append([datetime.datetime.fromtimestamp(int(record.created)), severity, message])

        return dump_report_data(table, headers=headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))