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
import datetime
import io
import itertools
import logging
import os
import socket
import threading
import time
from typing import Optional, List, Callable, Tuple, Any, Union
from colorama import Fore, Style

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding, utils

from .base import GroupCommand, Command, dump_report_data, user_choice
from .. import vault, attachment
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
                logging.debug('Failed to delete added ssh key')
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
    try:
        if 'BEGIN OPENSSH PRIVATE KEY' in header:
            return serialization.load_ssh_private_key(private_key_pem.encode(), password=password)
        else:
            return serialization.load_pem_private_key(private_key_pem.encode(), password=password)
    except TypeError as e:
        try:
            if 'BEGIN OPENSSH PRIVATE KEY' in header:
                return serialization.load_ssh_private_key(private_key_pem.encode(), password=None)
            else:
                return serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        except:
            raise e


def is_private_key(header):   # type: (str) -> bool
    header = header.rstrip('\r\n')
    header = header.strip('-')
    if header.startswith('BEGIN') and header.endswith('PRIVATE KEY'):
        return True
    return False

Key_Prefix = ['id_']
Key_Suffix = ['.key', '.pem']
Key_Suffix_Exclude = ['.pub']
def is_private_key_name(name):     # type: (str) -> bool
    if not name:
        return False
    if isinstance(name, str):
        name = name.lower()
        if any(True for x in Key_Suffix_Exclude if name.endswith(x)):
            return False
        if any(True for x in Key_Suffix if name.endswith(x)):
            return True
        if any(True for x in Key_Prefix if name.startswith(x)):
            return True

    return False

KEY_SIZE_MIN = 119 # Smallest possible size for ed25519 private key in PKCS#8 format
KEY_SIZE_MAX = 4000
def is_valid_key_value(value):
    return isinstance(value, str) and KEY_SIZE_MIN <= len(value) < KEY_SIZE_MAX

def is_valid_key_file(file):
    try:
        return KEY_SIZE_MIN <= file.size < KEY_SIZE_MAX
    except:
        return False

def try_extract_private_key(params, record_or_uid):
    # type: (KeeperParams, Union[str, vault.KeeperRecord]) -> Optional[Tuple[str, str]]
    if isinstance(record_or_uid, vault.KeeperRecord):
        record = record_or_uid
    elif isinstance(record_or_uid, str):
        record = vault.KeeperRecord.load(params, record_or_uid)
        if not record:
            return
    else:
        return

    private_key = ''
    passphrase = ''

    # check keyPair field
    if isinstance(record, vault.TypedRecord):
        key_field = record.get_typed_field('keyPair')
        if key_field:
            key_pair = key_field.get_default_value(value_type=dict)
            if key_pair:
                private_key = key_pair.get('privateKey')

    # check notes field
    if not private_key:
        if isinstance(record, (vault.PasswordRecord, vault.TypedRecord)):
            if is_valid_key_value(record.notes):
                header, _, _ = record.notes.partition('\n')
                if is_private_key(header):
                    private_key = record.notes

    # check custom fields
    if not private_key:
        if isinstance(record, vault.TypedRecord):
            try_values = (x.get_default_value() for x in itertools.chain(record.fields, record.custom) if x.type in ('text', 'multiline', 'secret', 'note'))
            for value in (x for x in try_values if x):
                if is_valid_key_value(value):
                    header, _, _ = value.partition('\n')
                    if is_private_key(header):
                        private_key = value
                        break
        elif isinstance(record, vault.PasswordRecord):
            for value in (x.value for x in record.custom if x.value):
                if is_valid_key_value(value):
                    header, _, _ = value.partition('\n')
                    if is_private_key(header):
                        private_key = value
                        break

    # check for a single attachment
    if not private_key:
        download_rq = None
        if isinstance(record, vault.TypedRecord):
            file_refs = record.get_typed_field('fileRef')
            if file_refs and isinstance(file_refs.value, list):
                key_file_uids = []
                for file_uid in file_refs.value:
                    file_record = vault.KeeperRecord.load(params, file_uid)
                    if isinstance(file_record, vault.FileRecord):
                        names = [file_record.title]
                        if file_record.name and file_record.name != file_record.title:
                            names.append(file_record.name)
                        if any(True for x in names if is_private_key_name(x)):
                            if is_valid_key_file(file_record):
                                key_file_uids.append(file_uid)
                if len(key_file_uids) == 1:
                    download_rq = next(attachment.prepare_attachment_download(params, key_file_uids[0]), None)
        elif isinstance(record, vault.PasswordRecord):
            key_attachment_ids = []
            if record.attachments:
                for atta in record.attachments:
                    names = []
                    if atta.title:
                        names.append(atta.title)
                    if atta.name and atta.title != atta.name:
                        names.append(atta.name)
                    if any(True for x in names if is_private_key_name(x)):
                        if is_valid_key_file(atta):
                            key_attachment_ids.append(atta.id)
            if len(key_attachment_ids) == 1:
                download_rq = next(attachment.prepare_attachment_download(params, record.record_uid, key_attachment_ids[0]), None)
        if download_rq:
            try:
                with io.BytesIO() as b:
                    download_rq.download_to_stream(params, b)
                    text = b.getvalue().decode('ascii')
                    header, _, _ = text.partition('\n')
                    if is_private_key(header):
                        private_key = text
            except:
                pass

    if isinstance(record, vault.PasswordRecord):
        passphrase = record.password
    elif isinstance(record, vault.TypedRecord):
        password_field = record.get_typed_field('password')
        if password_field:
            passphrase = password_field.get_default_value(str)

    if private_key:
        return private_key, passphrase


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
        curve_name = 'nistp384' if private_key.curve.name == 'secp384r1' else \
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
                            hash_algorithm = hashes.SHA256()
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
        except Exception as e:
            logging.info('ssh-agent stop error: %s', e)

    def load_private_keys(self, params):    # type: (KeeperParams) -> None
        for record_uid in params.record_cache:
            key = try_extract_private_key(params, record_uid)
            if not key:
                continue

            record = vault.KeeperRecord.load(params, record_uid)
            private_key_pem, passphrase = key
            try:
                private_key = load_private_key(private_key_pem, passphrase)
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

                elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                    key.key_type = 'ssh-ed25519'
                    public_key_bytes = private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                    key_blob = ssh_agent_encode_str(key.key_type)
                    key_blob += ssh_agent_encode_bytes(public_key_bytes)
                    key.key_blob = key_blob

                else:
                    self._logger.warning('Record \"%s\" [%s]. Not supported private key', record.title, record.record_uid)
                    continue

                if any(True for x in self.keys if x.key_blob == key.key_blob):
                    self._logger.info('Record \"%s\" [%s]. Key already loaded', record.title, record.record_uid)
                else:
                    self._logger.info('Record \"%s\" [%s]. \"%s\" key loaded', record.title, record.record_uid, key.key_type)
                    self.keys.append(key)

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

    def is_authorised(self):
        return True


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

    def is_authorised(self):
        return True

    def execute(self, params, **kwargs):
        if params.ssh_agent is None:
            params.ssh_agent = SshAgentContext()
        params.ssh_agent.keys = [x for x in params.ssh_agent.keys if x.record_uid]
        print(Style.BRIGHT + 'Starting Commander in SSH Agent Mode...' + Style.RESET_ALL)
        print('Loading keys...')
        params.ssh_agent.load_private_keys(params)
        params.ssh_agent.start(params.user)
        print(f'Loaded {len(params.ssh_agent.keys)} private key(s)')
        print('\033[2K' + Fore.LIGHTGREEN_EX + 'SSH Agent Started.' + Style.RESET_ALL)
        if os.name == 'posix':
            print(Fore.CYAN)
            print('Note: To use the Commander SSH Agent, run the below command in your terminal or startup file:')
            print(f'export SSH_AUTH_SOCK={params.ssh_agent.path}')
            print(Style.RESET_ALL)
        if params.batch_mode:
            log_command = SshAgentLogCommand()
            help_printed = False
            while True:
                answer = user_choice('Commander SSH Agent', '?lq', show_choice=False)
                if not answer:
                    if not help_printed:
                        help_printed = True
                        answer = '?'
                    else:
                        continue

                if answer == '?':
                    print('{0:>12} : {1}'.format('?', 'Print this help'))
                    print('{0:>12} : {1}'.format('(l)og', 'SSH Agent agent logs'))
                    print('{0:>12} : {1}'.format('(q)uit', 'Quit'))
                elif answer.lower() in {'l', 'log'}:
                    log_command.execute(params)
                elif answer.lower() in {'q', 'quit'}:
                    params.ssh_agent.stop()
                    break
                else:
                    print(f'Command \"{answer}\" is not recognized')


class SshAgentStopCommand(Command):
    def get_parser(self):
        return ssh_agent_stop_parser

    def execute(self, params, **kwargs):
        if isinstance(params.ssh_agent, SshAgentContext):
            params.ssh_agent.stop()
            params.ssh_agent = None
            print('\033[2K' + Fore.LIGHTGREEN_EX + 'SSH Agent Stopped.' + Style.RESET_ALL)


class SshAgentLogCommand(Command):
    def get_parser(self):
        return ssh_agent_log_parser

    def execute(self, params, **kwargs):
        if not isinstance(params.ssh_agent, SshAgentContext):
            logging.warning('SSH Agent is not started')
            return
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