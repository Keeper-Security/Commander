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

import logging
import os
import stat
import subprocess
import tempfile

import itertools
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from ... import crypto, vault
from ...commands.base import RecordMixin
from ...commands.ssh_agent import load_private_key


def rotate(record, new_password):   # type: (vault.KeeperRecord, str) -> bool
    private_key = ''
    if isinstance(record, vault.PasswordRecord):
        cf = next((x for x in record.custom if x.name == 'cmdr:private_key'), None)
        if cf:
            private_key = cf.value
    elif isinstance(record, vault.TypedRecord):
        ssh_key_field = record.get_typed_field('keyPair')
        if ssh_key_field:
            key_value = ssh_key_field.get_default_value(dict)
            if isinstance(key_value, dict):
                private_key = key_value.get('privateKey', '')
        else:
            cf = next((x for x in record.custom if x.label == 'cmdr:private_key'), None)
            if cf:
                value = cf.get_default_value(str)
                if value:
                    private_key = value

    old_password = RecordMixin.get_record_field(record, 'password')

    old_pk = None
    backend = default_backend()
    ssh_key_format = serialization.PrivateFormat.TraditionalOpenSSL
    if private_key:
        header, _, _ = private_key.partition('\n')
        if 'BEGIN OPENSSH PRIVATE KEY' in header:
            ssh_key_format = serialization.PrivateFormat.OpenSSH
        try:
            old_pk = load_private_key(private_key, old_password)
            if isinstance(old_pk, rsa.RSAPrivateKey):
                pub_key_exponent = old_pk.public_key().public_numbers().e
                new_pk = rsa.generate_private_key(
                    key_size=old_pk.key_size, public_exponent=pub_key_exponent, backend=backend)
            elif isinstance(old_pk, ec.EllipticCurvePrivateKey):
                new_pk = ec.generate_private_key(old_pk.curve, backend=backend)
            elif isinstance(old_pk, ed25519.Ed25519PrivateKey):
                new_pk = ed25519.Ed25519PrivateKey.generate()
                ssh_key_format = serialization.PrivateFormat.OpenSSH
            else:
                raise Exception('Unsupported private key type')
        except Exception as e:
            logging.info('SSH Key rotation plugin: load key error: %s', e)
            return False
    else:
        new_pk, _ = crypto.generate_rsa_key()

    new_private_key = new_pk.private_bytes(
        encoding=serialization.Encoding.PEM, format=ssh_key_format,
        encryption_algorithm=serialization.BestAvailableEncryption(new_password.encode('utf-8'))).decode()

    new_public_ssh_key = new_pk.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH).decode()

    optional_port = RecordMixin.get_custom_field(record, 'cmdr:port')
    if optional_port:
        try:
            port = int(optional_port)
        except ValueError:
            logging.info('SSH key plugin: port %s could not be converted to int', optional_port)
            return False
    else:
        port = None

    hosts = []
    if isinstance(record, vault.PasswordRecord):
        hosts.extend((x.value for x in record.custom if x.name == 'cmdr:host' and x.value))
    elif isinstance(record, vault.TypedRecord):
        for host_field in itertools.chain(record.fields, record.custom):
            if host_field.type == 'host':
                host_value = host_field.get_default_value(dict)
                if isinstance(host_value, dict):
                    if 'hostName' in host_value:
                        hostname = host_value['hostName']
                        if hostname:
                            hostport = host_value.get('port')
                            if hostport:
                                hostname = f'{hostname}:{hostport}'
                            hosts.append(hostname)
            elif host_field.type == 'text' and host_field.label == 'cmdr:host':
                hostname = host_field.get_default_value(str)
                if hostname:
                    hosts.append(hostname)

    login = RecordMixin.get_record_field(record, 'login')
    if len(hosts) > 0 and old_pk and login:
        old_public_ssh_key = old_pk.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH).decode()

        key_unencrypted = old_pk.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption())
        key_file_name = tempfile.mktemp()
        keyFile = os.open(key_file_name, os.O_WRONLY | os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR)
        os.write(keyFile, key_unencrypted)
        os.close(keyFile)

        try:
            for host in hosts:
                try:
                    host, _, dst_port = host.partition(':')
                    if not dst_port and port:
                        dst_port = str(port)

                    ssh_command = ['ssh', '-i', key_file_name, '-o', 'StrictHostKeyChecking=no']
                    if dst_port:
                        ssh_command.extend(('-p', dst_port))
                    ssh_command.append(f'{login}@{host}')

                    get_ssh_keys = list(ssh_command)
                    get_ssh_keys.append('cat .ssh/authorized_keys')
                    child = subprocess.Popen(get_ssh_keys, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (out_child, error_child) = child.communicate(timeout=10)
                    if child.poll() == 0:
                        keys = out_child.decode().splitlines()
                        keys = [x.replace('\'', '') for x in keys if len(x) > 0 and x != old_public_ssh_key]
                        keys.append(new_public_ssh_key)

                        set_ssh_keys = list(ssh_command)
                        set_ssh_keys.append('echo \'{0}\' > .ssh/authorized_keys'.format('\n'.join(keys)))
                        child = subprocess.Popen(set_ssh_keys, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        (out_child, error_child) = child.communicate(timeout=10)

                    if error_child:
                        logging.warning('Host: %s: Warning: %s', host, error_child.decode())

                except Exception as e:
                    logging.warning('Authorized Keys upload to host: %s: %s', host, str(e))
                    return False
        finally:
            os.remove(key_file_name)

    if isinstance(record, vault.PasswordRecord):
        for cf in record.custom:
            if cf.name == 'cmdr:private_key':
                cf.value = new_private_key
                new_private_key = ''
            elif cf.name == 'cmdr:ssh_public_key':
                cf.value = new_public_ssh_key
                new_public_ssh_key = ''
            elif cf.name == 'cmdr:rsa_public_key':
                cf.value = ''
                if isinstance(new_pk, rsa.RSAPrivateKey):
                    cf.value = new_pk.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1).decode()
        if new_private_key:
            record.custom.append(vault.CustomField.new_field('cmdr:private_key', new_private_key))
        if new_public_ssh_key:
            record.custom.append(vault.CustomField.new_field('cmdr:ssh_public_key', new_public_ssh_key))
    elif isinstance(record, vault.TypedRecord):
        ssh_key_field = record.get_typed_field('keyPair')
        if ssh_key_field:
            ssh_key_field.value = [{
                'privateKey': new_private_key,
                'publicKey': new_public_ssh_key
            }]
            new_private_key = ''
        else:
            for cf in record.custom:
                if cf.label == 'cmdr:private_key':
                    cf.value = new_private_key
                    new_private_key = ''
                elif cf.label == 'cmdr:ssh_public_key':
                    cf.value = new_public_ssh_key
        if new_private_key:
            kpf = vault.TypedField()
            kpf.type = 'keyPair'
            kpf.value = [{
                'privateKey': new_private_key,
                'publicKey': new_public_ssh_key
            }]

    return True
