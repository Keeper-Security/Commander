# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2016 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import subprocess
import tempfile
import logging
import os
import stat

from ..commands import update_custom_text_fields
from ..plugin_manager import get_custom_field_attr


class Rotator:
    def __init__(self, login=None, password=None, private_key=None, ssh_public_key=None, port=22, **kwargs):
        self.port = port
        self.login = login
        self.password = password
        self.private_key = private_key
        self.ssh_public_key = ssh_public_key

    def rotate(self, record, new_password):
        """Change a password over SSH"""
        return rotate_sshkey(
            record, new_password, self.port, self.login, self.password, self.private_key, self.ssh_public_key
        )


def rotate_sshkey(record, new_password, port=22, user=None, old_password=None, old_private_key=None,
                  ssh_public_key=None):
    key_file_name = None
    if old_private_key:
        breakpoint()
        pipe = subprocess.Popen(
            ['openssl', 'rsa', '-passin', f'pass:{old_password}'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        (output1, _) = pipe.communicate(input=old_private_key.encode(), timeout=3)
        if pipe.poll() == 0:
            key_file_name = tempfile.mktemp()
            key_file = os.open(key_file_name, os.O_WRONLY | os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR)
            os.write(key_file, output1)
            os.close(key_file)

    try:
        pipe = subprocess.Popen(['openssl', 'genrsa', '-aes128', '-passout', f'pass:{new_password}', '2048'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output1, _) = pipe.communicate(timeout=3)
        new_private_key = output1.decode('utf-8')

        pipe = subprocess.Popen(['openssl', 'rsa', '-passin', f'pass:{new_password}', '-pubout'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        (output2, _) = pipe.communicate(input=output1, timeout=3)
        new_public_key_PEM = output2.decode('utf-8')
        new_public_key_SSH = None
        with tempfile.NamedTemporaryFile() as rsa_public:
            rsa_public.write(output2)
            rsa_public.flush()
            pipe = subprocess.Popen(['ssh-keygen', '-i', '-f', rsa_public.name, '-mPKCS8'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            (output3, _) = pipe.communicate(input=output1, timeout=3)
            new_public_key_SSH = output3.decode('utf-8')

        fld_attr = get_custom_field_attr(record)
        hosts = [
            next((v for v in f.value), None) if isinstance(f.value, list) else f.value
            for f in record.custom if getattr(f, fld_attr) == 'cmdr:host'
        ]

        if key_file_name:
            old_public_key = ssh_public_key

            for host in hosts:
                get_keys_cmd = [
                    'ssh', '-i', key_file_name, '-o', 'StrictHostKeyChecking=no', '-p', str(port), f'{user}@{host}',
                    'cat .ssh/authorized_keys'
                ]
                try:
                    child = subprocess.Popen(
                        get_keys_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    (out_child, error_child) = child.communicate(timeout=10)
                    if child.poll() == 0:
                        keys = out_child.decode().splitlines()
                        keys = [l for l in keys if len(l) > 0]
                        keys = [l for l in keys if l != old_public_key]
                        keys.append(new_public_key_SSH)
                        new_authorized_keys = '\n'.join(keys)

                        update_keys_cmd = [
                            'ssh', '-i', key_file_name, '-o', 'StrictHostKeyChecking=no', f'{user}@{host}',
                            f"echo '{new_authorized_keys}' > .ssh/authorized_keys"
                        ]
                        child = subprocess.Popen(
                            update_keys_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                        )
                        (out_child, error_child) = child.communicate(timeout=10)

                    if error_child:
                        print(f'Host: {host}: Warning: {error_child.decode()}')

                except Exception as e:
                    print(f'Authorized Keys upload to host: {host}: {e}')

        update_custom_text_fields(record, {
            'cmdr:private_key': new_private_key,
            'cmdr:rsa_public_key': new_public_key_PEM,
            'cmdr:ssh_public_key': new_public_key_SSH,
        })
        return True

    except Exception as e:
        logging.error(e)
        return False

    finally:
        if key_file_name:
            os.remove(key_file_name)
