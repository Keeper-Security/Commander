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


def rotate(record, newpassword):
    old_private_key = record.get('cmdr:private_key')
    key_file_name = None
    if old_private_key:
        pipe = subprocess.Popen(['openssl', 'rsa', '-passin', 'pass:{0}'.format(record.password)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output1, _) = pipe.communicate(input=old_private_key.encode(), timeout=3)
        if pipe.poll() == 0:
            key_file_name = tempfile.mktemp()
            keyFile = os.open(key_file_name, os.O_WRONLY | os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR)
            os.write(keyFile, output1)
            os.close(keyFile)

    try:
        pipe = subprocess.Popen(['openssl', 'genrsa', '-aes128', '-passout', 'pass:{0}'.format(newpassword), '2048'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output1, _) = pipe.communicate(timeout=3)
        new_private_key = output1.decode('utf-8')

        pipe = subprocess.Popen(["openssl", "rsa", "-passin", "pass:{0}".format(newpassword), "-pubout"],
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

        hosts = [cf['value'] for cf in record.custom_fields if cf['name'] == 'cmdr:host']

        if key_file_name:
            oldPublicKey = record.get('cmdr:ssh_public_key')
            for host in hosts:
                try:
                    child = subprocess.Popen(['ssh', '-i', key_file_name, '-o', 'StrictHostKeyChecking=no', '{0}@{1}'.format(record.login, host), 'cat .ssh/authorized_keys'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (out_child, error_child) = child.communicate(timeout=10)
                    if child.poll() == 0:
                        keys = out_child.decode().splitlines()
                        keys = [l for l in keys if len(l) > 0]
                        keys = [l for l in keys if l != oldPublicKey]
                        keys.append(new_public_key_SSH)

                        child = subprocess.Popen(['ssh', '-i', key_file_name, '-o', 'StrictHostKeyChecking=no', '{0}@{1}'.format(record.login, host), 'echo \'{0}\' > .ssh/authorized_keys'.format('\n'.join(keys))], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        (out_child, error_child) = child.communicate(timeout=10)

                    if error_child:
                        print('Host: {0}: Warning: {1}'.format(host, error_child.decode()))

                except Exception as e:
                    print('Authorized Keys upload to host: {0}: {1}'.format(host, e))

        record.set_field('cmdr:private_key', new_private_key)
        record.set_field('cmdr:rsa_public_key', new_public_key_PEM)
        record.set_field('cmdr:ssh_public_key', new_public_key_SSH)
        record.password = newpassword

        return True

    except Exception as e:
        logging.error(e)
        return False

    finally:
        if key_file_name:
            os.remove(key_file_name)

