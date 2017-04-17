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
import re
import struct
import base64
import tempfile
import os, stat

def rotate(record, newpassword):
    """
    @type record: Record
    @type newpassword: str
    """

    oldPrivateKey = record.get('cmdr:private_key')
    keyFileName = None
    if oldPrivateKey:
        pipe = subprocess.Popen(['openssl', 'rsa', '-passin', 'pass:{0}'.format(record.password)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output1, _) = pipe.communicate(input=oldPrivateKey.encode(), timeout=3)
        if pipe.poll() == 0:
            keyFileName = tempfile.mktemp()
            keyFile = os.open(keyFileName, os.O_WRONLY | os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR)
            os.write(keyFile, output1)
            os.close(keyFile)

    try:

        pipe = subprocess.Popen(['openssl', 'genrsa', '-aes128', '-passout', 'pass:{0}'.format(newpassword), '2048'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output1, _) = pipe.communicate(timeout=3)

        newPrivateKey = output1.decode()

        pipe = subprocess.Popen(["openssl", "rsa", "-passin", "pass:{0}".format(newpassword), "-pubout"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        (output2, _) = pipe.communicate(input=output1, timeout=3)
        newPublicKeyPEM = output2.decode()

        pipe = subprocess.Popen(['openssl', 'rsa', '-pubin', '-noout', '-text'], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output3, _) = pipe.communicate(input=output2, timeout=3)
        lines = output3.decode().split('\n')
        modulus_hex = ''.join([l.strip() for l in lines if l.startswith('   ')])
        mod = bytearray.fromhex(''.join(modulus_hex.split(sep=':')))

        exponent = [l for l in lines if l.startswith('Exponent:')].pop(0)
        m = re.search('Exponent:\s+(\d+)\s+\((.+)\).*', exponent)
        exp = struct.pack('>I', int(m.group(1)))

        prefix = 'ssh-rsa'
        parts = [prefix.encode('ascii'), exp, mod]
        ssh_key_bytes = b''.join([b''.join([struct.pack('>I', len(i)), i]) for i in parts])
        newPublicKeySSH = ' '.join([prefix, base64.urlsafe_b64encode(ssh_key_bytes).decode()])

        hosts = [cf['value'] for cf in record.custom_fields if cf['name'] == 'cmdr:host']

        if keyFileName:
            oldPublicKey = record.get('cmdr:ssh_public_key')
            for host in hosts:
                try:
                    child = subprocess.Popen(['ssh', '-i', keyFileName, '-o', 'StrictHostKeyChecking=no', '{0}@{1}'.format(record.login, host), 'cat .ssh/authorized_keys'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (out_child, error_child) = child.communicate(timeout=10)
                    if child.poll() == 0:
                        keys = out_child.decode().splitlines()
                        keys = [l for l in keys if len(l) > 0]
                        keys = [l for l in keys if l != oldPublicKey]
                        keys.append(newPublicKeySSH)

                        child = subprocess.Popen(['ssh', '-i', keyFileName, '-o', 'StrictHostKeyChecking=no', '{0}@{1}'.format(record.login, host), 'echo \'{0}\' > .ssh/authorized_keys'.format('\n'.join(keys))], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        (out_child, error_child) = child.communicate(timeout=10)

                    if error_child:
                        print('Host: {0}: Warning: {1}'.format(host, error_child.decode()))

                except Exception as e:
                    print('Authorized Keys upload to host: {0}: {1}'.format(host, e))

        record.set_field('cmdr:private_key', newPrivateKey)
        record.set_field('cmdr:rsa_public_key', newPublicKeyPEM)
        record.set_field('cmdr:ssh_public_key', newPublicKeySSH)
        record.password = newpassword

        return True

    except Exception as e:
        print(e)
        return False

    finally:
        if keyFileName:
            os.remove(keyFileName)

