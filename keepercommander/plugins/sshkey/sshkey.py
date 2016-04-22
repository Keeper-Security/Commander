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


def rotate(record, newpassword):
    """
    @type record: Record
    @type newpassword: str
    """
    try:
        pipe = subprocess.Popen(['openssl', 'genrsa', '-aes128', '-passout', 'pass:{0}'.format(newpassword), '2048'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output1, _) = pipe.communicate(timeout=3)

        private_key = output1.decode()
        record.set_field('cmdr:private_key', private_key)

        try:  # extract public key
            pipe = subprocess.Popen(["openssl", "rsa", "-passin", "pass:{0}".format(newpassword), "-pubout"],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

            (output2, _) = pipe.communicate(input=output1, timeout=3)
            public_key = output2.decode()
            record.set_field('cmdr:rsa_public_key', public_key)

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
            ssh_key = ' '.join([prefix, base64.b64encode(ssh_key_bytes).decode()])
            record.set_field('cmdr:ssh_public_key', ssh_key)

        except Exception as e:
            print('Warning: {0}'.format(e))
            pass

        return True
    except Exception as e:
        print(e)
        return False
