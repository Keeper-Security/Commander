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

"""Change a *ix ssh key over ssh."""

import subprocess
import tempfile
import logging
import os
import stat


def rotate(record, newpassword):
    """Change a *ix ssh key over ssh."""
    old_private_key = record.get('cmdr:private_key')
    key_file_name = None
    # FIXME: I believe these pass:'s on shell commands are briefly visible in Linux/macOS' ps -ef; it's probably a security hole.
    # openssl does appear to be rewriting its argv, but that is probably just shrinking the window, not eliminating it.
    # https://www.openssl.org/docs/man1.0.2/man1/openssl.html#PASS-PHRASE-ARGUMENTS
    if old_private_key:
        pipe = subprocess.Popen(['openssl', 'rsa', '-passin', 'pass:{0}'.format(record.password)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output1, _) = pipe.communicate(input=old_private_key.encode(), timeout=3)
        if pipe.poll() == 0:
            key_file_name = tempfile.mktemp()
            keyFile = os.open(key_file_name, os.O_WRONLY | os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR)
            os.write(keyFile, output1)
            os.close(keyFile)
        # We intentionally do not fail on bad openssl rsa -passin.  The code below copes with this condition.

    try:
        # The openssl command unfortunately fails to return a nonzero return code on private key creation failure.  :(
        pipe = subprocess.Popen(['openssl', 'genrsa', '-aes128', '-passout', 'pass:{0}'.format(newpassword), '2048'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        (output1, error1) = pipe.communicate(timeout=3)
        returncode1 = pipe.poll()
        if returncode1 != 0:
            print('Obtaining new private key using openssl failed with return code {0}: {1}'.format(returncode1, error1))
            return False
        new_private_key = output1.decode('utf-8')

        # Here too: the openssl does not exit shell-false on an obvious error :(
        pipe = subprocess.Popen(["openssl", "rsa", "-passin", "pass:{0}".format(newpassword), "-pubout"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        (output2, error2) = pipe.communicate(input=output1, timeout=3)
        returncode2 = pipe.poll()
        if returncode2 != 0:
            print('Obtaining new public key pem using openssl failed with return code {0}: {1}'.format(returncode2, error2))
            return False
        new_public_key_PEM = output2.decode('utf-8')
        new_public_key_SSH = None
        with tempfile.NamedTemporaryFile() as rsa_public:
            rsa_public.write(output2)
            rsa_public.flush()
            gen_key_cmd = ['ssh-keygen', '-i', '-f', rsa_public.name, '-mPKCS8']
            pipe = subprocess.Popen(gen_key_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            (output3, error3) = pipe.communicate(input=output1, timeout=3)
            returncode3 = pipe.poll()
            if returncode3 != 0:
                print('Obtaining new public key using ssh-keygen failed with return code {0}: {1}'.format(returncode3, error3))
                return False
            new_public_key_SSH = output3.decode('utf-8')

        hosts = [cf['value'] for cf in record.custom_fields if cf['name'] == 'cmdr:host']

        if key_file_name:
            oldPublicKey = record.get('cmdr:ssh_public_key')

            optional_port = record.get('cmdr:port')
            if not optional_port:
                port = 22
            else:
                try:
                    port = int(optional_port)
                except ValueError:
                    print('port {} could not be converted to int'.format(optional_port))
                    return False

            base_cmd_list = [
                'ssh',
                '-i', key_file_name,
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile /dev/null',
                '-p', str(port),
            ]
            # FIXME: This should be reduced back down to 10 when done debugging.
            timeouts = 60
            for host in hosts:
                cat_keys_cmd = base_cmd_list[:]
                cat_keys_cmd.append('{0}@{1}'.format(record.login, host))
                cat_keys_cmd.append('cat .ssh/authorized_keys')
                try:
                    cat_child = subprocess.Popen(
                        cat_keys_cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    (cat_out_child, cat_error_child) = cat_child.communicate(timeout=timeouts)
                    cat_returncode = cat_child.poll()
                    if cat_returncode == 0:
                        keys = cat_out_child.decode().splitlines()
                        keys = [key for key in keys if len(key) > 0]
                        keys = [key for key in keys if key != oldPublicKey]
                        keys.append(new_public_key_SSH)

                        write_keys_cmd = base_cmd_list[:]
                        write_keys_cmd.append('{0}@{1}'.format(record.login, host))
                        write_keys_cmd.append("echo '{0}' > .ssh/authorized_keys".format('\n'.join(keys)))
                        write_child = subprocess.Popen(
                            write_keys_cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        (_, write_error_child) = write_child.communicate(timeout=timeouts)
                        write_returncode = write_child.poll()
                        if write_returncode != 0:
                            print('Host: {0}: {1} failed with return code {2}: {3}'.format(
                                host,
                                write_keys_cmd,
                                write_returncode,
                                write_error_child,
                            ))
                            return False
                    else:
                        print('Host: {0}: {1} failed with return code {2}: {3}'.format(
                            host,
                            cat_keys_cmd,
                            cat_returncode,
                            cat_error_child.decode(),
                        ))
                        return False

                except Exception as e:
                    print('Authorized Keys upload to host: {0}: {1}'.format(host, e))
                    return False

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
