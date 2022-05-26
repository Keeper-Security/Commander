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

"""Change a password over ssh."""


import logging
import paramiko
from paramiko_expect import SSHClientInteraction


# These characters don't work for Windows ssh password rotation
DISALLOW_SPECIAL_CHARACTERS = '<>^'


class Rotator:
    def __init__(self, host, login, password, port=22, **kwargs):
        self.host = host
        self.login = login
        self.password = password
        self.port = port
        self.disallow_special_characters = DISALLOW_SPECIAL_CHARACTERS

    def rotate(self, record, new_password):
        """Change a password over ssh"""
        return rotate_ssh(self.host, self.port, self.login, self.password, new_password)

    def revert(self, record, new_password):
        """Revert password change over ssh"""
        return rotate_ssh(self.host, self.port, self.login, new_password, self.password)


def rotate_ssh(host, port, user, old_password, new_password, timeout=5):
    rotate_success = False
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=host, port=port, username=user, password=old_password,
                timeout=timeout, allow_agent=False, look_for_keys=False
            )
        except paramiko.ssh_exception.AuthenticationException:
            logging.error(
                f"Can't SSH authenticate to host {host} on port {port} with user {user} and password in record."
            )
            return False
        stdin, stdout, stderr = ssh.exec_command('ver')
        if ''.join(stdout.readlines()).strip().startswith('Microsoft Windows'):
            try:
                stdin, stdout, stderr = ssh.exec_command(
                    f'net user {user} {new_password}'
                )
                result = ''.join(stdout.readlines()).strip()
                if result == 'The command completed successfully.':
                    rotate_success = True
                    logging.info(result)
                else:
                    logging.warning(f'Unrecognized result: "{result}"')
            except Exception as e:
                # Catch exception because password
                # could have still been rotated and we need to verify
                logging.error(str(e))
        else:
            stdin, stdout, stderr = ssh.exec_command('which passwd')
            passwd_cmd = ''.join(stdout.readlines()).strip()
            if not passwd_cmd.endswith('passwd'):
                logging.warning('"passwd" command not found on device')
                return False
            else:
                with SSHClientInteraction(ssh, timeout=timeout, display=False) as ia:
                    ia.send('passwd')
                    ia.expect(['.*password.*', '.*password.*'])
                    ia.send(old_password)
                    ia.expect('.*password.*')
                    ia.send(new_password)
                    ia.expect('.*password.*')
                    try:
                        ia.send(new_password)
                        ia.expect('.*')
                        result1 = ia.current_output
                        ia.send('')
                        ia.expect('.*')
                        result2 = ia.current_output
                        result_lines = (result1 + result2).splitlines()
                        result = next(
                            (r for r in result_lines if 'password' in r), ''
                        )
                        if 'password' in result:
                            rotate_success = True
                            logging.info(result.split(': ')[-1])
                    except Exception as e:
                        # Catch exception because password
                        # could have still been rotated and we need to verify
                        logging.error(str(e))

    # Verify which password connects to host
    with paramiko.SSHClient() as verify_ssh:
        passwords = {'old': old_password, 'new': new_password}
        pass_names = ('new', 'old') if rotate_success else ('old', 'new')
        for attempt, pass_name in enumerate(pass_names, start=1):
            verify_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                verify_ssh.connect(
                    hostname=host, username=user, password=passwords[pass_name],
                    timeout=timeout, allow_agent=False, look_for_keys=False
                )
            except Exception as e:
                if attempt == 2:
                    success_msg = f'{"successful" if rotate_success else "failed"} SSH password rotation'
                    logging.warning(f"Can't connect with either old or new password after {success_msg}")
                    logging.warning(f'Attempted new password: {passwords["new"]}')
                    rotate_success = False
            else:
                if pass_name == 'old':
                    logging.warning('SSH password rotation failed. Verified that old password is still valid.')
                else:
                    logging.info('Verified that SSH password rotation was successful.')
                    rotate_success = True
                break

    return rotate_success
