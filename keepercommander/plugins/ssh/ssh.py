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
import socket

import paramiko
from paramiko_expect import SSHClientInteraction

from ..windows.windows import DISALLOW_WINDOWS_SPECIAL_CHARACTERS


class Rotator:
    def __init__(self, host, login, password, port=22, **kwargs):
        self.host = host
        self.login = login
        self.password = password
        self.port = port
        # These characters don't work for Windows ssh password rotation
        self.disallow_special_characters = DISALLOW_WINDOWS_SPECIAL_CHARACTERS

    def rotate(self, record, new_password):
        """Change a password over SSH"""
        return rotate_ssh(self.host, self.port, self.login, self.password, new_password)

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        logging.info(
            f'Rotating with SSH plugin on host "{self.host}" and port "{self.port}" using login "{self.login}"...'
        )

    def revert(self, record, new_password):
        """Revert password change over SSH"""
        return rotate_ssh(self.host, self.port, self.login, new_password, self.password, revert=True)


def rotate_ssh(host, port, user, old_password, new_password, timeout=5, revert=False):
    """Rotate an SSH password

    host(str): SSH host
    port(int): SSH port
    user(str): SSH login name
    old_password(str): old password
    new_password(str): new password
    timeout(int): SSH connection timeout in seconds
    revert(bool): True if the new_password is the original password to revert a previous rotation.
                  This is used to print log messages that make more sense.
    """
    rotate_success = False
    ssh_logger = logging.getLogger('paramiko')
    ssh_logger.setLevel(logging.WARNING)
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=host, port=port, username=user, password=old_password,
                timeout=timeout, allow_agent=False, look_for_keys=False
            )
        except paramiko.ssh_exception.AuthenticationException:
            if revert:
                logging.error('SSH authentication was unsuccessful for revert of rotation.')
            else:
                logging.error('SSH authentication was unsuccessful using current password.')
            return False
        except socket.timeout:
            logging.error('Connection to host timed out.')
            return False
        except Exception as e:
            logging.error(f'Unrecognized connection error: {e}')
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
                    logging.debug(result)
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
                    rotate_msg = 'revert of rotation.' if revert else f'rotation.'
                    success_msg = f'{"successful" if rotate_success else "failed"} {rotate_msg}'
                    logging.warning(f"Can't connect with either old or new password after {success_msg}")
                    rotate_success = False
            else:
                if pass_name == 'old':
                    if revert:
                        logging.warning('Reverting the password rotation failed. The rotated password is still valid.')
                    else:
                        logging.warning('SSH password rotation failed. Verified that the old password is still valid.')
                    rotate_success = False
                else:
                    if revert:
                        logging.info('Verified that reverting the SSH password rotation was successful.')
                    else:
                        logging.info('Verified that the SSH password rotation was successful.')
                    rotate_success = True
                break

    return rotate_success
