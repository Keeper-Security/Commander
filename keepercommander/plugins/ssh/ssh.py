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

"""Change a *ix password over ssh."""


import logging
import os

if os.name == 'posix':
    from pexpect import pxssh, exceptions
else:
    raise Exception('Not available on Windows')

"""Commander Plugin for SSH Command
   Dependencies: s
       pip3 install pexpect
"""


class KeychainFailure(Exception):
    """An exception to raise when Keychain password update fails."""

    pass


def rotate(record, newpassword):
    """
    Change a *ix password over ssh.

    We're pretty platform-agnostic - just need a passwd command.  But pxssh is not.  pxssh wants a sh/ksh/bash/csh/tcsh.  zsh
    (macOS' default shell) doesn't work.  And routers are unlikely to work too, even if they support ssh, especially
    ones with dynamic prompts.

    Grab any required fields from the record.
    """
    user = record.login
    oldpassword = record.password

    port = 22
    if hasattr(record, 'port'):
        port = int(record.port)

    result = False

    host = record.get('cmdr:host')

    try:
        options = {
            'StrictHostKeyChecking': 'no',
            'UserKnownHostsFile': '/dev/null',
        }
        s = pxssh.pxssh(options=options)
        print('Logging into {}@{} on port {}'.format(user, host, port))
        s.login(server=host, username=user, password=oldpassword, sync_multiplier=3, port=port)
        s.sendline('passwd')
        i = s.expect(['[Oo]ld.*[Pp]assword', '[Cc]urrent.*[Pp]assword', '[Nn]ew.*[Pp]assword'])
        if i in (0, 1):
            s.sendline(oldpassword)
            i = s.expect(['[Nn]ew.*[Pp]assword', 'password unchanged'])
            if i != 0:
                return False

        s.sendline(newpassword)
        s.expect("Retype [Nn]ew.*[Pp]assword:")
        s.sendline(newpassword)
        s.prompt()

        pass_result = str(s.before)

        if "success" in pass_result:
            logging.info("Password changed successfully")
            record.password = newpassword
            result = True
        elif 'This tool does not update the login keychain password' in pass_result:
            # This means we need to update keychain too. It's a macOS thing.
            s.sendline('security set-keychain-password')
            if s.expect('[Oo]ld [Pp]assword') != 0:
                raise KeychainFailure
            s.sendline(oldpassword)
            if s.expect('[Nn]ew [Pp]assword') != 0:
                raise KeychainFailure
            s.sendline(newpassword)
            if s.expect("Retype [Nn]ew.*[Pp]assword:") != 0:
                raise KeychainFailure
            s.sendline(newpassword)
            index = s.expect('A default keychain could not be found')
            if index == 0:
                # This seems like a failure, but really it's a success; if there's no keychain to update, then we don't
                # need to do anything further with keychain.
                logging.info("Password changed successfully; no Keychain found")
                record.password = newpassword
                result = True
            elif 1 == 2:
                # FIXME: We should deal with a successful Keychain update here.
                pass
            else:
                logging.error("Keychain change failed: {}".format(str(pass_result)))
        else:
            logging.error("Password change failed: {}".format(str(pass_result)))

        s.logout()
    except exceptions.TIMEOUT:
        logging.error("Timed out waiting for response.")
    except pxssh.ExceptionPxssh as e:
        logging.error("Failed to login with ssh: {}".format(str(e)))
    except KeychainFailure:
        logging.error("Keychain change failed: {}".format(str(pass_result)))

    return result
