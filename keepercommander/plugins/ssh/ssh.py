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

from keepercommander.plugins.commands import get_v2_or_v3_custom_field_value

if os.name == 'posix':
    from pexpect import pxssh, exceptions
else:
    raise Exception('Not available on Windows')


def rotate(record, newpassword):
    """
    Change a *ix password over ssh.

    We're pretty platform-agnostic - just need a passwd command.  But pxssh is not.  pxssh wants a sh/ksh/bash/csh/tcsh.  zsh
    (macOS' 11.* default shell) doesn't work.  And routers are unlikely to work too, even if they support ssh, especially
    ones with dynamic prompts.

    Grab any required fields from the record.
    """
    user = record.login
    oldpassword = record.password

    result = False

    optional_port = get_v2_or_v3_custom_field_value(record, 'cmdr:port')
    if not optional_port:
        port = 22
    else:
        try:
            port = int(optional_port)
        except ValueError:
            print('port {} could not be converted to int'.format(optional_port))
            return result

    host = get_v2_or_v3_custom_field_value(record, 'cmdr:host')

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

        pass_result = str(s.before).lower()

        if "success" in pass_result:
            logging.info("Password changed successfully")
            record.password = newpassword
            result = True
        elif 'this tool does not update the login keychain password' in pass_result.lower():
            # This is a macOS thing.  The passwd command warns about updating the keychain.  We pass a little of that
            # up to the user.
            logging.info("Password changed successfully")
            logging.info("Consider updating login keychain with: security set-keychain-password ~/Library/Keychains/login-db")
            record.password = newpassword
            result = True
        else:
            logging.error("Password change failed: {}".format(str(pass_result)))

        s.logout()
    except exceptions.TIMEOUT:
        logging.error("Timed out waiting for response.")
    except pxssh.ExceptionPxssh as e:
        logging.error("Failed to login with ssh: {}".format(str(e)))

    return result
