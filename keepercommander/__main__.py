# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


import re
import sys
import os
import argparse
import shlex
import json
import logging
import base64
from pathlib import Path

from . import __version__
from .params import KeeperParams

from . import cli


def get_params_from_config(config_filename):
    params = KeeperParams()

    if os.getenv("KEEPER_COMMANDER_DEBUG"):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info('Debug ON')

    opts, flags = parser.parse_known_args(sys.argv[1:])

    if os.getenv('KEEPER_CONFIG_FILE'):
        logging.debug("Setting config file from KEEPER_CONFIG_FILE env variable %s" % os.getenv('KEEPER_CONFIG_FILE'))
        params.config_filename = os.getenv('KEEPER_CONFIG_FILE')
    elif opts.launched_with_shortcut:
        current_user_home_path = str(Path.home())
        path_sep = os.path.sep

        # unix: /Users/username/.keeper/
        # win: C:\\Users\\username\\.keeper\\

        laucher_keeper_folder_path = current_user_home_path + path_sep + '.keeper'
        logging.debug("Launcher keeper folder: %s" % laucher_keeper_folder_path)

        Path(laucher_keeper_folder_path).mkdir(parents=True, exist_ok=True)

        params.config_filename = laucher_keeper_folder_path + path_sep + 'config.json'
    else:
        params.config_filename = config_filename or 'config.json'

    if os.path.exists(params.config_filename):
        try:
            try:
                with open(params.config_filename) as config_file:
                    params.config = json.load(config_file)

                    if 'user' in params.config:
                        params.user = params.config['user'].lower()

                    if 'server' in params.config:
                        params.server = params.config['server']

                    if 'password' in params.config:
                        params.password = params.config['password']

                    if 'timedelay' in params.config:
                        params.timedelay = params.config['timedelay']

                    if 'mfa_token' in params.config:
                        params.mfa_token = params.config['mfa_token']

                    if 'mfa_type' in params.config:
                        params.mfa_type = params.config['mfa_type']

                    if 'commands' in params.config:
                        if params.config['commands']:
                            params.commands.extend(params.config['commands'])

                    if 'plugins' in params.config:
                        params.plugins = params.config['plugins']

                    if 'debug' in params.config:
                        if params.config['debug']:
                            logging.getLogger().setLevel(logging.DEBUG)
                            logging.info('Debug ON')

                    if 'batch_mode' in params.config:
                        params.batch_mode = params.config['batch_mode'] == True

                    if 'device_id' in params.config:
                        device_id = base64.urlsafe_b64decode(params.config['device_id'] + '==')
                        params.rest_context.device_id = device_id

                    if 'logout_timer' in params.config:
                        params.logout_timer = params.config['logout_timer']

                    if 'login_v3' in params.config:
                        params.login_v3 = params.config['login_v3']

                    if 'private_key' in params.config:
                        params.device_private_key = params.config['private_key']

            except Exception as e:
                logging.error('Unable to parse JSON configuration file "%s"', params.config_filename)
                answer = input('Do you want to delete it (y/N): ')
                if answer in ['y', 'Y']:
                    os.remove(params.config_filename)
                else:
                    raise e
        except IOError as ioe:
            logging.warning('Error: Unable to open config file %s: %s', params.config_filename, ioe)

    if not params.server:
        params.server = 'https://keepersecurity.com/api/v2/'

    return params


def usage(m):
    print(m)
    parser.print_help()
    cli.display_command_help(show_enterprise=True, show_shell=True)
    sys.exit(1)


parser = argparse.ArgumentParser(prog='keeper', add_help=False, allow_abbrev=False)
parser.add_argument('--server', '-ks', dest='server', action='store', help='Keeper Host address.')
parser.add_argument('--user', '-ku', dest='user', action='store', help='Email address for the account.')
parser.add_argument('--password', '-kp', dest='password', action='store', help='Master password for the account.')
parser.add_argument('--version', dest='version', action='store_true', help='Display version')
parser.add_argument('--config', dest='config', action='store', help='Config file to use')
parser.add_argument('--debug', dest='debug', action='store_true', help='Turn on debug mode')
parser.add_argument('--batch-mode', dest='batch_mode', action='store_true', help='Run commander in batch or basic UI mode.')
parser.add_argument('--login-v3', '-lv3', dest='login_v3', action='store', help='Use Login v3 to login to Keeper.')
parser.add_argument('--launched-with-shortcut', '-lwsc', dest='launched_with_shortcut', action='store',
                    help='Indicates that the app was launched using a shortcut, for example using Mac App or from '
                         'Windows Start Menu.')
parser.add_argument('command', nargs='?', type=str, action='store', help='Command')
parser.add_argument('options', nargs='*', action='store', help='Options')
parser.error = usage


def handle_exceptions(exc_type, exc_value, exc_traceback):
    import traceback
    traceback.print_exception(exc_type, exc_value, exc_traceback)
    input('Press Enter to exit')
    sys.exit(-1)


def main(from_package=False):

    set_working_dir()

    errno = 0

    if from_package:
        sys.excepthook = handle_exceptions

    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])

    opts, flags = parser.parse_known_args(sys.argv[1:])
    params = get_params_from_config(opts.config)

    if opts.debug:
        params.debug = opts.debug
        is_debug = logging.getLogger().level <= logging.DEBUG
        logging.getLogger().setLevel((logging.WARNING if params.batch_mode else logging.INFO) if is_debug else logging.DEBUG)
        logging.info('Debug %s', 'OFF' if is_debug else 'ON')

    if opts.batch_mode:
        params.batch_mode = True

    if opts.login_v3:
        params.login_v3 = 'TRUE'.startswith(str(opts.login_v3).upper())

    if opts.server:
        params.server = 'https://{0}/api/v2/'.format(opts.server)

    if opts.user:
        params.user = opts.user

    if opts.password:
        params.password = opts.password
    else:
        pwd = os.getenv('KEEPER_PASSWORD')
        if pwd:
            params.password = pwd

    if opts.version:
        print('Keeper Commander, version {0}'.format(__version__))
        return

    if flags and len(flags) > 0:
        if flags[0] == '-h':
            flags.clear()
            opts.command = '?'

    if not opts.command and from_package:
        opts.command = 'shell'

    if (opts.command or '') in {'?', ''}:
        if opts.command == '?' or not params.commands:
            usage('')

    logging.basicConfig(level=logging.WARNING if params.batch_mode else logging.INFO, format='%(message)s')

    if params.timedelay >= 1 and params.commands:
        cli.runcommands(params)
    else:
        if opts.command in {'shell', '-'}:
            if opts.command == '-':
                params.batch_mode = True
        elif os.path.isfile(opts.command):
            with open(opts.command, 'r') as f:
                lines = f.readlines()
                params.commands.extend([x.strip() for x in lines])
            params.commands.append('q')
            params.batch_mode = True
        else:
            flags = ' '.join([shlex.quote(x) for x in flags]) if flags is not None else ''
            options = ' '.join([shlex.quote(x) for x in opts.options]) if opts.options is not None else ''
            command = ' '.join([opts.command, flags])
            if options:
                command += ' -- ' + options
            params.commands.append(command)
            params.commands.append('q')
            params.batch_mode = True

        errno = cli.loop(params)

    sys.exit(errno)


def set_working_dir():

    opts, flags = parser.parse_known_args(sys.argv[1:])

    if opts.launched_with_shortcut:
        current_user_home_path = str(Path.home())

        logging.debug("User home: %s" % current_user_home_path)

        current_user_home_path = str(Path.home())
        os.chdir(current_user_home_path)


if __name__ == '__main__':
    main()
