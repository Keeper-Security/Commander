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


import argparse
from typing import Optional

import certifi
import json
import logging
import os
import re
import shlex
import sys
from pathlib import Path

from . import __version__
from . import cli
from .params import KeeperParams
from .config_storage import loader

def get_params_from_config(config_filename=None, launched_with_shortcut=False):    # type: (Optional[str], bool) -> KeeperParams
    if os.getenv("KEEPER_COMMANDER_DEBUG"):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info('Debug ON')

    def get_env_config():
        path = os.getenv('KEEPER_CONFIG_FILE')
        if path:
            logging.debug(f'Setting config file from KEEPER_CONFIG_FILE env variable {path}')
        return path

    def get_default_path():
        default_path = Path.home().joinpath('.keeper')
        default_path.mkdir(parents=True, exist_ok=True)
        return default_path

    config_filename = config_filename or get_env_config()
    if not config_filename:
        config_filename = 'config.json'
        if launched_with_shortcut or not os.path.isfile(config_filename):
            config_filename = os.path.join(get_default_path(), config_filename)
        else:
            config_filename = os.path.join(os.getcwd(), config_filename)
    else:
        config_filename = os.path.expanduser(config_filename)

    params = KeeperParams()
    params.config_filename = config_filename
    if os.path.exists(config_filename):
        try:
            try:
                with open(params.config_filename) as config_file:
                    params.config = json.load(config_file)
                    loader.load_config_properties(params)
                    if 'fail_on_throttle' in params.config:
                        params.rest_context.fail_on_throttle = params.config['fail_on_throttle'] is True
                    if 'certificate_check' in params.config:
                        params.rest_context.certificate_check = params.config['certificate_check'] is True
                    if 'commands' in params.config:
                        if params.config['commands']:
                            params.commands.extend(params.config['commands'])
                    if 'plugins' in params.config:
                        params.plugins = params.config['plugins']
                    if params.config.get('debug') is True:
                        params.debug = True
            except loader.SecureStorageException as sse:
                logging.error('Unable to load configuration from secure storage:\n%s',
                              '\033[1m' + str(sse) + '\033[0m')
                logging.error('Please check configuration file "%s" to make sure "%s" property is valid or deleted it.',
                              os.path.abspath(params.config_filename),
                              loader.CONFIG_STORAGE_URL)
                input('Press <Enter> to close Keeper Commander')
                sys.exit(1)
            except Exception as e:
                logging.error('Unable to parse JSON configuration file "%s"', os.path.abspath(params.config_filename))
                answer = input('Do you want to delete it (y/N): ')
                if answer in ['y', 'Y']:
                    os.remove(params.config_filename)
                else:
                    raise e
        except IOError as ioe:
            logging.warning('Error: Unable to open config file %s: %s', params.config_filename, ioe)

    if not params.server:
        params.server = 'keepersecurity.com'

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
parser.add_argument('--launched-with-shortcut', '-lwsc', dest='launched_with_shortcut', action='store',
                    help='Indicates that the app was launched using a shortcut, for example using Mac App or from '
                         'Windows Start Menu.')
parser.add_argument('--proxy', dest='proxy', action='store', help='Proxy server')
unmask_help = 'Disable default masking of sensitive information (e.g., passwords) in output'
parser.add_argument('--unmask-all', action='store_true', help=unmask_help)
fail_on_throttle_help = 'Disable default client-side pausing of command execution and re-sending of requests upon ' \
                        'server-side throttling'
parser.add_argument('--fail-on-throttle', action='store_true', help=fail_on_throttle_help)
parser.add_argument('command', nargs='?', type=str, action='store', help='Command')
parser.add_argument('options', nargs='*', action='store', help='Options')
parser.error = usage


def handle_exceptions(exc_type, exc_value, exc_traceback):
    import traceback
    traceback.print_exception(exc_type, exc_value, exc_traceback)
    input('Press Enter to exit')
    sys.exit(-1)


def main(from_package=False):
    if sys.platform == 'win32' and sys.version_info >= (3, 7):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except:
            pass
    os.environ['SSL_CERT_FILE'] = certifi.where()
    logging.basicConfig(format='%(message)s')

    errno = 0

    if from_package:
        sys.excepthook = handle_exceptions

    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    opts, flags = parser.parse_known_args(sys.argv[1:])
    if opts.launched_with_shortcut:
        os.chdir(Path.home())

    params = get_params_from_config(opts.config, opts.launched_with_shortcut)

    if opts.batch_mode:
        params.batch_mode = True

    if opts.debug:
        params.debug = opts.debug

    logging.getLogger().setLevel(logging.WARNING if params.batch_mode else logging.DEBUG if opts.debug else logging.INFO)

    if opts.proxy:
        params.proxy = opts.proxy

    if opts.server:
        params.server = opts.server

    if opts.user is not None:
        params.user = opts.user

    if opts.unmask_all:
        params.unmask_all = opts.unmask_all

    if opts.fail_on_throttle:
        params.rest_context.fail_on_throttle = opts.fail_on_throttle

    if opts.password:
        params.password = opts.password
    else:
        pwd = os.getenv('KEEPER_PASSWORD')
        if pwd:
            params.password = pwd

    if opts.version:
        print(f'Keeper Commander, version {__version__}')
        return

    if flags and len(flags) > 0:
        if flags[0] in ('-h', '--help'):
            flags.clear()
            opts.command = '?'
    elif opts.command == 'help' and len(opts.options) == 0:
        opts.command = '?'
    if (opts.command or '') == '?':
        usage('')

    if not opts.command and from_package:
        opts.command = 'shell'

    if isinstance(params.timedelay, int) and params.timedelay >= 1 and params.commands:
        cli.runcommands(params)
    else:
        if opts.command in {'shell', '-'}:
            if opts.command == '-':
                params.batch_mode = True
        elif opts.command and os.path.isfile(opts.command):
            with open(opts.command, 'r') as f:
                lines = f.readlines()
                params.commands.extend([x.strip() for x in lines])
            params.commands.append('q')
            params.batch_mode = True
        else:
            flags = ' '.join([shlex.quote(x) for x in flags]) if flags is not None else ''
            options = ' '.join([shlex.quote(x) for x in opts.options]) if opts.options is not None else ''
            if opts.command:
                options = ' -- ' + options if options.startswith('-') else options
                command = ' '.join([opts.command or '', options, flags])
                params.commands.append(command)
            params.commands.append('q')
            params.batch_mode = True

        errno = cli.loop(params)

    sys.exit(errno)


if __name__ == '__main__':
    main()
