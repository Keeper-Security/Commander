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

from . import __version__
from .params import KeeperParams

from . import cli


def get_params_from_config(config_filename):
    params = KeeperParams()
    params.config_filename = config_filename or 'config.json'

    try:
        with open(params.config_filename) as config_file:

            try:
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
                    logging.getLogger().setLevel(logging.DEBUG)

                if 'batch_mode' in params.config:
                    params.batch_mode = params.config['batch_mode'] == True

                if 'device_id' in params.config:
                    device_id = base64.urlsafe_b64decode(params.config['device_id'] + '==')
                    params.rest_context.device_id = device_id

            except:
                print('Error: Unable to parse JSON file ' + params.config_filename)
                raise

    except IOError:
        if config_filename:
            print('Error: Unable to open config file ' + config_filename)
        pass

    if not params.server:
        params.server = 'https://keepersecurity.com/api/v2/'

    return params


def usage(m):
    print(m)
    parser.print_help()
    cli.display_command_help(show_enterprise=True, show_shell=True)
    sys.exit(1)

parser = argparse.ArgumentParser(prog='keeper', add_help=False)
parser.add_argument('--server', '-ks', dest='server', action='store', help='Keeper Host address.')
parser.add_argument('--user', '-ku', dest='user', action='store', help='Email address for the account.')
parser.add_argument('--password', '-kp', dest='password', action='store', help='Master password for the account.')
parser.add_argument('--version', dest='version', action='store_true', help='Display version')
parser.add_argument('--config', dest='config', action='store', help='Config file to use')
parser.add_argument('--debug', dest='debug', action='store_true', help='Turn on debug mode')
parser.add_argument('--batch-mode', dest='batch_mode', action='store_true', help='Run commander in batch or basic UI mode.')
parser.add_argument('command', nargs='?', type=str, action='store', help='Command')
parser.add_argument('options', nargs='*', action='store', help='Options')
parser.error = usage


def main():
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])

    opts, flags = parser.parse_known_args(sys.argv[1:])
    params = get_params_from_config(opts.config)

    if opts.debug:
        params.debug = opts.debug

    if opts.batch_mode:
        params.batch_mode = True

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

    if (opts.command or '') in {'?', ''}:
        if opts.command == '?' or not params.commands:
            usage('')

    #logging.basicConfig(level=logging.WARNING if params.batch_mode else logging.INFO, format='%(message)s')
    # from https://python.civic-apps.com/logifle-logger/
    logger = logging.getLogger("logger")    #get logger name
    logger.setLevel(logging.WARNING if params.batch_mode else logging.INFO)

    handler1 = logging.StreamHandler()
    handler1.setFormatter(logging.Formatter("{%(pathname)s:%(lineno)d} %(message)s"))

    handler2 = logging.FileHandler(filename="keeper.log")  
    handler2.setLevel(logging.DEBUG)     
    handler2.setFormatter(logging.Formatter("%(asctime)s {%(pathname)s:%(lineno)d} %(levelname)8s %(message)s"))

    logger.addHandler(handler1)
    logger.addHandler(handler2)

    if params.timedelay >= 1 and params.commands:
        cli.runcommands(params)
    else:
        if opts.command != 'shell':
            if opts.command:
                flags = ' '.join([shlex.quote(x) for x in flags]) if flags is not None else ''
                options = ' '.join([shlex.quote(x) for x in opts.options]) if opts.options is not None else ''
                command = ' '.join([opts.command, flags, options])
                params.commands.append(command)
            params.commands.append('q')
        cli.loop(params)


if __name__ == '__main__':
    main()
