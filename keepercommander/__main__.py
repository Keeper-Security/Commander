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
from .error import InputError, OSException
from . import cli


def get_params_from_config(config_filename:str) -> KeeperParams :
    '''get params from config file'''
    if not config_filename:
        msg = "Exit from no config_filename."
        logger.warn(msg)
        raise InputError(config_filename, msg)
    params = KeeperParams()
    params.config_filename = config_filename or 'config.json'
    key_set = {'user', 'server', 'password', 'timedelay', 'mfa_token', 'mfa_type',
     'commands', 'plugins', 'debug', 'batch_mode', 'device_id'}
    try: # pick up keys from params.config[key] to params.key
        with open(params.config_filename) as config_file:
            try:
                params.config = json.load(config_file)
                json_set = params.config.keys()
                for key in key_set:
                    if key in json_set:
                        if key == 'debug':
                            logging.getLogger().setLevel(logging.DEBUG)
                        elif key == 'commands':
                            params.commands.extend(params.config[key])
                        elif key == 'device_id':
                            params.rest_context.device_id = base64.urlsafe_b64decode(params.config['device_id'] + '==')        
                        else:
                            setattr(params, key, params.config[key])  # lower()                 
                for key in json_set:
                    if key not in key_set:
                        logger.info(f"{key} in {config_file} is ignored because not supported.")
            except json.JSONDecodeError as err: #msg, doc, pos:
                emsg = f"Error: Unable to parse: {doc} ; at {pos} ; in JSON file: {params.config_filename}"
                logger.warn(f"msg:{err.msg}, doc:{err.doc}, pos:{err.pos}", emsg)
                raise InputError(msg, emsg) from json.JSONDecodeError
    except OSError as e:
        msg = f"Error: Unable to access config file: {params.config_filename}"
        logger.warn(e, msg)
        raise OSException(msg) from OSError
    if not params.server:
        params.server = 'https://keepersecurity.com/api/v2/'
        logger.info(f"params.server is set as {params.server}")

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
    logging.basicConfig(
        level=logging.WARNING if params.batch_mode else logging.INFO,
        format="%(levelname)s: %(message)s in %(filename)s[%(lineno)d] at %(asctime)s")
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
