# Keeper Commander for Python

import argparse
import json
import keeperapi
from keeperparams import KeeperParams

CONFIG_FILENAME = 'config.json'

params = KeeperParams()

try:
    with open(CONFIG_FILENAME) as config_file:

        print('Loading config from ' + CONFIG_FILENAME)
        config = json.load(config_file)

        if 'email' in config:
            params.email = config['email']

        if 'command' in config:
            params.command = config['command']

        if 'server' in config:
            params.server = config['server']

        if 'password' in config:
            params.password = config['password']

        if 'mfa_token' in config:
            params.mfa_token = config['mfa_token']

        if 'debug' in config:
            params.debug = config['debug']

except IOError:

    parser = argparse.ArgumentParser(description='Keeper Commander')
    parser.add_argument("email", help="Email address of the Keeper profile")
    parser.add_argument("command", help="Command to run")
    parser.add_argument("server", help="Server to connect")
    parser.add_argument("--debug", help="Turn on debug mode",
                        action="store_true")
    args = parser.parse_args()

    params.email = args.email
    params.password = args.password
    params.command = args.command
    params.server = args.server
    params.mfa_token = args.mfa_token
    params.debug = args.debug

# parse command line if not set
params.dump()

