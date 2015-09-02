# Keeper Commander for Python

import argparse
import json
from keeperapi import KeeperAPI

CONFIG_FILENAME = 'config.json'

keeper = KeeperAPI()

try:
    with open(CONFIG_FILENAME) as config_file:

        print('Loading config from ' + CONFIG_FILENAME)
        config = json.load(config_file)

        if 'email' in config:
            keeper.email = config['email']

        if 'command' in config:
            keeper.command = config['command']

        if 'server' in config:
            keeper.server = config['server']

        if 'password' in config:
            keeper.password = config['password']

        if 'mfa_token' in config:
            keeper.mfa_token = config['mfa_token']

        if 'debug' in config:
            debug = config['debug']

except IOError:

    parser = argparse.ArgumentParser(description='Keeper Commander')
    parser.add_argument("email", help="Email address of the Keeper profile")
    parser.add_argument("command", help="Command to run")
    parser.add_argument("server", help="Server to connect")
    parser.add_argument("--debug", help="Turn on debug mode",
                        action="store_true")
    args = parser.parse_args()

    keeper.email = args.email
    keeper.password = args.password
    keeper.command = args.command
    keeper.server = args.server
    keeper.mfa_token = args.mfa_token
    keeper.debug = args.debug

keeper.dump()
keeper.go()
