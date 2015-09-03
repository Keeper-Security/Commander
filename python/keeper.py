# Keeper Commander for Python

import sys
import argparse
import json
import keeperapi
from keeperparams import KeeperParams

CONFIG_FILENAME = 'config.json'

params = KeeperParams()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

print('\n')
print(bcolors.OKBLUE,' _  __  ' + bcolors.ENDC)
print(bcolors.OKBLUE,'| |/ /___ ___ _ __  ___ _ _ ®' + bcolors.ENDC)
print(bcolors.OKBLUE,'| \' </ -_) -_) \'_ \\/ -_) \'_|' + bcolors.ENDC)
print(bcolors.OKBLUE,'|_|\\_\\___\\___| .__/\\___|_|' + bcolors.ENDC)
print(bcolors.OKBLUE,'             |_|            ' + bcolors.ENDC)
print('')
print(bcolors.FAIL,' Keeper Commander v1.0' + bcolors.ENDC)
print(bcolors.FAIL,' www.keepersecurity.com' + bcolors.ENDC)
print('')
print('')

try:
    with open(CONFIG_FILENAME) as config_file:

        #print('Loading config from ' + CONFIG_FILENAME)
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

        if 'mfa_type' in config:
            params.mfa_type = config['mfa_type']

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
    params.mfa_type = args.mfa_type
    params.debug = args.debug

# parse command line if not set
# params.dump()

try:
    while not params.server:
        params.server = input("Enter Server name (e.g. keeperapp.com): ")
    
    while not params.email:
        params.email = input("Enter Keeper email: ")
    
    while not params.password:
        params.password = input("Enter Master Password: ")

    while not params.command:
        params.command = input("Command >> ")
        if params.command == 'list':
            keeperapi.list(params)
        elif params.command == '?':
            print('\n\nCommands:\n')
            print('1. list   ... display all folder/title/uid')
            print('2. show   ... display record details')
            print('3. set    ... sets record info')
            print('4. delete ... deletes record')
            print('5. share  ... share record to a user')
            print('6. help   ... show this screen')
            print('7. help <command> ... show help info')
            print('')
        elif params.command == 'list':
            keeperapi.list(params)

except (KeyboardInterrupt, SystemExit):
    print('\nGoodbye.\n');
    sys.exit()


