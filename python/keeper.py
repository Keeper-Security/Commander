# Keeper Commander for Python

import sys
import argparse
import json
import getpass
import keeperapi
from keepererror import AuthenticationError                                       
from keepererror import CommunicationError                                        
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
print(bcolors.FAIL,' Keeper Commander v1.2' + bcolors.ENDC)
print(bcolors.FAIL,' www.keepersecurity.com' + bcolors.ENDC)
print('')
print('')

def goodbye():
    print('\nGoodbye.\n');
    sys.exit()

def do_command(params):

    if (params.command == 'quit' or params.command == 'exit'): 
        return False 
    elif params.command == 'login':
        keeperapi.login(params)
    elif params.command == 'logout':
        params.logout()
    elif params.command == 'clear':
        print(chr(27) + "[2J") 
    elif params.command == 'list':
        keeperapi.list(params)
    elif params.command == '':
        pass
    else:
        print('\n\nCommands:\n')
        print('1. login           ... authenticate with server')
        print('2. logout          ... clear params and logout')
        print('3. search [string] ... find a record')
        print('4. get [UID]       ... display record details')
        print('5. clear           ... clear the screen')
        print('6. help            ... show this screen')
        print('7. quit            ... exit Keeper')
        print('')

    return True

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
    pass

# email, command, debug
parser = argparse.ArgumentParser(usage='%(prog)s [options]', 
                                 description='Keeper Commander')
parser.add_argument('--debug', help='Turn on debug mode', action='store_true')
parser.add_argument("--email", nargs='?', help='Email address')
parser.add_argument("--command", nargs='?', help='Command to run')

args = parser.parse_args()                                                     

if args.email:
    params.email = args.email

if args.command:
    params.command = args.command

if args.debug:
    params.debug = args.debug

try:

    if not params.server:
        params.server = 'https://keeperapp.com/v2/'

    while not params.email:
        params.email = getpass.getpass(prompt='Email: ', stream=None) 
    
    while not params.password:
        params.password = getpass.getpass(prompt='Password: ', stream=None) 

    while True:
        try:
            if not do_command(params):
                raise KeyboardInterrupt 
        except CommunicationError as e:
            print ("Communication Error:" + str(e.message))
        except AuthenticationError as e:
            print ("AuthenticationError Error: " + str(e.message))
        except KeyboardInterrupt:
            raise
        except:
            print('A weird exception occurred.')

        params.command = input("Keeper >> ")
                
except KeyboardInterrupt:
    goodbye()

