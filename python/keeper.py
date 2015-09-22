# Keeper Commander for Python

import sys
import argparse
import json
import getpass
import keeperapi
import display
from keepererror import AuthenticationError
from keepererror import CommunicationError
from keeperparams import KeeperParams

CONFIG_FILENAME = 'config.json'

params = KeeperParams()
stack = [] 

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

    if ( params.command == 'quit' or \
         params.command == 'exit' or \
         params.command == 'q'): 
        return False 
    elif ((params.command == 'login') or (params.command == 'li')):
        keeperapi.login(params)
    elif ((params.command == 'ls') or (params.command == 'list')):
        display.formatted_list(params)
    elif (params.command[:3] == 'get'): 
        display.formatted_record(params, params.command[4:])
    elif (params.command[:1] == 'g'): 
        display.formatted_record(params, params.command[2:])
    elif ((params.command == 'logout') or (params.command == 'lo')):
        params.logout()
    elif ((params.command == 'clear') or (params.command == 'c')):
        print(chr(27) + "[2J") 
    elif ((params.command == 'sync_down') or (params.command == 'sd')):
        keeperapi.sync_down(params)
    elif params.command == '':
        pass
    else:
        print('\n\nCommands:\n')
        print('  sd        ... sync down all records')
        print('  lo        ... logout')
        print('  li        ... login')
        print('  s /regex/ ... search with regex')
        print('  g <UID>   ... show record details for uid')
        print('  c         ... clear the screen')
        print('  q         ... quit')
        print('')

    if params.command:
        stack.append(params.command)
        stack.reverse()

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

# email, command, debug are optional
parser = argparse.ArgumentParser(usage='keeper [options]', 
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
    
    # only prompt for password when no device token
    if not params.mfa_token:
        while not params.password:
            params.password = getpass.getpass(prompt='Password: ', stream=None) 

    # go into interactive mode
    while True:
        if not params.command:
            try:
                params.command = input("Keeper > ") 
            except KeyboardInterrupt:
                print('')
            except EOFError:
                raise KeyboardInterrupt 

        try:
            if not do_command(params):
                raise KeyboardInterrupt 
        except CommunicationError as e:
            print ("Communication Error:" + str(e.message))
        except AuthenticationError as e:
            print ("AuthenticationError Error: " + str(e.message))
        except KeyboardInterrupt as e:
            raise
        except:
            print('An unexpected error occurred: ' + str(sys.exc_info()[0]))
            raise

        params.command = ''

except KeyboardInterrupt:
    goodbye()

