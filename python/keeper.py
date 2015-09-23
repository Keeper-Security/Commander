#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2015 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

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

display.welcome()

def goodbye():
    print('\nGoodbye.\n');
    sys.exit()

def do_command(params):

    if (params.command == 'q'): 
        return False 

    elif (params.command == 'l'): 
        display.formatted_search(params, '')

    elif (params.command[:2] == 'g '): 
        display.formatted_record(params, params.command[2:])

    elif (params.command[:2] == 'r '): 
        keeperapi.rotate_password(params, params.command[2:])

    elif (params.command == 'c'):
        print(chr(27) + "[2J") 

    elif (params.command[:2] == 's '): 
        display.formatted_search(params, params.command[2:])

    elif (params.command == 'd'):
        keeperapi.sync_down(params)

    elif (params.command == 'h'):
        display.formatted_history(stack) 

    elif (params.command == 'debug'): 
        if params.debug: 
            params.debug = False
            print('Debug OFF')
        else:
            params.debug = True
            print('Debug ON')

    elif params.command == '':
        pass

    else:
        print('\n\nCommands:\n')
        print('  d         ... download & decrypt data')
        print('  l         ... list folders and titles')
        print('  s <regex> ... search with regular expression')
        print('  g <uid>   ... get record details for uid')
        print('  r <uid>   ... rotate password for uid')
        print('  c         ... clear the screen')
        print('  h         ... show command history')
        print('  q         ... quit')
        print('')

    if params.command:
        if params.command != 'h':
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

    # start with a sync download
    if not params.command:
        params.command = 'd'

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

