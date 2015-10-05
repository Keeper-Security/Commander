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
import api
import display
import importlib
from error import AuthenticationError
from error import CommunicationError
from params import KeeperParams

params = KeeperParams()
params.config_filename = 'config.json'
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
        api.rotate_password(params, params.command[2:])

    elif (params.command == 'c'):
        print(chr(27) + "[2J") 

    elif (params.command[:2] == 's '): 
        display.formatted_search(params, params.command[2:])

    elif (params.command == 'd'):
        api.sync_down(params)

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
    with open(params.config_filename) as config_file:

        #print('Loading config from ' + CONFIG_FILENAME)
        try:
            params.config = json.load(config_file)

            if 'email' in params.config:
                params.email = params.config['email']
    
            if 'server' in params.config:
                params.server = params.config['server']
    
            if 'password' in params.config:
                params.password = params.config['password']
    
            if 'mfa_token' in params.config:
                params.mfa_token = params.config['mfa_token']
    
            if 'mfa_type' in params.config:
                params.mfa_type = params.config['mfa_type']
    
            if 'commands' in params.config:
                params.commands = params.config['commands']

            if 'plugins' in params.config:
                params.plugins = params.config['plugins']

            if 'debug' in params.config:
                params.debug = params.config['debug']

        except:
            print('Error: Unable to parse JSON file ' + CONFIG_FILENAME);
            goodbye()

except IOError:
    pass

# email, command, debug are optional
parser = argparse.ArgumentParser(usage='keeper [options]', 
                                 description='Keeper Commander')
parser.add_argument('--debug', help='Turn on debug mode', action='store_true')

args = parser.parse_args()                                                     

if args.debug:
    params.debug = args.debug

# import all specified plugins into 
# an array we can access later
params.imported_plugins = {} 
for module_name in params.plugins:
    try:
        full_name = 'plugins.' + module_name
        if params.debug: print('Importing ' + str(full_name))
        params.imported_plugins[module_name] = \
            importlib.import_module(full_name)
    except:
        print('Unable to load module ' + full_name)
        goodbye()

# Note: to access a plugin:
# foo = params.imported_plugins['foo'].Foo()

try:

    if not params.server:
        params.server = 'https://keeperapp.com/v2/'

    while not params.email:
        params.email = getpass.getpass(prompt='Email: ', stream=None) 
    
    # only prompt for password when no device token
    while not params.password:
        params.password = getpass.getpass(prompt='Password: ', stream=None) 

    # if commands are provided, execute those then exit
    if params.commands:
        for c in params.commands: 
            params.command = c
            print('Executing [' + params.command + ']...')
            try:
                if not do_command(params):
                    print('Command ' + params.command + ' failed.')
            except CommunicationError as e:
                print ("Communication Error:" + str(e.message))
            except AuthenticationError as e:
                print ("AuthenticationError Error: " + str(e.message))
            except:
                print('An unexpected error occurred: ' + str(sys.exc_info()[0]))

            params.command = '' 

        goodbye()

    if params.debug: print('Params: ' + str(params))

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

