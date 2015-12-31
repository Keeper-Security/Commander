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
import getpass
import json
import click
import datetime
import time

from keepercommander import display, api, imp_exp
from keepercommander.params import KeeperParams
from keepercommander.error import AuthenticationError, CommunicationError

@click.command(help = 'Print out current configuration')
@click.pass_obj
def info(params):
    print('Server: {0}'.format(params.server))
    print('User: {0}'.format(params.user))
    print('Password: {0}'.format(params.password))

@click.command(help = 'Use Keeper interactive shell')
@click.pass_obj
def shell(params):
    loop(params)

@click.command(help = 'List Keeper records')
@click.pass_obj
def list(params):
    try:
        api.sync_down(params)
        if (len(params.record_cache) == 0):
            print('No records')
            return
        results = api.search_records(params, '')
        display.formatted_records(results)
    except Exception as e:
        raise click.ClickException(e)

@click.command(help = 'Rotate Keeper record')
@click.pass_obj
@click.option('--uid', help='uid of the record to rotate the password on')
@click.option('--match', help='regular expression to select records for password rotation')
def rotate(params, uid, match):
    if not (uid or match):
        raise click.ClickException("Need to specify either uid or match option")
    try:
        api.sync_down(params)
        if uid:
            api.rotate_password(params, uid)
        else:
            if filter:
                results = api.search_records(params, match)
                for r in results:
                    api.rotate_password(params, r.record_uid)
    except Exception as e:
        raise click.ClickException(e)

@click.command('import', help='Import data from local file to Keeper')
@click.pass_obj
@click.option('--format', type=click.Choice(['tab-separated', 'json']))
@click.argument('filename')
def _import(params, format, filename):
    try:
        imp_exp._import(params, format, filename)
    except Exception as e:
        raise click.ClickException(e)

@click.command(help='Export data from Keeper to local file')
@click.pass_obj
@click.option('--format', type=click.Choice(['tab-separated', 'json']))
@click.argument('filename')
def export(params, format, filename):
    try:
        imp_exp.export(params, format, filename)
    except Exception as e:
        raise click.ClickException(e)

@click.command('delete-all', help='Delete all Keeper records on server')
@click.confirmation_option(prompt='Are you sure you want to delete all Keeper records on the server?')
@click.pass_obj
def delete_all(params):
    try:
        imp_exp.delete_all(params)
    except Exception as e:
        raise click.ClickException(e)

stack = []

def goodbye():
    print('\nGoodbye.\n')
    sys.exit()

def get_params(config_filename):
    params = KeeperParams()
    params.config_filename = 'config.json'
    if config_filename:
        params.config_filename = config_filename

    try:
        with open(params.config_filename) as config_file:

            try:
                params.config = json.load(config_file)

                if 'user' in params.config:
                    params.user = params.config['user']

                if 'server' in params.config:
                    params.server = params.config['server']

                if 'password' in params.config:
                    params.password = params.config['password']

                if 'challenge' in params.config:
                    try:
                        import keepercommander.yubikey.yubikey
                        challenge = params.config['challenge']
                        params.password = keepercommander.yubikey.yubikey.get_response(challenge)
                    except Exception as e:
                        print(e)
                        sys.exit(1)

                if 'timedelay' in params.config:
                    params.timedelay = params.config['timedelay']

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
                print('Error: Unable to parse JSON file ' + params.config_filename)
                raise

    except IOError:
        if config_filename:
            print('Error: Unable to open config file ' + config_filename)
        pass

    if not params.server:
        params.server = 'https://keeperapp.com/v2/'

    return params


def do_command(params):
    if (params.command == 'q'):
        return False

    elif (params.command == 'l'):
        if (len(params.record_cache) == 0):
            print('No records')
        else:
            results = api.search_records(params, '')
            display.formatted_records(results)

    elif (params.command[:2] == 'g '):
        r = api.get_record(params, params.command[2:])
        if r:
            r.display()

    elif (params.command[:2] == 'r '):
        api.rotate_password(params, params.command[2:])

    elif (params.command == 'c'):
        print(chr(27) + "[2J")

    elif (params.command[:2] == 's '):
        results = api.search_records(params, params.command[2:])
        display.formatted_records(results)

    elif (params.command[:2] == 'b '):
        results = api.search_records(params, params.command[2:])
        for r in results:
            api.rotate_password(params, r.record_uid)

    elif (params.command == 'd'):
        api.sync_down(params)

    elif (params.command == 'a'):
        api.add_record(params)

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
        print('  b <regex> ... rotate password for matches of regular expression')
        print('  a         ... add a new record interactively')
        print('  c         ... clear the screen')
        print('  h         ... show command history')
        print('  q         ... quit')
        print('')

    if params.command:
        if params.command != 'h':
            stack.append(params.command)
            stack.reverse()

    return True

def runcommands(params):
    keep_running = True
    timedelay = params.timedelay

    while keep_running:
        for c in params.commands:
            params.command = c
            print('Executing [' + params.command + ']...')
            try:
                if not do_command(params):
                    print('Command ' + params.command + ' failed.')
            except CommunicationError as e:
                print("Communication Error:" + str(e.message))
            except AuthenticationError as e:
                print("AuthenticationError Error: " + str(e.message))
            except:
                print('An unexpected error occurred: ' + str(sys.exc_info()[0]))

            params.command = ''

        if (timedelay == 0):
            keep_running = False
        else:
            print(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S') + \
                ' Waiting for ' + str(timedelay) + ' seconds')
            time.sleep(timedelay)

def loop(params):

    display.welcome()

    try:

        while not params.user:
            params.user = getpass.getpass(prompt='User(Email): ', stream=None)

            # only prompt for password when no device token
        while not params.password:
            params.password = getpass.getpass(prompt='Password: ', stream=None)

            # if commands are provided, execute those then exit
        if params.commands:
            runcommands(params)
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
                print("Communication Error:" + str(e.message))
            except AuthenticationError as e:
                print("AuthenticationError Error: " + str(e.message))
            except KeyboardInterrupt as e:
                raise
            except:
                print('An unexpected error occurred: ' + str(sys.exc_info()[0]))
                raise

            params.command = ''

    except KeyboardInterrupt:
        goodbye()