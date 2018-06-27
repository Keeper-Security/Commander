#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2017 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import os
import sys
import getpass
import json
import click
import datetime
import time

from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.enums import EditingMode

from keepercommander.record import Record
from keepercommander import display, api, imp_exp
from keepercommander.params import KeeperParams
from keepercommander.error import AuthenticationError, CommunicationError
from keepercommander.subfolder import BaseFolderNode
from keepercommander.autocomplete import CommandCompleter

from keepercommander.commands import register_commands as register_folder_commands

####### shell
@click.command(help = 'Use Keeper interactive shell')
@click.pass_obj
def shell(params):
    loop(params)

####### list
@click.command(help = 'Display all record UID/titles')
@click.pass_obj
def list(params):
    try:
        prompt_for_credentials(params)
        api.sync_down(params)
        if (len(params.record_cache) > 0):
            results = api.search_records(params, '')
            display.formatted_records(results)

        if (len(params.shared_folder_cache) > 0):
            results = api.search_shared_folders(params, '')
            display.formatted_shared_folders(results)

        if (len(params.team_cache) > 0):
            results = api.search_teams(params, '')
            display.formatted_teams(results)

    except Exception as e:
        raise click.ClickException(e)

####### list_sf
@click.command(help = 'Display all Shared Folder UID/titles')
@click.pass_obj
def list_sf(params):
    try:
        prompt_for_credentials(params)
        api.sync_down(params)

        if (len(params.shared_folder_cache) > 0):
            results = api.search_shared_folders(params, '')
            display.formatted_shared_folders(results)

    except Exception as e:
        raise click.ClickException(e)

####### list_teams
@click.command(help = 'Display all Teams')
@click.pass_obj
def list_teams(params):
    try:
        prompt_for_credentials(params)
        api.sync_down(params)

        if (len(params.team_cache) > 0):
            results = api.search_teams(params, '')
            display.formatted_teams(results)

    except Exception as e:
        raise click.ClickException(e)

####### get
@click.command('get', help = 'Display specified Keeper record')
@click.pass_obj
@click.argument('uid')
def get(params, uid):
    try:
        prompt_for_credentials(params)
        api.sync_down(params)
        if uid:
            api.get_record(params,uid).display()
    except Exception as e:
        raise click.ClickException(e)

####### search
@click.command(help = 'Search vault with a regular expression')
@click.argument('regex')
@click.pass_obj
def search(params, regex):
    try:
        prompt_for_credentials(params)
        api.sync_down(params)
        if (len(params.record_cache) == 0): 
            print('No records')
            return
        results = api.search_records(params, regex) 
        display.formatted_records(results)
    except Exception as e:
        raise click.ClickException(e)

####### rotate
@click.command(help = 'Rotate Keeper record')
@click.pass_obj
@click.argument('uid')
@click.option('--match', help='regular expression to select records for password rotation')
@click.option('--print', flag_value=True, help='display the record content after rotation')
def rotate(params, uid, match, print):
    try:
        prompt_for_credentials(params)
        api.sync_down(params)
        if uid:
            api.rotate_password(params, uid)
            if print:
                display.print_record(params, uid)
        else:
            if filter:
                results = api.search_records(params, match)
                for r in results:
                    api.rotate_password(params, r.record_uid)
                    if print:
                        display.print_record(params, uid)
    except Exception as e:
        raise click.ClickException(e)

####### import
@click.command('import', help='Import password records from local file')
@click.pass_obj
@click.option('--format', type=click.Choice(['tab-separated', 'json']))
@click.argument('filename')
def _import(params, format, filename):
    try:
        prompt_for_credentials(params)
        imp_exp._import(params, format, filename)
    except Exception as e:
        raise click.ClickException(e)

####### create_sf
@click.command('create_sf', help='Create shared folders from JSON input file')
@click.pass_obj
@click.argument('filename')
def create_sf(params, filename):
    try:
        prompt_for_credentials(params)
        imp_exp.create_sf(params, filename)
    except Exception as e:
        raise click.ClickException(e)

####### test_rsa
@click.command('test_rsa', help='Test RSA encryption/decryption')
@click.pass_obj
def test_rsa(params):
    try:
        prompt_for_credentials(params)
        api.sync_down(params)
        api.test_rsa(params)
    except Exception as e:
        raise click.ClickException(e)

####### test_aes
@click.command('test_aes', help='Test AES encryption/decryption')
@click.pass_obj
def test_aes(params):
    try:
        prompt_for_credentials(params)
        api.sync_down(params)
        api.test_aes(params)
    except Exception as e:
        raise click.ClickException(e)

####### export
@click.command(help='Export password records from Keeper')
@click.pass_obj
@click.option('--format', type=click.Choice(['tab-separated', 'json']))
@click.argument('filename')
def export(params, format, filename):
    try:
        prompt_for_credentials(params)
        imp_exp.export(params, format, filename)
    except Exception as e:
        raise click.ClickException(e)

####### delete-all
@click.command('delete-all', help='Delete all Keeper records on server')
@click.confirmation_option(prompt='Are you sure you want to delete all Keeper records on the server?')
@click.pass_obj
def delete_all(params):
    try:
        prompt_for_credentials(params)
        imp_exp.delete_all(params)
    except Exception as e:
        raise click.ClickException(e)

stack = []

def goodbye():
    print('\nGoodbye.\n')
    sys.exit()

def get_params_from_config(config_filename):
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
        params.server = 'https://keepersecurity.com/api/v2/'

    return params

commands = {}

register_folder_commands(commands)

def do_command(params):
    if params.command == 'q':
        return False

    cmd = params.command.strip()
    args = ''
    pos = cmd.find(' ')
    if pos > 0:
        args = cmd[pos+1:].strip()
        cmd = cmd[:pos]

    if len(cmd) > 0:

        if cmd in commands:
            commands[cmd].execute(params, args, command=cmd)
        elif cmd == 'l':
            if (len(params.record_cache) == 0):
                print('No records')
            else:
                results = api.search_records(params, '')
                display.formatted_records(results)

        elif cmd == 'lsf':
            if (len(params.shared_folder_cache) == 0):
                print('No shared folders')
            else:
                results = api.search_shared_folders(params, '')
                display.formatted_shared_folders(results)

        elif cmd == 'lt':
            if (len(params.team_cache) == 0):
                print('No teams')
            else:
                results = api.search_teams(params, '')
                display.formatted_teams(results)

        elif cmd == 'g':
            if api.is_shared_folder(params, args):
                sf = api.get_shared_folder(params, args)
                if sf:
                    sf.display()
            elif api.is_team(params, args):
                team = api.get_team(params, args)
                if team:
                    team.display()
            else:
                r = api.get_record(params, args)
                if r:
                    r.display()

        elif cmd == 'r':
            api.rotate_password(params, args)

        elif cmd == 'dr':
            api.delete_record(params, args)

        elif cmd == 'c':
            print(chr(27) + "[2J")

        elif cmd == 's':
            results = api.search_records(params, args)
            display.formatted_records(results, params=params)

        elif cmd == 'b':
            results = api.search_records(params, args)
            for r in results:
                api.rotate_password(params, r.record_uid)

        elif cmd == 'an':
            api.append_notes(params, args)

        elif cmd == 'd':
            api.sync_down(params)

        elif cmd == 'a':
            record = Record()
            while not record.title:
                record.title = input("... Title (req'd): ")
            record.folder = input("... Folder: ")
            record.login = input("... Login: ")
            record.password = input("... Password: ")
            record.login_url = input("... Login URL: ")
            record.notes = input("... Notes: ")
            while True:
                custom_dict = {}
                custom_dict['name'] = input("... Custom Field Name : ")
                if not custom_dict['name']:
                    break

                custom_dict['value'] = input("... Custom Field Value : ")
                custom_dict['type'] = 'text'
                record.custom_fields.append(custom_dict)

            api.add_record(params, record)

        elif cmd == 'h':
            display.formatted_history(stack)

        elif cmd == 'debug':
            if params.debug:
                params.debug = False
                print('Debug OFF')
            else:
                params.debug = True
                print('Debug ON')

        elif params.command == '':
            pass

        else:
            print('\n\nShell Commands:\n')
            print('  d              ... download & decrypt data')
            print('  l              ... list record titles')
            print('  lsf            ... list shared folders')
            print('  lt             ... list teams')
            print('  tree           ... display folder tree')
            print('  ls <folder>    ... list the content of folder')
            print('  cd <folder>    ... change current folder')
            print('  mv <src> <dst> ... move record or folder to another folder')
            print('  ln <src> <dst> ... link record or folder to another folder')
            print('  mkdir <folder> ... create a folder')
            print('  rmdir <folder> ... remove a folder')
            print('  rm <record>    ... remove a record')
            print('  s <regex>      ... search with regular expression')
            print('  g <uid>        ... get record or shared folder details for uid')
            print('  r <uid>        ... rotate password for uid')
            print('  b <regex>      ... rotate password for matches of regular expression')
            print('  a              ... add a new record interactively')
            print('  an <uid>       ... append some notes to the specified record')
            print('  c              ... clear the screen')
            print('  h              ... show command history')
            print('  q              ... quit')
            print('')

    if params.command:
        if params.command not in {'h'}:
            if len(stack) == 0 or stack[0] != params.command:
                stack.insert(0, params.command)

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


def prompt_for_credentials(params):
        while not params.user:
            params.user = getpass.getpass(prompt='User(Email): ', stream=None)

        while not params.password:
            params.password = getpass.getpass(prompt='Password: ', stream=None)


def loop(params):
    display.welcome()

    try:
        prompt_for_credentials(params)

        # if commands are provided, execute those then exit
        if params.commands:
            runcommands(params)
            goodbye()

        if params.debug: print('Params: ' + str(params))

        prompt_session = None
        if os.isatty(0):
            completer = CommandCompleter(params)
            prompt_session = PromptSession(multiline=False,
                                           editing_mode=EditingMode.VI,
                                           completer=completer,
                                           complete_style=CompleteStyle.MULTI_COLUMN,
                                           complete_while_typing=False)


        # go into interactive mode
        while True:
            if params.sync_data:
                api.sync_down(params)

            if not params.command:
                try:
                    if prompt_session is not None:
                        params.command = prompt_session.prompt(get_prompt(params)+ '> ')
                    else:
                        params.command = input(get_prompt(params) + '> ')

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


def get_prompt(params):
    if params.current_folder is None:
        if params.root_folder:
            params.current_folder = ''
        else:
            return 'Keeper'

    prompt = ''
    f = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder
    while True:
        if len(prompt) > 0:
            prompt = '/' + prompt
        name = f.name
        if f.type == BaseFolderNode.SharedFolderType:
            name = name + '$'
        prompt = name + prompt

        if f == params.root_folder:
            break

        if f.parent_uid is not None:
            f = params.folder_cache[f.parent_uid]
        else:
            if f.type == BaseFolderNode.SharedFolderFolderType:
                f = params.folder_cache[f.shared_folder_uid]
            else:
                f = params.root_folder
    if len(prompt) > 40:
        prompt = '...' + prompt[-40:]

    return prompt