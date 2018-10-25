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
import datetime
import time
import collections
import functools

from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.enums import EditingMode

from . import display, api
from .error import AuthenticationError, CommunicationError
from .subfolder import BaseFolderNode
from .autocomplete import CommandCompleter
from .commands import register_commands, register_enterprise_commands


stack = []


aliases = {}
commands = {}
command_info = collections.OrderedDict()
register_commands(commands, aliases, command_info)
enterprise_commands = {}
enterprise_command_info = collections.OrderedDict()
register_enterprise_commands(enterprise_commands, aliases, enterprise_command_info)


def display_command_help(showEnterprise = False, showShell = False):
    max_length = functools.reduce(lambda x, y: len(y) if len(y) > x else x, command_info.keys(), 0)

    if showEnterprise:
        max_length = functools.reduce(lambda x, y: len(y) if len(y) > x else x, enterprise_command_info.keys(), max_length)

    print('\nCommands:')
    for cmd in command_info:
        print('  ' + cmd.ljust(max_length + 2) + '... ' + command_info[cmd])

    if showEnterprise:
        for cmd in enterprise_command_info:
            print('  ' + cmd.ljust(max_length + 2) + '... ' + enterprise_command_info[cmd])

    if showShell:
        print('  ' + 'shell'.ljust(max_length + 2) + '... ' + 'Use Keeper interactive shell')

    print('  ' + 'c'.ljust(max_length + 2) + '... ' + 'Clear the screen')
    print('  ' + 'h'.ljust(max_length + 2) + '... ' + 'Show command history')
    print('  ' + 'q'.ljust(max_length + 2) + '... ' + 'Quit')

    print('')
    print('Type \'command -h\' to display help on command')


def goodbye():
    api.print_info('\nGoodbye.\n')
    sys.exit()


def do_command(params):

    if params.command == 'q':
        return False

    elif params.command == 'h':
        display.formatted_history(stack)

    elif params.command == 'c':
        print(chr(27) + "[2J")

    elif params.command == 'debug':
        if params.debug:
            params.debug = False
            print('Debug OFF')
        else:
            params.debug = True
            print('Debug ON')

    else:
        cmd = params.command
        args = ''
        pos = cmd.find(' ')
        if pos > 0:
            args = cmd[pos+1:]
            cmd = cmd[:pos]

        if len(cmd) > 0:
            orig_cmd = cmd
            if cmd in aliases and cmd not in commands and cmd not in enterprise_commands:
                cmd = aliases[cmd]

            if cmd in commands or cmd in enterprise_commands:
                if cmd in commands:
                    command = commands[cmd]
                else:
                    if params.enterprise:
                        command = enterprise_commands[cmd]
                    else:
                        api.print_error('This command is restricted to Keeper Enterprise administrators.')
                        return True

                if command.is_authorised():
                    if not params.session_token:
                        try:
                            prompt_for_credentials(params)
                            api.print_info('Logging in...')
                            api.login(params)
                            api.sync_down(params)
                        except KeyboardInterrupt as e:
                            api.print_info('Canceled')
                            return True

                command.execute_args(params, args, command=orig_cmd)

                if params.session_token:
                    if params.sync_data:
                        api.sync_down(params)
            else:
                display_command_help(showEnterprise=(params.enterprise is not None))
                return True

            if params.command:
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

        if timedelay == 0:
            keep_running = False
        else:
            print(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S') + ' Waiting for ' + str(timedelay) + ' seconds')
            try:
                time.sleep(timedelay)
            except KeyboardInterrupt:
                keep_running = False


def prompt_for_credentials(params):
        while not params.user:
            params.user = getpass.getpass(prompt='User(Email): ', stream=None)

        while not params.password:
            params.password = getpass.getpass(prompt='Password: ', stream=None)


def loop(params):
    global prompt_session
    try:
        if params.debug: print('Params: ' + str(params))

        prompt_session = None
        if not params.batch_mode:
            if os.isatty(0) and os.isatty(1):
                completer = CommandCompleter(params, commands)
                prompt_session = PromptSession(multiline=False,
                                               editing_mode=EditingMode.VI,
                                               completer=completer,
                                               complete_style=CompleteStyle.MULTI_COLUMN,
                                               complete_while_typing=False)

        if len(params.commands) == 0:
            api.is_interactive_mode = True
            display.welcome()

        if params.user:
            if not params.password:
                print('Enter password for {0}'.format(params.user))
                params.password = getpass.getpass(prompt='Password: ', stream=None)
            if params.password:
                api.print_info('Logging in...')
                api.login(params)
                api.sync_down(params)

        while True:
            if len(params.commands) > 0:
                params.command = params.commands[0].strip()
                params.commands = params.commands[1:]

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
    if params.session_token:
        if params.current_folder is None:
            if params.root_folder:
                params.current_folder = ''
            else:
                return 'Keeper'
    else:
        return 'Not logged in'

    prompt = ''
    f = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder
    while True:
        if len(prompt) > 0:
            prompt = '/' + prompt
        name = f.name
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
        prompt = '...' + prompt[-37:]

    return prompt