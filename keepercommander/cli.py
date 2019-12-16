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
import functools
import logging

from collections import OrderedDict

from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.enums import EditingMode

from .params import KeeperParams
from . import display
from .api import sync_down, login, communicate
from .error import AuthenticationError, CommunicationError
from .subfolder import BaseFolderNode
from .autocomplete import CommandCompleter
from .commands import register_commands, register_enterprise_commands, aliases, commands, enterprise_commands


stack = []
command_info = OrderedDict()
register_commands(commands, aliases, command_info)
enterprise_command_info = OrderedDict()
register_enterprise_commands(enterprise_commands, aliases, enterprise_command_info)


def display_command_help(show_enterprise = False, show_shell = False):
    max_length = functools.reduce(lambda x, y: len(y) if len(y) > x else x, command_info.keys(), 0)

    if show_enterprise:
        max_length = functools.reduce(lambda x, y: len(y) if len(y) > x else x, enterprise_command_info.keys(), max_length)

    print('\nCommands:')
    for cmd in command_info:
        print('  ' + cmd.ljust(max_length + 2) + '... ' + command_info[cmd])

    if show_enterprise:
        for cmd in enterprise_command_info:
            print('  ' + cmd.ljust(max_length + 2) + '... ' + enterprise_command_info[cmd])

    if show_shell:
        print('  ' + 'shell'.ljust(max_length + 2) + '... ' + 'Use Keeper interactive shell')

    print('  ' + 'c'.ljust(max_length + 2) + '... ' + 'Clear the screen')
    print('  ' + 'h'.ljust(max_length + 2) + '... ' + 'Show command history')
    print('  ' + 'q'.ljust(max_length + 2) + '... ' + 'Quit')

    print('')
    print('Type \'command -h\' to display help on command')


def goodbye():
    logging.info('\nGoodbye.\n')
    sys.exit()


def do_command(params, command_line):

    if command_line == 'q':
        return False

    elif command_line == 'h':
        display.formatted_history(stack)

    elif command_line == 'c':
        print(chr(27) + "[2J")

    elif command_line == 'debug':
        is_debug = logging.getLogger().level <= logging.DEBUG
        logging.getLogger().setLevel((logging.WARNING if params.batch_mode else logging.INFO) if is_debug else logging.DEBUG)
        logging.info('Debug %s', 'OFF' if is_debug else 'ON')
    else:
        args = ''
        pos = command_line.find(' ')
        if pos > 0:
            cmd = command_line[:pos]
            args = command_line[pos+1:].strip()
        else:
            cmd = command_line

        if cmd:
            orig_cmd = cmd
            if cmd in aliases and cmd not in commands and cmd not in enterprise_commands:
                ali = aliases[cmd]
                if type(ali) == tuple:
                    cmd = ali[0]
                    for i in range(1, len(ali)):
                        args = ali[i] + ' ' + args
                else:
                    cmd = ali

            if cmd in commands or cmd in enterprise_commands:
                if cmd in commands:
                    command = commands[cmd]
                else:
                    if params.enterprise:
                        command = enterprise_commands[cmd]
                    else:
                        logging.error('This command is restricted to Keeper Enterprise administrators.')
                        return True

                if command.is_authorised():
                    if not params.session_token:
                        try:
                            prompt_for_credentials(params)
                            logging.info('Logging in...')
                            login(params)
                            sync_down(params)
                        except KeyboardInterrupt as e:
                            logging.info('Canceled')
                            return True

                params.event_queue.clear()
                command.execute_args(params, args, command=orig_cmd)
                if params.session_token:
                    if params.event_queue:
                        try:
                            rq = {
                                'command': 'audit_event_client_logging',
                                'item_logs': params.event_queue
                            }
                            communicate(params, rq)
                        except Exception as e:
                            logging.debug('Post client events error: %s', e)
                        params.event_queue.clear()
                    if params.sync_data:
                        sync_down(params)
            else:
                display_command_help(show_enterprise=(params.enterprise is not None))
                return True

            if len(stack) == 0 or stack[0] != command_line:
                stack.insert(0, command_line)

    return True


def runcommands(params):
    keep_running = True
    timedelay = params.timedelay

    while keep_running:
        for command in params.commands:
            logging.info('Executing [%s]...', command)
            try:
                if not do_command(params, command):
                    logging.warning('Command %s failed.', command)
            except CommunicationError as e:
                logging.error("Communication Error: %s", e.message)
            except AuthenticationError as e:
                logging.error("AuthenticationError Error: %s", e.message)
            except:
                logging.error('An unexpected error occurred: %s', sys.exc_info()[0])

        if timedelay == 0:
            keep_running = False
        else:
            logging.info("%s Waiting for %d seconds", datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'), timedelay)
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
    # type: (KeeperParams) -> None

    global prompt_session
    logging.debug('Params: %s', params)

    enforcement_checked = set()
    prompt_session = None
    if not params.batch_mode:
        if os.isatty(0) and os.isatty(1):
            completer = CommandCompleter(params, aliases)
            prompt_session = PromptSession(multiline=False,
                                           editing_mode=EditingMode.VI,
                                           completer=completer,
                                           complete_style=CompleteStyle.MULTI_COLUMN,
                                           complete_while_typing=False)

        if len(params.commands) == 0:
            display.welcome()
        else:
            logging.getLogger().setLevel(logging.WARNING)

    if params.user:
        if len(params.commands) == 0:
            if not params.password:
                logging.info('Enter password for {0}'.format(params.user))
                try:
                    params.password = getpass.getpass(prompt='Password: ', stream=None)
                except KeyboardInterrupt:
                    print('')
        if params.password:
            logging.info('Logging in...')
            try:
                login(params)
                if params.session_token:
                    do_command(params, 'sync-down')
            except AuthenticationError as e:
                logging.error(e)

    while True:
        command = ''
        if len(params.commands) > 0:
            command = params.commands[0].strip()
            params.commands = params.commands[1:]

        if not command:
            try:
                if prompt_session is not None:
                    if params.enforcements and params.user not in enforcement_checked:
                        enforcement_checked.add(params.user)
                        do_command(params, 'check-enforcements')

                    command = prompt_session.prompt(get_prompt(params))
                else:
                    command = input(get_prompt(params))
            except KeyboardInterrupt:
                pass
            except EOFError:
                break

        try:
            if not do_command(params, command):
                break
        except CommunicationError as e:
            logging.error("Communication Error: %s", e.message)
        except AuthenticationError as e:
            logging.error("AuthenticationError Error: %s", e.message)
        except KeyboardInterrupt:
            print('')
        except:
            logging.error('An unexpected error occurred: %s', sys.exc_info()[0])
            raise

    logging.info('\nGoodbye.\n')


def get_prompt(params):
    if params.session_token:
        if params.current_folder is None:
            if params.root_folder:
                params.current_folder = ''
            else:
                return 'Keeper> '
    else:
        return 'Not logged in> '

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

    return prompt + '> '
