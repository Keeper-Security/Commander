#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import datetime
import logging
import os
import shlex
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from typing import Union

from keepercommander.commands.utils import LoginCommand
from prompt_toolkit import PromptSession
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.shortcuts import CompleteStyle

from . import api, display, ttk
from . import versioning
from .autocomplete import CommandCompleter
from .commands import (
    register_commands, register_enterprise_commands, register_msp_commands,
    aliases, commands, command_info, enterprise_commands, msp_commands
)
from .commands.base import dump_report_data, CliCommand, GroupCommand
from .commands import msp
from .constants import OS_WHICH_CMD, KEEPER_PUBLIC_HOSTS
from .error import CommandError, Error
from .params import KeeperParams
from .subfolder import BaseFolderNode

current_command = None  # type: Union[None, CliCommand]
stack = []
register_commands(commands, aliases, command_info)
enterprise_command_info = OrderedDict()
msp_command_info = OrderedDict()
register_enterprise_commands(enterprise_commands, aliases, enterprise_command_info)
register_msp_commands(msp_commands, aliases, msp_command_info)

not_msp_admin_error_msg = 'This command is restricted to Keeper MSP administrators logged in to MSP ' \
                          'Company. \nIf you are an MSP administrator then try to run `switch-to-msp` ' \
                          'command before executing this command.'

command_info['server'] = 'Sets or displays current Keeper region.'

logging.getLogger('asyncio').setLevel(logging.WARNING)


def display_command_help(show_enterprise=False, show_shell=False):
    headers = ['Category', 'Command', 'Alias', '', 'Description']
    alias_lookup = {x[1]: x[0] for x in aliases.items()}
    table = []
    cmds = list(command_info.keys())
    cmds.sort()
    group_shown = False
    for cmd in cmds:
        table.append(['Vault' if not group_shown else '', cmd, alias_lookup.get(cmd) or '', '...', command_info.get(cmd, '')])
        group_shown = True

    if show_enterprise:
        cmds = list(enterprise_command_info.keys())
        cmds.sort()
        group_shown = False
        for cmd in cmds:
            table.append(['Enterprise' if not group_shown else '', cmd, alias_lookup.get(cmd) or '', '...', enterprise_command_info.get(cmd, '')])
            group_shown = True

        cmds = list(msp_command_info.keys())
        cmds.sort()
        group_shown = False
        for cmd in cmds:
            table.append(['MSP' if not group_shown else '', cmd, alias_lookup.get(cmd) or '', '...', msp_command_info.get(cmd, '')])
            group_shown = True

    if show_shell:
        table.append(['Misc', 'clear', 'c', '...', 'Clear the screen.'])
        table.append(['', 'history', 'h', '...', 'Show command history.'])
        table.append(['', 'shell', '', '...', 'Use Keeper interactive shell.'])
        table.append(['', 'quit', 'q', '...', 'Quit.'])

    print('\nCommands:')
    dump_report_data(table, headers, no_header=True)
    print('')
    print('Type \'help <command>\' to display help on command')


def is_executing_as_msp_admin():
    return msp.msp_params is not None


def check_if_running_as_mc(params, args):
    if msp.current_mc_id is not None:
        if msp.current_mc_id in msp.mc_params_dict:
            params = msp.mc_params_dict[msp.current_mc_id]
        else:
            msp.current_mc_id = None
    else:                                                       # Not impersonating
        if msp.msp_params is not None:
            params = msp.msp_params
            msp.msp_params = None

    return params, args


def is_enterprise_command(name, command, args):   # type: (str, CliCommand, str) -> bool
    if name in enterprise_commands:
        return True
    elif isinstance(command, GroupCommand):
        args = args.split(' ')
        verb = next(iter(args), None)
        subcommand = command.subcommands.get(verb)
        from keepercommander.commands.enterprise_common import EnterpriseCommand
        return isinstance(subcommand, EnterpriseCommand)
    else:
        return False


def command_and_args_from_cmd(command_line):
    args = ''
    pos = command_line.find(' ')
    if pos > 0:
        cmd = command_line[:pos]
        args = command_line[pos + 1:].strip()
    else:
        cmd = command_line.strip()

    return cmd, args


def do_command(params, command_line):
    def is_msp(params_local):
        if params_local.enterprise:
            if 'licenses' in params_local.enterprise:
                msp_license = next((x for x in params_local.enterprise['licenses'] if x['lic_status'].startswith('msp')),
                                   None)
                if msp_license:
                    return True
        return False

    if command_line.lower() == 'h' or command_line.lower() == 'history':
        display.formatted_history(stack)
        return

    if command_line.lower().startswith('server'):
        _, sp, server = command_line.partition(' ')
        if server:
            if not params.session_token:
                server = server.strip()
                region = next((x for x in KEEPER_PUBLIC_HOSTS.items()
                               if server.casefold() in [x[0].casefold(), x[1].casefold()]), None)
                if region:
                    params.server = region[1]
                    logging.info('Keeper region is set to %s', region[0])
                else:
                    params.server = server
                    logging.info('Keeper server is set to %s',  params.server)
            else:
                logging.warning('Cannot change Keeper region while logged in')
        else:
            print(params.server)
        return

    if command_line.startswith('ksm'):
        try:
            subprocess.check_call([OS_WHICH_CMD, 'ksm'], stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            logging.error(
                'Please install the ksm application to run ksm commands.\n'
                'See https://docs.keeper.io/secrets-manager/secrets-manager'
                '/secrets-manager-command-line-interface'
                '#secrets-manager-cli-installation'
            )
        else:
            if sys.platform.startswith('win'):
                subprocess.check_call(command_line)
            else:
                subprocess.check_call(shlex.split(command_line))
        return
    elif '-h' in command_line.lower():
        if command_line.lower().startswith('h ') or command_line.lower().startswith('history '):
            print("usage: history|h [-h]")
            print("\nShow command history.")
            print("\noptional arguments:")
            print("  -h, --help            show this help message and exit")
            return
        elif command_line.lower().startswith('c ') or command_line.lower().startswith('cls ') or command_line.lower().startswith('clear '):
            print("usage: clear|cls|c [-h]")
            print("\nClear the screen.")
            print("\noptional arguments:")
            print("  -h, --help            show this help message and exit")
            return
        elif command_line.lower().startswith('debug '):
            print("usage: debug [-h]")
            print("\nToggle debug mode")
            print("\noptional arguments:")
            print("  -h, --help            show this help message and exit")
            return
        elif command_line.lower().startswith('q ') or command_line.lower().startswith('quit '):
            print("usage: quit|q [-h]")
            print("\nExit commander")
            print("\noptional arguments:")
            print("  -h, --help            show this help message and exit")
            return

    # Track commands history
    if len(stack) == 0 or stack[0] != command_line:
        stack.insert(0, command_line)

    if command_line.lower() == 'c' or command_line.lower() == 'cls' or command_line.lower() == 'clear':
        print(chr(27) + "[2J")

    elif command_line == 'debug':
        is_debug = logging.getLogger().level <= logging.DEBUG
        logging.getLogger().setLevel((logging.WARNING if params.batch_mode else logging.INFO) if is_debug else logging.DEBUG)
        logging.getLogger('aiortc').setLevel(logging.WARNING if is_debug or params.batch_mode else logging.DEBUG)
        logging.getLogger('aioice').setLevel(logging.WARNING if is_debug or params.batch_mode else logging.DEBUG)
        logging.info('Debug %s', 'OFF' if is_debug else 'ON')

    else:
        cmd, args = command_and_args_from_cmd(command_line)
        if cmd:
            orig_cmd = cmd
            if cmd in aliases and cmd not in commands and cmd not in enterprise_commands and cmd not in msp_commands:
                ali = aliases[cmd]
                if isinstance(ali, (tuple, list)):
                    cmd = ali[0]
                    args = ' '.join(ali[1:]) + ' ' + args
                else:
                    cmd = ali

            if cmd in commands or cmd in enterprise_commands or cmd in msp_commands:
                command = commands.get(cmd) or enterprise_commands.get(cmd) or msp_commands.get(cmd)
                global current_command
                current_command = command

                if command.is_authorised():
                    if not params.session_token:
                        try:
                            LoginCommand().execute(params, email=params.user, password=params.password, new_login=False)
                        except KeyboardInterrupt:
                            logging.info('Canceled')
                            return

                    if is_enterprise_command(cmd, command, args) or cmd in msp_commands:
                        params, args = check_if_running_as_mc(params, args)

                    if is_enterprise_command(cmd, command, args) and not params.enterprise:
                        if is_executing_as_msp_admin():
                            logging.debug("OK to execute command: %s", cmd)
                        else:
                            logging.error('This command is restricted to Keeper Enterprise administrators.')
                            return

                    if cmd in msp_commands:
                        if not is_msp(params):
                            logging.error(not_msp_admin_error_msg)
                            return

                params.event_queue.clear()
                result = command.execute_args(params, args, command=orig_cmd)
                if params.session_token:
                    if params.event_queue:
                        try:
                            rq = {
                                'command': 'audit_event_client_logging',
                                'item_logs': params.event_queue
                            }
                            api.communicate(params, rq)
                        except Exception as e:
                            logging.debug('Post client events error: %s', e)
                        params.event_queue.clear()
                    if params.sync_data:
                        api.sync_down(params)
                return result
            else:
                display_command_help(show_enterprise=(params.enterprise is not None))


def runcommands(params, commands=None, command_delay=0, quiet=False):
    if commands is None:
        commands = params.commands

    keep_running = True
    first_command = True
    timedelay = params.timedelay

    while keep_running:
        for command in commands:
            if first_command:
                first_command = False
            elif command_delay != 0:
                time.sleep(command_delay)

            if not quiet:
                logging.info('Executing [%s]...', command)
            try:
                result = do_command(params, command)
                if result is not None:
                    print(result)
            except CommandError as e:
                msg = f'{e.command}: {e.message}' if e.command else f'{e.message}'
                logging.error(msg)
            except Error as e:
                logging.error("Communication Error: %s", e.message)
            except Exception as e:
                logging.debug(e, exc_info=True)
                logging.error('An unexpected error occurred: %s', sys.exc_info()[0])

        if timedelay == 0:
            keep_running = False
        else:
            logging.info("%s Waiting for %d seconds", datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'), timedelay)
            try:
                time.sleep(timedelay)
            except KeyboardInterrupt:
                keep_running = False


def force_quit():
    try:
        if os.name == 'posix':
            subprocess.run('reset')
        elif os.name == 'nt':
            subprocess.run('cls')
        print('Auto-logout timer activated.')
    except:
        pass
    os._exit(0)


prompt_session = None


def loop(params):  # type: (KeeperParams) -> int
    global prompt_session
    error_no = 0
    suppress_errno = False

    logging.getLogger().setLevel(logging.DEBUG if params.debug else logging.WARNING if params.batch_mode else logging.INFO)
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

        display.welcome()
        versioning.welcome_print_version(params)

    if not params.batch_mode:
        if params.user:
            try:
                LoginCommand().execute(params, email=params.user, password=params.password, new_login=False)
            except KeyboardInterrupt:
                print('')
            except EOFError:
                return 0
            except Exception as e:
                logging.error(e)
        else:
            if params.device_token:
                logging.info('Current Keeper region: %s', params.server)
            else:
                logging.info('Use "server" command to change Keeper region > "server US"')
                for region in KEEPER_PUBLIC_HOSTS:
                    logging.info('\t%s: %s', region, KEEPER_PUBLIC_HOSTS[region])
            logging.info('To login type: login <email>')

    while True:
        if params.session_token:
            ttk.TTK.update(params)

        command = ''
        if len(params.commands) > 0:
            command = params.commands[0].strip()
            params.commands = params.commands[1:]

        try:
            if not command:
                tmer = None
                try:
                    if params.session_token and params.logout_timer > 0:
                        tmer = threading.Timer(params.logout_timer * 60, force_quit)
                        tmer.start()
                    if prompt_session is not None:
                        if params.enforcements and params.user not in enforcement_checked:
                            enforcement_checked.add(params.user)
                            do_command(params, 'check-enforcements')

                        command = prompt_session.prompt(get_prompt(params))
                    else:
                        command = input(get_prompt(params))
                    if tmer:
                        tmer.cancel()
                        tmer = None
                finally:
                    if tmer:
                        tmer.cancel()

            if command.lower() == 'q' or command.lower() == "quit":
                break

            suppress_errno = False
            command = command.strip()
            if command.startswith("@"):
                suppress_errno = True
                command = command[1:]
            if params.batch_mode:
                logging.info('> %s', command)
            error_no = 1
            result = do_command(params, command)
            error_no = 0
            if result:
                print(result)
        except EOFError:
            break
        except KeyboardInterrupt:
            pass
        except CommandError as e:
            if e.command:
                logging.warning('%s: %s', e.command, e.message)
            else:
                logging.warning('%s', e.message)
        except Error as e:
            logging.error("Communication Error: %s", e.message)
        except Exception as e:
            logging.debug(e, exc_info=True)
            logging.error('An unexpected error occurred: %s. Type "debug" to toggle verbose error output', e)
        finally:
            global current_command
            try:
                if current_command:
                    current_command.clean_up()
            finally:
                current_command = None

        if params.batch_mode and error_no != 0 and not suppress_errno:
            break

    if not params.batch_mode:
        logging.info('\nGoodbye.\n')

    return error_no


def get_prompt(params):
    if params.batch_mode:
        return ''

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
