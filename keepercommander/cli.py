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
import functools
import logging
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from collections import OrderedDict

from prompt_toolkit import PromptSession
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.shortcuts import CompleteStyle

from . import api, display, loginv3, ttk
from .commands import (
    register_commands, register_enterprise_commands, register_msp_commands,
    aliases, commands, command_info, enterprise_commands, msp_commands
)
from .commands.base import expand_cmd_args
from .commands.msp import get_mc_by_name_or_id
from .constants import OS_WHICH_CMD, KEEPER_PUBLIC_HOSTS
from .error import AuthenticationError, CommunicationError, CommandError
from .params import KeeperParams
from .recordv3 import init_recordv3_commands
from .subfolder import BaseFolderNode
from .autocomplete import CommandCompleter
from . import versioning


stack = []
command_info = OrderedDict()
register_commands(commands, aliases, command_info)
enterprise_command_info = OrderedDict()
msp_command_info = OrderedDict()
register_enterprise_commands(enterprise_commands, aliases, enterprise_command_info)
register_msp_commands(msp_commands, aliases, msp_command_info)

not_msp_admin_error_msg = 'This command is restricted to Keeper MSP administrators logged in to MSP ' \
                          'Company. \nIf you are an MSP administrator then try to run `switch-to-msp` ' \
                          'command before executing this command.'


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

        for cmd in msp_command_info:
            print('  ' + cmd.ljust(max_length + 2) + '... ' + msp_command_info[cmd])

        print('  ' + "switch-to-mc".ljust(max_length + 2) + '... ' + 'Switch user\'s company to Managed Company')
        print('  ' + "switch-to-msp".ljust(max_length + 2) + '... ' + 'Switch user\'s context back to MSP Company')

    if show_shell:
        print('  ' + 'shell'.ljust(max_length + 2) + '... ' + 'Use Keeper interactive shell')

    print('  ' + 'clear|c'.ljust(max_length + 2) + '... ' + 'Clear the screen')
    print('  ' + 'history|h'.ljust(max_length + 2) + '... ' + 'Show command history')
    print('  ' + 'quit|q'.ljust(max_length + 2) + '... ' + 'Quit')

    print('')
    print('Type \'command -h\' to display help on command')


msp_params = None
mc_params_dict = {}
current_mc_id = None


def is_executing_as_msp_admin():
    return msp_params is not None


def check_if_running_as_mc(params, args):
    has_mc_id_regex = r"--mc[\s=](\d+)"

    global msp_params

    m = re.search(has_mc_id_regex, args)
    if m is not None:                                   # Impersonating as Managed Company (MC)
        try:
            mc_id = int(m.group(1))  # get id of the MC from args
        except AttributeError:
            logging.error("No Managed company provided")  # apply your error handling
            raise

        cur_msp_params = params if msp_params is None else params

        managed_companies = cur_msp_params.enterprise['managed_companies']
        found_mc = get_mc_by_name_or_id(managed_companies, mc_id)

        if found_mc is None:
            can_manage_mcs = ', '.join(str(mc['mc_enterprise_id']) for mc in managed_companies)

            raise CommandError('', "You do not have permission to manage company %s. MCs able to manage: %s" % (mc_id, can_manage_mcs))

        if mc_id not in mc_params_dict:
            mc_params = api.login_and_get_mc_params(params, mc_id)
            mc_params_dict[mc_id] = mc_params

        if msp_params is None:
            msp_params = params

        params = mc_params_dict[mc_id]

        args = re.sub(has_mc_id_regex, '', args)         # to remove impersonation args

    elif current_mc_id is not None:
        # Running commands as Managed Company admin via MSP

        if current_mc_id not in mc_params_dict:
            mc_params = api.login_and_get_mc_params_login_v3(params, current_mc_id)
            mc_params_dict[current_mc_id] = mc_params

        params = mc_params_dict[current_mc_id]

    else:                                                       # Not impersonating
        if msp_params is not None:
            params = msp_params
            msp_params = None

    return params, args


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
    global current_mc_id

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
        elif command_line.lower().startswith('d ') or command_line.lower().startswith('sync-down '):
            print("usage: sync-down|d [-h]")
            print("\nDownload your vault from the Keeper Cloud.")
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
        elif command_line.lower().startswith('switch-to-mc '):
            print("usage: switch-to-mc [-h] mcId")
            print("\nSwitch user's company to Managed Company.")
            print("\npositional arguments:")
            print("  mcId               ID of the Managed Company")
            print("\noptional arguments:")
            print("  -h, --help            show this help message and exit")
            return
        elif command_line.lower().startswith('switch-to-msp '):
            print("usage: switch-to-msp [-h]")
            print("\nSwitch user's context back to MSP Company.")
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
        logging.info('Debug %s', 'OFF' if is_debug else 'ON')

    elif 'switch-to-mc' in command_line:

        if current_mc_id is not None:
            raise CommandError('switch-to-mc', "Already switched to Managed Company id=%s" % current_mc_id)

        cmd, args = command_and_args_from_cmd(command_line)
        args = expand_cmd_args(args, params.environment_variables)

        if not args or not loginv3.CommonHelperMethods.check_int(args):
            raise CommandError('switch-to-mc', "Please provide Managed Company ID as integer. Your input was '%s'" % args)

        if not params.enterprise:
            logging.error('This command is restricted to Keeper Enterprise administrators.')
            return

        if not is_msp(params):
            logging.error(not_msp_admin_error_msg)
            return

        managed_companies = params.enterprise['managed_companies']
        found_mc = get_mc_by_name_or_id(managed_companies, int(args))

        if found_mc is None:
            can_manage_mcs = ', '.join(str(mc['mc_enterprise_id']) for mc in managed_companies)
            raise CommandError('', "You do not have permission to manage company %s. MCs able to manage: %s" % (int(args), can_manage_mcs))

        current_mc_id = int(args)

        print("Switched to MC '%s'" % found_mc['mc_enterprise_name'])

    elif command_line == 'switch-to-msp':

        if not params.enterprise:
            logging.error('This command is restricted to Keeper Enterprise administrators.')
            return

        if not is_msp(params):
            logging.error(not_msp_admin_error_msg)
            return

        if current_mc_id is None:
            raise CommandError('switch-to-mc', "Already MSP")

        print("Switching back to MSP")
        current_mc_id = None

        api.query_enterprise(params)

    else:
        cmd, args = command_and_args_from_cmd(command_line)

        params, args = check_if_running_as_mc(params, args)

        if cmd:
            orig_cmd = cmd
            if cmd in aliases and cmd not in commands and cmd not in enterprise_commands and cmd not in msp_commands:
                ali = aliases[cmd]
                if type(ali) == tuple:
                    cmd = ali[0]
                    for i in range(1, len(ali)):
                        args = ali[i] + ' ' + args
                else:
                    cmd = ali

            if cmd in commands or cmd in enterprise_commands or cmd in msp_commands:
                if cmd in commands:
                    command = commands[cmd]
                else:
                    if cmd in enterprise_commands:
                        command = enterprise_commands[cmd]
                    elif cmd in msp_commands:
                        command = msp_commands[cmd]

                if command.is_authorised():
                    if not params.session_token:
                        try:
                            api.login(params)
                            api.sync_down(params)
                        except KeyboardInterrupt as e:
                            logging.info('Canceled')
                            return

                    if cmd in enterprise_commands and not params.enterprise:
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
                do_command(params, command)
            except CommunicationError as e:
                logging.error("Communication Error: %s", e.message)
            except AuthenticationError as e:
                logging.error("AuthenticationError Error: %s", e.message)
            except CommandError as e:
                msg = f'{e.command}: {e.message}' if e.command else f'{e.message}'
                logging.error(msg)
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
            os.system('reset')
        elif os.name == 'nt':
            os.system('cls')
        os.system('echo Auto-logout timer activated.')
    except:
        pass
    os._exit(0)


prompt_session = None


def loop(params):  # type: (KeeperParams) -> int
    global prompt_session
    error_no = 0
    suppress_errno = False

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

    else:
        logging.getLogger().setLevel(logging.WARNING)

    if params.user:
        try:
            api.login(params)
            if params.session_token:
                do_command(params, 'sync-down')
        except KeyboardInterrupt:
            print('')
        except EOFError:
            return 0
        except Exception as e:
            logging.error(e)

        # add ability to manipulate w/ legacy or v3 records
        # determined by the response from the server
        init_recordv3_commands(params)
    else:
        if params.server:
            logging.info('Current Keeper region: %s', params.server)
        logging.info('Use "server" command to change Keeper region > "server US"')
        for region in KEEPER_PUBLIC_HOSTS:
            logging.info('\t%s: %s', region, KEEPER_PUBLIC_HOSTS[region])

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
        except CommunicationError as e:
            logging.error("Communication Error: %s", e.message)
        except AuthenticationError as e:
            logging.error("AuthenticationError Error: %s", e.message)
        except Exception as e:
            logging.debug(e, exc_info=True)
            logging.error('An unexpected error occurred: %s. Toggle debug to print traceback', e)

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
