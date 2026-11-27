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

import argparse
import datetime
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Union

from colorama import Fore, Style
from prompt_toolkit import PromptSession
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.key_binding import KeyBindings

from . import api, display, rest_api, ttk, utils
from . import versioning
from .autocomplete import CommandCompleter
from .commands import (
    register_commands, register_enterprise_commands, register_msp_commands,
    aliases, commands, command_info, enterprise_commands, msp_commands
)
from .commands.base import CliCommand, GroupCommand, ParseError, raise_parse_exception, suppress_exit
from .commands.utils import LoginCommand
from .commands import msp
from .constants import OS_WHICH_CMD, KEEPER_PUBLIC_HOSTS, resolve_server, invalid_server_message
from .command_categories import COMMAND_CATEGORIES
from .error import CommandError, Error
from .params import KeeperParams
from .subfolder import BaseFolderNode

NESTED_SHARE_FOLDER_COMMANDS = COMMAND_CATEGORIES.get('Nested Share Folder Commands', set())

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

command_info['server'] = 'Sets or displays current Keeper region'

# Shell-specific commands (handled inline in the shell loop)
command_info['clear'] = 'Clear the screen'
command_info['history'] = 'Show command history'
command_info['quit'] = 'Exit the shell'
aliases['c'] = 'clear'
aliases['h'] = 'history'
aliases['q'] = 'quit'

# These commands operate on the interactive Commander session rather than on
# vault data, so they must not be grantable through Service Mode.
SHELL_ONLY_COMMANDS = frozenset({'clear', 'history', 'quit', 'server'})


def get_shell_only_command_names():
    """Return shell/session commands and their registered aliases."""
    command_names = {command.lower() for command in SHELL_ONLY_COMMANDS}
    for alias, command in aliases.items():
        target = command[0] if isinstance(command, (tuple, list)) else command
        if isinstance(target, str) and target.lower() in command_names:
            command_names.add(alias.lower())
    return command_names

logging.getLogger('asyncio').setLevel(logging.WARNING)


def display_command_help(show_enterprise=False, show_shell=False, show_legacy=False, show_nested_share_folder=True):
    from .command_categories import get_command_category, get_category_order
    from .display import bcolors
    from colorama import Fore, Style
    import shutil

    # Build a lookup of command -> list of aliases
    alias_lookup = {}
    for alias, command in aliases.items():
        if command not in alias_lookup:
            alias_lookup[command] = []
        alias_lookup[command].append(alias)
    DIM = Fore.WHITE  # Use white for better readability (not too bright, not too dim)

    # Get terminal width
    try:
        terminal_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    except:
        terminal_width = 80

    def clean_description(desc):
        """Remove trailing period from description"""
        if desc and desc.endswith('.'):
            return desc[:-1]
        return desc

    # Collect all commands from all sources
    all_commands = {}
    all_commands.update(command_info)
    if show_enterprise:
        all_commands.update(enterprise_command_info)
        all_commands.update(msp_command_info)

    # Group commands by category and build display info
    categorized_commands = {}
    for cmd, description in all_commands.items():
        category = get_command_category(cmd)
        if category not in categorized_commands:
            categorized_commands[category] = []
        categorized_commands[category].append((cmd, clean_description(description)))

    # Pre-compute all command display strings and find global max width
    # This allows alignment across all categories when terminal is wide enough
    all_cmd_displays = []  # List of (category, cmd_display, description)
    global_max_width = 0

    # Special subcommands for certain categories
    pam_subcommands = [
        ('pam action', 'Execute action on the Gateway'),
        ('pam config', 'Manage PAM Configurations'),
        ('pam connection', 'Manage Connections'),
        ('pam gateway', 'Manage Gateways'),
        ('pam legacy', 'Switch to legacy PAM commands'),
        ('pam project', 'PAM Project Import/Export'),
        ('pam rbi', 'Manage Remote Browser Isolation'),
        ('pam rotation', 'Manage Rotations'),
        ('pam split', 'Split credentials from legacy PAM Machine'),
        ('pam tunnel', 'Manage Tunnels'),
        ('pam workflow', 'Manage PAM Workflows'),
    ]
    domain_subcommands = [
        ('domain list (dl)', 'List all reserved domains for the enterprise'),
        ('domain reserve (dr)', 'Reserve, delete or generate token for a domain'),
        ('domain alias list (dal)', 'List domain aliases for the enterprise'),
        ('domain alias create (dac)', 'Create a domain alias for the enterprise'),
        ('domain alias delete (dad)', 'Delete a domain alias for the enterprise'),
    ]

    for category in get_category_order():
        if category not in categorized_commands:
            continue
        if category == 'Legacy Commands' and not show_legacy:
            continue
        if category == 'Nested Share Folder Commands' and not show_nested_share_folder:
            continue

        if category == 'KeeperPAM Commands':
            for cmd_display, description in sorted(pam_subcommands):
                all_cmd_displays.append((category, cmd_display, description))
                global_max_width = max(global_max_width, len(cmd_display))
        elif category == 'Domain Management Commands':
            for cmd_display, description in sorted(domain_subcommands):
                all_cmd_displays.append((category, cmd_display, description))
                global_max_width = max(global_max_width, len(cmd_display))
        else:
            commands_in_category = sorted(categorized_commands[category], key=lambda x: x[0])
            for cmd, description in commands_in_category:
                aliases_list = alias_lookup.get(cmd) or []
                alias_str = f' ({", ".join(sorted(aliases_list))})' if aliases_list else ''
                cmd_display = f'{cmd}{alias_str}'
                all_cmd_displays.append((category, cmd_display, description))
                global_max_width = max(global_max_width, len(cmd_display))

    # Determine if we should use global alignment
    # Use global alignment if terminal is wide enough (command + padding + reasonable description)
    min_desc_width = 40
    use_global_alignment = terminal_width >= (4 + global_max_width + 2 + min_desc_width)

    print()
    print(f"  {Style.BRIGHT}Available Commands{Style.RESET_ALL}")
    print(f"  {DIM}{'─' * 70}{Fore.RESET}")

    # Display commands grouped by category
    current_category = None
    category_cmd_widths = {}  # Cache per-category max widths for non-global alignment

    # Pre-compute per-category max widths
    if not use_global_alignment:
        for category, cmd_display, _ in all_cmd_displays:
            if category not in category_cmd_widths:
                category_cmd_widths[category] = 0
            category_cmd_widths[category] = max(category_cmd_widths[category], len(cmd_display))

    for category, cmd_display, description in all_cmd_displays:
        if category != current_category:
            if current_category is not None:
                print()
            print(f"  {Style.BRIGHT}{category}{Style.RESET_ALL}")
            current_category = category

        # Use global or per-category width
        width = global_max_width if use_global_alignment else category_cmd_widths[category]
        print(f"    {Fore.GREEN}{cmd_display:<{width}}{Fore.RESET}  {DIM}{description}{Fore.RESET}")

    print()
    print(f"  {DIM}Type {Fore.GREEN}help <command>{DIM} to display help on command{Fore.RESET}")
    # Only show these hints inside the shell (not from terminal)
    if not show_shell:
        print(f"  {DIM}Type {Fore.GREEN}help basics{DIM} for a quick start guide{Fore.RESET}")
        if not show_legacy:
            print(f"  {DIM}Type {Fore.GREEN}help --legacy{DIM} to show legacy/deprecated commands{Fore.RESET}")
    print()


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
        from .commands.enterprise_common import EnterpriseCommand
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


_DISALLOWED_COMMAND_CHARS = ('\r', '\n', '\x00')


server_parser = argparse.ArgumentParser(
    prog='server', description='Set or display the Keeper server: a region, a Keeper host, '
                               'or the host of a self-managed Keeper deployment.',
    epilog='Regions: US, EU, AU, CA, JP, GOV. Dev: US_DEV, EU_DEV, AU_DEV, CA_DEV, JP_DEV, GOV_DEV. '
           'QA: US_QA, EU_QA, AU_QA, CA_QA, JP_QA, GOV_QA. '
           'A self-managed deployment has its own server key. Over a verified HTTPS connection Commander '
           'fetches it from the server; use --key-id and --public-key to set it yourself instead. '
           'With --insecure, or over plain HTTP, the key must be set.')
server_parser.add_argument('--key-id', dest='key_id', type=int, action='store',
                           help='self-managed server: server key ID')
server_parser.add_argument('--public-key', dest='public_key', action='store',
                           help='self-managed server: server public key, base64url encoded')
server_parser.add_argument('--insecure', dest='insecure', action='store_true',
                           help='self-managed server: do not check its TLS certificate. Needs --key-id and '
                                '--public-key, since a key fetched this way cannot be trusted')
server_parser.add_argument('--clear-key', dest='clear_key', action='store_true',
                           help='self-managed server: forget its key and --insecure, and fetch the key from the server')
server_parser.add_argument('server', nargs='?', type=str, action='store', help='region or host name')
server_parser.error = raise_parse_exception
server_parser.exit = suppress_exit


def save_server_keys(params):   # type: (KeeperParams) -> None
    """Write only the "server_keys" property, leaving the rest of the file as it is."""
    if not params.config_filename:
        return
    config = {}
    if os.path.isfile(params.config_filename):
        with open(params.config_filename) as fd:
            config = json.load(fd)
    if params.config.get('server_keys'):
        config['server_keys'] = params.config['server_keys']
    else:
        config.pop('server_keys', None)
    with open(params.config_filename, 'w') as fd:
        json.dump(config, fd, ensure_ascii=False, indent=2)
    utils.set_file_permissions(params.config_filename)


def server_command(params, args):   # type: (KeeperParams, str) -> None
    try:
        opts = server_parser.parse_args(shlex.split(args))
    except ParseError as e:
        if e.args and e.args[0]:
            logging.error(e)
        return

    set_key = opts.key_id is not None or opts.public_key or opts.clear_key or opts.insecure
    if (opts.server or set_key) and params.session_token:
        logging.warning('Cannot change the Keeper server or its key while logged in')
        return

    if opts.server:
        server = resolve_server(opts.server)
        if not server:
            logging.error(invalid_server_message(opts.server))
            return
        params.server = server
        logging.info('Keeper server is set to %s', params.server)

    host = rest_api.server_host(params.server)
    if not set_key:
        if not opts.server:
            print(params.server)
        return

    if rest_api.is_keeper_cloud_host(host):
        logging.error('%s is a Keeper cloud host. It uses Keeper\'s own server keys and a checked certificate.', host)
        return
    if opts.clear_key and (opts.key_id is not None or opts.public_key or opts.insecure):
        logging.error('Use --clear-key on its own')
        return

    server_keys = params.config.setdefault('server_keys', {})
    entry = dict(server_keys.get(host) or {})
    if opts.clear_key:
        rest_api.clear_server_public_key(host)
        rest_api.set_server_insecure(host, False)
        entry = {}
        logging.info('Server key of %s is cleared. It will be fetched from the server.', host)
    else:
        if opts.key_id is not None or opts.public_key:
            if opts.key_id is None or not opts.public_key:
                logging.error('Use both --key-id and --public-key')
                return
            try:
                key = rest_api.set_server_public_key(host, opts.key_id, opts.public_key)
            except ValueError as e:
                logging.error(e)
                return
            entry['key_id'] = key.key_id
            entry['public_key'] = key.public_key
            logging.info('Server key of %s is set: key ID %d, %s',
                         host, key.key_id, rest_api.server_key_fingerprint(key.public_key))
        if opts.insecure:
            rest_api.set_server_insecure(host, True)
            entry['insecure'] = True
            logging.warning('TLS certificate of %s is not checked. Anyone between you and this server can '
                            'read this session unless its server key is set by you.', host)
            if not rest_api.get_configured_server_key(host):
                logging.warning('Set the server key of %s, as Commander does not fetch it over a connection '
                                'it cannot check: server %s --key-id <ID> --public-key <KEY>', host, host)

    if entry:
        server_keys[host] = entry
    else:
        server_keys.pop(host, None)
    if not server_keys:
        params.config.pop('server_keys', None)
    try:
        save_server_keys(params)
    except Exception as e:
        logging.warning('The server settings are set for this session, but could not be saved to %s: %s',
                        params.config_filename, e)


def do_command(params, command_line):
    # Block control characters to prevent newline-injection at the shell boundary.
    if isinstance(command_line, str) and any(ch in command_line for ch in _DISALLOWED_COMMAND_CHARS):
        logging.error('Invalid command: control characters are not allowed in command input.')
        return

    if getattr(params, 'service_mode', False):
        try:
            command_tokens = shlex.split(command_line)
        except ValueError:
            command_tokens = []
        if command_tokens and command_tokens[0].lower() in get_shell_only_command_names():
            logging.error('Interactive shell/session commands are not available in Service Mode')
            return

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
        _, sp, args = command_line.partition(' ')
        server_command(params, args)
        return

    if command_line.startswith('ksm'):
        # Exclude cwd from PATH on Windows so a local `ksm.bat` can't hijack
        # the `ksm` prefix via CreateProcess's implicit cwd search.
        search_path = os.environ.get('PATH', os.defpath)
        if sys.platform.startswith('win'):
            try:
                cwd_abs = os.path.abspath(os.getcwd())
            except OSError:
                cwd_abs = None
            if cwd_abs:
                search_path = os.pathsep.join(
                    p for p in search_path.split(os.pathsep)
                    if p and os.path.abspath(p) != cwd_abs
                )

        ksm_path = shutil.which('ksm', path=search_path)
        if not ksm_path:
            logging.error(
                'Please install the ksm application to run ksm commands.\n'
                'See https://docs.keeper.io/secrets-manager/secrets-manager'
                '/secrets-manager-command-line-interface'
                '#secrets-manager-cli-installation'
            )
            return

        try:
            ksm_args = shlex.split(command_line, posix=not sys.platform.startswith('win'))
        except ValueError as e:
            logging.error('Invalid ksm command: %s', e)
            return

        if not ksm_args or ksm_args[0].lower() != 'ksm':
            logging.error('Invalid ksm command.')
            return

        # Invoke via argv list with shell=False so arguments aren't re-parsed.
        ksm_args[0] = ksm_path
        try:
            subprocess.check_call(ksm_args, shell=False)
        except subprocess.CalledProcessError as cpe:
            if cpe.returncode != 2:
                raise cpe
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
            print("  --file=PATH           write all logs, including DEBUG, and the commands run to PATH")
            print("                        (relative or absolute; terminal DEBUG is not enabled)")
            return
        elif command_line.lower().startswith('q ') or command_line.lower().startswith('quit '):
            print("usage: quit|q [-h]")
            print("\nExit commander")
            print("\noptional arguments:")
            print("  -h, --help            show this help message and exit")
            return

    # Track commands history
    # Service Mode serves multiple API keys in one process. Never place its raw
    # command lines (which may contain credentials) in the interactive shell's
    # process-global history buffer.
    if (
            not getattr(params, 'service_mode', False)
            and (len(stack) == 0 or stack[0] != command_line)):
        stack.insert(0, command_line)

    if command_line.lower() == 'c' or command_line.lower() == 'cls' or command_line.lower() == 'clear':
        print(chr(27) + "[2J")

    elif command_line.startswith('debug'):
        try:
            tokens = shlex.split(command_line)
            debug_manager.process_command(tokens, params.batch_mode)
        except Exception as e:
            logging.error(f"Error processing debug command: {e}")


        # Toggle Rust verbose logging if available
        try:
            import keeper_pam_webrtc_rs
            new_debug_state = debug_manager.is_console_debug_on(params.batch_mode)

            level = logging.DEBUG if new_debug_state else logging.INFO
            logging.getLogger('keeper_pam_webrtc_rs').setLevel(level)

            keeper_pam_webrtc_rs.set_verbose_logging(new_debug_state)
            logging.debug('Rust verbose logging %s', 'ON' if new_debug_state else 'OFF')
        except ImportError:
            pass  # Rust library not available, skip
        except Exception as e:
            logging.debug(f'Failed to toggle Rust verbose logging: {e}')

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

            is_nsf_hidden = cmd in NESTED_SHARE_FOLDER_COMMANDS and params.is_feature_disallowed('keeper_drive')

            if not is_nsf_hidden and (cmd in commands or cmd in enterprise_commands or cmd in msp_commands):
                command = commands.get(cmd) or enterprise_commands.get(cmd) or msp_commands.get(cmd)
                global current_command
                current_command = command

                if command.is_authorised():
                    if not params.session_token:
                        # Service Mode: enable federated login before the auto-login below
                        from .service.core.globals import FEDERATED_LOGIN_COMMANDS, init_federated_login
                        if cmd in FEDERATED_LOGIN_COMMANDS:
                            try:
                                init_federated_login(params)
                            except Exception as e:
                                logging.error(e)
                                return
                        try:
                            # Some commands (like logout) need auth but not sync
                            skip_sync = getattr(command, 'skip_sync_on_auth', False)
                            # Auto-login for commands - don't show help text (show_help=False)
                            LoginCommand().execute(params, email=params.user, password=params.password, new_login=False, skip_sync=skip_sync, show_help=False)
                        except KeyboardInterrupt:
                            logging.info('Canceled')
                        if not params.session_token:
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
                if not params.session_token and utils.is_email(orig_cmd):
                    return LoginCommand().execute(params, email=orig_cmd, new_login=False)
                display_command_help(
                    show_enterprise=(params.enterprise is not None),
                    show_nested_share_folder=not params.is_feature_disallowed('keeper_drive')
                )


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
        logging.warning('Auto-logout timer activated.')
    except:
        pass
    os._exit(0)


prompt_session = None

DEFAULT_LOG_FILE = 'keeper.log'
COMMAND_LOGGER_NAME = 'keepercommander.command'
_COMMAND_WORD_RE = re.compile(r'''(?:[^\s"']|"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$))+''')
_OPTION_NAME_RE = re.compile(r'^--?[A-Za-z][\w-]*')

def redact_command_for_log(command_line):
    """Return only the command name and option flags, stripping all values."""
    words = _COMMAND_WORD_RE.findall(command_line or '')
    if not words:
        return ''
    cmd = words[0].lstrip('@')
    if not cmd:
        return ''
    kept = [cmd]
    for word in words[1:]:
        if word == '--':
            break
        match = _OPTION_NAME_RE.match(word)
        if match:
            kept.append(match.group(0))
    return ' '.join(kept)


def _file_missing_trailing_newline(file_path):
    """Return True if ``file_path`` exists, is non-empty, and lacks a trailing newline."""
    try:
        with open(file_path, 'rb') as f:
            f.seek(-1, os.SEEK_END)
            return f.read(1) not in (b'\n', b'\r')
    except OSError:
        return False


def _sanitize_log_file_path(file_path):
    if not file_path or not isinstance(file_path, str):
        raise ValueError("File path must be a non-empty string")
    sanitized = ''.join(ch for ch in file_path if ord(ch) >= 32 and ch != '\x7f')
    if not sanitized.strip():
        raise ValueError("File path contains only invalid characters")
    return sanitized


class DebugManager:
    """Debug manager for console and file logging."""

    def __init__(self):
        self.logger = logging.getLogger()
        self.command_logger = logging.getLogger(COMMAND_LOGGER_NAME)
        self.command_logger.propagate = False
        self.command_logger.setLevel(logging.INFO)
        self._log_file_handler = None
        self._debug_file_enabled = False

    def _console_handlers(self):
        return [
            h for h in self.logger.handlers
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        ]

    def _active_log_file_handler(self):
        h = self._log_file_handler
        return h if h is not None and h in self.logger.handlers else None

    def has_file_logging(self):
        """Check if any log file handler is active."""
        return self._active_log_file_handler() is not None

    def has_debug_file_logging(self):
        """Check if ``debug --file`` logging is active."""
        return self._active_log_file_handler() is not None and self._debug_file_enabled

    def log_command(self, command_line):
        """Write the redacted command line to the log file only."""
        if self._active_log_file_handler() is None:
            return
        redacted = redact_command_for_log((command_line or '').strip())
        if redacted:
            self.command_logger.info('%s', redacted)

    def is_console_debug_on(self, batch_mode):
        """Check if console debug is enabled."""
        handlers = self._console_handlers()
        if handlers:
            return any((h.level or self.logger.level) == logging.DEBUG for h in handlers)
        return self.logger.level == logging.DEBUG and not self.has_debug_file_logging()

    def set_console_debug(self, enabled, batch_mode):
        """Set console debug level."""
        level = logging.DEBUG if enabled else (logging.WARNING if batch_mode else logging.INFO)
        for h in self._console_handlers():
            h.setLevel(level)

    def attach_log_file(self, file_path, debug=False):
        """Attach a log file handler to root and command loggers.

        Existing ``keeper.log`` files rotate to a timestamped sibling; custom
        names are appended to. When ``debug=True``, DEBUG records are written
        without enabling console DEBUG. Returns the log file path or ``None``.
        """
        file_handler = None
        try:
            validated_path = self._resolve_log_file_path(file_path)
            os.makedirs(os.path.dirname(validated_path), mode=0o750, exist_ok=True)

            needs_newline = _file_missing_trailing_newline(validated_path)
            file_handler = logging.FileHandler(validated_path, mode='a', encoding='utf-8')
            if file_handler.stream is not None:
                stamp = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
                prefix = '\n' if needs_newline else ''
                file_handler.stream.write(
                    f'{prefix}==================== NEW SESSION STARTED AT : {stamp} ====================\n'
                )
                file_handler.stream.flush()
            file_handler.setLevel(logging.NOTSET)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s %(name)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            ))
            file_handler._debug_file = debug

            self._detach_log_file()
            self.logger.addHandler(file_handler)
            self.command_logger.addHandler(file_handler)
            self._log_file_handler = file_handler
            self._debug_file_enabled = debug
            if debug:
                for h in self._console_handlers():
                    if h.level == logging.NOTSET and self.logger.level != logging.NOTSET:
                        h.setLevel(self.logger.level)
                self.logger.setLevel(logging.DEBUG)
            try:
                from . import utils
                utils.set_file_permissions(file_handler.baseFilename)
            except Exception:
                logging.warning('Failed to set permissions on log file %s', file_handler.baseFilename)
            return file_handler.baseFilename
        except (ValueError, OSError) as e:
            logging.error('Failed to set up log file: %s', e)
            if file_handler is not None:
                file_handler.close()
            return None

    def _detach_log_file(self):
        h = self._log_file_handler
        if h is not None:
            self.logger.removeHandler(h)
            self.command_logger.removeHandler(h)
            try:
                h.close()
            except OSError as close_error:
                logging.warning('Failed to close log handler: %s', close_error)
        self._log_file_handler = None
        self._debug_file_enabled = False

    def _resolve_log_file_path(self, file_path):
        sanitized = _sanitize_log_file_path(file_path)
        expanded = os.path.expanduser(sanitized)
        separators = tuple(sep for sep in (os.sep, os.altsep) if sep)
        if expanded.endswith(separators) or os.path.isdir(expanded):
            expanded = os.path.join(expanded, DEFAULT_LOG_FILE)
        validated = self._validate_log_file_path(expanded)
        return self._timestamped_default_log_path(validated)

    def _timestamped_default_log_path(self, file_path, now=None):
        if os.path.basename(file_path) != DEFAULT_LOG_FILE or not os.path.exists(file_path):
            return file_path
        now = now or datetime.datetime.now()
        stem, ext = os.path.splitext(file_path)
        base = f"{stem}.{now.strftime('%Y-%m-%d.%H-%M-%S')}"
        candidate = base + ext
        counter = 1
        while os.path.exists(candidate):
            candidate = f'{base}.{counter}{ext}'
            counter += 1
        return candidate

    def _validate_log_file_path(self, file_path):
        """Validate and sanitize log file path to prevent security issues."""
        sanitized_path = _sanitize_log_file_path(file_path)
        path_obj = Path(sanitized_path)
        try:
            resolved_path = path_obj.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid file path: {e}")

        resolved_str = str(resolved_path).lower()
        forbidden_paths = (
            '/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
            '/boot/', '/dev/', '/proc/', '/sys/', '/root/',
        )
        for forbidden in forbidden_paths:
            if resolved_str.startswith(forbidden):
                raise ValueError(f"Access to system directory '{forbidden}' is not allowed")

        filename = path_obj.name
        if not filename or filename in ('.', '..'):
            raise ValueError("Invalid filename")

        for pattern in ('..', '~/', '$', '`', ';', '|', '&', '<', '>', '*', '?'):
            if pattern in filename:
                raise ValueError(f"Filename contains suspicious pattern: '{pattern}'")

        if not any(filename.lower().endswith(ext) for ext in ('.log', '.txt', '.out')):
            logging.warning("Log file '%s' does not have a standard log extension", filename)

        return str(resolved_path)

    def _looks_like_filename(self, token):
        """Check if a token looks like a filename with proper validation."""
        if not token or not isinstance(token, str):
            return False

        token = token.strip()

        if len(token) < 1:
            return False

        has_extension = re.search(r'\.[a-zA-Z0-9]{1,10}$', token)

        has_path_separator = '/' in token or '\\' in token

        looks_like_name = len(token) > 2 and re.match(r'^[a-zA-Z0-9._-]+$', token)

        return bool(has_extension or has_path_separator or looks_like_name)

    def toggle_console_debug(self, batch_mode):
        """Toggle console debug on/off."""
        current = self.is_console_debug_on(batch_mode)
        new_state = not current

        self.set_console_debug(new_state, batch_mode)

        if not self.has_debug_file_logging():
            level = logging.DEBUG if new_state else (logging.WARNING if batch_mode else logging.INFO)
            self.logger.setLevel(level)

        logging.info('Debug %s', 'ON' if new_state else 'OFF')
        return new_state

    def process_command(self, tokens, batch_mode):
        """Process debug command."""
        # Look for --file argument
        file_path = None
        file_flag_present = False

        for i, token in enumerate(tokens[1:], 1):
            if token == '--file':
                file_flag_present = True
                if i + 1 < len(tokens):
                    next_token = tokens[i + 1]
                    if not next_token.startswith('-'):
                        file_path = next_token
                break
            elif token.startswith('--file='):
                file_flag_present = True
                file_path = token.split('=', 1)[1]
                # Handle empty value after equals sign
                if not file_path.strip():
                    file_path = None
                break

        if file_flag_present and not file_path:
            print("Please specify the file path for logging to file: debug --file <file_path>")
            return False
        elif file_path:
            log_path = self.attach_log_file(file_path, debug=True)
            if log_path:
                logging.info('Logging to file: %s', log_path)
            return bool(log_path)
        else:
            # No --file flag present, check for potential filename arguments
            if len(tokens) > 1:
                for token in tokens[1:]:
                    # Check if token looks like a filename
                    if not token.startswith('-') and self._looks_like_filename(token):
                        print(f"Please specify the --file flag for logging to file: debug --file {token}")
                        return False

            self.toggle_console_debug(batch_mode)
            return True

debug_manager = DebugManager()


def read_command_with_continuation(prompt_session, params):
    """Read command with support for line continuation using backslash."""
    command_lines = []
    continuation_prompt = "... "
    current_prompt = get_prompt(params)

    while True:
        if prompt_session is not None:
            line = prompt_session.prompt(current_prompt)
        else:
            line = input(current_prompt)

        # Check if line ends with backslash (line continuation)
        # First strip all trailing whitespace, then check for backslash
        stripped_line = line.rstrip()
        if stripped_line.endswith('\\'):
            # Remove the backslash and any remaining whitespace
            line_content = stripped_line[:-1].strip()
            if line_content:  # Only add non-empty lines
                command_lines.append(line_content)
            current_prompt = continuation_prompt
        else:
            # No continuation, add the final line if it has content
            line_content = stripped_line
            if line_content:
                command_lines.append(line_content)
            break

    # Join all lines with spaces, ensuring no extra spaces
    # Also clean up any multiple spaces that might have been introduced
    result = ' '.join(command_lines)
    # Replace multiple spaces with single spaces to handle any remaining formatting issues
    import re
    result = re.sub(r'\s+', ' ', result).strip()
    return result


def loop(params, skip_init=False, suppress_goodbye=False, new_login=False):  # type: (KeeperParams, bool, bool, bool) -> int  # suppress_goodbye kept for API compat
    global prompt_session
    error_no = 0
    suppress_errno = False

    logging.getLogger().setLevel(logging.DEBUG if params.debug else logging.WARNING if params.batch_mode else logging.INFO)
    enforcement_checked = set()
    prompt_session = None
    if not params.batch_mode:
        if os.isatty(0) and os.isatty(1):
            completer = CommandCompleter(params, aliases)
            # Create key bindings with Ctrl+Q to exit (consistent with supershell)
            bindings = KeyBindings()
            @bindings.add('c-q')
            def _(event):
                """Exit shell on Ctrl+Q"""
                event.app.exit(exception=EOFError)
            prompt_session = PromptSession(multiline=False,
                                           editing_mode=EditingMode.VI,
                                           completer=completer,
                                           complete_style=CompleteStyle.MULTI_COLUMN,
                                           complete_while_typing=False,
                                           key_bindings=bindings)

        if not skip_init:
            display.welcome()
            versioning.welcome_print_version(params)
            # Show government warning for GOV environments when entering interactive shell
            if params.server and 'govcloud' in params.server.lower():
                display.show_government_warning()

    if not params.batch_mode and not skip_init:
        if params.user:
            try:
                LoginCommand().execute(params, email=params.user, password=params.password, new_login=new_login)
            except KeyboardInterrupt:
                logging.info('')
            except EOFError:
                return 0
            except Exception as e:
                logging.error(e)
        else:
            if params.device_token:
                logging.info('Region: %s', params.server)
            logging.info('')
            logging.info("You are not logged in.")
            logging.info(f'Type {Fore.GREEN}login <email>{Fore.RESET} to authenticate or {Fore.GREEN}server <region>{Fore.RESET} to change data centers.')
            logging.info(f'Type {Fore.GREEN}?{Fore.RESET} for a list of all available commands.')

    # Mark that we're in the shell loop (used by supershell to know if it should start a shell on exit)
    params._in_shell_loop = True

    # NB! USE_LOCAL_DAG=TRUE should be used only for testing. Warn here — after the
    # login/decrypt output, right before the first prompt — so the notice isn't buried:
    # the local test DAG engine routes PAM/DAG/discovery commands to a local SQLite
    # graph instead of the gateway/router, so they may fail or behave incorrectly
    # until it is disabled or removed.
    if not params.batch_mode and not skip_init:
        from .utils import value_to_boolean
        if value_to_boolean(os.environ.get('USE_LOCAL_DAG', False)):
            logging.warning(
                f"{Fore.YELLOW}USE_LOCAL_DAG=TRUE environment variable is enabled (local test DAG engine); "
                f"some PAM/DAG commands may fail. Unset it or set it to false to use the live gateway.{Fore.RESET}"
            )

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

                        command = read_command_with_continuation(prompt_session, params)
                    else:
                        command = read_command_with_continuation(None, params)
                    if tmer:
                        tmer.cancel()
                        tmer = None
                finally:
                    if tmer:
                        tmer.cancel()

            debug_manager.log_command(command)

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

    # Clear the shell loop flag
    params._in_shell_loop = False

    # Offer to update (install-script installations only; asks once per new version)
    from . import updater
    updater.prompt_for_update_on_exit(params)

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
            if f.parent_uid in params.folder_cache:
                f = params.folder_cache[f.parent_uid]
            else:
                # Parent UID not in folder_cache (e.g., Nested Share Folders with special root UID)
                f = params.root_folder
        else:
            if f.type == BaseFolderNode.SharedFolderFolderType:
                f = params.folder_cache[f.shared_folder_uid]
            else:
                f = params.root_folder
    if len(prompt) > 40:
        prompt = '...' + prompt[-37:]

    return prompt + '> '
