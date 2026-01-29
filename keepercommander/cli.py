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
import re
import shlex
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

from . import api, display, ttk, utils
from . import versioning
from .autocomplete import CommandCompleter
from .commands import (
    register_commands, register_enterprise_commands, register_msp_commands,
    aliases, commands, command_info, enterprise_commands, msp_commands
)
from .commands.base import CliCommand, GroupCommand
from .commands.utils import LoginCommand
from .commands import msp
from .constants import OS_WHICH_CMD, KEEPER_PUBLIC_HOSTS, KEEPER_SERVERS
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

command_info['server'] = 'Sets or displays current Keeper region'

# Shell-specific commands (handled inline in the shell loop)
command_info['clear'] = 'Clear the screen'
command_info['history'] = 'Show command history'
command_info['quit'] = 'Exit the shell'
aliases['c'] = 'clear'
aliases['h'] = 'history'
aliases['q'] = 'quit'

logging.getLogger('asyncio').setLevel(logging.WARNING)


def display_command_help(show_enterprise=False, show_shell=False, show_legacy=False):
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
    ]
    domain_subcommands = [
        ('domain list (dl)', 'List all reserved domains for the enterprise'),
        ('domain reserve (dr)', 'Reserve, delete, or generate token for a domain'),
    ]

    for category in get_category_order():
        if category not in categorized_commands:
            continue
        if category == 'Legacy Commands' and not show_legacy:
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
        server = server.strip() if server else ''

        # Handle help flag
        if server in ('-h', '--help'):
            print('Usage: server [REGION]')
            print()
            print('Set or display the current Keeper region.')
            print()
            print('Valid regions:')
            print(f'  Production: US, EU, AU, CA, JP, GOV')
            print(f'  Dev:        US_DEV, EU_DEV, AU_DEV, CA_DEV, JP_DEV, GOV_DEV')
            print(f'  QA:         US_QA, EU_QA, AU_QA, CA_QA, JP_QA, GOV_QA')
            return

        if server:
            if not params.session_token:
                # Look up server in KEEPER_SERVERS (case insensitive)
                server_upper = server.upper()
                if server_upper in KEEPER_SERVERS:
                    params.server = KEEPER_SERVERS[server_upper]
                    logging.info('Keeper region is set to %s', server_upper)
                else:
                    # Check if it matches a valid hostname directly
                    server_lower = server.lower()
                    if server_lower in KEEPER_SERVERS.values():
                        params.server = server_lower
                        logging.info('Keeper server is set to %s', params.server)
                    else:
                        logging.error('Invalid region: %s', server)
                        print(f'Valid regions: {", ".join(sorted(KEEPER_SERVERS.keys()))}')
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
            print("  --file=PATH           write DEBUG logs to PATH (does not enable terminal DEBUG)")
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

            if cmd in commands or cmd in enterprise_commands or cmd in msp_commands:
                command = commands.get(cmd) or enterprise_commands.get(cmd) or msp_commands.get(cmd)
                global current_command
                current_command = command

                if command.is_authorised():
                    if not params.session_token:
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

class DebugManager:
    """Debug manager for console and file logging."""
    
    def __init__(self):
        self.logger = logging.getLogger()
    
    def has_file_logging(self):
        """Check if file logging is active."""
        return any(getattr(h, '_debug_file', False) for h in self.logger.handlers)
    
    def is_console_debug_on(self, batch_mode):
        """Check if console debug is enabled."""
        for h in self.logger.handlers:
            if isinstance(h, logging.StreamHandler) and not getattr(h, '_debug_file', False):
                return h.level == logging.DEBUG
        return self.logger.level == logging.DEBUG and not self.has_file_logging()
    
    def set_console_debug(self, enabled, batch_mode):
        """Set console debug level."""
        level = logging.DEBUG if enabled else (logging.WARNING if batch_mode else logging.INFO)
        for h in self.logger.handlers:
            if isinstance(h, logging.StreamHandler) and not getattr(h, '_debug_file', False):
                h.setLevel(level)
    
    def setup_file_logging(self, file_path):
        """Setup debug file logging."""
        try:
            validated_path = self._validate_log_file_path(file_path)
            
            log_dir = os.path.dirname(validated_path)
            os.makedirs(log_dir, mode=0o750, exist_ok=True)
            
            for h in list(self.logger.handlers):
                if getattr(h, '_debug_file', False):
                    self.logger.removeHandler(h)
                    try:
                        h.close()
                    except (OSError, IOError) as close_error:
                        logging.warning(f'Failed to close log handler: {close_error}')
                    except Exception as unexpected_error:
                        logging.error(f'Unexpected error closing log handler: {unexpected_error}')
            
            # Add new file handler
            fh = logging.FileHandler(validated_path, mode='a', encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s'))
            fh.addFilter(lambda record: record.levelno != logging.INFO)  # Filter out INFO
            fh._debug_file = True
            self.logger.addHandler(fh)
            self.logger.setLevel(logging.DEBUG)
            
            logging.info(f'Debug file logging enabled: {validated_path}')
            return True
        except (ValueError, OSError, IOError) as e:
            logging.error(f'Failed to setup file logging: {e}')
            return False
        except Exception as e:
            logging.error(f'Unexpected error setting up file logging: {e}')
            return False

    def _validate_log_file_path(self, file_path):
        """Validate and sanitize log file path to prevent security issues."""
        if not file_path or not isinstance(file_path, str):
            raise ValueError("File path must be a non-empty string")
        
        sanitized_path = ''.join(char for char in file_path if ord(char) >= 32 and char != '\x7f')
        
        if not sanitized_path:
            raise ValueError("File path contains only invalid characters")
        
        try:
            path_obj = Path(sanitized_path)
            
            resolved_path = path_obj.resolve()
                        
            resolved_str = str(resolved_path).lower()
            forbidden_paths = ['/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', 
                             '/boot/', '/dev/', '/proc/', '/sys/', '/root/']
            
            for forbidden in forbidden_paths:
                if resolved_str.startswith(forbidden):
                    raise ValueError(f"Access to system directory '{forbidden}' is not allowed")
            
            filename = path_obj.name
            if not filename or filename in ('.', '..'):
                raise ValueError("Invalid filename")
            
            suspicious_patterns = ['..', '~/', '$', '`', ';', '|', '&', '<', '>', '*', '?']
            for pattern in suspicious_patterns:
                if pattern in filename:
                    raise ValueError(f"Filename contains suspicious pattern: '{pattern}'")
            
            valid_extensions = ['.log', '.txt', '.out']
            if not any(filename.lower().endswith(ext) for ext in valid_extensions):
                logging.warning(f"Log file '{filename}' does not have a standard log extension")
            
            return str(resolved_path)
            
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid file path: {e}")
        except Exception as e:
            raise ValueError(f"Path validation failed: {e}")
    
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
        
        if not self.has_file_logging():
            level = logging.DEBUG if new_state else (logging.WARNING if batch_mode else logging.INFO)
            self.logger.setLevel(level)
        
        logging.info(f'Debug {"ON" if new_state else "OFF"}')
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
            return self.setup_file_logging(file_path)
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
                print('')
            except EOFError:
                return 0
            except Exception as e:
                logging.error(e)
        else:
            if params.device_token:
                logging.info('Region: %s', params.server)
            print()
            logging.info("You are not logged in.")
            print(f'Type {Fore.GREEN}login <email>{Fore.RESET} to authenticate or {Fore.GREEN}server <region>{Fore.RESET} to change data centers.')
            print(f'Type {Fore.GREEN}?{Fore.RESET} for a list of all available commands.')

    # Mark that we're in the shell loop (used by supershell to know if it should start a shell on exit)
    params._in_shell_loop = True

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
