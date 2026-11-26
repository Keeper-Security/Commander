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


"""File and console logging for the Commander shell.

Holds the startup ``--file`` option parsing, the log file handler used by
``--file`` and ``debug --file``, and the ``debug`` command manager.
"""

import datetime
import logging
import os
import re
from pathlib import Path

from . import utils
from .commands.base import aliases, commands, enterprise_commands, msp_commands

# Root-logger file written when the shell is started with --file, or by debug --file.
DEFAULT_LOG_FILE = 'keeper.log'
# Handler markers. Every log file handler has KEEPER_LOG_FILE_ATTR; one opened
# by debug --file also has DEBUG_FILE_ATTR.
KEEPER_LOG_FILE_ATTR = '_keeper_log_file'
DEBUG_FILE_ATTR = '_debug_file'
# Logger for the command lines written by DebugManager.log_command.
COMMAND_LOGGER_NAME = 'keepercommander.command'
# Startup commands that open the shell. --file is honored only for these.
SHELL_START_COMMANDS = {'shell', '-'}


class LogFileOptionError(ValueError):
    """The startup ``--file`` option was given in a form that is not accepted."""


def _is_command_name(token):
    """True when token names a shell start command, a command or an alias."""
    name = token.lstrip('@')
    return (name in SHELL_START_COMMANDS or name in commands
            or name in enterprise_commands or name in msp_commands or name in aliases)


def _looks_like_path(token):
    """True when token has a file extension or a path separator."""
    return bool(re.search(r'\.[A-Za-z0-9]{1,10}$', token)) or '/' in token or '\\' in token


def _validate_bare_file_value(tokens, index):
    """Raise LogFileOptionError when the bare --file at index is followed by a path.

    A bare ``--file`` never takes a value, so ``--file my.log`` would log to
    ``keeper.log`` and then run ``my.log`` as a command. A following command
    name (``--file login``) is allowed.
    """
    if index + 1 >= len(tokens):
        return
    following = tokens[index + 1]
    if following.startswith('-') or _is_command_name(following):
        return
    if _looks_like_path(following):
        raise LogFileOptionError(
            f'--file does not take a separate value. Use --file={following}, '
            f'or a bare --file to write ./{DEFAULT_LOG_FILE}')


def parse_startup_command(parser, tokens):
    """Parse ``tokens`` only to find the startup command and its positional arguments.

    ``--file`` tokens are dropped first. They are not main-parser options, and
    before Python 3.12 an unknown option between the command and its arguments
    makes argparse return no ``options`` (``shell --file=a.log import`` gives
    ``options=[]``). Without them the result is the same on every version.
    """
    tokens = [t for t in tokens if t != '--file' and not t.startswith('--file=')]
    opts, _ = parser.parse_known_args(tokens)
    return opts


def extract_shell_log_file_arg(tokens, command, options=()):
    """Take ``--file`` from a shell startup command line.

    The flag is honored when this process is starting the shell (``shell`` or
    ``-``) and when no command is given. ``keeper.py`` starts the shell in that
    second case. A named command other than the shell keeps the tokens, so a
    command's own ``--file`` option (``import --file`` and so on) is untouched.

    * ``--file`` uses ``keeper.log``. The following token is not the file name.
      When that token looks like a path and is not a command, LogFileOptionError
      is raised so the user is told to write ``--file=PATH`` instead.
    * ``--file=NAME`` uses NAME. An empty NAME falls back to ``keeper.log``.

    Only the tokens before the shell's sub-command are read, so the
    sub-command's own ``--file`` (``shell import --file=a.json``) is kept.
    When the flag is given more than once, the last one wins.

    ``command`` is the startup command found by the main argument parser, or
    None when no command is given. ``options`` are the positional arguments the
    parser found after the command; the first one is the shell's sub-command.

    Returns ``(log_file, remaining_tokens)``. ``log_file`` is None
    when the flag is absent or this command is not a shell start.
    """
    tokens = list(tokens)
    # The parser already told the command and its arguments apart from option values,
    # so locate them by value rather than re-parsing the main-parser options here.
    command_index = len(tokens)
    if command is not None and command in tokens:
        command_index = tokens.index(command)

    if command is not None and command not in SHELL_START_COMMANDS:
        # Only a --file before the command belongs to startup. keeper --file my.log
        # would otherwise make my.log the command and run it as a batch file.
        for index in range(command_index):
            if tokens[index] == '--file':
                _validate_bare_file_value(tokens, index)
        return None, tokens

    # Tokens from the sub-command on belong to the sub-command.
    end = len(tokens)
    if command is not None and options and options[0] in tokens[command_index + 1:]:
        end = tokens.index(options[0], command_index + 1)

    log_file = None
    remaining = []
    for index, token in enumerate(tokens):
        if index >= end:
            remaining.append(token)
        elif token == '--file':
            _validate_bare_file_value(tokens, index)
            log_file = DEFAULT_LOG_FILE
        elif token.startswith('--file='):
            log_file = token.split('=', 1)[1].strip() or DEFAULT_LOG_FILE
        else:
            remaining.append(token)
    return log_file, remaining


_ANSI_ESCAPE_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


class PlainLogFormatter(logging.Formatter):
    """File formatter. Console color codes are removed from the stored line."""

    def format(self, record):
        return _ANSI_ESCAPE_RE.sub('', super().format(record))


class NonEmptyLogFilter(logging.Filter):
    """Skip blank records. Those calls only add space on the console."""

    def filter(self, record):
        text = _ANSI_ESCAPE_RE.sub('', record.getMessage())
        return bool(text.strip())


def _session_start_line():
    """A raw marker that shows where a new shell session was appended.

    The clock time is the machine's local time. The offset says which zone
    that clock used, without printing the zone name.
    """
    stamp = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    return '==================== NEW SESSION STARTED AT : %s ====================' % stamp


# One shell word. Quoted text stays inside its word, so a quoted value is never
# split into pieces that look like options. An unclosed quote runs to the end.
_COMMAND_WORD_RE = re.compile(r'''(?:[^\s"']|"[^"]*(?:"|$)|'[^']*(?:'|$))+''')
# Option name at the start of a word: -t, -kp, --format, --format=json -> --format
_OPTION_NAME_RE = re.compile(r'^--?[A-Za-z][\w-]*')


def redact_command_for_log(command_line):
    """Return the command name and the option names it was run with.

    Values the user typed (option values, positional arguments, field
    assignments) are left out, so ``record-add -t x --title=T password=p``
    becomes ``record-add -t --title``. Words after ``--`` are all arguments.
    """
    words = _COMMAND_WORD_RE.findall(command_line or '')
    if not words:
        return ''
    kept = [words[0].lstrip('@')]
    for word in words[1:]:
        if word == '--':
            break
        match = _OPTION_NAME_RE.match(word)
        if match:
            kept.append(match.group(0))
    return ' '.join(w for w in kept if w)


class DebugManager:
    """Debug manager for console and file logging."""
    
    def __init__(self):
        self.logger = logging.getLogger()
        # Command lines go only to the log file, never to the console, so this
        # logger does not propagate. attach_log_file gives it the file handler.
        self.command_logger = logging.getLogger(COMMAND_LOGGER_NAME)
        self.command_logger.propagate = False
        self.command_logger.setLevel(logging.INFO)
        self._log_file_handler = None

    def _expand_log_file_path(self, file_path):
        """Return the path the log file is written to.

        The path is used as given. A leading ``~`` is expanded, and a relative
        path is taken from the current directory.
        """
        return os.path.expanduser(file_path)

    def _validate_log_file_writable(self, file_path):
        """Raise ValueError when file_path cannot be opened for appending.

        A missing parent folder is allowed; attach_log_file creates it. The
        nearest folder that already exists must then be writable.
        """
        if os.path.isdir(file_path):
            raise ValueError(f"'{file_path}' is a directory, not a file")
        log_dir = os.path.dirname(file_path) or os.curdir
        if os.path.exists(file_path):
            if not os.access(file_path, os.W_OK):
                raise ValueError(f"No permission to write to '{file_path}'")
            return
        existing_dir = log_dir
        while not os.path.exists(existing_dir):
            parent = os.path.dirname(existing_dir)
            if parent == existing_dir:
                break
            existing_dir = parent
        if not os.path.isdir(existing_dir):
            raise ValueError(f"'{existing_dir}' is not a directory")
        if not os.access(existing_dir, os.W_OK | os.X_OK):
            raise ValueError(f"No permission to create a file in '{existing_dir}'")

    def has_debug_file_logging(self):
        """True when debug --file asked for DEBUG records in the log file."""
        return any(getattr(h, DEBUG_FILE_ATTR, False) for h in self.logger.handlers)

    def log_command(self, command_line):
        """Write the executed command to the log file only. The console does not show it again.

        Only the command name and its option names are written; the values the
        user typed are not (see redact_command_for_log).
        """
        if self._log_file_handler is None:
            return
        command_line = redact_command_for_log((command_line or '').strip())
        if command_line:
            self.command_logger.info('%s', command_line)
    
    def is_console_debug_on(self, batch_mode):
        """Check if console debug is enabled."""
        for h in self.logger.handlers:
            if not isinstance(h, logging.StreamHandler) or isinstance(h, logging.FileHandler):
                continue
            if not getattr(h, DEBUG_FILE_ATTR, False):
                return h.level == logging.DEBUG
        return self.logger.level == logging.DEBUG and not self.has_debug_file_logging()
    
    def set_console_debug(self, enabled, batch_mode):
        """Set console debug level."""
        level = logging.DEBUG if enabled else (logging.WARNING if batch_mode else logging.INFO)
        for h in self.logger.handlers:
            # Log files are FileHandlers (a StreamHandler subclass) and keep their own level.
            if not isinstance(h, logging.StreamHandler) or isinstance(h, logging.FileHandler):
                continue
            h.setLevel(level)

    def attach_log_file(self, file_path, debug=False):
        """Copy every root-logger record into file_path. Console logging is unchanged.

        Used by the shell startup option ``--file`` and by ``debug --file``.
        With ``debug=True`` the root logger is lowered to DEBUG so DEBUG records
        reach the file as well; the console keeps its own level.

        Child loggers propagate to the root logger, so this one handler covers
        logs emitted anywhere in Commander. A custom name and the default name
        both append to an existing file. Every session, including a new file,
        starts with a session-start line. Returns the path being written, or
        None when the file could not be opened.
        """
        fh = None
        try:
            expanded = self._expand_log_file_path(file_path)
            validated_path = self._validate_log_file_path(expanded)
            self._validate_log_file_writable(validated_path)
            # debug --file logs/debug.log has always created the missing folder.
            os.makedirs(os.path.dirname(validated_path), mode=0o750, exist_ok=True)

            self._detach_log_files()

            append_session = self._log_file_has_content(validated_path)
            needs_leading_newline = append_session and self._log_file_missing_trailing_newline(validated_path)
            fh = logging.FileHandler(validated_path, mode='a', encoding='utf-8')
            self._write_session_start(fh, needs_leading_newline)
            fh.setLevel(logging.NOTSET)
            fh.setFormatter(PlainLogFormatter(
                '%(asctime)s %(levelname)s %(name)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            ))
            fh.addFilter(NonEmptyLogFilter())
            setattr(fh, KEEPER_LOG_FILE_ATTR, True)
            if debug:
                setattr(fh, DEBUG_FILE_ATTR, True)
            self.logger.addHandler(fh)
            self.command_logger.addHandler(fh)
            self._log_file_handler = fh
            if debug:
                self.logger.setLevel(logging.DEBUG)
            try:
                utils.set_file_permissions(fh.baseFilename)
            except Exception:
                logging.warning('Failed to set permissions on log file %s', fh.baseFilename)
            return fh.baseFilename
        except (ValueError, OSError, IOError) as e:
            logging.error('Failed to set up log file: %s', e)
            if fh is not None:
                fh.close()
            return None
        except Exception as e:
            logging.error('Unexpected error setting up log file: %s', e)
            if fh is not None:
                fh.close()
            return None

    def _detach_log_files(self):
        """Remove and close the open log file handler, if any."""
        for h in list(self.logger.handlers):
            if getattr(h, KEEPER_LOG_FILE_ATTR, False):
                self.logger.removeHandler(h)
                self.command_logger.removeHandler(h)
                try:
                    h.close()
                except (OSError, IOError) as close_error:
                    logging.warning('Failed to close log handler: %s', close_error)
        self._log_file_handler = None

    def _log_file_has_content(self, file_path):
        """True when this session will continue an existing log, not a new file."""
        try:
            return os.path.getsize(file_path) > 0
        except OSError:
            return False

    def _log_file_missing_trailing_newline(self, file_path):
        """True when the last byte of file_path is not a line break."""
        try:
            with open(file_path, 'rb') as f:
                f.seek(-1, os.SEEK_END)
                return f.read(1) not in (b'\n', b'\r')
        except OSError:
            return False

    def _write_session_start(self, handler, needs_leading_newline):
        """Write the session marker directly, so it is not formatted as a log record.

        This writes to handler.stream without taking the handler lock. It is
        safe only because it runs before the handler is added to any logger,
        so no other thread can be writing to it yet.
        """
        stream = handler.stream
        if stream is None:
            return
        if needs_leading_newline:
            stream.write('\n')
        stream.write(_session_start_line() + '\n')
        stream.flush()

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
        
        if not self.has_debug_file_logging():
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
