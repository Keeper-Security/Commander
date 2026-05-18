#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""Confirmation prompts that gate every record-driven side effect in the
``connect`` / ``ssh`` commands. Defaults are *deny* (EOF, Ctrl-C and any
non-``y``/``yes`` answer all return False). Record text is stripped of
control characters before display so a malicious record cannot rewrite the
prompt with ANSI sequences.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, List, Optional


_BANNER_WIDTH = 72
_LONG_ARG_THRESHOLD = 80

_SHELL_INTERPRETERS = frozenset({
    'sh', 'bash', 'zsh', 'ksh', 'dash', 'ash', 'fish', 'tcsh', 'csh',
})

_OTHER_INTERPRETERS = frozenset({
    'python', 'python2', 'python3',
    'perl', 'ruby', 'node', 'nodejs', 'deno',
    'osascript', 'powershell', 'pwsh', 'cmd',
    'php', 'lua', 'tclsh', 'awk',
})

_DANGEROUS_ENV_NAMES = frozenset({
    'PATH', 'IFS',
    'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT',
    'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH',
    'BASH_ENV', 'ENV', 'PROMPT_COMMAND', 'PS4',
    'PYTHONSTARTUP', 'PYTHONPATH', 'PYTHONHOME',
    'PERL5OPT', 'PERL5LIB',
    'RUBYOPT', 'RUBYLIB',
    'NODE_OPTIONS', 'NODE_PATH',
    'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS',
    'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_EXEC_PATH',
    'SSH_ASKPASS', 'EDITOR', 'VISUAL', 'PAGER',
})

_DANGEROUS_ENV_PREFIXES = ('LD_', 'DYLD_')

_INTERPRETER_DASH_C_FLAGS = (
    '-c', '-lc', '-ic', '-Command', '-EncodedCommand',
    '-e', '-E', '/c', '/C',
)

_CONTROL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def _use_color() -> bool:
    isatty = getattr(sys.stderr, 'isatty', None)
    return bool(isatty and isatty()) and os.environ.get('NO_COLOR') is None


def _c(code: str, text: str) -> str:
    return f'\x1b[{code}m{text}\x1b[0m' if _use_color() else text


def _bold(s: str) -> str:        return _c('1', s)
def _dim(s: str) -> str:         return _c('2', s)
def _red(s: str) -> str:         return _c('31', s)
def _yellow(s: str) -> str:      return _c('33', s)
def _cyan(s: str) -> str:        return _c('36', s)
def _bold_red(s: str) -> str:    return _c('1;31', s)
def _bold_yellow(s: str) -> str: return _c('1;33', s)
def _bold_cyan(s: str) -> str:   return _c('1;36', s)


def _sanitize(text: Optional[str]) -> str:
    """Strip C0/C1 control characters (incl. ESC) from attacker-supplied text."""
    if not isinstance(text, str):
        return ''
    return _CONTROL_CHAR_RE.sub('', text)


def _is_interpreter(prog: Optional[str]) -> bool:
    if not prog:
        return False
    base = os.path.basename(prog).lower()
    if base.endswith('.exe'):
        base = base[:-4]
    return base in _SHELL_INTERPRETERS or base in _OTHER_INTERPRETERS


def _is_dangerous_env_name(name: Optional[str]) -> bool:
    upper = (name or '').upper()
    return upper in _DANGEROUS_ENV_NAMES or upper.startswith(_DANGEROUS_ENV_PREFIXES)


def _looks_multi_statement(arg: str) -> bool:
    return (
        len(arg) > _LONG_ARG_THRESHOLD
        or ';' in arg
        or '\n' in arg
        or '&&' in arg
        or '||' in arg
    )


def split_shell_statements(script: Optional[str]) -> List[str]:
    """Split a shell-script into top-level statements"""
    if not script:
        return []

    parts: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    escaped = False
    i, n = 0, len(script)

    def flush() -> None:
        stmt = ''.join(buf).strip()
        if stmt:
            parts.append(stmt)
        buf.clear()

    while i < n:
        c = script[i]
        if escaped:
            buf.append(c)
            escaped = False
        elif c == '\\' and quote != "'":
            buf.append(c)
            escaped = True
        elif quote is not None:
            buf.append(c)
            if c == quote:
                quote = None
        elif c in ('"', "'"):
            quote = c
            buf.append(c)
        elif c in ('\n', ';'):
            flush()
        elif c in ('&', '|') and i + 1 < n and script[i + 1] == c:
            flush()
            parts.append(c * 2)
            i += 1
        else:
            buf.append(c)
        i += 1

    flush()
    return parts


def read_yes_no(prompt: Optional[str] = None) -> bool:
    """Default-deny y/n reader."""
    if prompt is None:
        prompt = f'{_bold("Proceed? [y/n]")}{_dim(" (default: n): ")}'
    try:
        return input(prompt).strip().lower() in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        sys.stderr.write(_dim('\n(aborted - treated as "no")\n'))
        return False


def _hr() -> str:
    return _dim('─' * _BANNER_WIDTH)


def _emit_header(stage: str) -> None:
    sys.stderr.write(f'\n{_hr()}\n')
    sys.stderr.write(
        f'  {_bold_cyan("Confirmation required")}  {_dim("·")}  '
        f'{_cyan(_sanitize(stage))}\n'
    )
    sys.stderr.write(f'{_hr()}\n')


def _emit_record_source(record: Any) -> None:
    if record is None:
        return
    title = _sanitize(getattr(record, 'title', '')) or '<untitled>'
    uid = _sanitize(getattr(record, 'record_uid', '')) or '<no-uid>'
    sys.stderr.write(f'\n  {_bold("Source record")}: "{title}"\n')
    sys.stderr.write(f'  {_bold("UID")}:           {uid}\n')


def _emit_warning(lines: List[str]) -> None:
    if not lines:
        return
    sys.stderr.write(f'\n  {_bold_red("WARNING")}\n')
    for line in lines:
        sys.stderr.write(f'    {_red(line)}\n')


def _emit_section(label: str, body: List[str]) -> None:
    sys.stderr.write(f'\n  {_bold_yellow(label)}\n')
    for line in body:
        sys.stderr.write(line + '\n')


def _argv_block(argv: List[str]) -> List[str]:
    if not argv:
        return [f'    {_dim("(empty argv)")}']

    is_dash_c = (
        len(argv) >= 3
        and _is_interpreter(argv[0])
        and argv[1] in _INTERPRETER_DASH_C_FLAGS
    )

    lines: List[str] = []
    for i, raw in enumerate(argv):
        label = _dim(f'argv[{i}]')
        if is_dash_c and i == 2 and _looks_multi_statement(raw):
            stmts = split_shell_statements(raw)
            real = [s for s in stmts if s not in ('&&', '||')]
            if len(real) > 1:
                lines.append(f'    {label}  {len(real)} statements ({len(raw)} chars):')
                bar = _yellow('┃')
                for s in stmts:
                    lines.append(f'             {bar} {_sanitize(s)}')
                continue
        lines.append(f'    {label}  {_sanitize(raw)}')
    return lines


def confirm_argv(stage: str, argv: List[str], record: Any = None) -> bool:
    """Prompt before running a subprocess. Default-deny."""
    _emit_header(stage)
    _emit_record_source(record)
    warning_lines = [
        'Runs an external program with your user privileges.',
        'Can modify files, settings, or reach the network.',
    ]
    if argv and _is_interpreter(argv[0]):
        warning_lines.append(
            'argv[0] is a shell/scripting interpreter - it can run any code.'
        )
    _emit_warning(warning_lines)
    _emit_section('Command to execute:', _argv_block(argv))
    sys.stderr.write('\n')
    return read_yes_no(
        f'{_bold("Run this external command? [y/n]")}{_dim(" (default: n): ")}'
    )


def confirm_env(stage: str, name: str, value: str, record: Any = None) -> bool:
    """Prompt before setting an environment variable. Default-deny."""
    _emit_header(stage)
    _emit_record_source(record)
    if _is_dangerous_env_name(name):
        _emit_warning([
            f'{_sanitize(name)} can alter how subsequent programs load',
            'or execute code (loader hijack, init hook, runtime option).',
        ])
    _emit_section('Environment variable to set:', [
        f'    {_bold(_sanitize(name))} {_dim("=")} {_sanitize(value)}',
    ])
    sys.stderr.write('\n')
    return read_yes_no(
        f'{_bold("Set this variable? [y/n]")}{_dim(" (default: n): ")}'
    )


def confirm_ssh_key(stage: str, key_name: str, record: Any = None,
                    hint: Optional[str] = None) -> bool:
    """Prompt before loading a private key into the local ssh-agent. Default-deny."""
    _emit_header(stage)
    _emit_record_source(record)
    _emit_warning([
        'An SSH private key will be added to your local ssh-agent.',
        'Once loaded it can authenticate as you to any host that',
        'trusts it (including via forwarded agent: ssh -A).',
    ])
    details = [f'    {_dim("Name:")}  {_sanitize(key_name) or "<unnamed>"}']
    if hint:
        details.append(f'    {_dim("Hint:")}  {_sanitize(hint)}')
    _emit_section('Key details:', details)
    sys.stderr.write('\n')
    return read_yes_no(
        f'{_bold("Add this key to your agent? [y/n]")}{_dim(" (default: n): ")}'
    )
