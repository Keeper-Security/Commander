#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
AI mode for Keeper Commander.

Translates natural language queries into Commander CLI commands using an
OpenAI-compatible LLM API. Zero vault secrets are sent to the cloud -- only
the public CLI grammar is included as context for the model.
"""

import argparse
import json
import logging
import os
import shlex
from collections import OrderedDict
from pathlib import Path
from typing import Optional, Tuple, Dict, List

from .base import (
    Command, GroupCommand, GroupCommandNew, ParseError,
    raise_parse_exception, suppress_exit,
    commands, enterprise_commands, msp_commands, aliases, command_info,
)
from ..params import KeeperParams

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AI_CONFIG_FILE = Path.home() / '.keeper' / 'ai_config.json'

_DEFAULT_CONFIG = {
    'endpoint': 'https://api.openai.com',
    'api_key': '',
    'model': 'gpt-4o',
    'tier': 0,
}


def load_ai_config():  # type: () -> dict
    """Load AI configuration from file, with env-var overrides."""
    config = dict(_DEFAULT_CONFIG)
    try:
        if AI_CONFIG_FILE.exists():
            with open(AI_CONFIG_FILE, 'r') as f:
                stored = json.load(f)
                config.update(stored)
    except Exception as e:
        logging.debug('Error loading AI config: %s', e)

    # Environment variable overrides
    env_endpoint = os.environ.get('KEEPER_AI_ENDPOINT')
    if env_endpoint:
        config['endpoint'] = env_endpoint
    env_key = os.environ.get('KEEPER_AI_API_KEY')
    if env_key:
        config['api_key'] = env_key
    env_model = os.environ.get('KEEPER_AI_MODEL')
    if env_model:
        config['model'] = env_model

    return config


def save_ai_config(config):  # type: (dict) -> None
    """Persist AI configuration to disk."""
    try:
        AI_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AI_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logging.error('Error saving AI config: %s', e)


# ---------------------------------------------------------------------------
# Grammar serializer
# ---------------------------------------------------------------------------

def _build_reverse_alias_map(alias_dict):
    # type: (Dict[str, object]) -> Dict[str, List[str]]
    """Build command-name -> [alias, ...] from the global aliases dict."""
    rev = {}  # type: Dict[str, List[str]]
    for alias, target in alias_dict.items():
        if isinstance(target, (tuple, list)):
            key = ' '.join(target)
        else:
            key = target
        rev.setdefault(key, []).append(alias if isinstance(alias, str) else ' '.join(alias))
    return rev


def _serialize_parser(parser, indent='  '):
    # type: (argparse.ArgumentParser, str) -> str
    """Serialize an argparse parser into a compact text grammar."""
    lines = []  # type: List[str]

    # Collect mutually exclusive groups
    mutex_map = {}  # type: Dict[int, int]
    for group_idx, group in enumerate(parser._mutually_exclusive_groups):
        for action in group._group_actions:
            mutex_map[id(action)] = group_idx

    positionals = []   # type: List[str]
    optionals = []     # type: List[str]

    for action in parser._actions:
        # Skip hidden/internal actions
        if action.help is argparse.SUPPRESS:
            continue
        if isinstance(action, argparse._HelpAction):
            continue
        if isinstance(action, argparse._SubParsersAction):
            # Handled separately below
            continue

        parts = []
        if action.option_strings:
            parts.append(', '.join(action.option_strings))
        else:
            parts.append(action.dest)

        # Type / choices / metavar
        if action.choices:
            parts.append('{' + ','.join(str(c) for c in action.choices) + '}')
        elif action.metavar:
            if isinstance(action.metavar, tuple):
                parts.append(' '.join(action.metavar))
            else:
                parts.append(action.metavar)
        elif action.type and action.type is not None:
            parts.append(action.type.__name__.upper())

        # Nargs annotation
        nargs_str = ''
        if action.nargs == '*':
            nargs_str = 'zero or more'
        elif action.nargs == '+':
            nargs_str = 'one or more'
        elif action.nargs == '?':
            nargs_str = 'optional'
        elif isinstance(action.nargs, int) and action.nargs > 1:
            nargs_str = f'{action.nargs} values'

        # Build description fragments
        desc_parts = []
        if isinstance(action, argparse._AppendAction):
            desc_parts.append('repeatable')
        if nargs_str:
            desc_parts.append(nargs_str)
        if action.required:
            desc_parts.append('required')
        if action.help and action.help is not argparse.SUPPRESS:
            desc_parts.append(action.help)
        if action.default is not None and action.default is not argparse.SUPPRESS:
            if not isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
                if action.default != '':
                    desc_parts.append(f'(default: {action.default})')

        # Mutex annotation
        if id(action) in mutex_map:
            desc_parts.append(f'[mutex group {mutex_map[id(action)]}]')

        line = indent + '  '.join(parts)
        if desc_parts:
            line += '  ' + '. '.join(desc_parts)

        if action.option_strings:
            optionals.append(line)
        else:
            positionals.append(line)

    if optionals:
        lines.append(indent + 'Options:')
        lines.extend(optionals)
    if positionals:
        lines.append(indent + 'Positional:')
        lines.extend(positionals)

    return '\n'.join(lines)


def _serialize_subparsers(parser, prefix, indent='  '):
    # type: (argparse.ArgumentParser, str, str) -> str
    """Serialize any add_subparsers()-based sub-commands."""
    lines = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, subparser in action.choices.items():
                sub_prefix = f'{prefix} {name}'
                desc = subparser.description or ''
                lines.append(f'\nCOMMAND: {sub_prefix}')
                if desc:
                    lines.append(f'{indent}Description: {desc}')
                body = _serialize_parser(subparser, indent)
                if body:
                    lines.append(body)
    return '\n'.join(lines)


def _walk_group_command(group_cmd, prefix, alias_rev, category_lookup, indent='  '):
    # type: (GroupCommand, str, Dict, Dict, str) -> List[str]
    """Recursively walk a GroupCommand tree and serialize each leaf."""
    blocks = []
    for verb, sub_cmd in group_cmd._commands.items():
        sub_prefix = f'{prefix} {verb}'

        # Build sub-alias list from the group's own _aliases
        sub_aliases = [a for a, v in group_cmd._aliases.items() if v == verb]

        if isinstance(sub_cmd, (GroupCommand, GroupCommandNew)):
            # Recurse
            blocks.extend(_walk_group_command(sub_cmd, sub_prefix, alias_rev, category_lookup, indent))
        elif isinstance(sub_cmd, Command):
            parser = sub_cmd.get_parser()
            desc = ''
            if parser:
                desc = parser.description or ''
            if not desc:
                desc = group_cmd._command_info.get(verb, '')
            block_lines = [f'COMMAND: {sub_prefix}']
            if sub_aliases:
                block_lines.append(f'{indent}Aliases: {", ".join(sub_aliases)}')
            if desc:
                block_lines.append(f'{indent}Description: {desc}')
            if parser:
                body = _serialize_parser(parser, indent)
                if body:
                    block_lines.append(body)
                # Check for add_subparsers
                sp = _serialize_subparsers(parser, sub_prefix, indent)
                if sp:
                    block_lines.append(sp)
            blocks.append('\n'.join(block_lines))
        # else: CliCommand without parser -- skip
    return blocks


def serialize_grammar(include_enterprise=False, include_msp=False):
    # type: (bool, bool) -> str
    """Walk all registered command parsers and produce a compact text grammar."""
    from ..command_categories import get_command_category

    alias_rev = _build_reverse_alias_map(aliases)
    category_lookup = {}  # cmd_name -> category

    # Determine which command dicts to include
    cmd_sources = [('commands', commands)]
    if include_enterprise:
        cmd_sources.append(('enterprise', enterprise_commands))
    if include_msp:
        cmd_sources.append(('msp', msp_commands))

    blocks = []  # type: List[str]
    indent = '  '

    for source_label, cmd_dict in cmd_sources:
        for cmd_name, cmd_obj in cmd_dict.items():
            category = get_command_category(cmd_name)
            category_lookup[cmd_name] = category

            # Collect top-level aliases for this command
            cmd_aliases = alias_rev.get(cmd_name, [])

            if isinstance(cmd_obj, (GroupCommand, GroupCommandNew)):
                # Emit a header for the group, then recurse
                desc = ''
                if isinstance(cmd_obj, GroupCommandNew):
                    desc = cmd_obj.description or ''
                if not desc:
                    # Check command_info
                    desc = command_info.get(cmd_name, '')
                block_lines = [f'COMMAND: {cmd_name}']
                if cmd_aliases:
                    block_lines.append(f'{indent}Aliases: {", ".join(cmd_aliases)}')
                if category:
                    block_lines.append(f'{indent}Category: {category}')
                if desc:
                    block_lines.append(f'{indent}Description: {desc}')
                if cmd_obj.default_verb:
                    block_lines.append(f'{indent}Default subcommand: {cmd_obj.default_verb}')
                sub_verbs = list(cmd_obj._commands.keys())
                if sub_verbs:
                    block_lines.append(f'{indent}Subcommands: {", ".join(sub_verbs)}')
                blocks.append('\n'.join(block_lines))

                # Recurse into subcommands
                sub_blocks = _walk_group_command(
                    cmd_obj, cmd_name, alias_rev, category_lookup, indent)
                blocks.extend(sub_blocks)

            elif isinstance(cmd_obj, Command):
                parser = cmd_obj.get_parser()
                desc = ''
                if parser:
                    desc = parser.description or ''
                if not desc:
                    desc = command_info.get(cmd_name, '')
                block_lines = [f'COMMAND: {cmd_name}']
                if cmd_aliases:
                    block_lines.append(f'{indent}Aliases: {", ".join(cmd_aliases)}')
                if category:
                    block_lines.append(f'{indent}Category: {category}')
                if desc:
                    block_lines.append(f'{indent}Description: {desc}')
                if parser:
                    body = _serialize_parser(parser, indent)
                    if body:
                        block_lines.append(body)
                    # Check for add_subparsers
                    sp = _serialize_subparsers(parser, cmd_name, indent)
                    if sp:
                        block_lines.append(sp)
                blocks.append('\n'.join(block_lines))

    return '\n\n'.join(blocks)


# ---------------------------------------------------------------------------
# Parse validator
# ---------------------------------------------------------------------------

def validate_command(command_str):
    # type: (str) -> Tuple[bool, Optional[str]]
    """
    Validate a generated command string against registered parsers without
    executing.  Returns (True, None) on success or (False, error_message).
    """
    from ..cli import command_and_args_from_cmd

    command_str = command_str.strip()
    if not command_str:
        return False, 'Empty command'

    cmd, args = command_and_args_from_cmd(command_str)
    if not cmd:
        return False, 'Empty command'

    orig_cmd = cmd

    # Resolve aliases (same logic as cli.py:371-377)
    if cmd in aliases and cmd not in commands and cmd not in enterprise_commands and cmd not in msp_commands:
        ali = aliases[cmd]
        if isinstance(ali, (tuple, list)):
            cmd = ali[0]
            args = ' '.join(ali[1:]) + ' ' + args
        else:
            cmd = ali

    # Find the command object
    cmd_obj = commands.get(cmd) or enterprise_commands.get(cmd) or msp_commands.get(cmd)
    if cmd_obj is None:
        return False, f"Unknown command: '{orig_cmd}'"

    return _validate_command_obj(cmd_obj, cmd, args)


def _validate_command_obj(cmd_obj, cmd_name, args):
    # type: (object, str, str) -> Tuple[bool, Optional[str]]
    """Validate args against a Command or GroupCommand."""
    if isinstance(cmd_obj, (GroupCommand, GroupCommandNew)):
        return _validate_group_command(cmd_obj, cmd_name, args)
    elif isinstance(cmd_obj, Command):
        return _validate_simple_command(cmd_obj, cmd_name, args)
    return True, None  # Unknown command type -- allow


def _validate_group_command(group_cmd, cmd_name, args):
    # type: (GroupCommand, str, str) -> Tuple[bool, Optional[str]]
    """Validate against a GroupCommand by extracting the verb and recursing."""
    args = args.strip()
    if args.startswith('-- '):
        args = args[3:].strip()

    pos = args.find(' ')
    if pos > 0:
        verb = args[:pos].strip()
        remaining = args[pos + 1:].strip()
    else:
        verb = args.strip()
        remaining = ''

    if not verb:
        if group_cmd.default_verb:
            verb = group_cmd.default_verb
        else:
            return False, f"'{cmd_name}' requires a subcommand"

    verb = verb.lower()
    if verb in ('-h', '--help', 'help'):
        return True, None

    # Resolve group-level aliases
    if verb in group_cmd._aliases:
        verb = group_cmd._aliases[verb]

    sub_cmd = group_cmd._commands.get(verb)
    if sub_cmd is None:
        valid_verbs = ', '.join(group_cmd._commands.keys())
        return False, f"Unknown subcommand '{verb}' for '{cmd_name}'. Valid: {valid_verbs}"

    return _validate_command_obj(sub_cmd, f'{cmd_name} {verb}', remaining)


def _validate_simple_command(cmd_obj, cmd_name, args):
    # type: (Command, str, str) -> Tuple[bool, Optional[str]]
    """Validate args against a Command's argparse parser."""
    parser = cmd_obj.get_parser()
    if parser is None:
        return True, None  # No parser -- any args accepted

    # Temporarily wire up error/exit handlers
    old_error = parser.error
    old_exit = parser.exit
    parser.error = raise_parse_exception
    parser.exit = suppress_exit

    try:
        tokens = shlex.split(args)
    except ValueError as e:
        return False, f"Parse error for '{cmd_name}': {e}"

    try:
        if cmd_obj.support_extra_parameters():
            parser.parse_known_args(tokens)
        else:
            parser.parse_args(tokens)
        return True, None
    except ParseError as e:
        msg = str(e).strip()
        if msg:
            return False, f"Parse error for '{cmd_name}': {msg}"
        return False, f"Parse error for '{cmd_name}'"
    except SystemExit:
        return False, f"Parse error for '{cmd_name}'"
    finally:
        parser.error = old_error
        parser.exit = old_exit


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_TEMPLATE = """\
You are a command-line assistant for Keeper Commander.
Translate the user's natural language request into a single Commander command.

RULES:
1. Output ONLY the command string. No explanation, no markdown, no quotes.
2. Use only commands and options from the grammar below.
3. Never invent options that don't exist in the grammar.
4. For record/folder references, use the name or UID the user provides.
5. Use shell quoting for arguments containing spaces.
6. If the request cannot be mapped, output: ERROR: <brief reason>

COMMAND GRAMMAR:
{grammar}
"""


def _call_llm_api(config, messages):
    # type: (dict, list) -> str
    """Make a single OpenAI-compatible chat completions request."""
    import requests

    endpoint = config['endpoint'].rstrip('/')
    # Auto-append path if not already present
    if not endpoint.endswith('/v1/chat/completions'):
        if endpoint.endswith('/v1'):
            endpoint += '/chat/completions'
        else:
            endpoint += '/v1/chat/completions'

    headers = {'Content-Type': 'application/json'}
    api_key = config.get('api_key', '')
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'

    payload = {
        'model': config.get('model', 'gpt-4o'),
        'messages': messages,
        'temperature': 0,
        'max_tokens': 256,
    }

    resp = requests.post(endpoint, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    # Extract the response text
    choices = data.get('choices', [])
    if not choices:
        raise RuntimeError('LLM returned no choices')
    return choices[0].get('message', {}).get('content', '').strip()


def _clean_response(text):
    # type: (str) -> str
    """Strip markdown fencing and whitespace from LLM response."""
    text = text.strip()
    # Remove markdown code fencing
    if text.startswith('```'):
        lines = text.split('\n')
        # Remove first line (```bash, ```shell, ```, etc.)
        lines = lines[1:]
        # Remove trailing ```
        if lines and lines[-1].strip() == '```':
            lines = lines[:-1]
        text = '\n'.join(lines).strip()
    # Remove inline backticks
    if text.startswith('`') and text.endswith('`'):
        text = text[1:-1].strip()
    return text


def call_llm_with_retry(config, grammar, query, max_retries=2):
    # type: (dict, str, str, int) -> Tuple[bool, str]
    """
    Send the grammar + query to the LLM, validate the response, and retry
    on parse errors.

    Returns (success, result) where result is the command string on success
    or an error message on failure.
    """
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(grammar=grammar)
    messages = [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': query},
    ]

    for attempt in range(1 + max_retries):
        try:
            raw = _call_llm_api(config, messages)
        except Exception as e:
            return False, f'LLM API error: {e}'

        candidate = _clean_response(raw)
        if not candidate:
            return False, 'LLM returned an empty response'

        # Model signals it cannot map the request
        if candidate.upper().startswith('ERROR:'):
            return False, candidate

        # Validate against parsers
        valid, err = validate_command(candidate)
        if valid:
            return True, candidate

        # Retry: append the error as a new user message
        if attempt < max_retries:
            messages.append({'role': 'assistant', 'content': raw})
            messages.append({'role': 'user', 'content': f'That command failed validation: {err}\nPlease fix and output only the corrected command.'})
        else:
            return False, f'Command failed validation after {max_retries + 1} attempts: {err}\nLast attempt: {candidate}'

    return False, 'Unexpected error in retry loop'


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

ai_parser = argparse.ArgumentParser(
    prog='ai',
    description='Translate natural language to Commander commands using AI',
)
ai_parser.add_argument('query', nargs='+', help='natural language query')
ai_parser.add_argument('--yes', '-y', dest='auto_execute', action='store_true',
                        help='skip confirmation and auto-execute')
ai_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                        help='show generated command but do not execute')
ai_parser.add_argument('--tier', dest='tier', type=int, choices=[0, 1, 2],
                        help='metadata tier override (0=grammar only)')
ai_parser.add_argument('--enterprise', dest='enterprise', action='store_true',
                        help='include enterprise commands in grammar')
ai_parser.add_argument('--msp', dest='msp', action='store_true',
                        help='include MSP commands in grammar')


class AiCommand(Command):
    def get_parser(self):
        return ai_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        query_parts = kwargs.get('query') or []
        query = ' '.join(query_parts)
        if not query:
            logging.error('Please provide a natural language query.')
            return

        auto_execute = kwargs.get('auto_execute', False)
        dry_run = kwargs.get('dry_run', False)
        include_enterprise = kwargs.get('enterprise', False)
        include_msp = kwargs.get('msp', False)

        config = load_ai_config()
        if not config.get('api_key') and not os.environ.get('KEEPER_AI_API_KEY'):
            endpoint = config.get('endpoint', '')
            # Allow keyless access for local endpoints (Ollama, etc.)
            if endpoint and not any(h in endpoint for h in ('localhost', '127.0.0.1', '0.0.0.0', '192.168.', '10.')):
                logging.error('AI not configured. Set API key in ~/.keeper/ai_config.json or KEEPER_AI_API_KEY env var.')
                return

        # Generate grammar
        grammar = serialize_grammar(
            include_enterprise=include_enterprise,
            include_msp=include_msp,
        )

        # Call LLM
        success, result = call_llm_with_retry(config, grammar, query)
        if not success:
            logging.error(result)
            return

        print(f'  {result}')

        if dry_run:
            return

        # Confirm unless --yes
        if not auto_execute:
            try:
                answer = input('\nExecute this command? [Y/n] ').strip().lower()
                if answer and answer not in ('y', 'yes', ''):
                    print('Cancelled.')
                    return
            except (EOFError, KeyboardInterrupt):
                print('\nCancelled.')
                return

        # Execute
        from ..cli import do_command
        return do_command(params, result)


ai_grammar_parser = argparse.ArgumentParser(
    prog='ai-grammar',
    description='Dump the command grammar used by AI mode',
)
ai_grammar_parser.add_argument('--enterprise', dest='enterprise', action='store_true',
                                help='include enterprise commands')
ai_grammar_parser.add_argument('--msp', dest='msp', action='store_true',
                                help='include MSP commands')
ai_grammar_parser.add_argument('--output', dest='output', action='store',
                                help='write grammar to file instead of stdout')
ai_grammar_parser.add_argument('--count-tokens', dest='count_tokens', action='store_true',
                                help='estimate token count (chars/4)')


class AiGrammarCommand(Command):
    def get_parser(self):
        return ai_grammar_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        include_enterprise = kwargs.get('enterprise', False)
        include_msp = kwargs.get('msp', False)
        output_file = kwargs.get('output')
        count_tokens = kwargs.get('count_tokens', False)

        grammar = serialize_grammar(
            include_enterprise=include_enterprise,
            include_msp=include_msp,
        )

        if output_file:
            with open(output_file, 'w') as f:
                f.write(grammar)
            logging.info('Grammar written to %s', os.path.abspath(output_file))
        else:
            print(grammar)

        if count_tokens:
            char_count = len(grammar)
            est_tokens = char_count // 4
            print(f'\n--- Token estimate: ~{est_tokens:,} tokens ({char_count:,} chars) ---')
