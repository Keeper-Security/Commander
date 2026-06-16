#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""The ``mcp`` command: manage AI-agent (MCP) access to Commander.

All management verbs run in an interactive, human-authenticated session and write to the
dedicated MCP config vault record. ``mcp start`` runs the stdio MCP server itself and is
launched by the AI client.
"""

import argparse
import datetime
import json
import logging
import os
import uuid

from . import capabilities as caps_module, config as config_module
from ..commands.base import Command, GroupCommand, dump_report_data


def register_commands(commands):
    commands['mcp'] = MCPCommand()


def register_command_info(aliases, command_info):
    command_info['mcp'] = 'Manage AI agent (MCP) access to Commander'


CLIENT_TOKEN_ENV = 'KEEPER_MCP_CLIENT_TOKEN'


USAGE_HELP = """
The "mcp" command lets approved AI assistants (Claude Desktop, Cursor, VS Code, etc.)
securely operate on your vault, Secrets Manager, and KeeperPAM over the Model Context
Protocol (MCP). You decide which capabilities are exposed and which client agents may
connect; the running server can never read or change its own access settings.

Typical workflow:

  1. Turn on AI access:
       mcp enable

  2. Allow specific capabilities (see them with "mcp capability list"):
       mcp capability enable read_secret
       mcp capability enable search_records

  3. (Recommended) Scope sensitive capabilities to folders/records:
       mcp scope read_secret --add-folder <FOLDER_UID>

  4. Approve a client agent. This prints a one-time token and a ready-to-paste
     configuration block for your AI client:
       mcp client approve --name "Claude Desktop" --expire 7d \\
           --capabilities read_secret,search_records

  5. Paste the printed config into your AI client. It will launch the server itself:
       keeper mcp start --client-token <TOKEN>
     (or set the {env} environment variable instead of passing --client-token)

  6. Review and revoke at any time:
       mcp status
       mcp client list
       mcp client revoke "Claude Desktop"

Notes:
  - Capability/approval settings live in a dedicated vault record that the MCP server
    is forbidden from reading or modifying, so an agent cannot escalate its own access.
  - High-risk PAM capabilities (rotate, exec, query, sessions) default to OFF.
  - Revocation takes effect within the server refresh interval (default 60s); no restart
    of the agent is required.
  - "mcp start" requires the "mcp" Python package (pip install mcp) and a usable login
    (persistent login / device token) so the agent can open the vault non-interactively.
""".format(env=CLIENT_TOKEN_ENV)


class MCPCommand(GroupCommand):
    def __init__(self):
        super(MCPCommand, self).__init__()
        self.register_command('status', MCPStatusCommand(), 'Show MCP access status', 's')
        self.register_command('enable', MCPEnableCommand(), 'Enable AI agent access')
        self.register_command('disable', MCPDisableCommand(), 'Disable AI agent access')
        self.register_command('capability', MCPCapabilityCommand(), 'Manage allowed capabilities')
        self.register_command('scope', MCPScopeCommand(), 'Set folder/record scope for a capability')
        self.register_command('client', MCPClientCommand(), 'Manage connected agents (clients)')
        self.register_command('start', MCPStartCommand(), 'Start the stdio MCP server', 'serve')
        self.default_verb = 'status'

    def print_help(self, **kwargs):
        print(USAGE_HELP)
        super(MCPCommand, self).print_help(**kwargs)


# --------------------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------------------
class MCPStatusCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp status', description='Show MCP access status')

    def get_parser(self):
        return MCPStatusCommand.parser

    def execute(self, params, **kwargs):
        config = config_module.load_config(params)
        print('')
        print(f'AI Agent Access : {"ENABLED" if config.enabled else "disabled"}')
        if config.config_record_uid:
            print(f'Config record   : {config.config_record_uid}')
        else:
            print('Config record   : (not created yet — run "mcp enable")')
        print('')

        rows = []
        for name in caps_module.capability_names():
            cap = caps_module.get_capability(name)
            grant = config.capabilities.get(name)
            enabled = bool(grant and grant.enabled)
            scope = ''
            guard = ''
            if grant:
                parts = []
                if grant.scope.get('folders'):
                    parts.append(f'{len(grant.scope["folders"])} folder(s)')
                if grant.scope.get('records'):
                    parts.append(f'{len(grant.scope["records"])} record(s)')
                scope = ', '.join(parts) or ('all' if cap.scoped else '-')
                guard = ', '.join(f'{k}={v}' for k, v in (grant.guardrails or {}).items())
            elif cap.scoped:
                scope = 'all'
            rows.append([name, 'on' if enabled else 'off', 'yes' if cap.high_risk else '', scope, guard])
        dump_report_data(rows, headers=['Capability', 'Allowed', 'High-risk', 'Scope', 'Guardrails'],
                         title='Capabilities')
        print('')

        client_rows = []
        for c in config.clients:
            status = 'revoked' if c.revoked else ('expired' if c.is_expired() else 'active')
            client_rows.append([c.client_id[:12], c.name, status, c.created, c.expiration or 'never'])
        dump_report_data(client_rows, headers=['Client ID', 'Name', 'Status', 'Created', 'Expires'],
                         title=f'Connected Agents ({len(config.clients)})')
        print('')


# --------------------------------------------------------------------------------------
# enable / disable
# --------------------------------------------------------------------------------------
class MCPEnableCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp enable', description='Enable AI agent access')

    def get_parser(self):
        return MCPEnableCommand.parser

    def execute(self, params, **kwargs):
        config = config_module.load_config(params)
        config.enabled = True
        uid = config_module.save_config(params, config)
        logging.info('AI agent access enabled. Config stored in record %s', uid)


class MCPDisableCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp disable', description='Disable AI agent access')

    def get_parser(self):
        return MCPDisableCommand.parser

    def execute(self, params, **kwargs):
        config = config_module.load_config(params)
        if not config.config_record_uid:
            logging.info('AI agent access is not configured.')
            return
        config.enabled = False
        config_module.save_config(params, config)
        logging.info('AI agent access disabled.')


# --------------------------------------------------------------------------------------
# capability
# --------------------------------------------------------------------------------------
class MCPCapabilityCommand(GroupCommand):
    def __init__(self):
        super(MCPCapabilityCommand, self).__init__()
        self.register_command('list', MCPCapabilityListCommand(), 'List capabilities', 'l')
        self.register_command('enable', MCPCapabilityEnableCommand(), 'Enable a capability')
        self.register_command('disable', MCPCapabilityDisableCommand(), 'Disable a capability')
        self.default_verb = 'list'


class MCPCapabilityListCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp capability list', description='List capabilities')

    def get_parser(self):
        return MCPCapabilityListCommand.parser

    def execute(self, params, **kwargs):
        config = config_module.load_config(params)
        rows = []
        for name in caps_module.capability_names():
            cap = caps_module.get_capability(name)
            grant = config.capabilities.get(name)
            rows.append([name, 'on' if (grant and grant.enabled) else 'off',
                         'yes' if cap.high_risk else '', cap.description])
        dump_report_data(rows, headers=['Capability', 'Allowed', 'High-risk', 'Description'])


def _capability_arg(parser):
    parser.add_argument('capability', help='Capability name (see "mcp capability list")')


class MCPCapabilityEnableCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp capability enable', description='Enable a capability')
    _capability_arg(parser)

    def get_parser(self):
        return MCPCapabilityEnableCommand.parser

    def execute(self, params, **kwargs):
        name = kwargs['capability']
        if not caps_module.get_capability(name):
            logging.error('Unknown capability: %s', name)
            return
        config = config_module.load_config(params)
        grant = config.capabilities.setdefault(name, config_module.CapabilityGrant())
        grant.enabled = True
        config_module.save_config(params, config)
        logging.info('Capability "%s" enabled.', name)


class MCPCapabilityDisableCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp capability disable', description='Disable a capability')
    _capability_arg(parser)

    def get_parser(self):
        return MCPCapabilityDisableCommand.parser

    def execute(self, params, **kwargs):
        name = kwargs['capability']
        config = config_module.load_config(params)
        grant = config.capabilities.get(name)
        if grant:
            grant.enabled = False
            config_module.save_config(params, config)
        logging.info('Capability "%s" disabled.', name)


# --------------------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------------------
class MCPScopeCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp scope', description='Set folder/record scope for a capability')
    parser.add_argument('capability', help='Capability name')
    parser.add_argument('--add-folder', dest='add_folder', action='append', help='Add a folder UID to scope')
    parser.add_argument('--remove-folder', dest='remove_folder', action='append', help='Remove a folder UID')
    parser.add_argument('--add-record', dest='add_record', action='append', help='Add a record UID to scope')
    parser.add_argument('--remove-record', dest='remove_record', action='append', help='Remove a record UID')
    parser.add_argument('--clear', action='store_true', help='Clear all scope (unscoped)')

    def get_parser(self):
        return MCPScopeCommand.parser

    def execute(self, params, **kwargs):
        name = kwargs['capability']
        cap = caps_module.get_capability(name)
        if not cap:
            logging.error('Unknown capability: %s', name)
            return
        if not cap.scoped:
            logging.warning('Capability "%s" does not support folder/record scope.', name)
            return
        config = config_module.load_config(params)
        grant = config.capabilities.setdefault(name, config_module.CapabilityGrant())
        scope = grant.scope
        if kwargs.get('clear'):
            scope.clear()
        else:
            folders = set(scope.get('folders') or [])
            records = set(scope.get('records') or [])
            folders.update(kwargs.get('add_folder') or [])
            folders.difference_update(kwargs.get('remove_folder') or [])
            records.update(kwargs.get('add_record') or [])
            records.difference_update(kwargs.get('remove_record') or [])
            if folders:
                scope['folders'] = sorted(folders)
            else:
                scope.pop('folders', None)
            if records:
                scope['records'] = sorted(records)
            else:
                scope.pop('records', None)
        config_module.save_config(params, config)
        logging.info('Scope updated for "%s": %s', name, scope or 'unscoped')


# --------------------------------------------------------------------------------------
# client (connected agents)
# --------------------------------------------------------------------------------------
class MCPClientCommand(GroupCommand):
    def __init__(self):
        super(MCPClientCommand, self).__init__()
        self.register_command('approve', MCPClientApproveCommand(), 'Approve a new client agent', 'add')
        self.register_command('list', MCPClientListCommand(), 'List connected agents', 'l')
        self.register_command('revoke', MCPClientRevokeCommand(), 'Revoke a client agent', 'rm')
        self.default_verb = 'list'


class MCPClientApproveCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp client approve', description='Approve a new client agent')
    parser.add_argument('--name', required=True, help='Friendly name for the agent (e.g. "Claude Desktop")')
    parser.add_argument('--expire', help='Expiration (e.g. 30m, 24h, 7d). Default: never')
    parser.add_argument('--capabilities', help='Comma-separated capability subset for this client. Default: all enabled')

    def get_parser(self):
        return MCPClientApproveCommand.parser

    def execute(self, params, **kwargs):
        config = config_module.load_config(params)
        token = config_module.new_client_token()

        expiration = None
        if kwargs.get('expire'):
            from ..service.config.config_validation import ConfigValidator
            try:
                delta = ConfigValidator.parse_expiration_time(kwargs['expire'])
            except Exception as e:
                logging.error('Invalid --expire value: %s', e)
                return
            expiration = (datetime.datetime.now(datetime.timezone.utc) + delta).isoformat()

        grants = None
        if kwargs.get('capabilities'):
            grants = [c.strip() for c in kwargs['capabilities'].split(',') if c.strip()]
            unknown = [c for c in grants if not caps_module.get_capability(c)]
            if unknown:
                logging.error('Unknown capabilities: %s', ', '.join(unknown))
                return

        client = config_module.MCPClient(
            client_id=uuid.uuid4().hex,
            name=kwargs['name'],
            token_hash=config_module.hash_token(token),
            created=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            expiration=expiration,
            grants=grants,
        )
        config.clients.append(client)
        if not config.enabled:
            config.enabled = True
        config_module.save_config(params, config)

        snippet = {
            'mcpServers': {
                'keeper': {
                    'command': 'keeper',
                    'args': ['mcp', 'start', '--client-token', token],
                }
            }
        }
        print('')
        print(f'Approved client "{client.name}" (id {client.client_id}).')
        print('')
        print('Client token (shown ONCE — store it now; only its hash is saved):')
        print(f'  {token}')
        print('')
        print('Add this to your AI client\'s MCP configuration:')
        print(json.dumps(snippet, indent=2))
        print('')


class MCPClientListCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp client list', description='List connected agents')

    def get_parser(self):
        return MCPClientListCommand.parser

    def execute(self, params, **kwargs):
        config = config_module.load_config(params)
        rows = []
        for c in config.clients:
            status = 'revoked' if c.revoked else ('expired' if c.is_expired() else 'active')
            grants = 'all' if c.grants is None else ', '.join(c.grants)
            rows.append([c.client_id, c.name, status, c.created, c.expiration or 'never', grants])
        dump_report_data(rows, headers=['Client ID', 'Name', 'Status', 'Created', 'Expires', 'Capabilities'])


class MCPClientRevokeCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp client revoke', description='Revoke a client agent')
    parser.add_argument('client', help='Client ID or name')

    def get_parser(self):
        return MCPClientRevokeCommand.parser

    def execute(self, params, **kwargs):
        config = config_module.load_config(params)
        client = config.find_client(kwargs['client'])
        if not client:
            logging.error('No client matching: %s', kwargs['client'])
            return
        client.revoked = True
        config_module.save_config(params, config)
        logging.info('Revoked client "%s" (%s).', client.name, client.client_id)


# --------------------------------------------------------------------------------------
# start (run the stdio MCP server; launched by the AI client)
# --------------------------------------------------------------------------------------
class MCPStartCommand(Command):
    parser = argparse.ArgumentParser(prog='mcp start', description='Start the stdio MCP server')
    parser.add_argument('--client-token', dest='client_token',
                        help=f'Client token (or set {CLIENT_TOKEN_ENV})')
    parser.add_argument('--refresh-ttl', dest='refresh_ttl', type=int, default=60,
                        help='Seconds between config re-checks (revocation latency). Default 60')

    def get_parser(self):
        return MCPStartCommand.parser

    def execute(self, params, **kwargs):
        token = kwargs.get('client_token') or os.environ.get(CLIENT_TOKEN_ENV)
        if not token:
            logging.error('A client token is required. Pass --client-token or set %s.', CLIENT_TOKEN_ENV)
            return
        from . import server as server_module
        try:
            server_module.serve(params, token, refresh_ttl=kwargs.get('refresh_ttl') or 60)
        except server_module.MCPServerError as e:
            logging.error('%s', e)
