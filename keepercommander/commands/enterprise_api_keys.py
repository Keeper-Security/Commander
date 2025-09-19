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

import argparse
import json
import logging
import base64
import os
import datetime
from typing import Optional, List, Dict, Any

from .base import GroupCommand, dump_report_data, report_output_parser, field_to_title, user_choice
from .enterprise_common import EnterpriseCommand
from .. import api, utils
from ..display import bcolors
from ..error import CommandError
from ..params import KeeperParams
from ..proto import publicapi_pb2

api_key_list_parser = argparse.ArgumentParser(
    prog='public-api-key list', 
    parents=[report_output_parser],
    description='Display a list of enterprise API keys.',
    epilog='''
Examples:
  # List all API keys in table format
  public-api-key list
  
  # List API keys in JSON format
  public-api-key list --format json
  
  # Save API keys list to CSV file
  public-api-key list --format csv --output api_keys.csv
    ''',
    formatter_class=argparse.RawDescriptionHelpFormatter
)

api_key_generate_parser = argparse.ArgumentParser(
    prog='public-api-key generate', 
    description='Generate a new enterprise API key.',
    epilog='''
Examples:
  # Generate API key with SIEM role and 30-day expiration
  public-api-key generate --name "SIEM Integration" --roles "SIEM:2" --expires 30d
  
  # Generate API key with multiple roles and 24-hour expiration
  public-api-key generate --name "Temp Access" --roles "Admin:1,SIEM:2" --expires 24h
  
  # Generate permanent API key with read-only access
  public-api-key generate --name "Monitoring Tool" --roles "ReadOnly:1" --expires never
  
  # Generate API key and save details to JSON file
  public-api-key generate --name "Backup Tool" --roles "Backup:2" --expires 1y --format json --output backup_key.json
    ''',
    formatter_class=argparse.RawDescriptionHelpFormatter
)
api_key_generate_parser.add_argument('--name', dest='name', required=True, 
                                     help='API key name. Examples: "SIEM Integration", "Backup Tool", "Monitoring Service"')
api_key_generate_parser.add_argument('--roles', dest='roles', required=True, action='store', 
                                     help='''Comma-separated list of role IDs with action types. 
Format: "RoleID:ActionType" or "RoleName:ActionType"
Action types: 0=NONE (no permissions), 1=READ (read-only), 2=READ_WRITE (full access)
Examples: 
  --roles "SIEM:2"                    # SIEM role with read-write access
  --roles "Admin:1,SIEM:2"            # Multiple roles with different permissions
  --roles "123:1,456:2"               # Using role IDs instead of names
  --roles "ReadOnly:1"                # Read-only access
  --roles "Backup:2,Monitor:1"        # Backup with full access, Monitor with read-only''')
api_key_generate_parser.add_argument('--expires', dest='expires', action='store',
                                     choices=['24h', '7d', '30d', '1y', 'never'],
                                     default='never',
                                     help='''Expiration time for the API key:
  24h   = 24 hours from now (temporary access)
  7d    = 7 days from now (short-term projects)
  30d   = 30 days from now (monthly integrations)
  1y    = 1 year from now (long-term integrations)
  never = never expires (permanent access, use with caution)
Default: never''')
api_key_generate_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                                     help='''Output format:
  table = human-readable table format (default)
  json  = JSON format for programmatic use''')
api_key_generate_parser.add_argument('--output', dest='output', action='store',
                                     help='''Output file name (only used with --format json).
Examples: 
  --output api_key.json
  --output /path/to/keys/siem_key.json
If not specified, JSON output is printed to console.''')

api_key_revoke_parser = argparse.ArgumentParser(
    prog='public-api-key revoke', 
    description='Revoke an enterprise API key.',
    epilog='''
Examples:
  # Revoke API key with confirmation prompt
  public-api-key revoke 12345
  
  # Revoke API key without confirmation (force)
  public-api-key revoke 12345 --force
  
  # Short form with force flag
  public-api-key revoke 12345 -f

Tips:
  - Use 'public-api-key list' to find the Token you want to revoke
  - Revoked keys cannot be restored, only new keys can be generated
  - Use --force to skip the confirmation prompt (useful for scripts)
    ''',
    formatter_class=argparse.RawDescriptionHelpFormatter
)
api_key_revoke_parser.add_argument('token', 
                                   help='API key Token (get this from "api-key list" command). Example: 12345')
api_key_revoke_parser.add_argument('--force', '-f', dest='force', action='store_true', 
                                   help='Revoke without confirmation prompt (useful for automated scripts)')


def register_commands(commands):
    commands['public-api-key'] = ApiKeyCommand()


def register_command_info(aliases, command_info):
    command_info['public-api-key'] = 'Manage Admin REST API keys for 3rd party integrations'


class ApiKeyCommand(GroupCommand):
    def __init__(self):
        super(ApiKeyCommand, self).__init__()
        self.register_command('list', ApiKeyListCommand())
        self.register_command('generate', ApiKeyGenerateCommand())
        self.register_command('revoke', ApiKeyRevokeCommand())
        self.default_verb = 'list'
    
    def print_help(self, **kwargs):
        print('Enterprise API Key Management')
        print('=' * 50)
        print()
        print('Commands:')
        print('  list      - Display all enterprise API keys')
        print('  generate  - Create a new API key with specified roles and expiration')
        print('  revoke    - Revoke an existing API key')
        print()
        print('Quick Start Examples:')
        print('  # List all API keys')
        print('  public-api-key list')
        print()
        print('  # Generate a new API key for SIEM integration (30-day expiration)')
        print('  public-api-key generate --name "SIEM Tool" --roles "SIEM:2" --expires 30d')
        print()
        print('  # Revoke an API key')
        print('  public-api-key revoke 12345')
        print()
        print('Role Action Types:')
        print('  1 = READ       (read-only access)')
        print('  2 = READ_WRITE (full access)')
        print()
        print('Expiration Options:')
        print('  24h   = 24 hours    7d = 7 days    30d = 30 days')
        print('  1y    = 1 year      never = permanent (use with caution)')
        print()
        print('For detailed help on any command, use:')
        print('  public-api-key <command> --help')
        print('  Example: public-api-key generate --help')
        print()


class ApiKeyListCommand(EnterpriseCommand):
    def get_parser(self):
        return api_key_list_parser

    def execute(self, params, **kwargs):
        fmt = kwargs.get('format') or ''
        headers = ['token', 'enterprise_id', 'name', 'status', 'issued_date', 'expiration_date', 'roles']
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]

        table = []
        try:
            # Create request for listing tokens
            rq = publicapi_pb2.ListPublicApiTokenRequest()
            rq.statusFilter = publicapi_pb2.StatusFilter.ALL
            
            # Call the REST API
            rs = api.communicate_rest(
                params, rq, 
                'public_api/list_token',
                rs_type=publicapi_pb2.PublicApiTokenResponseList
            )
            
            for token in rs.tokens:
                issued_date = ''
                if token.issuedDate:
                    dt = datetime.datetime.fromtimestamp(token.issuedDate / 1000)
                    issued_date = dt.strftime('%Y-%m-%d %H:%M:%S')
                
                expiration_date = 'Never'
                if token.expirationDate:
                    dt = datetime.datetime.fromtimestamp(token.expirationDate / 1000)
                    expiration_date = dt.strftime('%Y-%m-%d %H:%M:%S')
                
                roles_str = ', '.join([f"{integration.roleName}:{integration.actionType}" 
                                     for integration in token.integrations])
                
                if token.expirationDate and token.expirationDate < int(datetime.datetime.now().timestamp() * 1000):
                    status = 'Expired'
                else:
                    status = 'Active'
                
                
                row = [
                    token.token,
                    token.enterprise_id,
                    token.name,
                    status,
                    issued_date,
                    expiration_date,
                    roles_str
                ]
                table.append(row)
                
        except Exception as e:
            logging.error(f"Failed to list API keys: {e}")
            raise CommandError("Failed to retrieve API keys")
        
        return dump_report_data(table, headers=headers, fmt=fmt, filename=kwargs.get('output'))


class ApiKeyGenerateCommand(EnterpriseCommand):
    def get_parser(self):
        return api_key_generate_parser

    def execute(self, params, **kwargs):
        name = kwargs.get('name')
        if not name:
            print("API key name is required")
            return

        try:
            # Create the generate token request
            rq = publicapi_pb2.GenerateTokenRequest()
            rq.tokenName = name
            rq.issuedDate = int(datetime.datetime.now().timestamp() * 1000)
            
            # Set expiration based on the selected option
            expires = kwargs.get('expires', 'never')
            if expires != 'never':
                now = datetime.datetime.now()
                if expires == '24h':
                    expiration_date = now + datetime.timedelta(hours=24)
                elif expires == '7d':
                    expiration_date = now + datetime.timedelta(days=7)
                elif expires == '30d':
                    expiration_date = now + datetime.timedelta(days=30)
                elif expires == '1y':
                    expiration_date = now + datetime.timedelta(days=365)
                else:
                    print(f"Invalid expiration option: {expires}")
                    return
                
                rq.expirationDate = int(expiration_date.timestamp() * 1000)
            # If expires == 'never', don't set expirationDate (it remains unset/blank)
            
            # Parse roles - now required
            roles_str = kwargs.get('roles')
            if not roles_str:
                print("At least one role is required. Example: --roles 'SIEM:2,CSPM:1'")
                return
            
            for role_spec in roles_str.split(','):
                role_spec = role_spec.strip()
                
                # Require format: "RoleName:ActionType" or "RoleID:ActionType"

                if ':' in role_spec:
                    role_id_str, action_type_str = role_spec.split(':', 1)
                    allowed_roles = [("SIEM", 1), ("CSPM", 2), ("BILLING", 3)]
                    allowed_role_names = [role[0].upper() for role in allowed_roles]
                    if role_id_str.strip().upper() not in allowed_role_names:
                        print(f"Role '{role_id_str.strip()}' does not match allowed roles: {', '.join(allowed_role_names)}. Skipping.")
                        return
                    role_id_str = role_id_str.strip()
                    role_id = next(role[1] for role in allowed_roles if role[0].upper() == role_id_str.upper())
                    action_type_str = action_type_str.strip()
                else:
                    # If no action type specified, default to READ-write (2)
                    print(f"Error: Role specification must include action type. Got: '{role_spec}'")
                    print("Required format: 'RoleName:ActionType' (e.g., 'SIEM:1,CSPM:2,Billing:1')")
                    return
                
                # Map action type number to enum
                try:
                    action_type_num = int(action_type_str)
                    if action_type_num == 1:
                        action_type = publicapi_pb2.ActionType.READ
                    elif action_type_num == 2:
                        action_type = publicapi_pb2.ActionType.READ_WRITE
                    else:
                        print(f"Invalid action type: '{action_type_str}'. Valid values are: 1=READ, 2=READ_WRITE. Defaulting to READ-write (2)")
                        action_type = publicapi_pb2.ActionType.READ_WRITE
                except ValueError:
                    print(f"Invalid action type: '{action_type_str}'. Action type must be a number: 1=READ, 2=READ_WRITE. Defaulting to read-write (2)")
                    action_type = publicapi_pb2.ActionType.READ_WRITE
                
                role = publicapi_pb2.Role()
                role.roleId = role_id
                role.actionType = action_type
                rq.roles.append(role)
            
            # Send the request
            rs = api.communicate_rest(
                params, rq,
                'public_api/generate_token',
                rs_type=publicapi_pb2.PublicApiTokenResponse
            )
            
            fmt = kwargs.get('format') or 'table'
            if fmt == 'json':
                output = {
                    'name': rs.name,
                    'token': rs.token,
                    'enterprise_id': rs.enterprise_id,
                    'issued_date': rs.issuedDate,
                    'expiration_date': rs.expirationDate if rs.expirationDate else 'never',
                    'integrations': [
                        {
                            'role_name': integration.roleName,
                            'action_type': integration.actionType,
                            'action_type_name': publicapi_pb2.ActionType.Name(integration.actionType)
                        } for integration in rs.integrations
                    ]
                }
                
                output_file = kwargs.get('output')
                if output_file:
                    with open(output_file, 'w') as f:
                        json.dump(output, f, indent=2)
                    print('File name: %s', os.path.abspath(output_file))
                else:
                    return json.dumps(output, indent=2)
            else:
                print(f"{bcolors.OKGREEN}API Key generated successfully{bcolors.ENDC}")
                print(f"Token: {rs.token}")
                print(f"Name: {rs.name}")
                print(f"Token: {rs.token}")
                print(f"Enterprise ID: {rs.enterprise_id}")
                if rs.expirationDate:
                    exp_date = datetime.datetime.fromtimestamp(rs.expirationDate / 1000)
                    print(f"Expires: {exp_date.strftime('%Y-%m-%d %H:%M:%S')}")
                else:
                    print("Expires: Never")
                
                if rs.integrations:
                    print("Roles:")
                    for integration in rs.integrations:
                        action_name = publicapi_pb2.ActionType.Name(integration.actionType)
                        print(f"  - {integration.roleName}: {action_name} ({integration.actionType})")
                        
        except Exception as e:
            logging.error(f"Failed to generate API key: {e}")
            raise CommandError("Failed to generate API key")


class ApiKeyRevokeCommand(EnterpriseCommand):
    def get_parser(self):
        return api_key_revoke_parser

    def execute(self, params, **kwargs):
        token = kwargs.get('token')
        if not token:
            print("Token is required")
            return
        
        # Confirm revocation unless force flag is set
        if not kwargs.get('force'):
            answer = user_choice(
                bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                f'You are about to revoke API key with Token {token}' +
                '\n\nDo you want to proceed with revocation?', 'yn', 'n'
            )
            if answer.lower() != 'y':
                return
        
        try:
            # Create the revoke token request
            rq = publicapi_pb2.RevokeTokenRequest()
            rq.token = token
            
            # Send the request
            rs = api.communicate_rest(
                params, rq,
                'public_api/revoke_token',
                rs_type=publicapi_pb2.RevokeTokenResponse
            )
            
            print(f"{bcolors.OKGREEN}API Key with Token {token} revoked successfully{bcolors.ENDC}")
            if rs.message:
                print(f"Message: {rs.message}")
                
        except Exception as e:
            logging.error(f"Failed to revoke API key: {e}")
            raise CommandError("Failed to revoke API key") 
