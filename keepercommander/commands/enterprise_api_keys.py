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
import os
import datetime

from .base import GroupCommand, dump_report_data, report_output_parser, field_to_title, user_choice
from .enterprise_common import EnterpriseCommand
from .. import api
from ..display import bcolors
from ..error import CommandError
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
  public-api-key generate --name "SIEM Integration" --integrations "SIEM:2" --expires 30d
  
  # Generate API key with BILLING role and 24-hour expiration
  public-api-key generate --name "Billing Tool" --integrations "BILLING:2" --expires 24h
  
  # Generate permanent API key with read-only access
  public-api-key generate --name "Monitoring Tool" --integrations "SIEM:1" --expires never
  
  # Generate API key with BILLING role and save details to JSON file
  public-api-key generate --name "Billing Integration" --integrations "BILLING:2" --expires 1y --format json --output billing_key.json
    ''',
    formatter_class=argparse.RawDescriptionHelpFormatter
)
api_key_generate_parser.add_argument('--name', dest='name', required=True, 
                                     help='API key name. Examples: "SIEM Integration", "Billing Tool", "Backup Tool", "Monitoring Service"')
api_key_generate_parser.add_argument('--integrations', dest='integrations', required=True, action='store', 
                                     help='''Integration with action type. 
Format: "RoleName:ActionType"
Available integrations: SIEM, BILLING
Action types: 1=READ (read-only), 2=READ_WRITE (full access)
Examples: 
  --integrations "SIEM:2"                    # SIEM role with read-write access
  --integrations "SIEM:1"                    # SIEM role with read-only access
  --integrations "BILLING:2"                 # BILLING role with read-write access
  --integrations "BILLING:1"                 # BILLING role with read-only access''')
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
  public-api-key revoke "SIEM Integration"
  
  # Revoke API key without confirmation (force)
  public-api-key revoke "SIEM Integration" --force
  
  # Short form with force flag
  public-api-key revoke "SIEM Integration" -f

Tips:
  - Use 'public-api-key list' to find the Name you want to revoke
  - Revoked keys cannot be restored, only new keys can be generated
  - Use --force to skip the confirmation prompt (useful for scripts)
    ''',
    formatter_class=argparse.RawDescriptionHelpFormatter
)
api_key_revoke_parser.add_argument('name', 
                                   help='API key Name (get this from "api-key list" command). Example: "SIEM Integration"')
api_key_revoke_parser.add_argument('--force', '-f', dest='force', action='store_true', 
                                   help='Revoke without confirmation prompt (useful for automated scripts)')


def register_commands(commands):
    commands['public-api-key'] = ApiKeyCommand()


def register_command_info(aliases, command_info):
    command_info['public-api-key'] = 'Manage Admin REST API keys for 3rd party integrations'

def get_enterprise_id(enterprise_user_id):
    return enterprise_user_id >> 32

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
        print('  generate  - Create a new API key with specified integrations and expiration')
        print('  revoke    - Revoke an existing API key')
        print()
        print('Quick Start Examples:')
        print('  # List all API keys')
        print('  public-api-key list')
        print()
        print('  # Generate a new API key for SIEM integration (30-day expiration)')
        print('  public-api-key generate --name "SIEM Tool" --integrations "SIEM:2" --expires 30d')
        print()
        print('  # Generate a new API key for BILLING integration (30-day expiration)')
        print('  public-api-key generate --name "Billing Tool" --integrations "BILLING:2" --expires 30d')
        print()
        print('  # Revoke an API key')
        print('  public-api-key revoke "SIEM Integration"')
        print()
        print('Available Integrations:')
        print('  SIEM    - Security Information and Event Management')
        print('  BILLING - Billing and subscription management')
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
        headers = ['enterprise_id', 'name', 'status', 'issued_date', 'expiration_date', 'integration']
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
                
                api_integrations_str = ', '.join([f"{integration.apiIntegrationTypeName}:{integration.actionType}" 
                                     for integration in token.integrations])
                
                if token.expirationDate and token.expirationDate < int(datetime.datetime.now().timestamp() * 1000):
                    status = 'Expired'
                else:
                    status = 'Active'
                
                
                row = [
                    token.enterprise_id,
                    token.name,
                    status,
                    issued_date,
                    expiration_date,
                    api_integrations_str
                ]
                table.append(row)
                
        except Exception as e:
            logging.error(f"Failed to list API keys: {e}")
            raise CommandError("public-api-key list", "Failed to retrieve API keys")
        
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
            rq.issuedDate = int(datetime.datetime.now().timestamp() * 1000) + 3000
            
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
            
            # Parse integrations - now required
            integrations_str = kwargs.get('integrations')
            if not integrations_str:
                print("At least one integration is required. Example: --integrations 'SIEM:2' or --integrations 'BILLING:2'")
                return
            
            for integration_spec in integrations_str.split(','):
                integration_spec = integration_spec.strip()
                
                # Require format: "RoleName:ActionType" or "RoleID:ActionType"

                if ':' in integration_spec:
                    integration_id_str, action_type_str = integration_spec.split(':', 1)
                    allowed_integrations = [("SIEM", 1), ("BILLING", 3)]
                    allowed_integration_names = [integration[0].upper() for integration in allowed_integrations]
                    if integration_id_str.strip().upper() not in allowed_integration_names:
                        print(f"Integration '{integration_id_str.strip()}' does not match allowed integrations: {', '.join(allowed_integration_names)}. Skipping.")
                        return

                    if integration_id_str.strip().upper() == "BILLING" and not EnterpriseCommand.is_msp(params):
                        print("The 'Billing' integration is only available for MSP (Managed Service Provider) enterprises.")
                        return

                    integration_id_str = integration_id_str.strip()
                    integration_id = next(integration[1] for integration in allowed_integrations if integration[0].upper() == integration_id_str.upper())
                    action_type_str = action_type_str.strip()
                else:
                    # If no action type specified, default to READ-write (2)
                    print(f"Error: Integration specification must include action type. Got: '{integration_spec}'")
                    print("Required format: 'IntegrationName:ActionType' (e.g., 'SIEM:1' or 'BILLING:2')")
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
                        return
                except ValueError:
                    print(f"Invalid action type: '{action_type_str}'. Action type must be a number: 1=READ, 2=READ_WRITE. Defaulting to read-write (2)")
                    return
                
                integration = publicapi_pb2.IntegrationRequest()
                integration.apiIntegrationTypeId = integration_id
                integration.actionType = action_type
                rq.integrationRequests.append(integration)
            
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
                            'api_integration_type_name': integration.apiIntegrationTypeName,
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
                print(f"Name: {rs.name}")
                print(f"Token: {rs.token}")
                print(f"Enterprise ID: {get_enterprise_id(self.get_enterprise_id(params))}")
                if rs.expirationDate:
                    exp_date = datetime.datetime.fromtimestamp(rs.expirationDate / 1000)
                    print(f"Expires: {exp_date.strftime('%Y-%m-%d %H:%M:%S')}")
                else:
                    print("Expires: Never")
                
                if rs.integrations:
                    print("Integrations:")
                    for integration in rs.integrations:
                        action_name = publicapi_pb2.ActionType.Name(integration.actionType)
                        print(f"  - {integration.roleName}: {action_name} ({integration.actionType})")
                        
        except Exception as e:
            err = str(e)
            if "(" in err and ")" in err and err.find("(") < err.find(")"):
                idx1 = err.find("(") + 1
                idx2 = err.find(")", idx1)
                err = err[idx1:idx2]
            logging.error(f"Failed to generate API key: {err}")
            raise CommandError("public-api-key generate", "Failed to generate API key")


class ApiKeyRevokeCommand(EnterpriseCommand):
    def get_parser(self):
        return api_key_revoke_parser

    def execute(self, params, **kwargs):
        name = kwargs.get('name')
        if not name:
            print("Name is required")
            return
        
        # Confirm revocation unless force flag is set
        if not kwargs.get('force'):
            answer = user_choice(
                bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                f'You are about to revoke API key with Name {name}' +
                '\n\nDo you want to proceed with revocation?', 'yn', 'n'
            )
            if answer.lower() != 'y':
                return
        
        try:
            # Create the revoke token request
            rq = publicapi_pb2.RevokeTokenRequest()
            rq.name = name
            
            # Send the request
            rs = api.communicate_rest(
                params, rq,
                'public_api/revoke_token',
                rs_type=publicapi_pb2.RevokeTokenResponse
            )
            
            print(f"{bcolors.OKGREEN}API Key with Name {name} revoked successfully{bcolors.ENDC}")
            
            if rs.message:
                print(f"Message: {rs.message}")
                
        except Exception as e:
            err = str(e)
            if "(" in err and ")" in err and err.find("(") < err.find(")"):
                idx1 = err.find("(") + 1
                idx2 = err.find(")", idx1)
                err = err[idx1:idx2]
            logging.error(f"Failed to revoke API key: {err}")
            raise CommandError("public-api-key revoke", "Failed to revoke API key") 
