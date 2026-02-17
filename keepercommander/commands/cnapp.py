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

"""
CNAPP (Cloud-Native Application Protection Platform) Integration Commands

This module provides CLI commands for managing CNAPP integrations with Keeper PAM.
It includes commands for:
- Managing webhooks (create, list, view, delete, test)
- Viewing and filtering the issue queue
- Configuring default remediation behaviors
- Executing manual remediation actions
- Managing resource mappings and onboarding
"""

import argparse
import base64
import json
import logging
from typing import Optional, Dict, Any, List

from .base import GroupCommand, dump_report_data, report_output_parser, field_to_title, suppress_exit, raise_parse_exception, CommandError
from .enterprise_common import EnterpriseCommand
from .pam.router_helper import router_send_action_to_gateway
from .pam.pam_dto import GatewayAction
from .. import api, utils, crypto, rest_api, vault
from .. import record_management
from ..display import bcolors
from ..params import KeeperParams
from ..proto import pam_pb2


# ==================== Argument Parsers ====================

# Webhook parsers
webhook_create_parser = argparse.ArgumentParser(prog='cnapp webhook create', description='Create a new CNAPP webhook.')
webhook_create_parser.add_argument('--config', dest='config', required=True, 
                                   help='PAM Network Configuration UID (required, associates webhook with this config)')
webhook_create_parser.add_argument('--provider', dest='provider', required=True, choices=['wiz'], help='CNAPP provider')
webhook_create_parser.add_argument('--name', dest='name', required=True, help='Webhook name')
webhook_create_parser.error = raise_parse_exception
webhook_create_parser.exit = suppress_exit

webhook_list_parser = argparse.ArgumentParser(prog='cnapp webhook list', parents=[report_output_parser],
                                               description='List all CNAPP webhooks for a PAM Network Configuration.')
webhook_list_parser.add_argument('--config', dest='config', required=True,
                                 help='PAM Network Configuration UID (required)')
webhook_list_parser.error = raise_parse_exception
webhook_list_parser.exit = suppress_exit

webhook_view_parser = argparse.ArgumentParser(prog='cnapp webhook view', description='View CNAPP webhook details.')
webhook_view_parser.add_argument('webhook_id', help='Webhook ID')
webhook_view_parser.add_argument('--config', dest='config', required=True,
                                 help='PAM Network Configuration UID (required)')
webhook_view_parser.add_argument('--format', dest='format', choices=['table', 'json'], default='table', help='Output format')
webhook_view_parser.error = raise_parse_exception
webhook_view_parser.exit = suppress_exit

webhook_delete_parser = argparse.ArgumentParser(prog='cnapp webhook delete', description='Delete a CNAPP webhook.')
webhook_delete_parser.add_argument('webhook_id', help='Webhook ID')
webhook_delete_parser.add_argument('--config', dest='config', required=True,
                                   help='PAM Network Configuration UID (required)')
webhook_delete_parser.add_argument('--force', '-f', dest='force', action='store_true', help='Delete without confirmation')
webhook_delete_parser.error = raise_parse_exception
webhook_delete_parser.exit = suppress_exit

webhook_test_parser = argparse.ArgumentParser(prog='cnapp webhook test', description='Test a CNAPP webhook.')
webhook_test_parser.add_argument('webhook_id', help='Webhook ID')
webhook_test_parser.add_argument('--config', dest='config', required=True,
                                 help='PAM Network Configuration UID (required)')
webhook_test_parser.error = raise_parse_exception
webhook_test_parser.exit = suppress_exit

# Queue parsers
queue_list_parser = argparse.ArgumentParser(prog='cnapp queue list', parents=[report_output_parser],
                                            description='List CNAPP issues in the queue.')
queue_list_parser.add_argument('--severity', dest='severity', choices=['critical', 'high', 'medium', 'low', 'info'],
                               help='Filter by severity')
queue_list_parser.add_argument('--status', dest='status', choices=['pending', 'in_progress', 'resolved', 'failed'],
                               help='Filter by status')
queue_list_parser.add_argument('--managed', dest='managed', choices=['yes', 'no', 'all'], default='all',
                               help='Filter by managed status')
queue_list_parser.add_argument('--sort', dest='sort', choices=['date', 'severity', 'status'], default='date',
                               help='Sort by field')
queue_list_parser.add_argument('--limit', dest='limit', type=int, default=50, help='Maximum number of results')
queue_list_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
queue_list_parser.error = raise_parse_exception
queue_list_parser.exit = suppress_exit

queue_view_parser = argparse.ArgumentParser(prog='cnapp queue view', description='View CNAPP issue details.')
queue_view_parser.add_argument('issue_id', help='Issue ID')
queue_view_parser.add_argument('--format', dest='format', choices=['table', 'json'], default='table', help='Output format')
queue_view_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
queue_view_parser.error = raise_parse_exception
queue_view_parser.exit = suppress_exit

queue_backup_parser = argparse.ArgumentParser(prog='cnapp queue backup',
                                               description='Backup the CNAPP queue from gateway to a vault record.')
queue_backup_parser.add_argument('--gateway', dest='gateway', required=True, help='Gateway UID')
queue_backup_parser.add_argument('--record', dest='record', required=True,
                                 help='Record UID to store the queue backup (custom field cnapp_queue)')
queue_backup_parser.error = raise_parse_exception
queue_backup_parser.exit = suppress_exit

queue_restore_parser = argparse.ArgumentParser(prog='cnapp queue restore',
                                               description='Restore the CNAPP queue from a vault record to the gateway.')
queue_restore_parser.add_argument('--gateway', dest='gateway', required=True, help='Gateway UID')
queue_restore_parser.add_argument('--record', dest='record', required=True,
                                  help='Record UID containing the queue backup (custom field cnapp_queue)')
queue_restore_parser.error = raise_parse_exception
queue_restore_parser.exit = suppress_exit

# Behavior parsers
behavior_add_parser = argparse.ArgumentParser(prog='cnapp behavior add', description='Add a default behavior for a control.')
behavior_add_parser.add_argument('--control-id', dest='control_id', required=True, help='Control ID')
behavior_add_parser.add_argument('--action', dest='action', required=True,
                                  choices=['rotate_password', 'remove_privileges', 'configure_jit', 'manual'],
                                  help='Default remediation action')
behavior_add_parser.add_argument('--enabled', dest='enabled', action='store_true', default=True, help='Enable the behavior')
behavior_add_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
behavior_add_parser.error = raise_parse_exception
behavior_add_parser.exit = suppress_exit

behavior_list_parser = argparse.ArgumentParser(prog='cnapp behavior list', parents=[report_output_parser],
                                                description='List all default behaviors.')
behavior_list_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
behavior_list_parser.error = raise_parse_exception
behavior_list_parser.exit = suppress_exit

behavior_remove_parser = argparse.ArgumentParser(prog='cnapp behavior remove', description='Remove a default behavior.')
behavior_remove_parser.add_argument('control_id', help='Control ID')
behavior_remove_parser.add_argument('--force', '-f', dest='force', action='store_true', help='Remove without confirmation')
behavior_remove_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
behavior_remove_parser.error = raise_parse_exception
behavior_remove_parser.exit = suppress_exit

# Remediate parsers
remediate_rotate_parser = argparse.ArgumentParser(prog='cnapp remediate rotate', description='Rotate password for an issue.')
remediate_rotate_parser.add_argument('issue_id', help='Issue ID')
remediate_rotate_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
remediate_rotate_parser.error = raise_parse_exception
remediate_rotate_parser.exit = suppress_exit

remediate_remove_privileges_parser = argparse.ArgumentParser(prog='cnapp remediate remove-privileges',
                                                              description='Remove privileges for an issue.')
remediate_remove_privileges_parser.add_argument('issue_id', help='Issue ID')
remediate_remove_privileges_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
remediate_remove_privileges_parser.error = raise_parse_exception
remediate_remove_privileges_parser.exit = suppress_exit

remediate_jit_parser = argparse.ArgumentParser(prog='cnapp remediate jit', description='Configure JIT access for an issue.')
remediate_jit_parser.add_argument('issue_id', help='Issue ID')
remediate_jit_parser.add_argument('--duration', dest='duration', type=int, default=60, help='JIT duration in minutes')
remediate_jit_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
remediate_jit_parser.error = raise_parse_exception
remediate_jit_parser.exit = suppress_exit

remediate_resolve_parser = argparse.ArgumentParser(prog='cnapp remediate resolve', description='Mark an issue as resolved.')
remediate_resolve_parser.add_argument('issue_id', help='Issue ID')
remediate_resolve_parser.add_argument('--reason', dest='reason', help='Resolution reason')
remediate_resolve_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
remediate_resolve_parser.error = raise_parse_exception
remediate_resolve_parser.exit = suppress_exit

# Resource parsers
resource_search_parser = argparse.ArgumentParser(prog='cnapp resource search', parents=[report_output_parser],
                                                  description='Search for PAM records matching a resource.')
resource_search_parser.add_argument('--query', dest='query', required=True, help='Search query (hostname, ARN, username)')
resource_search_parser.add_argument('--type', dest='type', choices=['all', 'user', 'machine', 'database'], default='all',
                                     help='Resource type filter')
resource_search_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
resource_search_parser.error = raise_parse_exception
resource_search_parser.exit = suppress_exit

resource_map_parser = argparse.ArgumentParser(prog='cnapp resource map', description='Map an issue to a PAM record.')
resource_map_parser.add_argument('issue_id', help='Issue ID')
resource_map_parser.add_argument('--record', dest='record', required=True, help='PAM record UID')
resource_map_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
resource_map_parser.error = raise_parse_exception
resource_map_parser.exit = suppress_exit

resource_onboard_parser = argparse.ArgumentParser(prog='cnapp resource onboard',
                                                   description='Generate onboarding template for an unmanaged resource.')
resource_onboard_parser.add_argument('issue_id', help='Issue ID')
resource_onboard_parser.add_argument('--format', dest='format', choices=['url', 'json'], default='url',
                                      help='Output format (url = Vault deep-link, json = record template)')
resource_onboard_parser.add_argument('--gateway', dest='gateway', help='Gateway UID')
resource_onboard_parser.error = raise_parse_exception
resource_onboard_parser.exit = suppress_exit


# ==================== Registration ====================

def register_commands(commands):
    commands['cnapp'] = CNAPPCommand()


def register_command_info(aliases, command_info):
    aliases['cn'] = 'cnapp'
    command_info['cnapp'] = 'Manage CNAPP integrations (Wiz, etc.)'


# ==================== Helper Functions ====================

def get_router_url(params: KeeperParams) -> str:
    """Get the Krouter URL for API calls."""
    # This should be configured or derived from params
    return params.config.get('krouter_url', 'https://connect.keepersecurity.com')


def cnapp_api_call(params: KeeperParams, endpoint: str, method: str = 'GET', data: Optional[Dict] = None) -> Dict:
    """Make an API call to the CNAPP endpoints in Krouter."""
    router_url = get_router_url(params)
    url = f"{router_url}/api/cnapp/{endpoint}"

    # Generate transmission key and encrypt credentials (Keeper authentication)
    transmission_key = utils.generate_aes_key()
    server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]

    if params.rest_context.server_key_id < 7:
        encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
    else:
        encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)

    encrypted_session_token = crypto.encrypt_aes_v2(
        utils.base64_url_decode(params.session_token), transmission_key)

    headers = {
        'TransmissionKey': base64.b64encode(encrypted_transmission_key).decode('ascii'),
        'Authorization': f'KeeperUser {base64.b64encode(encrypted_session_token).decode("ascii")}',
        'Content-Type': 'application/json'
    }

    import requests
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data or {})
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers)
        else:
            raise CommandError(f'Unsupported HTTP method: {method}')

        if response.status_code >= 400:
            raise CommandError(f'API error: {response.status_code} - {response.text}')

        return response.json() if response.text else {}
    except requests.RequestException as e:
        raise CommandError(f'Network error: {e}')


def gateway_action(params: KeeperParams, gateway_uid: str, action: str, data: Dict) -> Dict:
    """Send an action to a Gateway via the Krouter (same path as other PAM commands)."""
    gateway_action_obj = GatewayAction(
        action=action,
        is_scheduled=False,
        inputs=data,
        conversation_id=GatewayAction.generate_conversation_id(),
    )
    router_response = router_send_action_to_gateway(
        params,
        gateway_action=gateway_action_obj,
        message_type=pam_pb2.CMT_GENERAL,
        is_streaming=False,
        destination_gateway_uid_str=gateway_uid,
    )
    return (router_response or {}).get('response')


def validate_pam_network_config(params: KeeperParams, config_uid: str) -> None:
    """Validate that a record UID is a valid PAM Network Configuration.
    
    Raises CommandError if the config is not found or is not a pamNetworkConfiguration.
    """
    if config_uid not in params.record_cache:
        raise CommandError(f'PAM Network Configuration not found: {config_uid}')
    
    record = params.record_cache[config_uid]
    
    # Check if it's a v6 record (PAM configuration)
    if record.get('version') != 6:
        raise CommandError(f'Record {config_uid} is not a PAM configuration record')
    
    # Try to determine if it's a pamNetworkConfiguration
    # This checks the record type from decrypted data
    try:
        from .pam.config_helper import pam_decrypt_configuration_data
        decrypted = pam_decrypt_configuration_data(record)
        record_type = decrypted.get('type', '')
        if record_type != 'pamNetworkConfiguration':
            raise CommandError(f'Record {config_uid} is not a PAM Network Configuration (type: {record_type})')
    except Exception as e:
        # If we can't decrypt, log warning but allow to proceed
        logging.warning(f'Could not validate PAM config type: {e}')


# Custom field label for storing queue JSON in a vault record (Option A durable storage)
CNAPP_QUEUE_FIELD = 'cnapp_queue'


def get_cnapp_queue_from_record(params: KeeperParams, record_uid: str) -> Dict[str, Any]:
    """Load CNAPP queue JSON from a vault record's custom field. Returns {} if empty or missing."""
    if record_uid not in params.record_cache:
        raise CommandError(f'Record not found: {record_uid}')
    storage_record = params.record_cache[record_uid]
    record = vault.KeeperRecord.load(params, storage_record)
    raw = None
    if hasattr(record, 'get_custom_value'):
        raw = record.get_custom_value(CNAPP_QUEUE_FIELD)
    elif hasattr(record, 'custom') and isinstance(record.custom, list):
        for f in record.custom:
            if getattr(f, 'label', None) == CNAPP_QUEUE_FIELD:
                val = getattr(f, 'value', None)
                raw = val[0] if isinstance(val, list) and val else (val if isinstance(val, str) else None)
                break
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise CommandError(f'Invalid JSON in record {record_uid} field {CNAPP_QUEUE_FIELD}: {e}')


def save_cnapp_queue_to_record(params: KeeperParams, record_uid: str, queue_dict: Dict[str, Any]) -> None:
    """Save CNAPP queue JSON to a vault record's custom field."""
    if record_uid not in params.record_cache:
        raise CommandError(f'Record not found: {record_uid}')
    storage_record = params.record_cache[record_uid]
    record = vault.KeeperRecord.load(params, storage_record)
    payload = json.dumps(queue_dict, default=str)
    if hasattr(record, 'set_custom_value'):
        record.set_custom_value(CNAPP_QUEUE_FIELD, payload)
    elif hasattr(record, 'custom') and isinstance(record.custom, list):
        from ..vault import TypedField
        existing = [f for f in record.custom if getattr(f, 'label', None) != CNAPP_QUEUE_FIELD]
        record.custom = existing + [TypedField.new_field('text', payload, CNAPP_QUEUE_FIELD)]
    else:
        raise CommandError(f'Record {record_uid} does not support custom fields')
    record_management.update_record(params, record)
    params.sync_data = True
    api.sync_down(params)


# ==================== Group Commands ====================

class CNAPPCommand(GroupCommand):
    """Main CNAPP command group."""

    def __init__(self):
        super(CNAPPCommand, self).__init__()
        self.register_command('webhook', CNAPPWebhookCommand())
        self.register_command('queue', CNAPPQueueCommand())
        self.register_command('behavior', CNAPPBehaviorCommand())
        self.register_command('remediate', CNAPPRemediateCommand())
        self.register_command('resource', CNAPPResourceCommand())
        self.default_verb = 'queue'


class CNAPPWebhookCommand(GroupCommand):
    """CNAPP webhook management command group."""

    def __init__(self):
        super(CNAPPWebhookCommand, self).__init__()
        self.register_command('create', WebhookCreateCommand())
        self.register_command('list', WebhookListCommand())
        self.register_command('view', WebhookViewCommand())
        self.register_command('delete', WebhookDeleteCommand())
        self.register_command('test', WebhookTestCommand())
        self.default_verb = 'list'


class CNAPPQueueCommand(GroupCommand):
    """CNAPP queue management command group."""

    def __init__(self):
        super(CNAPPQueueCommand, self).__init__()
        self.register_command('list', QueueListCommand())
        self.register_command('view', QueueViewCommand())
        self.register_command('backup', QueueBackupCommand())
        self.register_command('restore', QueueRestoreCommand())
        self.default_verb = 'list'


class CNAPPBehaviorCommand(GroupCommand):
    """CNAPP behavior management command group."""

    def __init__(self):
        super(CNAPPBehaviorCommand, self).__init__()
        self.register_command('add', BehaviorAddCommand())
        self.register_command('list', BehaviorListCommand())
        self.register_command('remove', BehaviorRemoveCommand())
        self.default_verb = 'list'


class CNAPPRemediateCommand(GroupCommand):
    """CNAPP remediation command group."""

    def __init__(self):
        super(CNAPPRemediateCommand, self).__init__()
        self.register_command('rotate', RemediateRotateCommand())
        self.register_command('remove-privileges', RemediateRemovePrivilegesCommand())
        self.register_command('jit', RemediateJitCommand())
        self.register_command('resolve', RemediateResolveCommand())


class CNAPPResourceCommand(GroupCommand):
    """CNAPP resource management command group."""

    def __init__(self):
        super(CNAPPResourceCommand, self).__init__()
        self.register_command('search', ResourceSearchCommand())
        self.register_command('map', ResourceMapCommand())
        self.register_command('onboard', ResourceOnboardCommand())
        self.default_verb = 'search'


# ==================== Webhook Commands ====================

class WebhookCreateCommand(EnterpriseCommand):
    """Create a new CNAPP webhook.
    
    Associates the webhook with a PAM Network Configuration, which provides:
    - Persistence of webhook configuration in Keeper Vault
    - Automatic gateway routing via the config's controllerUid
    - Enterprise-level security via Vault permissions
    """

    def get_parser(self):
        return webhook_create_parser

    def execute(self, params, config=None, provider=None, name=None, **kwargs):
        if not config:
            raise CommandError('PAM Network Configuration UID is required. Use --config option.')

        # Validate that the config exists and is a pamNetworkConfiguration
        validate_pam_network_config(params, config)

        data = {
            'provider': provider.upper(),
            'name': name,
            'network_uid': config,
        }

        result = cnapp_api_call(params, 'create_webhook', 'POST', data)

        logging.info('')
        logging.info(f"{bcolors.OKGREEN}Webhook created successfully!{bcolors.ENDC}")
        logging.info(f"Webhook ID: {result.get('webhook_id')}")
        logging.info(f"Webhook URL: {result.get('webhook_url')}")
        logging.info(f"PAM Config: {config}")
        logging.info('')
        logging.info(f"{bcolors.WARNING}Configure this URL in your {provider} integration.{bcolors.ENDC}")
        logging.info('')

        return result


class WebhookListCommand(EnterpriseCommand):
    """List all CNAPP webhooks for a PAM Network Configuration."""

    def get_parser(self):
        return webhook_list_parser

    def execute(self, params, config=None, **kwargs):
        if not config:
            raise CommandError('PAM Network Configuration UID is required. Use --config option.')

        data = {'network_uid': config}
        result = cnapp_api_call(params, 'list_webhooks', 'POST', data)

        fmt = kwargs.get('format', 'table')
        headers = ['webhook_id', 'provider', 'name', 'network_uid', 'enabled', 'created_at']
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]

        table = []
        webhooks = result if isinstance(result, list) else []

        for webhook in webhooks:
            row = [
                webhook.get('webhook_id', ''),
                webhook.get('provider', ''),
                webhook.get('name', ''),
                webhook.get('network_uid', '')[:8] + '...' if webhook.get('network_uid', '') else '',
                'Yes' if webhook.get('enabled') else 'No',
                webhook.get('created_at', '')
            ]
            table.append(row)

        return dump_report_data(table, headers=headers, fmt=fmt, filename=kwargs.get('output'))


class WebhookViewCommand(EnterpriseCommand):
    """View CNAPP webhook details."""

    def get_parser(self):
        return webhook_view_parser

    def execute(self, params, webhook_id=None, config=None, **kwargs):
        if not config:
            raise CommandError('PAM Network Configuration UID is required. Use --config option.')

        data = {'webhook_id': webhook_id, 'network_uid': config}
        result = cnapp_api_call(params, 'get_webhook', 'POST', data)

        fmt = kwargs.get('format', 'table')
        if fmt == 'json':
            return json.dumps(result, indent=2)

        table = [
            ['Webhook ID', result.get('webhook_id', '')],
            ['Provider', result.get('provider', '')],
            ['Name', result.get('name', '')],
            ['Enabled', 'Yes' if result.get('enabled') else 'No'],
            ['Webhook URL', result.get('webhook_url', '')],
            ['Created At', result.get('created_at', '')],
            ['Created By', result.get('created_by', '')],
            ['PAM Network Config', result.get('network_uid', 'N/A')],
            ['Gateway', result.get('gateway_uid', 'Auto (from config)')],
        ]
        return dump_report_data(table, ['Key', 'Value'], no_header=True, right_align=(0,))


class WebhookDeleteCommand(EnterpriseCommand):
    """Delete a CNAPP webhook."""

    def get_parser(self):
        return webhook_delete_parser

    def execute(self, params, webhook_id=None, config=None, force=False, **kwargs):
        if not config:
            raise CommandError('PAM Network Configuration UID is required. Use --config option.')

        if not force:
            from .base import user_choice
            answer = user_choice(
                f'{bcolors.FAIL}Delete webhook {webhook_id}?{bcolors.ENDC}',
                'yn', 'n'
            )
            if answer.lower() != 'y':
                logging.info('Cancelled.')
                return

        data = {'webhook_id': webhook_id, 'network_uid': config}
        cnapp_api_call(params, 'delete_webhook', 'POST', data)
        logging.info(f'{bcolors.OKGREEN}Webhook {webhook_id} deleted.{bcolors.ENDC}')


class WebhookTestCommand(EnterpriseCommand):
    """Test a CNAPP webhook."""

    def get_parser(self):
        return webhook_test_parser

    def execute(self, params, webhook_id=None, config=None, **kwargs):
        if not config:
            raise CommandError('PAM Network Configuration UID is required. Use --config option.')

        data = {'webhook_id': webhook_id, 'network_uid': config}
        result = cnapp_api_call(params, 'test_webhook', 'POST', data)

        logging.info('')
        if result.get('test_result') == 'SUCCESS':
            logging.info(f"{bcolors.OKGREEN}Webhook test passed!{bcolors.ENDC}")
        else:
            logging.info(f"{bcolors.FAIL}Webhook test failed: {result.get('message')}{bcolors.ENDC}")
        logging.info('')

        return result


# ==================== Queue Commands ====================

class QueueListCommand(EnterpriseCommand):
    """List CNAPP issues in the queue."""

    def get_parser(self):
        return queue_list_parser

    def execute(self, params, gateway=None, severity=None, status=None, managed=None, sort=None, limit=50, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'limit': limit,
            'sort': sort,
        }
        if severity:
            data['severity'] = severity.upper()
        if status:
            data['status'] = status.upper()
        if managed and managed != 'all':
            data['is_managed'] = managed == 'yes'

        result = gateway_action(params, gateway, 'cnapp-queue-list', data)

        fmt = kwargs.get('format', 'table')
        headers = ['issue_id', 'severity', 'status', 'managed', 'resource', 'control', 'created_at']
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]

        table = []
        issues = result.get('issues', []) if isinstance(result, dict) else []
        for issue in issues:
            is_managed = issue.get('resource_match', {}).get('is_managed', False)
            row = [
                issue.get('internal_issue_id', '')[:8],
                issue.get('severity', ''),
                issue.get('status', ''),
                bcolors.OKGREEN + 'Yes' + bcolors.ENDC if is_managed else bcolors.WARNING + 'No' + bcolors.ENDC,
                issue.get('resource', {}).get('name', ''),
                issue.get('control', {}).get('name', '')[:30],
                issue.get('created_at', '')
            ]
            table.append(row)

        return dump_report_data(table, headers=headers, fmt=fmt, filename=kwargs.get('output'))


class QueueViewCommand(EnterpriseCommand):
    """View CNAPP issue details."""

    def get_parser(self):
        return queue_view_parser

    def execute(self, params, issue_id=None, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        result = gateway_action(params, gateway, 'cnapp-queue-view', {'issue_id': issue_id})

        fmt = kwargs.get('format', 'table')
        if fmt == 'json':
            return json.dumps(result, indent=2)

        issue = result.get('issue', result)
        resource = issue.get('resource', {})
        control = issue.get('control', {})
        match = issue.get('resource_match', {})

        table = [
            ['Issue ID', issue.get('internal_issue_id', '')],
            ['Provider Issue ID', issue.get('provider_issue_id', '')],
            ['Severity', issue.get('severity', '')],
            ['Status', issue.get('status', '')],
            ['', ''],
            ['Resource Name', resource.get('name', '')],
            ['Resource Type', resource.get('type', '')],
            ['Cloud Platform', resource.get('cloud_platform', '')],
            ['Region', resource.get('region', 'N/A')],
            ['Account', resource.get('account_name', 'N/A')],
            ['', ''],
            ['Control ID', control.get('id', '')],
            ['Control Name', control.get('name', '')],
            ['Control Category', control.get('category', '')],
            ['', ''],
            ['Managed by Keeper', bcolors.OKGREEN + 'Yes' + bcolors.ENDC if match.get('is_managed') else bcolors.WARNING + 'No' + bcolors.ENDC],
            ['Match Method', match.get('match_method', 'N/A')],
            ['Matched Records', ', '.join(match.get('matched_records', [])) or 'None'],
        ]
        return dump_report_data(table, ['Field', 'Value'], no_header=True, right_align=(0,))


class QueueBackupCommand(EnterpriseCommand):
    """Backup the CNAPP queue from the gateway to a vault record."""

    def get_parser(self):
        return queue_backup_parser

    def execute(self, params, gateway=None, record=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')
        if not record:
            raise CommandError('Record UID is required. Use --record option.')
        result = gateway_action(params, gateway, 'cnapp-queue-export', {})
        if not isinstance(result, dict):
            raise CommandError('Failed to export queue from gateway.')
        queue_dict = result.get('queue') or (result.get('data') or {}).get('queue') or {}
        save_cnapp_queue_to_record(params, record, queue_dict)
        logging.info(f'{bcolors.OKGREEN}Backed up {len(queue_dict)} issues to record {record}{bcolors.ENDC}')
        return result


class QueueRestoreCommand(EnterpriseCommand):
    """Restore the CNAPP queue from a vault record to the gateway."""

    def get_parser(self):
        return queue_restore_parser

    def execute(self, params, gateway=None, record=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')
        if not record:
            raise CommandError('Record UID is required. Use --record option.')
        queue_dict = get_cnapp_queue_from_record(params, record)
        if not queue_dict:
            logging.warning('Record has no queue data; restoring empty queue.')
        result = gateway_action(params, gateway, 'cnapp-queue-restore', {'queue': queue_dict})
        count = (result or {}).get('restored_count') or ((result or {}).get('data') or {}).get('restored_count')
        if count is not None:
            logging.info(f'{bcolors.OKGREEN}Restored {count} issues to gateway{bcolors.ENDC}')
        return result


# ==================== Behavior Commands ====================

class BehaviorAddCommand(EnterpriseCommand):
    """Add a default behavior for a control."""

    def get_parser(self):
        return behavior_add_parser

    def execute(self, params, control_id=None, action=None, enabled=True, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'control_id': control_id,
            'action': action.upper(),
            'enabled': enabled
        }

        result = gateway_action(params, gateway, 'cnapp-behavior-add', data)
        logging.info(f'{bcolors.OKGREEN}Default behavior added for control {control_id}: {action}{bcolors.ENDC}')
        return result


class BehaviorListCommand(EnterpriseCommand):
    """List all default behaviors."""

    def get_parser(self):
        return behavior_list_parser

    def execute(self, params, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        result = gateway_action(params, gateway, 'cnapp-behavior-list', {})

        fmt = kwargs.get('format', 'table')
        headers = ['control_id', 'action', 'enabled', 'created_at']
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]

        table = []
        behaviors = result.get('behaviors', []) if isinstance(result, dict) else []
        for behavior in behaviors:
            row = [
                behavior.get('control_id', ''),
                behavior.get('action', ''),
                'Yes' if behavior.get('enabled') else 'No',
                behavior.get('created_at', '')
            ]
            table.append(row)

        return dump_report_data(table, headers=headers, fmt=fmt, filename=kwargs.get('output'))


class BehaviorRemoveCommand(EnterpriseCommand):
    """Remove a default behavior."""

    def get_parser(self):
        return behavior_remove_parser

    def execute(self, params, control_id=None, force=False, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        if not force:
            from .base import user_choice
            answer = user_choice(
                f'Remove default behavior for control {control_id}?',
                'yn', 'n'
            )
            if answer.lower() != 'y':
                logging.info('Cancelled.')
                return

        result = gateway_action(params, gateway, 'cnapp-behavior-remove', {'control_id': control_id})
        logging.info(f'{bcolors.OKGREEN}Default behavior removed for control {control_id}{bcolors.ENDC}')
        return result


# ==================== Remediate Commands ====================

class RemediateRotateCommand(EnterpriseCommand):
    """Rotate password for an issue."""

    def get_parser(self):
        return remediate_rotate_parser

    def execute(self, params, issue_id=None, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'issue_id': issue_id,
            'action': 'rotate'
        }

        result = gateway_action(params, gateway, 'cnapp-remediate', data)

        if result.get('success'):
            logging.info(f'{bcolors.OKGREEN}Password rotation initiated for issue {issue_id}{bcolors.ENDC}')
        else:
            logging.error(f'{bcolors.FAIL}Failed to rotate password: {result.get("error")}{bcolors.ENDC}')

        return result


class RemediateRemovePrivilegesCommand(EnterpriseCommand):
    """Remove privileges for an issue."""

    def get_parser(self):
        return remediate_remove_privileges_parser

    def execute(self, params, issue_id=None, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'issue_id': issue_id,
            'action': 'remove_privileges'
        }

        result = gateway_action(params, gateway, 'cnapp-remediate', data)

        if result.get('success'):
            logging.info(f'{bcolors.OKGREEN}Privileges removed for issue {issue_id}{bcolors.ENDC}')
        else:
            logging.error(f'{bcolors.FAIL}Failed to remove privileges: {result.get("error")}{bcolors.ENDC}')

        return result


class RemediateJitCommand(EnterpriseCommand):
    """Configure JIT access for an issue."""

    def get_parser(self):
        return remediate_jit_parser

    def execute(self, params, issue_id=None, duration=60, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'issue_id': issue_id,
            'action': 'jit',
            'duration_minutes': duration
        }

        result = gateway_action(params, gateway, 'cnapp-remediate', data)

        if result.get('success'):
            logging.info(f'{bcolors.OKGREEN}JIT access configured for issue {issue_id} (duration: {duration} min){bcolors.ENDC}')
        else:
            logging.error(f'{bcolors.FAIL}Failed to configure JIT: {result.get("error")}{bcolors.ENDC}')

        return result


class RemediateResolveCommand(EnterpriseCommand):
    """Mark an issue as resolved."""

    def get_parser(self):
        return remediate_resolve_parser

    def execute(self, params, issue_id=None, reason=None, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'issue_id': issue_id,
            'action': 'resolve',
        }
        if reason:
            data['reason'] = reason

        result = gateway_action(params, gateway, 'cnapp-remediate', data)

        if result.get('success'):
            logging.info(f'{bcolors.OKGREEN}Issue {issue_id} marked as resolved{bcolors.ENDC}')
        else:
            logging.error(f'{bcolors.FAIL}Failed to resolve issue: {result.get("error")}{bcolors.ENDC}')

        return result


# ==================== Resource Commands ====================

class ResourceSearchCommand(EnterpriseCommand):
    """Search for PAM records matching a resource."""

    def get_parser(self):
        return resource_search_parser

    def execute(self, params, query=None, type='all', gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'query': query,
            'resource_type': type
        }

        result = gateway_action(params, gateway, 'cnapp-resource-search', data)

        fmt = kwargs.get('format', 'table')
        headers = ['record_uid', 'title', 'type', 'hostname', 'username']
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]

        table = []
        records = result.get('records', []) if isinstance(result, dict) else []
        for record in records:
            row = [
                record.get('record_uid', ''),
                record.get('title', ''),
                record.get('type', ''),
                record.get('hostname', ''),
                record.get('username', '')
            ]
            table.append(row)

        return dump_report_data(table, headers=headers, fmt=fmt, filename=kwargs.get('output'))


class ResourceMapCommand(EnterpriseCommand):
    """Map an issue to a PAM record."""

    def get_parser(self):
        return resource_map_parser

    def execute(self, params, issue_id=None, record=None, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'issue_id': issue_id,
            'record_uid': record
        }

        result = gateway_action(params, gateway, 'cnapp-resource-map', data)

        if result.get('success'):
            logging.info(f'{bcolors.OKGREEN}Issue {issue_id} mapped to record {record}{bcolors.ENDC}')
        else:
            logging.error(f'{bcolors.FAIL}Failed to map issue: {result.get("error")}{bcolors.ENDC}')

        return result


class ResourceOnboardCommand(EnterpriseCommand):
    """Generate onboarding template for an unmanaged resource."""

    def get_parser(self):
        return resource_onboard_parser

    def execute(self, params, issue_id=None, gateway=None, **kwargs):
        if not gateway:
            raise CommandError('Gateway UID is required. Use --gateway option.')

        data = {
            'issue_id': issue_id
        }

        result = gateway_action(params, gateway, 'cnapp-resource-onboard', data)

        fmt = kwargs.get('format', 'url')
        template = result.get('template', {})

        if fmt == 'json':
            return json.dumps(template, indent=2)
        else:
            vault_url = template.get('vault_url', '')
            if vault_url:
                logging.info('')
                logging.info(f'{bcolors.OKGREEN}Onboarding URL generated:{bcolors.ENDC}')
                logging.info('')
                logging.info(f'  {vault_url}')
                logging.info('')
                logging.info('Open this URL in your browser to create the PAM record with pre-filled data.')
                logging.info('')
            else:
                logging.warning('No onboarding URL available for this resource.')

        return result
