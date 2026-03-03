"""CNAPP CLI commands for managing CNAPP integration with KeeperPAM."""
import argparse
import logging
from datetime import datetime
from typing import Any

from ..base import Command, GroupCommand, dump_report_data, report_output_parser
from ...params import KeeperParams
from . import cnapp_helper

logger = logging.getLogger(__name__)

STATUS_MAP = {1: 'PENDING', 2: 'IN_PROGRESS', 3: 'RESOLVED', 4: 'FAILED', 5: 'CANCELLED'}
ACTION_TYPE_MAP = {1: 'ROTATE_PASSWORD', 2: 'REMOVE_PRIVILEGES', 3: 'CONFIGURE_JIT', 4: 'MANUAL', 5: 'OTHER'}
PROVIDER_MAP = {1: 'WIZ', 2: 'TENABLE', 3: 'PRISMA_CLOUD'}


# ============================================================
# Top-level CNAPP command group
# ============================================================

class PAMCnappCommand(GroupCommand):
    def __init__(self):
        super(PAMCnappCommand, self).__init__()
        self.register_command('setup', PAMCnappSetupCommand(), 'Create CNAPP integration', 's')
        self.register_command('update', PAMCnappUpdateCommand(), 'Update CNAPP credentials', 'u')
        self.register_command('remove', PAMCnappRemoveCommand(), 'Remove CNAPP integration', 'rm')
        self.register_command('info', PAMCnappInfoCommand(), 'Show CNAPP details', 'i')
        self.register_command('test', PAMCnappTestCommand(), 'Test provider credentials', 't')
        self.register_command('queue', PAMCnappQueueCommand(), 'Manage CNAPP queue', 'q')
        self.register_command('behavior', PAMCnappBehaviorCommand(), 'Manage default behaviors', 'b')
        self.default_verb = 'info'


# ============================================================
# Webhook management commands
# ============================================================

class PAMCnappSetupCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp setup')
    parser.add_argument('--network', '-n', required=True, dest='network', help='PAM Network UID')
    parser.add_argument('--provider', '-p', required=True, dest='provider', help='CNAPP provider (wiz)')
    parser.add_argument('--client-id', required=True, dest='client_id', help='OAuth2 Client ID')
    parser.add_argument('--client-secret', required=True, dest='client_secret', help='OAuth2 Client Secret')
    parser.add_argument('--api-url', required=True, dest='api_url', help='Provider API endpoint URL')
    parser.add_argument('--auth-url', required=True, dest='auth_url', help='Provider OAuth2 auth URL')
    parser.add_argument('--encryption-key', required=True, dest='encryption_key', help='Encryption record key UID')
    parser.add_argument('--controller', '-c', required=True, dest='controller', help='PAM Controller/Gateway UID')
    parser.add_argument('--webhook-id', required=True, dest='webhook_id', help='Webhook identifier')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table')

    def get_parser(self):
        return PAMCnappSetupCommand.parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, Any) -> Any
        try:
            rs = cnapp_helper.cnapp_create_webhook(
                params,
                network_uid=kwargs['network'],
                provider=kwargs['provider'],
                client_id=kwargs['client_id'],
                client_secret=kwargs['client_secret'],
                api_url=kwargs['api_url'],
                auth_url=kwargs['auth_url'],
                encryption_record_key_id=kwargs['encryption_key'],
                controller_uid=kwargs['controller'],
                webhook_id=kwargs['webhook_id']
            )
            if rs and hasattr(rs, 'webhookUrl'):
                print(f'CNAPP integration created successfully.')
                print(f'  Webhook ID:  {rs.webhookId}')
                print(f'  Webhook TOKEN:  {rs.webhookToken}')
                print(f'  Webhook URL: {rs.webhookUrl}')
                print(f'\nConfigure this URL in your {kwargs["provider"].upper()} webhook settings.')
            else:
                print(f'Response: {rs}')
        except Exception as e:
            print(f'Failed to create CNAPP integration: {e}')


class PAMCnappUpdateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp update')
    parser.add_argument('--network', '-n', required=True, dest='network', help='PAM Network UID')
    parser.add_argument('--client-id', dest='client_id', help='New OAuth2 Client ID')
    parser.add_argument('--client-secret', dest='client_secret', help='New OAuth2 Client Secret')
    parser.add_argument('--api-url', dest='api_url', help='New API endpoint URL')
    parser.add_argument('--auth-url', dest='auth_url', help='New OAuth2 auth URL')

    def get_parser(self):
        return PAMCnappUpdateCommand.parser

    def execute(self, params, **kwargs):
        rs = cnapp_helper.cnapp_update_webhook(
            params,
            network_uid=kwargs['network'],
            client_id=kwargs.get('client_id'),
            client_secret=kwargs.get('client_secret'),
            api_url=kwargs.get('api_url'),
            auth_url=kwargs.get('auth_url')
        )
        print('CNAPP integration updated successfully.')


class PAMCnappRemoveCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp remove')
    parser.add_argument('--network', '-n', required=True, dest='network', help='PAM Network UID')
    parser.add_argument('--force', '-f', action='store_true', dest='force', help='Skip confirmation')

    def get_parser(self):
        return PAMCnappRemoveCommand.parser

    def execute(self, params, **kwargs):
        if not kwargs.get('force'):
            confirm = input('Remove CNAPP integration? This will disable the webhook. [y/N]: ')
            if confirm.lower() != 'y':
                print('Cancelled.')
                return
        cnapp_helper.cnapp_delete_webhook(params, network_uid=kwargs['network'])
        print('CNAPP integration removed.')


class PAMCnappInfoCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp info')
    parser.add_argument('--network', '-n', dest='network', help='PAM Network UID')

    def get_parser(self):
        return PAMCnappInfoCommand.parser

    def execute(self, params, **kwargs):
        network = kwargs.get('network')
        if not network:
            print('Use --network to specify a PAM network UID.')
            return

        # Show integration configuration
        try:
            integration_rs = cnapp_helper.cnapp_get_integration(params, network_uid=network)
            if integration_rs and hasattr(integration_rs, 'integrations') and integration_rs.integrations:
                print(f'CNAPP Integration for Network: {network}')
                for entry in integration_rs.integrations:
                    print(f'  Provider:       {entry.provider}')
                    print(f'  Webhook ID:     {entry.webhookId}')
                    print(f'  API URL:        {entry.apiUrl}')
                    print(f'  Auth URL:       {entry.authUrl}')
                    print(f'  Controller UID: {entry.controllerUid}')
                    print(f'  Webhook URL:    {entry.webhookUrl}')
                    print()
            else:
                print(f'No CNAPP integration configured for network {network}')
                print()
        except Exception as e:
            print(f'Could not retrieve integration info: {e}')
            print()

        # Show queue summary for the network
        rs = cnapp_helper.cnapp_list_queue(params, network_uid=network, limit=5)
        if rs and hasattr(rs, 'items'):
            print(f'CNAPP Queue Summary for Network: {network}')
            print(f'  Total items: {rs.total}')
            print(f'  Recent items: {len(rs.items)}')
            if rs.items:
                headers = ['Queue ID', 'Control', 'Provider', 'Status', 'Received']
                rows = []
                for item in rs.items:
                    rows.append([
                        item.cnappQueueId[:12] + '...',
                        item.controlKey[:40],
                        PROVIDER_MAP.get(item.cnappProviderId, str(item.cnappProviderId)),
                        STATUS_MAP.get(item.cnappQueueStatusId, str(item.cnappQueueStatusId)),
                        datetime.fromtimestamp(item.receivedAt / 1000).strftime('%Y-%m-%d %H:%M')
                        if item.receivedAt else '-'
                    ])
                dump_report_data(rows, headers, fmt=kwargs.get('format', ''))
        else:
            print(f'No CNAPP queue data for network {network}')


class PAMCnappTestCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp test')
    parser.add_argument('--provider', '-p', required=True, dest='provider', help='CNAPP provider (wiz)')
    parser.add_argument('--client-id', required=True, dest='client_id', help='OAuth2 Client ID')
    parser.add_argument('--client-secret', required=True, dest='client_secret', help='OAuth2 Client Secret')
    parser.add_argument('--api-url', required=True, dest='api_url', help='Provider API endpoint URL')
    parser.add_argument('--auth-url', required=True, dest='auth_url', help='Provider OAuth2 auth URL')

    def get_parser(self):
        return PAMCnappTestCommand.parser

    def execute(self, params, **kwargs):
        rs = cnapp_helper.cnapp_test_credentials(
            params,
            provider=kwargs['provider'],
            client_id=kwargs['client_id'],
            client_secret=kwargs['client_secret'],
            api_url=kwargs['api_url'],
            auth_url=kwargs['auth_url']
        )
        if rs and hasattr(rs, 'valid'):
            if rs.valid:
                print(f'Credentials are valid. {rs.message}')
            else:
                print(f'Credentials are invalid. Error: {rs.error}')
                if rs.message:
                    print(f'  Details: {rs.message}')
        else:
            print(f'Response: {rs}')


# ============================================================
# Queue management commands
# ============================================================

class PAMCnappQueueCommand(GroupCommand):
    def __init__(self):
        super(PAMCnappQueueCommand, self).__init__()
        self.register_command('list', PAMCnappQueueListCommand(), 'List queue items', 'l')
        self.register_command('detail', PAMCnappQueueDetailCommand(), 'Show item detail', 'd')
        self.register_command('associate', PAMCnappQueueAssociateCommand(), 'Link PAM record', 'a')
        self.register_command('remediate', PAMCnappQueueRemediateCommand(), 'Trigger remediation', 'r')
        self.register_command('resolve', PAMCnappQueueResolveCommand(), 'Mark as resolved', 'rs')
        self.register_command('ignore', PAMCnappQueueIgnoreCommand(), 'Dismiss item', 'ig')
        self.default_verb = 'list'


class PAMCnappQueueListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue list')
    parser.add_argument('--network', '-n', required=True, dest='network', help='PAM Network UID')
    parser.add_argument('--status', '-s', dest='status', type=int, help='Filter by status (1-5)')
    parser.add_argument('--limit', '-l', dest='limit', type=int, default=50, help='Max items')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table')

    def get_parser(self):
        return PAMCnappQueueListCommand.parser

    def execute(self, params, **kwargs):
        rs = cnapp_helper.cnapp_list_queue(
            params,
            network_uid=kwargs['network'],
            status_filter=kwargs.get('status'),
            limit=kwargs.get('limit', 50)
        )
        if rs and hasattr(rs, 'items'):
            headers = ['Queue ID', 'Control Key', 'Provider', 'Status', 'Received', 'Record UID']
            rows = []
            for item in rs.items:
                record_uid = '-'
                if item.recordUid:
                    from ... import utils as ku
                    record_uid = ku.base64_url_encode(item.recordUid)
                rows.append([
                    item.cnappQueueId,
                    item.controlKey[:50],
                    PROVIDER_MAP.get(item.cnappProviderId, str(item.cnappProviderId)),
                    STATUS_MAP.get(item.cnappQueueStatusId, str(item.cnappQueueStatusId)),
                    datetime.fromtimestamp(item.receivedAt / 1000).strftime('%Y-%m-%d %H:%M:%S')
                    if item.receivedAt else '-',
                    record_uid
                ])
            dump_report_data(rows, headers, title=f'CNAPP Queue ({rs.total} total)',
                             fmt=kwargs.get('format', ''))
        else:
            print('No queue items found.')


class PAMCnappQueueDetailCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue detail')
    parser.add_argument('queue_id', help='Queue item ID')

    def get_parser(self):
        return PAMCnappQueueDetailCommand.parser

    def execute(self, params, **kwargs):
        rs = cnapp_helper.cnapp_get_queue_item(params, queue_id=kwargs['queue_id'])
        if rs and hasattr(rs, 'cnappQueueId'):
            print(f'Queue ID:    {rs.cnappQueueId}')
            print(f'Control Key: {rs.controlKey}')
            print(f'Provider:    {PROVIDER_MAP.get(rs.cnappProviderId, str(rs.cnappProviderId))}')
            print(f'Status:      {STATUS_MAP.get(rs.cnappQueueStatusId, str(rs.cnappQueueStatusId))}')
            print(f'Received:    {datetime.fromtimestamp(rs.receivedAt / 1000) if rs.receivedAt else "-"}')
            if rs.resolvedAt:
                print(f'Resolved:    {datetime.fromtimestamp(rs.resolvedAt / 1000)}')
            if rs.recordUid:
                from ... import utils as ku
                print(f'Record UID:  {ku.base64_url_encode(rs.recordUid)}')
        else:
            print(f'Queue item not found: {kwargs["queue_id"]}')


class PAMCnappQueueAssociateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue associate')
    parser.add_argument('queue_id', help='Queue item ID')
    parser.add_argument('--record', '-r', required=True, dest='record_uid', help='PAM record UID')
    parser.add_argument('--execute', '-e', action='store_true', dest='execute_after',
                        help='Trigger remediation after association')

    def get_parser(self):
        return PAMCnappQueueAssociateCommand.parser

    def execute(self, params, **kwargs):
        rs = cnapp_helper.cnapp_associate_record(
            params,
            queue_id=kwargs['queue_id'],
            record_uid=kwargs['record_uid'],
            execute_after_setup=kwargs.get('execute_after', False)
        )
        if rs and hasattr(rs, 'status'):
            print(f'Status: {rs.status}')
            if rs.remediationTriggered:
                print('Remediation has been triggered.')
        else:
            print(f'Response: {rs}')


class PAMCnappQueueRemediateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue remediate')
    parser.add_argument('queue_id', help='Queue item ID')
    parser.add_argument('--action', '-a', dest='action_type', required=True,
                        help='Action type (e.g. ROTATE_PASSWORD)')

    def get_parser(self):
        return PAMCnappQueueRemediateCommand.parser

    def execute(self, params, **kwargs):
        rs = cnapp_helper.cnapp_remediate(
            params,
            queue_id=kwargs['queue_id'],
            action_type=kwargs['action_type']
        )
        if rs and hasattr(rs, 'status'):
            print(f'Remediation Status: {rs.status}')
            print(f'Action Type: {rs.actionType}')
            print(f'Result: {rs.result}')
        else:
            print(f'Response: {rs}')


class PAMCnappQueueResolveCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue resolve')
    parser.add_argument('queue_id', help='Queue item ID')
    parser.add_argument('--notes', dest='notes', help='Resolution notes')

    def get_parser(self):
        return PAMCnappQueueResolveCommand.parser

    def execute(self, params, **kwargs):
        cnapp_helper.cnapp_resolve(params, queue_id=kwargs['queue_id'], notes=kwargs.get('notes'))
        print(f'Queue item {kwargs["queue_id"]} marked as resolved.')


class PAMCnappQueueIgnoreCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue ignore')
    parser.add_argument('queue_id', help='Queue item ID')
    parser.add_argument('--reason', dest='reason', help='Reason for ignoring')

    def get_parser(self):
        return PAMCnappQueueIgnoreCommand.parser

    def execute(self, params, **kwargs):
        cnapp_helper.cnapp_ignore(params, queue_id=kwargs['queue_id'], reason=kwargs.get('reason'))
        print(f'Queue item {kwargs["queue_id"]} dismissed.')


# ============================================================
# Default behavior commands
# ============================================================

class PAMCnappBehaviorCommand(GroupCommand):
    def __init__(self):
        super(PAMCnappBehaviorCommand, self).__init__()
        self.register_command('list', PAMCnappBehaviorListCommand(), 'List behavior rules', 'l')
        self.register_command('add', PAMCnappBehaviorAddCommand(), 'Create behavior rule', 'a')
        self.register_command('update', PAMCnappBehaviorUpdateCommand(), 'Update behavior rule', 'u')
        self.register_command('remove', PAMCnappBehaviorRemoveCommand(), 'Delete behavior rule', 'rm')
        self.default_verb = 'list'


class PAMCnappBehaviorListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp behavior list')
    parser.add_argument('--network', '-n', dest='network', help='Filter by PAM Network UID')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table')

    def get_parser(self):
        return PAMCnappBehaviorListCommand.parser

    def execute(self, params, **kwargs):
        rs = cnapp_helper.cnapp_list_behaviors(params, network_uid=kwargs.get('network'))
        if rs and hasattr(rs, 'items'):
            headers = ['ID', 'Network', 'Provider', 'Control Key', 'Action', 'Auto-Execute', 'Enabled']
            rows = []
            for item in rs.items:
                from ... import utils as ku
                network_str = ku.base64_url_encode(item.networkId) if item.networkId else '-'
                rows.append([
                    item.id,
                    network_str,
                    PROVIDER_MAP.get(item.cnappProviderId, str(item.cnappProviderId)),
                    item.controlKey[:50],
                    ACTION_TYPE_MAP.get(item.cnappActionTypeId, str(item.cnappActionTypeId)),
                    'Yes' if item.autoExecute else 'No',
                    'Yes' if item.enabled else 'No'
                ])
            dump_report_data(rows, headers, title='CNAPP Default Behaviors',
                             fmt=kwargs.get('format', ''))
        else:
            print('No behavior rules found.')


class PAMCnappBehaviorAddCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp behavior add')
    parser.add_argument('--control-key', '-k', required=True, dest='control_key', help='CNAPP control key/ID')
    parser.add_argument('--action', '-a', required=True, dest='action_type', type=int,
                        help='Action type ID (1=ROTATE_PASSWORD, 2=REMOVE_PRIVILEGES, 3=CONFIGURE_JIT, 4=MANUAL)')
    parser.add_argument('--network', '-n', required=True, dest='network', help='PAM Network UID')
    parser.add_argument('--provider', '-p', required=True, dest='provider_id', type=int, help='Provider ID (1=WIZ)')
    parser.add_argument('--no-auto-execute', action='store_true', dest='no_auto', help='Disable auto-execution')

    def get_parser(self):
        return PAMCnappBehaviorAddCommand.parser

    def execute(self, params, **kwargs):
        rs = cnapp_helper.cnapp_create_behavior(
            params,
            control_key=kwargs['control_key'],
            action_type_id=kwargs['action_type'],
            network_uid=kwargs['network'],
            provider_id=kwargs['provider_id'],
            auto_execute=not kwargs.get('no_auto', False)
        )
        if rs and hasattr(rs, 'cnappDefaultBehaviorId'):
            print(f'Behavior rule created. ID: {rs.cnappDefaultBehaviorId}')
        else:
            print(f'Response: {rs}')


class PAMCnappBehaviorUpdateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp behavior update')
    parser.add_argument('behavior_id', type=int, help='Behavior rule ID')
    parser.add_argument('--control-key', '-k', dest='control_key', help='New control key')
    parser.add_argument('--action', '-a', dest='action_type', type=int, help='New action type ID')
    parser.add_argument('--auto-execute', dest='auto_execute', choices=['true', 'false'],
                        help='Enable/disable auto-execution')
    parser.add_argument('--enabled', dest='enabled', choices=['true', 'false'],
                        help='Enable/disable rule')

    def get_parser(self):
        return PAMCnappBehaviorUpdateCommand.parser

    def execute(self, params, **kwargs):
        auto_exec = None
        if kwargs.get('auto_execute') is not None:
            auto_exec = kwargs['auto_execute'] == 'true'
        enabled = None
        if kwargs.get('enabled') is not None:
            enabled = kwargs['enabled'] == 'true'

        cnapp_helper.cnapp_update_behavior(
            params,
            behavior_id=kwargs['behavior_id'],
            control_key=kwargs.get('control_key'),
            action_type_id=kwargs.get('action_type'),
            auto_execute=auto_exec,
            enabled=enabled
        )
        print(f'Behavior rule {kwargs["behavior_id"]} updated.')


class PAMCnappBehaviorRemoveCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp behavior remove')
    parser.add_argument('behavior_id', type=int, help='Behavior rule ID')
    parser.add_argument('--force', '-f', action='store_true', dest='force', help='Skip confirmation')

    def get_parser(self):
        return PAMCnappBehaviorRemoveCommand.parser

    def execute(self, params, **kwargs):
        if not kwargs.get('force'):
            confirm = input(f'Delete behavior rule {kwargs["behavior_id"]}? [y/N]: ')
            if confirm.lower() != 'y':
                print('Cancelled.')
                return
        cnapp_helper.cnapp_delete_behavior(params, behavior_id=kwargs['behavior_id'])
        print(f'Behavior rule {kwargs["behavior_id"]} deleted.')
