import argparse
import json
import logging

from keepercommander.commands.base import Command, GroupCommand
from keepercommander.commands.pam.pam_dto import (
    GatewayAction,
    GatewayActionIdpInputs,
    GatewayActionIdpCreateUser,
    GatewayActionIdpDeleteUser,
    GatewayActionIdpAddUserToGroup,
    GatewayActionIdpRemoveUserFromGroup,
    GatewayActionIdpGroupList,
)
from keepercommander.commands.pam.router_helper import router_send_action_to_gateway
from keepercommander.error import CommandError
from keepercommander import vault
from keepercommander.proto import pam_pb2


logger = logging.getLogger(__name__)


VALID_IDP_CONFIG_TYPES = {
    'pamAzureConfiguration',
    'pamOktaConfiguration',
    'pamDomainConfiguration',
    'pamAwsConfiguration',
    'pamGcpConfiguration',
}


def resolve_idp_config(params, config_uid):
    """Resolve the Identity Provider config UID from a PAM configuration.

    Reads the 'identityProviderUid' custom text field on the PAM config record.
    If set, returns the referenced config UID (the IdP).
    If empty, returns config_uid itself (self-managing).
    """
    record = vault.KeeperRecord.load(params, config_uid)
    if not record:
        raise CommandError('pam-idp', f'PAM configuration "{config_uid}" not found.')
    if not isinstance(record, vault.TypedRecord):
        raise CommandError('pam-idp', 'Only typed PAM configuration records are supported.')

    # Check custom field for identityProviderUid
    for field in record.custom:
        if field.type == 'text' and field.label == 'identityProviderUid':
            values = list(field.get_external_value())
            if values and values[0]:
                idp_uid = values[0]
                idp_record = vault.KeeperRecord.load(params, idp_uid)
                if not idp_record:
                    raise CommandError('pam-idp',
                                       f'Identity Provider config "{idp_uid}" not found.')
                if isinstance(idp_record, vault.TypedRecord):
                    if idp_record.record_type not in VALID_IDP_CONFIG_TYPES:
                        raise CommandError('pam-idp',
                                           f'Referenced config type "{idp_record.record_type}" '
                                           f'does not support identity provider operations.')
                return idp_uid

    # Self-managing — verify config type supports IdP
    if record.record_type in VALID_IDP_CONFIG_TYPES:
        return config_uid

    raise CommandError('pam-idp',
                       f'No Identity Provider available for config type "{record.record_type}". '
                       f'Link one with: pam config edit {config_uid} --identity-provider <idp-uid>')


def _dispatch_idp_action(params, gateway_action, gateway_uid=None):
    """Dispatch a GatewayAction to the gateway and return the response."""
    conversation_id = GatewayAction.generate_conversation_id()
    gateway_action.conversationId = conversation_id

    router_response = router_send_action_to_gateway(
        params=params,
        gateway_action=gateway_action,
        message_type=pam_pb2.CMT_GENERAL,
        is_streaming=False,
        destination_gateway_uid_str=gateway_uid,
    )

    if not router_response:
        raise CommandError('pam-idp', 'No response received from gateway.')

    response = router_response.get('response', {})
    payload_str = response.get('payload')
    if not payload_str:
        raise CommandError('pam-idp', 'Empty response payload from gateway.')

    payload = json.loads(payload_str)

    if not (payload.get('is_ok') or payload.get('isOk')):
        error_msg = payload.get('error', payload.get('message', 'Unknown gateway error'))
        raise CommandError('pam-idp', f'Gateway error: {error_msg}')

    return payload


# --- Command Groups ---


class PAMIdpCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('user', PAMIdpUserCommand(), 'Manage Identity Provider users')
        self.register_command('group', PAMIdpGroupCommand(), 'Manage Identity Provider groups')


class PAMIdpUserCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('provision', PAMIdpUserProvisionCommand(),
                              'Provision a user in the Identity Provider')
        self.register_command('deprovision', PAMIdpUserDeprovisionCommand(),
                              'Deprovision a user from the Identity Provider')
        self.register_command('list', PAMIdpUserListCommand(),
                              'List users in the Identity Provider')


class PAMIdpGroupCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('add-user', PAMIdpGroupAddUserCommand(),
                              'Add a user to a group')
        self.register_command('remove-user', PAMIdpGroupRemoveUserCommand(),
                              'Remove a user from a group')
        self.register_command('list', PAMIdpGroupListCommand(),
                              'List groups in the Identity Provider')


# --- User Commands ---


class PAMIdpUserProvisionCommand(Command):
    parser = argparse.ArgumentParser(prog='pam idp user provision',
                                     description='Provision a user in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--username', '-u', required=True, dest='username',
                        help='Username to create')
    parser.add_argument('--display-name', '-d', dest='display_name',
                        help='Display name (defaults to username)')
    parser.add_argument('--password', '-p', dest='password',
                        help='Initial password (auto-generated if omitted)')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMIdpUserProvisionCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        username = kwargs['username']
        idp_config_uid = resolve_idp_config(params, config_uid)

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=username,
            displayName=kwargs.get('display_name') or username,
            password=kwargs.get('password'),
        )
        action = GatewayActionIdpCreateUser(inputs=inputs)

        payload = _dispatch_idp_action(params, action, kwargs.get('gateway'))

        data = payload.get('data', {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                pass

        logging.info(f'User provisioned successfully.')
        if isinstance(data, dict):
            print(f'  Username:     {data.get("name", username)}')
            if data.get('id'):
                print(f'  User ID:      {data["id"]}')
            print(f'  Password:     {"**********" if data.get("password") else "(none)"}')
        else:
            print(f'  Username:     {username}')
            print(f'  Response:     {data}')


class PAMIdpUserDeprovisionCommand(Command):
    parser = argparse.ArgumentParser(prog='pam idp user deprovision',
                                     description='Deprovision a user from the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--username', '-u', required=True, dest='username',
                        help='Username or user principal name')
    parser.add_argument('--force', dest='force', action='store_true',
                        help='Skip confirmation prompt')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMIdpUserDeprovisionCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        username = kwargs['username']
        idp_config_uid = resolve_idp_config(params, config_uid)

        if not kwargs.get('force'):
            try:
                answer = input(f'Are you sure you want to deprovision user "{username}"? (y/N): ')
                if answer.lower() not in ('y', 'yes'):
                    print('Cancelled.')
                    return
            except EOFError:
                print('Cancelled.')
                return

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=username,
        )
        action = GatewayActionIdpDeleteUser(inputs=inputs)

        _dispatch_idp_action(params, action, kwargs.get('gateway'))

        logging.info(f'User "{username}" deprovisioned successfully.')


class PAMIdpUserListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam idp user list',
                                     description='List users in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMIdpUserListCommand.parser

    def execute(self, params, **kwargs):
        raise CommandError('pam-idp',
                           'User listing is not yet implemented. '
                           'Use "pam idp group list" to list groups, or check the IdP portal directly.')


# --- Group Commands ---


class PAMIdpGroupListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam idp group list',
                                     description='List groups in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--format', '-f', dest='output_format', choices=['table', 'json'],
                        default='table', help='Output format (default: table)')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMIdpGroupListCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        idp_config_uid = resolve_idp_config(params, config_uid)

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            includeUsers=True,
        )
        action = GatewayActionIdpGroupList(inputs=inputs)

        payload = _dispatch_idp_action(params, action, kwargs.get('gateway'))

        data = payload.get('data', [])
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                pass

        if kwargs.get('output_format') == 'json':
            print(json.dumps(data, indent=2))
            return

        if not data or not isinstance(data, list):
            print('No groups found.')
            return

        from keepercommander.commands.base import dump_report_data
        headers = ['Group ID', 'Name', 'Members']
        table = []
        for group in data:
            if isinstance(group, dict):
                table.append([
                    group.get('id', ''),
                    group.get('name', ''),
                    str(group.get('memberCount', group.get('members', ''))),
                ])
        dump_report_data(table, headers=headers)


class PAMIdpGroupAddUserCommand(Command):
    parser = argparse.ArgumentParser(prog='pam idp group add-user',
                                     description='Add a user to a group in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--username', '-u', required=True, dest='username',
                        help='Username or user ID')
    parser.add_argument('--group', '-gr', required=True, dest='group_id',
                        help='Group name or ID')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMIdpGroupAddUserCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        username = kwargs['username']
        group_id = kwargs['group_id']
        idp_config_uid = resolve_idp_config(params, config_uid)

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=username,
            groupId=group_id,
        )
        action = GatewayActionIdpAddUserToGroup(inputs=inputs)

        _dispatch_idp_action(params, action, kwargs.get('gateway'))

        logging.info(f'User "{username}" added to group "{group_id}".')


class PAMIdpGroupRemoveUserCommand(Command):
    parser = argparse.ArgumentParser(prog='pam idp group remove-user',
                                     description='Remove a user from a group in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--username', '-u', required=True, dest='username',
                        help='Username or user ID')
    parser.add_argument('--group', '-gr', required=True, dest='group_id',
                        help='Group name or ID')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMIdpGroupRemoveUserCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        username = kwargs['username']
        group_id = kwargs['group_id']
        idp_config_uid = resolve_idp_config(params, config_uid)

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=username,
            groupId=group_id,
        )
        action = GatewayActionIdpRemoveUserFromGroup(inputs=inputs)

        _dispatch_idp_action(params, action, kwargs.get('gateway'))

        logging.info(f'User "{username}" removed from group "{group_id}".')
