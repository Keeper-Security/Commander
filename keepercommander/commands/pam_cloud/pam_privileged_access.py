import argparse
import base64
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
from keepercommander import api, crypto, record_management, vault
from keepercommander.proto import pam_pb2
from keepercommander.subfolder import find_parent_top_folder


logger = logging.getLogger(__name__)


VALID_CONFIG_TYPES = {
    'pamAzureConfiguration',
    'pamOktaConfiguration',
    'pamDomainConfiguration',
    'pamAwsConfiguration',
    'pamGcpConfiguration',
}


def resolve_pam_idp_config(params, config_uid):
    """Resolve the Identity Provider config UID from a PAM configuration.

    Reads the 'identityProviderUid' custom text field on the PAM config record.
    If set, returns the referenced config UID (the IdP).
    If empty, returns config_uid itself (self-managing).
    """
    record = vault.KeeperRecord.load(params, config_uid)
    if not record:
        raise CommandError('pam-privileged-access', f'PAM configuration "{config_uid}" not found.')
    if not isinstance(record, vault.TypedRecord):
        raise CommandError('pam-privileged-access', 'Only typed PAM configuration records are supported.')

    # Check custom field for identityProviderUid
    for field in record.custom:
        if field.type == 'text' and field.label == 'identityProviderUid':
            values = list(field.get_external_value())
            if values and values[0]:
                idp_uid = values[0]
                idp_record = vault.KeeperRecord.load(params, idp_uid)
                if not idp_record:
                    raise CommandError('pam-privileged-access',
                                       f'PAM Identity Provider config "{idp_uid}" not found.')
                if isinstance(idp_record, vault.TypedRecord):
                    if idp_record.record_type not in VALID_CONFIG_TYPES:
                        raise CommandError('pam-privileged-access',
                                           f'Referenced config type "{idp_record.record_type}" '
                                           f'does not support identity provider operations.')
                return idp_uid

    # Self-managing — verify config type supports IdP
    if record.record_type in VALID_CONFIG_TYPES:
        return config_uid

    raise CommandError('pam-privileged-access',
                       f'No Identity Provider available for config type "{record.record_type}". '
                       f'Link one with: pam config edit {config_uid} --identity-provider <idp-uid>')


def _get_record_key(params, config_uid):
    """Get the record key for a PAM config record."""
    record = vault.KeeperRecord.load(params, config_uid)
    if not record or not record.record_key:
        raise CommandError('pam-privileged-access', 'Record key unavailable for config record.')
    return record.record_key


def _encrypt_field(value, record_key):
    """Encrypt a string value with the record key, return base64."""
    encrypted = crypto.encrypt_aes_v2(value.encode('utf-8'), record_key)
    return base64.b64encode(encrypted).decode('utf-8')


def _decrypt_gateway_data(params, config_uid, encrypted_data):
    """Decrypt record-key-encrypted data from gateway response."""
    record_key = _get_record_key(params, config_uid)
    enc_bytes = base64.b64decode(encrypted_data)
    decrypted = crypto.decrypt_aes_v2(enc_bytes, record_key)
    return json.loads(decrypted.decode('utf-8'))


def _friendly_error(error_msg):
    """Convert raw gateway/Azure error messages into user-friendly text."""
    msg_lower = error_msg.lower()
    if 'request_resourcenotfound' in msg_lower:
        if 'group' in msg_lower:
            return 'User is not a member of this group.'
        return 'The specified resource was not found.'
    if 'request_badrequest' in msg_lower:
        # Try to extract the Azure message
        try:
            parsed = json.loads(error_msg.split(':', 1)[1].strip()) if ':' in error_msg else {}
            inner_msg = parsed.get('error', {}).get('message', '')
            if inner_msg:
                return inner_msg
        except (json.JSONDecodeError, IndexError):
            pass
    if 'already exist' in msg_lower or 'one or more added object references already exist' in msg_lower:
        return 'User is already a member of this group.'
    if 'does not exist' in msg_lower and 'user' in msg_lower:
        return 'User not found in the Identity Provider.'
    return error_msg


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
        raise CommandError('pam-privileged-access', 'No response received from gateway.')

    response = router_response.get('response', {})
    payload_str = response.get('payload')
    if not payload_str:
        raise CommandError('pam-privileged-access', 'Empty response payload from gateway.')

    payload = json.loads(payload_str)

    if not (payload.get('is_ok') or payload.get('isOk')):
        error_msg = payload.get('error', payload.get('message', 'Unknown gateway error'))
        raise CommandError('pam-privileged-access', f'Gateway error: {error_msg}')

    data = payload.get('data', {})
    if isinstance(data, dict) and not data.get('success', True):
        error_msg = data.get('error', 'Unknown error')
        raise CommandError('pam-privileged-access', _friendly_error(error_msg))

    return payload


# --- Command Groups ---


class PAMPrivilegedAccessCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('user', PAMAccessUserCommand(), 'Manage privileged IdP users')
        self.register_command('group', PAMAccessGroupCommand(), 'Manage privileged IdP groups')


class PAMAccessUserCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('provision', PAMAccessUserProvisionCommand(),
                              'Provision a privileged user in the Identity Provider')
        self.register_command('deprovision', PAMAccessUserDeprovisionCommand(),
                              'Deprovision a privileged user from the Identity Provider')
        self.register_command('list', PAMAccessUserListCommand(),
                              'List users in the Identity Provider')


class PAMAccessGroupCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('add-user', PAMAccessGroupAddUserCommand(),
                              'Add a user to a privileged group in the Identity Provider')
        self.register_command('remove-user', PAMAccessGroupRemoveUserCommand(),
                              'Remove a user from privileged group in the Identity Provider')
        self.register_command('list', PAMAccessGroupListCommand(),
                              'List groups in the Identity Provider')


# --- User Commands ---


class PAMAccessUserProvisionCommand(Command):
    parser = argparse.ArgumentParser(prog='pam access user provision',
                                     description='Provision a privileged user in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--username', '-u', required=True, dest='username',
                        help='Username to create (e.g. testuser or testuser@domain.com)')
    parser.add_argument('--domain', '-d', dest='domain',
                        help='Domain for the user (e.g. domain.com, if not included in --username)')
    parser.add_argument('--display-name', '-n', dest='display_name',
                        help='Display name (defaults to --username)')
    parser.add_argument('--password', '-p', dest='password',
                        help='Initial password (auto-generated if omitted)')
    parser.add_argument('--save-record', '-s', dest='save_record', action='store_true',
                        help='Save provisioned credentials as a pamUser record')
    parser.add_argument('--folder', '-f', dest='folder_uid',
                        help='Folder UID to save the record in (used with --save-record)')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMAccessUserProvisionCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        username = kwargs['username']
        domain = kwargs.get('domain')

        if '@' in username:
            if domain:
                logging.warning('Username already contains @domain, ignoring --domain flag.')
        elif domain:
            username = f'{username}@{domain}'
        else:
            raise CommandError('pam-privileged-access',
                               'Username must include domain (e.g. user@domain.com), '
                               'or use --domain to specify one.')
        idp_config_uid = resolve_pam_idp_config(params, config_uid)
        record_key = _get_record_key(params, config_uid)

        meta = {}
        display_name = kwargs.get('display_name')
        if display_name:
            meta['display_name'] = display_name
        encrypted_meta = _encrypt_field(json.dumps(meta), record_key) if meta else None

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=_encrypt_field(username, record_key),
            password=kwargs.get('password'),
        )
        if encrypted_meta:
            inputs.meta = encrypted_meta
        action = GatewayActionIdpCreateUser(inputs=inputs)

        payload = _dispatch_idp_action(params, action, kwargs.get('gateway'))

        response_data = payload.get('data', {})
        if isinstance(response_data, str):
            try:
                response_data = json.loads(response_data)
            except (json.JSONDecodeError, TypeError):
                response_data = {}

        if isinstance(response_data, dict) and not response_data.get('success', True):
            error = response_data.get('error', 'Unknown error')
            raise CommandError('pam-privileged-access', f'Gateway reported failure: {error}')

        # Decrypt the response data if encrypted
        data = {}
        encrypted_content = response_data.get('data') if isinstance(response_data, dict) else None
        if encrypted_content:
            try:
                data = _decrypt_gateway_data(params, config_uid, encrypted_content)
            except Exception:
                data = {}

        if isinstance(data, dict):
            # Handle different response formats (Azure returns 'name' as string, GCP returns dict)
            raw_name = data.get('name', username)
            if isinstance(raw_name, dict):
                user_name = data.get('primaryEmail', username)
            else:
                user_name = raw_name
            user_password = data.get('password', '')
            user_id = data.get('id', '')
        else:
            user_name = username
            user_password = ''
            user_id = ''

        logging.info(f'User provisioned successfully.')
        print(f'  Username:     {user_name}')
        if user_id:
            print(f'  User ID:      {user_id}')
        print(f'  Password:     {"**********" if user_password else "(none)"}')

        if kwargs.get('save_record'):
            display_name = kwargs.get('display_name') or username
            record = vault.TypedRecord()
            record.type_name = 'pamUser'
            record.title = display_name
            record.fields.append(vault.TypedField.new_field('login', user_name))
            record.fields.append(vault.TypedField.new_field('password', user_password))
            if user_id:
                idp_record = vault.KeeperRecord.load(params, idp_config_uid)
                idp_type = idp_record.record_type if isinstance(idp_record, vault.TypedRecord) else ''
                idp_label_map = {
                    'pamAzureConfiguration': 'Azure User ID',
                    'pamGcpConfiguration': 'GCP User ID',
                    'pamOktaConfiguration': 'Okta User ID',
                    'pamAwsConfiguration': 'AWS User ID',
                    'pamDomainConfiguration': 'Domain User ID',
                }
                user_id_label = idp_label_map.get(idp_type, 'IdP User ID')
                record.custom.append(vault.TypedField.new_field('text', user_id, user_id_label))

            folder_uid = kwargs.get('folder_uid')
            if not folder_uid:
                shared_folders = find_parent_top_folder(params, config_uid)
                if shared_folders:
                    sf = shared_folders[0]
                    folder_uid = sf.parent_uid if sf.parent_uid else sf.uid
            record_management.add_record_to_folder(params, record, folder_uid)
            params.sync_data = True

            print(f'  Record UID:   {record.record_uid}')
            logging.info(f'Credentials saved as pamUser record.')


class PAMAccessUserDeprovisionCommand(Command):
    parser = argparse.ArgumentParser(prog='pam access user deprovision',
                                     description='Deprovision a privileged user from the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--username', '-u', required=True, dest='username',
                        help='Username or user principal name')
    parser.add_argument('--delete-record', '-d', dest='delete_record', nargs='?', const='auto',
                        metavar='RECORD_UID',
                        help='Delete the associated pamUser record. Optionally pass a record UID, '
                             'or omit to auto-find by Azure user ID.')
    parser.add_argument('--force', dest='force', action='store_true',
                        help='Skip confirmation prompt')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMAccessUserDeprovisionCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        username = kwargs['username']
        idp_config_uid = resolve_pam_idp_config(params, config_uid)
        record_key = _get_record_key(params, config_uid)

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
            user=_encrypt_field(username, record_key),
        )
        action = GatewayActionIdpDeleteUser(inputs=inputs)

        _dispatch_idp_action(params, action, kwargs.get('gateway'))

        logging.info(f'User "{username}" deprovisioned successfully.')

        delete_record = kwargs.get('delete_record')
        if delete_record:
            if delete_record == 'auto':
                record_uid = _find_pam_user_record_by_user_id(params, username)
                if record_uid:
                    api.delete_record(params, record_uid)
                    logging.info(f'Deleted pamUser record {record_uid}.')
                else:
                    logging.warning(f'No pamUser record with matching IdP User ID found for "{username}".')

            else:
                record = vault.KeeperRecord.load(params, delete_record)
                if record:
                    api.delete_record(params, delete_record)
                    logging.info(f'Deleted record {delete_record}.')
                else:
                    logging.warning(f'Record "{delete_record}" not found.')


def _find_pam_user_record_by_user_id(params, username):
    """Find a pamUser record with an IdP User ID custom field matching the given username."""
    username_lower = username.lower()
    for record_uid in params.record_cache:
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            continue
        if record.type_name != 'pamUser':
            continue
        # Check login matches (exact or prefix match for username without domain)
        login_match = False
        for field in record.fields:
            if field.type == 'login':
                values = list(field.get_external_value())
                if values and values[0]:
                    login_lower = values[0].lower()
                    if login_lower == username_lower or login_lower.split('@')[0] == username_lower:
                        login_match = True
                        break
        if not login_match:
            continue
        # Prefer records that have an IdP User ID custom field
        idp_user_id_labels = {'Azure User ID', 'GCP User ID', 'Okta User ID', 'AWS User ID',
                              'Domain User ID', 'IdP User ID'}
        for field in record.custom:
            if field.label in idp_user_id_labels:
                values = list(field.get_external_value())
                if values and values[0]:
                    return record_uid
    return None


class PAMAccessUserListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam access user list',
                                     description='List users in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMAccessUserListCommand.parser

    def execute(self, params, **kwargs):
        raise CommandError('pam-privileged-access',
                           'User listing is not yet implemented. '
                           'Use "pam idp group list" to list groups, or check the IdP portal directly.')


# --- Group Commands ---


class PAMAccessGroupListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam access group list',
                                     description='List groups in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--format', '-f', dest='output_format', choices=['table', 'json'],
                        default='table', help='Output format (default: table)')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMAccessGroupListCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        idp_config_uid = resolve_pam_idp_config(params, config_uid)

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            includeUsers=True,
        )
        action = GatewayActionIdpGroupList(inputs=inputs)

        payload = _dispatch_idp_action(params, action, kwargs.get('gateway'))

        # Gateway response: data = {configurationUid, success, data: <encrypted_base64>}
        response_data = payload.get('data', {})
        if isinstance(response_data, str):
            try:
                response_data = json.loads(response_data)
            except (json.JSONDecodeError, TypeError):
                response_data = {}

        if not isinstance(response_data, dict) or not response_data.get('success'):
            error = response_data.get('error', 'Unknown error') if isinstance(response_data, dict) else str(response_data)
            raise CommandError('pam-privileged-access', f'Gateway reported failure: {error}')

        # Decrypt the inner encrypted data using the config record key
        encrypted_content = response_data.get('data')
        if not encrypted_content:
            print('No groups found.')
            return

        groups = _decrypt_gateway_data(params, config_uid, encrypted_content)

        if kwargs.get('output_format') == 'json':
            print(json.dumps(groups, indent=2))
            return

        if not groups or not isinstance(groups, list):
            print('No groups found.')
            return

        from keepercommander.commands.base import dump_report_data
        headers = ['Group ID', 'Name', 'Members']
        table = []
        for group in groups:
            if isinstance(group, dict):
                users = group.get('users', [])
                member_count = len(users) if isinstance(users, list) else 0
                table.append([
                    group.get('id', ''),
                    group.get('name', ''),
                    str(member_count),
                ])
        dump_report_data(table, headers=headers)


class PAMAccessGroupAddUserCommand(Command):
    parser = argparse.ArgumentParser(prog='pam access group add-user',
                                     description='Add a user to a privileged group in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--username', '-u', required=True, dest='username',
                        help='Username or user ID')
    parser.add_argument('--group', '-gr', required=True, dest='group_id',
                        help='Group name or ID')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMAccessGroupAddUserCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        username = kwargs['username']
        group_id = kwargs['group_id']
        idp_config_uid = resolve_pam_idp_config(params, config_uid)
        record_key = _get_record_key(params, config_uid)

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=_encrypt_field(username, record_key),
            groupId=group_id,
        )
        action = GatewayActionIdpAddUserToGroup(inputs=inputs)

        _dispatch_idp_action(params, action, kwargs.get('gateway'))

        logging.info(f'User "{username}" added to group "{group_id}".')


class PAMAccessGroupRemoveUserCommand(Command):
    parser = argparse.ArgumentParser(prog='pam access group remove-user',
                                     description='Remove a user from a privileged group in the Identity Provider')
    parser.add_argument('--config', '-c', required=True, dest='config_uid',
                        help='PAM configuration UID')
    parser.add_argument('--username', '-u', required=True, dest='username',
                        help='Username or user ID')
    parser.add_argument('--group', '-gr', required=True, dest='group_id',
                        help='Group name or ID')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name')

    def get_parser(self):
        return PAMAccessGroupRemoveUserCommand.parser

    def execute(self, params, **kwargs):
        config_uid = kwargs['config_uid']
        username = kwargs['username']
        group_id = kwargs['group_id']
        idp_config_uid = resolve_pam_idp_config(params, config_uid)
        record_key = _get_record_key(params, config_uid)

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=_encrypt_field(username, record_key),
            groupId=group_id,
        )
        action = GatewayActionIdpRemoveUserFromGroup(inputs=inputs)

        _dispatch_idp_action(params, action, kwargs.get('gateway'))

        logging.info(f'User "{username}" removed from group "{group_id}".')