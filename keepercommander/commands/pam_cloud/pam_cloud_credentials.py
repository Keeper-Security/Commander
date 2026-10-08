import argparse
import base64
import json
import datetime
import logging

from keepercommander.commands.base import Command, GroupCommand, RecordMixin
from keepercommander.commands.pam_cloud import entra_sign_in
from keepercommander.commands.pam.pam_dto import GatewayAction
from keepercommander.commands.pam.router_helper import dispatch_streamed_access_elevation_action, get_dag_leafs
from keepercommander.commands.pam.vault_target import (
    create_record_in_folder, resolve_access_user_save_folder, resolve_pam_record)
from keepercommander.commands.tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from keepercommander.display import bcolors
from keepercommander.error import CommandError
from keepercommander import crypto, vault


logger = logging.getLogger(__name__)


class _GrantTemporaryAccessToken(GatewayAction):
    def __init__(self, inputs, conversation_id):
        super().__init__(action='rm-grant-temporary-access-token', is_scheduled=False,
                         inputs=inputs, conversation_id=conversation_id)


class PAMCloudCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('generate-credentials', PAMCloudGenerateCredentialsCommand(),
                              'Generate a temporary cloud access token for a PAM cloud resource', 'gc')


def _resolve_configuration_record(params, configuration, linked_config_uids):
    config_rec = RecordMixin.resolve_single_record(params, configuration)
    if config_rec is None:
        for uid in params.record_cache:
            if params.record_cache[uid].get('version', 0) == 6:
                r = vault.KeeperRecord.load(params, uid)
                if r and r.title.casefold() == configuration.casefold():
                    config_rec = r
                    break
    if config_rec is None:
        raise CommandError('pam-cloud-generate-credentials', f'PAM Configuration "{configuration}" not found.')
    config_uid = config_rec.record_uid
    if linked_config_uids is not None and config_uid not in linked_config_uids:
        raise CommandError('pam-cloud-generate-credentials',
                           f'PAM Configuration "{configuration}" is not linked to this record.')
    return config_uid


def _resolve_config_uid(params, record_uid, configuration):
    encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(params)
    config_leafs = get_dag_leafs(params, encrypted_session_token, encrypted_transmission_key, record_uid)
    config_uids = [leaf.get('value') for leaf in (config_leafs or []) if leaf.get('value')]

    if len(config_uids) == 0:
        if not configuration:
            raise CommandError('pam-cloud-generate-credentials',
                               'Record is not linked to a PAM Configuration; specify --configuration|-c.')
        return _resolve_configuration_record(params, configuration, linked_config_uids=None)

    if len(config_uids) == 1:
        config_uid = config_uids[0]
        if configuration:
            specified_uid = _resolve_configuration_record(params, configuration, linked_config_uids=config_uids)
            if specified_uid != config_uid:
                raise CommandError('pam-cloud-generate-credentials',
                                   f'PAM Configuration "{configuration}" is not linked to this record.')
        return config_uid

    if not configuration:
        raise CommandError('pam-cloud-generate-credentials',
                           'Record is linked to multiple PAM Configurations; specify --configuration|-c.')
    return _resolve_configuration_record(params, configuration, linked_config_uids=config_uids)


def _config_field(record, label):
    """Value of the config record field called `label` (e.g. tenantId), or ''."""
    for field in list(record.fields) + list(record.custom):
        if (field.label or '').casefold() == label.casefold():
            return field.get_default_value(str) or ''
    return ''


# Not narrowed to any one API or application: .default asks for everything the app registration is
# already consented for, against the tenant directory the user lives in.
DEFAULT_SIGN_IN_SCOPE = 'https://graph.microsoft.com/.default'


def _sign_in_locally(config_record, login, client_id_override, scope_override=None):
    """Sign the user in to Entra in their own browser (MFA happens there) and return the
    (credential_record, expiration) the Gateway would otherwise have minted."""
    tenant_id = _config_field(config_record, 'tenantId')
    client_id = client_id_override or _config_field(config_record, 'clientId')
    if not tenant_id or not client_id:
        raise CommandError('pam-cloud-generate-credentials',
                           'The PAM configuration needs a tenant ID and client ID (or pass --client-id).')

    scope = scope_override or DEFAULT_SIGN_IN_SCOPE
    token = entra_sign_in.sign_in(tenant_id, client_id, scope, login_hint=login)

    expires_in = int(token.get('expires_in') or 3600)
    expiration = (datetime.datetime.now(datetime.timezone.utc)
                  + datetime.timedelta(seconds=expires_in)).isoformat()
    return {
        'record_type': 'pamUser',
        'title': f'Temporary AZURE access token - {login}',
        'fields': [
            {'type': 'login', 'value': login},
            {'type': 'password', 'value': ''},
            {'type': 'secret', 'label': 'privatePEMKey', 'value': json.dumps({'accessToken': token['access_token']})},
            {'type': 'text', 'label': 'Provider', 'value': 'azure'},
        ],
        'notes': (f"Short-lived AZURE credentials issued by Keeper PAM for '{login}'. "
                  f"Auto-expires {expiration}. Do not share."),
    }, expiration


class PAMCloudGenerateCredentialsCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cloud generate-credentials',
                                     description='Generate a temporary cloud access token for a PAM cloud resource, '
                                                 'scoped to the logged-in user; the gateway never creates a new account. '
                                                 'Azure: the Gateway grants the access, then you sign in to Microsoft '
                                                 'in your browser (MFA works) to receive the token.')
    parser.add_argument('record', help='PAM cloud resource (pamCloudResource) UID, title, or folder path')
    parser.add_argument('--configuration', '-c', dest='configuration',
                        help='PAM configuration UID or title, if the resource is linked to more than one')
    parser.add_argument('--client-id', dest='client_id',
                        help='Azure: application (client) ID to sign in with. Defaults to '
                             'the PAM configuration\'s client ID, which needs a public-client '
                             'http://localhost redirect.')
    parser.add_argument('--scope', dest='scope',
                        help='Azure: narrow the token to a specific API, e.g. '
                             'https://management.azure.com/.default. Not needed normally: the default is '
                             'https://graph.microsoft.com/.default, the tenant the user exists in, with '
                             'nothing narrowed. The API must be in the app registration\'s permissions.')
    parser.add_argument('--duration-seconds', '-d', dest='duration_seconds', type=int,
                        help='Credential lifetime in seconds (provider-clamped). Leave unset to use the '
                             'resource\'s own configured elevation time, which also matches how long the '
                             'router keeps the grant active before auto-revoking it.')
    parser.add_argument('--save-record', '-s', dest='save_record', action='store_true',
                        help='Save the credential as a pamUser record. Without this flag the credential is '
                             'masked on screen and not retrievable again.')
    parser.add_argument('--folder', '-f', dest='folder_uid',
                        help='Folder UID, name, or path to save the record in (used with --save-record)')
    parser.add_argument('--gateway', '-g', dest='gateway',
                        help='Gateway UID or name (only needed if more than one Gateway is connected)')

    def get_parser(self):
        return PAMCloudGenerateCredentialsCommand.parser

    def execute(self, params, **kwargs):
        record_identifier = kwargs['record']

        record = resolve_pam_record(params, record_identifier, rec_type='pamCloudResource')
        if record is None:
            raise CommandError('pam-cloud-generate-credentials',
                               f'PAM cloud resource "{record_identifier}" not found.')
        if not isinstance(record, vault.TypedRecord) or record.record_type != 'pamCloudResource':
            record_type = record.record_type if isinstance(record, vault.TypedRecord) else 'unknown'
            raise CommandError('pam-cloud-generate-credentials',
                               f'Record "{record.title}" is of type "{record_type}", not "pamCloudResource".')

        config_uid = _resolve_config_uid(params, record.record_uid, kwargs.get('configuration'))

        private_key, public_key = crypto.generate_ec_key()
        sender_public_key = base64.urlsafe_b64encode(crypto.unload_ec_public_key(public_key)).rstrip(b'=').decode('ascii')

        inputs = {
            'configurationUid': config_uid,
            'resourceUid': record.record_uid,
            'username': params.user,
            'senderPublicKey': sender_public_key,
        }

        config_record = vault.KeeperRecord.load(params, config_uid)
        if isinstance(config_record, vault.TypedRecord) and config_record.record_type == 'pamAzureConfiguration':
            # Entra cannot mint a token for a user without that user signing in (MFA included), so the
            # Gateway only attaches the access and the requester signs in to Microsoft themselves below.
            inputs['clientSideAuth'] = True
        duration_seconds = kwargs.get('duration_seconds')
        if duration_seconds:
            inputs['durationSeconds'] = duration_seconds

        action = _GrantTemporaryAccessToken(inputs=inputs, conversation_id=GatewayAction.generate_conversation_id())

        gateway = kwargs.get('gateway')
        if gateway:
            action.gateway_destination = gateway

        data = dispatch_streamed_access_elevation_action(params, action)

        if not data.get('success', False):
            raise CommandError('pam-cloud-generate-credentials', data.get('error') or 'Unknown error')

        if data.get('clientSideAuth'):
            credential_record, expiration = _sign_in_locally(
                config_record, inputs['username'], kwargs.get('client_id'), kwargs.get('scope'))
        else:
            encrypted_record = data.get('encrypted_record')
            if not encrypted_record:
                raise CommandError('pam-cloud-generate-credentials',
                                   'The Gateway did not return any credential material.')

            decrypted = crypto.decrypt_ec(base64.b64decode(encrypted_record), private_key)
            credential_record = json.loads(decrypted)
            expiration = data.get('expiration', '')

        fields = credential_record.get('fields', [])
        login = next((f.get('value') for f in fields if f.get('type') == 'login'), '')
        provider = next((f.get('value') for f in fields if f.get('label') == 'Provider'), data.get('provider', ''))
        has_secret = any(f.get('type') == 'secret' and f.get('value') for f in fields)

        print(f'{bcolors.OKGREEN}Temporary access token generated.{bcolors.ENDC}')
        print(f'  Provider:     {provider}')
        print(f'  Login:        {login}')
        print(f'  Credential:   {"**********" if has_secret else "(none)"}')
        print(f'  Expiration:   {expiration}')

        if kwargs.get('save_record'):
            typed_record = vault.TypedRecord()
            typed_record.type_name = credential_record.get('record_type', 'pamUser')
            typed_record.title = credential_record.get('title') or f'Temporary access token - {login}'
            for field in fields:
                if field.get('label'):
                    typed_record.custom.append(
                        vault.TypedField.new_field(field['type'], field.get('value', ''), field['label']))
                else:
                    typed_record.fields.append(
                        vault.TypedField.new_field(field['type'], field.get('value', '')))
            notes = credential_record.get('notes')
            if notes:
                typed_record.notes = notes

            folder_uid = resolve_access_user_save_folder(
                params, config_uid, folder_spec=kwargs.get('folder_uid'), command='pam-cloud-generate-credentials')
            create_record_in_folder(params, typed_record, folder_uid, command='pam-cloud-generate-credentials')
            params.sync_data = True

            print(f'  Record UID:   {typed_record.record_uid}')
        else:
            print(f'{bcolors.WARNING}  Not saved -- the credential cannot be retrieved again. '
                  f'Re-run with --save-record to persist it as a pamUser record.{bcolors.ENDC}')
