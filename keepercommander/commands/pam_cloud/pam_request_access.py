import argparse
import json
import logging

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from keepercommander.commands.base import Command, RecordMixin
from keepercommander.commands.pam.pam_dto import (
    GatewayAction,
    GatewayActionIdpInputs,
    GatewayActionIdpValidateDomain,
)
from keepercommander.commands.pam.router_helper import router_send_action_to_gateway
from keepercommander.commands.pam_cloud.pam_idp import resolve_idp_config
from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (
    get_config_uid_from_record,
    get_gateway_uid_from_record,
)
from keepercommander.error import CommandError
from keepercommander import api, vault
from keepercommander.proto import NotificationCenter_pb2, GraphSync_pb2, pam_pb2


ELIGIBLE_RECORD_TYPES = {'pamRemoteBrowser', 'pamDatabase', 'pamMachine'}


class PAMRequestAccessCommand(Command):
    parser = argparse.ArgumentParser(prog='pam request-access', description='Request access to a shared PAM record')

    parser.add_argument('record', action='store', help='Record UID or title of the shared PAM record')
    parser.add_argument('--message', '-m', dest='message', action='store',
                                           help='Justification message to include with the request')

    def get_parser(self):
        return PAMRequestAccessCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        record = RecordMixin.resolve_single_record(params, record_name)

        if not record:
            raise CommandError('pam-request-access', f'Record "{record_name}" not found.')

        if not isinstance(record, vault.TypedRecord):
            raise CommandError('pam-request-access', 'Only typed records are supported.')

        if record.record_type not in ELIGIBLE_RECORD_TYPES:
            allowed = ', '.join(sorted(ELIGIBLE_RECORD_TYPES))
            raise CommandError('pam-request-access',
                               f'Record type "{record.record_type}" is not eligible. Allowed types: {allowed}')

        # Load share info to find the record owner
        api.get_record_shares(params, [record.record_uid])

        rec_cached = params.record_cache.get(record.record_uid)
        if not rec_cached:
            raise CommandError('pam-request-access', 'Record not found in cache.')

        shares = rec_cached.get('shares', {})
        user_perms = shares.get('user_permissions', [])

        owner = next((up.get('username') for up in user_perms if up.get('owner')), None)
        if not owner:
            raise CommandError('pam-request-access', 'Could not determine record owner.')

        if owner == params.user:
            raise CommandError('pam-request-access', 'You are the owner of this record.')

        # Resolve PAM config and IdP config for this resource
        config_uid = get_config_uid_from_record(params, vault, record.record_uid)
        if not config_uid:
            raise CommandError('pam-request-access', 'Could not resolve PAM configuration for this resource.')

        gateway_uid = get_gateway_uid_from_record(params, vault, record.record_uid)

        # Validate the requesting user's domain against the IdP
        try:
            idp_config_uid = resolve_idp_config(params, config_uid)
        except CommandError:
            idp_config_uid = config_uid

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=params.user,
            resourceUid=record.record_uid,
        )
        action = GatewayActionIdpValidateDomain(inputs=inputs)
        conversation_id = GatewayAction.generate_conversation_id()
        action.conversationId = conversation_id

        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=action,
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_uid,
        )

        if router_response:
            response = router_response.get('response', {})
            payload_str = response.get('payload')
            if payload_str:
                payload = json.loads(payload_str)
                data = payload.get('data', {})
                if isinstance(data, dict) and not data.get('success', True):
                    error_msg = data.get('error', 'Domain validation failed')
                    raise CommandError('pam-request-access', error_msg)

        # Domain validated — send approval notification to record owner
        record_uid_bytes = url_safe_str_to_bytes(record.record_uid)

        record_ref = GraphSync_pb2.GraphSyncRef()
        record_ref.type = GraphSync_pb2.RFT_REC
        record_ref.value = record_uid_bytes

        owner_ref = GraphSync_pb2.GraphSyncRef()
        owner_ref.type = GraphSync_pb2.RFT_USER
        owner_ref.name = owner

        notification = NotificationCenter_pb2.Notification()
        notification.type = NotificationCenter_pb2.NT_APPROVAL_REQUEST
        notification.category = NotificationCenter_pb2.NC_REQUEST
        notification.refs.append(record_ref)

        message = kwargs.get('message')
        if message:
            notification.senderFullName = message

        send_rq = NotificationCenter_pb2.NotificationSendRequest()
        send_rq.recipients.append(owner_ref)
        send_rq.notification.CopyFrom(notification)

        batch_rq = NotificationCenter_pb2.NotificationsSendRequest()
        batch_rq.notifications.append(send_rq)

        api.communicate_rest(params, batch_rq, 'vault/notifications_send')

        logging.info(f'Access request sent to {owner} for record "{record.title}".')
