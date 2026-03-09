import argparse
import logging

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from keepercommander.commands.base import Command, RecordMixin
from keepercommander.error import CommandError
from keepercommander import api, vault
from keepercommander.proto import NotificationCenter_pb2, GraphSync_pb2


ELIGIBLE_RECORD_TYPES = {'pamRemoteBrowser', 'pamDatabase', 'pamMachine'}


class PAMCredentialRequestCommand(Command):
    parser = argparse.ArgumentParser(prog='pam credential-request')

    parser.add_argument('record', action='store', help='Record UID or title of the shared PAM record')
    parser.add_argument('--message', '-m', dest='message', action='store',
                                           help='Justification message to include with the request')

    def get_parser(self):
        return PAMCredentialRequestCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        record = RecordMixin.resolve_single_record(params, record_name)

        if not record:
            raise CommandError('pam-credential-request', f'Record "{record_name}" not found.')

        if not isinstance(record, vault.TypedRecord):
            raise CommandError('pam-credential-request', 'Only typed records are supported.')

        if record.record_type not in ELIGIBLE_RECORD_TYPES:
            allowed = ', '.join(sorted(ELIGIBLE_RECORD_TYPES))
            raise CommandError('pam-credential-request',
                               f'Record type "{record.record_type}" is not eligible. Allowed types: {allowed}')

        # Load share info to find the record owner
        api.get_record_shares(params, [record.record_uid])

        rec_cached = params.record_cache.get(record.record_uid)
        if not rec_cached:
            raise CommandError('pam-credential-request', 'Record not found in cache.')

        shares = rec_cached.get('shares', {})
        user_perms = shares.get('user_permissions', [])

        owner = next((up.get('username') for up in user_perms if up.get('owner')), None)
        if not owner:
            raise CommandError('pam-credential-request', 'Could not determine record owner.')

        if owner == params.user:
            raise CommandError('pam-credential-request', 'You are the owner of this record.')

        # Build notification
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

        logging.info(f'Credential request sent to {owner} for record "{record.title}".')
