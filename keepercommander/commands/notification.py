#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import datetime
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from . import base
from .helpers import report_utils
from .. import api, crypto, notification_center, utils
from ..notification_center import NC, NotificationEntry
from ..params import KeeperParams
from ..proto import APIRequest_pb2, GraphSync_pb2, NotificationCenter_pb2, enterprise_pb2, pedm_pb2, workflow_pb2


def register_commands(commands):
    commands['notification'] = NotificationCommand()


def register_command_info(aliases, command_info):
    aliases['ntf'] = 'notification'
    command_info['notification'] = 'Notification Center: view and act on notifications'


class NotificationCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('Notification Center: view and act on notifications')
        self.register_command_new(NotificationListCommand(), 'list', 'l')
        self.register_command_new(NotificationViewCommand(), 'view', 'v')
        self.register_command_new(NotificationReadCommand(), 'read')
        self.register_command_new(NotificationUnreadCommand(), 'unread')
        self.register_command_new(NotificationApproveCommand(), 'approve')
        self.register_command_new(NotificationDenyCommand(), 'deny')
        self.default_verb = 'list'


def _format_time(ts: int) -> Optional[datetime.datetime]:
    return datetime.datetime.fromtimestamp(ts) if ts else None


def _ref_type_name(ref_type: int) -> str:
    try:
        return GraphSync_pb2.RefType.Name(ref_type)
    except ValueError:
        return str(ref_type)


def _resolve_entry(params: KeeperParams, uid: str) -> NotificationEntry:
    entry = params.notification_cache.get(uid)
    if entry is None:
        matches = [x for x in notification_center.get_notifications(params) if x.uid.startswith(uid)]
        if len(matches) == 1:
            entry = matches[0]
        elif len(matches) > 1:
            raise base.CommandError(f'Notification UID prefix "{uid}" is ambiguous')
    if entry is None or entry.notification is None:
        raise base.CommandError(f'Notification "{uid}" not found. Run "sync-down" to refresh notifications')
    return entry


def _send_read_status(params: KeeperParams, uids: List[str], status: int) -> None:
    for i in range(0, len(uids), 1000):
        rq = NotificationCenter_pb2.ProcessMarkReadEventsRequest()
        for uid in uids[i:i + 1000]:
            rsu = NotificationCenter_pb2.ReadStatusUpdate()
            rsu.notificationUid = utils.base64_url_decode(uid)
            rsu.status = status
            rq.readStatusUpdate.append(rsu)
        api.communicate_rest(params, rq, 'notification/process_mark_read_events')
    notification_center.apply_local_read_status(params, uids, status)


class NotificationListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List notifications', parents=[base.report_output_parser])
        parser.add_argument('--unread', dest='unread', action='store_true', help='show unread notifications only')
        parser.add_argument('--pending', dest='pending', action='store_true', help='show notifications awaiting approve/deny only')
        parser.add_argument('--all', dest='all', action='store_true', help='include notification types the Vault hides')
        super().__init__(parser)

    def execute(self, params: KeeperParams, **kwargs) -> Any:
        fmt = kwargs.get('format')
        headers = ['notification_uid', 'created', 'type', 'title', 'from', 'message', 'read', 'status']
        table = []   # type: List[List[Any]]
        accessible_mcs = None   # type: Optional[Set[int]]
        for entry in notification_center.get_notifications(params):
            n = entry.notification
            if not kwargs.get('all') and n.type in notification_center.HIDDEN_TYPES:
                continue
            if n.type == NC.NT_PEDM_APPROVAL_REQUEST:
                # Skip approvals of managed companies this admin cannot manage.
                if accessible_mcs is None:
                    accessible_mcs = _get_accessible_mcs(params)
                envelope = notification_center.get_pedm_approval(n)
                if not envelope or envelope.enterprise_id not in accessible_mcs:
                    continue
            if kwargs.get('unread') and entry.is_read:
                continue
            if kwargs.get('pending') and not notification_center.is_actionable(entry):
                continue
            table.append([entry.uid, _format_time(entry.timestamp), notification_center.type_name(n.type),
                          notification_center.TYPE_TITLES.get(n.type, ''), notification_center.sender_name(n),
                          notification_center.get_message(params, entry), entry.is_read,
                          notification_center.status_label(entry)])
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'), row_number=True)


class NotificationViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='view', description='Show notification details')
        parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table', help='output format')
        parser.add_argument('uid', help='Notification UID or a unique UID prefix')
        super().__init__(parser)

    def execute(self, params: KeeperParams, **kwargs) -> Any:
        entry = _resolve_entry(params, kwargs.get('uid'))
        n = entry.notification
        details = {
            'notification_uid': entry.uid,
            'type': notification_center.type_name(n.type),
            'title': notification_center.TYPE_TITLES.get(n.type, ''),
            'created': str(_format_time(entry.timestamp)),
            'from': notification_center.sender_name(n),
            'message': notification_center.get_message(params, entry),
            'read': entry.is_read,
            'read_status': NC.NotificationReadStatus.Name(entry.read_status),
            'approval_status': notification_center.status_label(entry),
        }   # type: Dict[str, Any]
        if entry.approval_timestamp:
            details['approval_status_time'] = str(_format_time(entry.approval_timestamp))
        details['refs'] = [f'{_ref_type_name(x.type)}: {utils.base64_url_encode(x.value)}' + (f' ({x.name})' if x.name else '')
                           for x in n.refs]

        if n.type == NC.NT_DEVICE_APPROVAL:
            data = notification_center.decrypt_device_approval(params, n)
            if data:
                details['device'] = {k: v for k, v in data.items() if k != 'publicKey'}
        elif n.type == NC.NT_APPROVAL_REQUEST:
            for key in ('reason', 'ticket'):
                value = notification_center.decrypt_record_parameter(params, n, key)
                if value:
                    details[key] = value
        elif n.type == NC.NT_PEDM_APPROVAL_REQUEST:
            details['pedm_approval'] = _get_pedm_approval_details(params, n)

        if kwargs.get('format') == 'json':
            return json.dumps(details, indent=2, default=str)
        table = []
        for key, value in details.items():
            if isinstance(value, dict):
                value = [f'{k}: {v}' for k, v in value.items()]
            table.append([report_utils.field_to_title(key), value])
        base.dump_report_data(table, ['key', 'value'], no_header=True)


class NotificationReadCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='read', description='Mark notifications as read')
        parser.add_argument('--all', dest='all', action='store_true', help='mark all notifications as read')
        parser.add_argument('uid', nargs='*', help='Notification UID or a unique UID prefix')
        super().__init__(parser)

    def execute(self, params: KeeperParams, **kwargs) -> None:
        if kwargs.get('all'):
            entries = notification_center.get_notifications(params)
            if not entries:
                return
            # NRS_LAST on the newest notification marks it and every older notification as read.
            _send_read_status(params, [entries[0].uid], NC.NRS_LAST)
            return
        uids = [_resolve_entry(params, x).uid for x in kwargs.get('uid') or []]
        if not uids:
            raise base.CommandError('Specify notification UID(s) or --all')
        _send_read_status(params, uids, NC.NRS_READ)


class NotificationUnreadCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='unread', description='Mark notifications as unread')
        parser.add_argument('uid', nargs='+', help='Notification UID or a unique UID prefix')
        super().__init__(parser)

    def execute(self, params: KeeperParams, **kwargs) -> None:
        uids = [_resolve_entry(params, x).uid for x in kwargs.get('uid') or []]
        _send_read_status(params, uids, NC.NRS_UNREAD)


class _NotificationActionCommand(base.ArgparseCommand):
    def __init__(self, deny: bool):
        verb = 'deny' if deny else 'approve'
        parser = argparse.ArgumentParser(prog=verb, description=f'{verb.capitalize()} a request notification')
        parser.add_argument('uid', help='Notification UID or a unique UID prefix')
        if deny:
            parser.add_argument('-r', '--reason', dest='reason', action='store', help='denial reason (PAM workflow requests only)')
        super().__init__(parser)
        self.deny = deny

    def execute(self, params: KeeperParams, **kwargs) -> None:
        entry = _resolve_entry(params, kwargs.get('uid'))
        n = entry.notification
        if n.type not in notification_center.ACTION_TYPES:
            raise base.CommandError(f'Notification type {notification_center.type_name(n.type)} has no approve/deny action')
        if entry.approval_status != NC.NAS_UNSPECIFIED:
            raise base.CommandError(f'Request is already {notification_center.approval_status_name(entry.approval_status)}')

        if n.type == NC.NT_DEVICE_APPROVAL:
            _act_device_approval(params, n, self.deny)
        elif n.type == NC.NT_SHARE_APPROVAL:
            _act_share_approval(params, n, self.deny)
        elif n.type == NC.NT_APPROVAL_REQUEST:
            _act_workflow_approval(params, n, self.deny, kwargs.get('reason'))
        elif n.type == NC.NT_PEDM_APPROVAL_REQUEST:
            _act_pedm_approval(params, n, self.deny)

        # The server posts the approval status for the notification; a sync picks it up.
        if not entry.is_read:
            try:
                _send_read_status(params, [entry.uid], NC.NRS_READ)
            except Exception as e:
                logging.debug('Mark notification read error: %s', e)
        params.sync_data = True
        logging.info('Request %s', 'denied' if self.deny else 'approved')


class NotificationApproveCommand(_NotificationActionCommand):
    def __init__(self):
        super().__init__(deny=False)


class NotificationDenyCommand(_NotificationActionCommand):
    def __init__(self):
        super().__init__(deny=True)


def _act_device_approval(params: KeeperParams, n: NotificationCenter_pb2.Notification, deny: bool) -> None:
    data = notification_center.decrypt_device_approval(params, n)
    public_key = data.get('publicKey') if data else None
    if not public_key:
        raise base.CommandError('Cannot decrypt device approval notification')
    device_public_key = utils.base64_url_decode(public_key)

    from ..loginv3 import LoginV3API
    summary = LoginV3API.accountSummary(params)
    device = next((x for x in summary.devices if x.devicePublicKey == device_public_key), None)
    if device is None:
        raise base.CommandError('The device requesting approval was not found')

    rq = APIRequest_pb2.ApproveDeviceRequest()
    rq.encryptedDeviceToken = device.encryptedDeviceToken
    if deny:
        rq.denyApproval = True
    elif summary.settings.ssoUser:
        rq.encryptedDeviceDataKey = crypto.encrypt_ec(params.data_key, crypto.load_ec_public_key(device_public_key))
    api.communicate_rest(params, rq, 'authentication/approve_device')


def _act_share_approval(params: KeeperParams, n: NotificationCenter_pb2.Notification, deny: bool) -> None:
    from_email = n.sender.name
    if not from_email:
        raise base.CommandError('Share request has no sender email')
    rq = {'command': 'cancel_share' if deny else 'accept_share', 'from_email': from_email}
    api.communicate(params, rq)
    params.pending_share_requests.discard(from_email)


def _act_workflow_approval(params: KeeperParams, n: NotificationCenter_pb2.Notification, deny: bool, reason: Optional[str]) -> None:
    from .pam.router_helper import _post_request_to_router
    wf_ref = notification_center.get_ref(n, GraphSync_pb2.RFT_WORKFLOW)
    if not wf_ref:
        raise base.CommandError('Approval request has no workflow reference')
    rq = workflow_pb2.WorkflowApprovalOrDenial()
    rq.flowUid = wf_ref.value
    rq.deny = deny
    if deny and reason:
        # Same encryption as the Vault: AES-GCM with the key of the requested record.
        rec_ref = notification_center.get_ref(n, GraphSync_pb2.RFT_REC)
        r_key = notification_center.record_key(params, utils.base64_url_encode(rec_ref.value)) if rec_ref else None
        if r_key:
            rq.denialReason = crypto.encrypt_aes_v2(reason.encode('utf-8'), r_key)
        else:
            logging.warning('Record key is not available; the denial reason is not attached')
    _post_request_to_router(params, 'approve_or_deny_workflow_access', rq_proto=rq)


def _get_mcs_info(params: KeeperParams, enterprise_ids: List[int], include_keys: bool) -> enterprise_pb2.GetMCsInfoResponse:
    rq = enterprise_pb2.GetMCsInfoRequest(mcEnterpriseId=enterprise_ids, includePrivateKeys=include_keys)
    rs = api.communicate_rest(params, rq, 'enterprise/get_mcs_info', rs_type=enterprise_pb2.GetMCsInfoResponse)
    if rs is None:
        raise base.CommandError('KeeperApp did not return managed company information')
    return rs


def _get_accessible_mcs(params: KeeperParams) -> Set[int]:
    # An empty list asks for every managed company this admin can manage.
    from .enterprise_common import EnterpriseCommand
    if not EnterpriseCommand.is_msp(params):
        return set()
    try:
        return {int(x.enterpriseId) for x in _get_mcs_info(params, [], False).mcInfo}
    except Exception as e:
        logging.debug('Get managed companies error: %s', e)
        return set()


def _get_pedm_approval(params: KeeperParams, n: NotificationCenter_pb2.Notification) -> Tuple[pedm_pb2.ApprovalEnvelope, bytes]:
    envelope = notification_center.get_pedm_approval(n)
    if not envelope:
        raise base.CommandError('EPM approval notification has no approval data')
    from ..pedm import admin_plugin
    plugin = admin_plugin.get_pedm_plugin(params, skip_sync=True)
    plugin.load_mc_agent_keys(_get_mcs_info(params, [envelope.enterprise_id], True).mcInfo)
    agent_key = plugin.get_mc_agent_key(envelope.enterprise_id)
    if agent_key is None:
        raise base.CommandError(f'Managed company {envelope.enterprise_id} is not accessible')
    return envelope, agent_key


def _get_pedm_approval_details(params: KeeperParams, n: NotificationCenter_pb2.Notification) -> Dict[str, Any]:
    try:
        envelope, agent_key = _get_pedm_approval(params, n)
    except Exception as e:
        return {'error': str(e)}
    from ..pedm import pedm_shared
    from .pedm.msp_approvals import decrypt_approval
    approval = envelope.approval
    details = {
        'enterprise_id': envelope.enterprise_id,
        'approval_uid': utils.base64_url_encode(approval.approvalUid),
        'approval_type': pedm_shared.approval_type_to_name(approval.approvalType),
        'agent_uid': utils.base64_url_encode(approval.agentUid),
        'created': str(_format_time(approval.created // 1000)) if approval.created else '',
        'expire_in': approval.expireIn,
    }   # type: Dict[str, Any]
    try:
        account_info, application_info, justification = decrypt_approval(approval, agent_key)
        details['account_info'] = account_info
        details['application_info'] = application_info
        details['justification'] = justification
    except Exception as e:
        details['data_error'] = f'Cannot decrypt approval data: {e}'
    return details


def _act_pedm_approval(params: KeeperParams, n: NotificationCenter_pb2.Notification, deny: bool) -> None:
    envelope = notification_center.get_pedm_approval(n)
    if not envelope:
        raise base.CommandError('EPM approval notification has no approval data')
    rq = pedm_pb2.MspApprovalActionRequest()
    ref = rq.deny.add() if deny else rq.approve.add()
    ref.enterprise_id = envelope.enterprise_id
    ref.approval_uid = envelope.approval.approvalUid
    rs = api.execute_router(params, 'pedm/msp_approval_action', rq, rs_type=pedm_pb2.PedmStatusResponse)
    if rs is None:
        raise base.CommandError('Router did not return the approval action status')
    for st in list(rs.addStatus) + list(rs.updateStatus) + list(rs.removeStatus):
        if not st.success:
            raise base.CommandError(f'EPM approval action failed: {st.message}')
