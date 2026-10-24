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

import datetime
import json
import logging
from typing import Any, Dict, Iterable, List, Optional

from . import crypto, utils
from .params import KeeperParams
from .pedm import pedm_shared
from .proto import GraphSync_pb2, NotificationCenter_pb2, pedm_pb2

NC = NotificationCenter_pb2

# Notification types that carry approve/deny actions.
ACTION_TYPES = {NC.NT_DEVICE_APPROVAL, NC.NT_SHARE_APPROVAL, NC.NT_APPROVAL_REQUEST, NC.NT_PEDM_APPROVAL_REQUEST}

# Types the Vault hides from its notification list; shown by "notification list --all".
HIDDEN_TYPES = {NC.NT_UNSPECIFIED, NC.NT_ALERT, NC.NT_LICENSE_LIMIT_REACHED, NC.NT_SHARE_APPROVAL_DENIED,
                NC.NT_DEVICE_APPROVAL_APPROVED, NC.NT_DEVICE_APPROVAL_DENIED}

TYPE_TITLES = {
    NC.NT_ALERT: 'Alert',
    NC.NT_DEVICE_APPROVAL: 'Login approval required',
    NC.NT_MASTER_PASS_UPDATED: 'Master password updated',
    NC.NT_SHARE_APPROVAL: 'Share request',
    NC.NT_SHARE_APPROVAL_APPROVED: 'Share request accepted',
    NC.NT_SHARE_APPROVAL_DENIED: 'Share request denied',
    NC.NT_SHARED: 'Shared with you',
    NC.NT_TRANSFERRED: 'Ownership transferred',
    NC.NT_LICENSE_LIMIT_REACHED: 'User license limit reached',
    NC.NT_APPROVAL_REQUEST: 'Approval request',
    NC.NT_APPROVED_RESPONSE: 'Request approved',
    NC.NT_DENIED_RESPONSE: 'Request denied',
    NC.NT_2FA_CONFIGURED: '2FA configured',
    NC.NT_DEVICE_APPROVAL_APPROVED: 'Login approved',
    NC.NT_DEVICE_APPROVAL_DENIED: 'Login denied',
    NC.NT_ACCOUNT_CREATED: 'Account created',
    NC.NT_2FA_ENABLED: '2FA enabled',
    NC.NT_2FA_DISABLED: '2FA disabled',
    NC.NT_SECURITY_KEYS_ENABLED: 'Security keys enabled',
    NC.NT_SECURITY_KEYS_DISABLED: 'Security keys disabled',
    NC.NT_SSL_CERTIFICATE_EXPIRES_SOON: 'SSL certificate expires soon',
    NC.NT_SSL_CERTIFICATE_EXPIRED: 'SSL certificate expired',
    NC.NT_RECORD_REMINDER: 'Record reminder',
    NC.NT_PEDM_APPROVAL_REQUEST: 'Endpoint privilege approval request',
}

# Types this client handles; other notifications are dropped on sync.
SUPPORTED_TYPES = set(TYPE_TITLES) | HIDDEN_TYPES


class NotificationEntry:
    def __init__(self, uid: str):
        self.uid = uid
        self.notification = None    # type: Optional[NotificationCenter_pb2.Notification]
        self.timestamp = 0          # epoch seconds of the notification wrapper
        self.read_status = NC.NRS_UNSPECIFIED
        self.read_timestamp = 0
        self.approval_status = NC.NAS_UNSPECIFIED
        self.approval_timestamp = 0
        self.is_read = False        # derived by update_read_statuses


def clear_cache(params: KeeperParams) -> None:
    params.notification_cache.clear()


def process_notification_sync(params: KeeperParams, wrappers: Iterable[NotificationCenter_pb2.NotificationWrapper]) -> None:
    cache = params.notification_cache   # type: Dict[str, NotificationEntry]
    for wrapper in wrappers:
        if not wrapper.uid:
            continue
        uid = utils.base64_url_encode(wrapper.uid)
        content_type = wrapper.content.WhichOneof('type')
        if content_type == 'trimmingPoint':
            _apply_trimming_point(cache, uid)
            continue
        if content_type == 'notification' and wrapper.content.notification.type not in SUPPORTED_TYPES:
            cache.pop(uid, None)
            continue
        entry = cache.get(uid)
        if entry is None:
            entry = NotificationEntry(uid)
            cache[uid] = entry
        if content_type == 'notification':
            entry.notification = wrapper.content.notification
            entry.timestamp = wrapper.timestamp
        elif content_type == 'readStatus':
            entry.read_status = wrapper.content.readStatus
            entry.read_timestamp = wrapper.timestamp
        elif content_type == 'approvalStatus':
            entry.approval_status = wrapper.content.approvalStatus
            entry.approval_timestamp = wrapper.timestamp
    update_read_statuses(params)


def _apply_trimming_point(cache: Dict[str, NotificationEntry], uid: str) -> None:
    # The server trimmed the notification at uid and everything older than it.
    point = cache.get(uid)
    if point is None or not point.timestamp:
        cache.pop(uid, None)
        return
    for key in [k for k, v in cache.items() if v.timestamp <= point.timestamp]:
        del cache[key]


def update_read_statuses(params: KeeperParams) -> None:
    # NRS_LAST marks the newest such notification and everything before it as read; see Vault notification-utils.ts.
    entries = [x for x in params.notification_cache.values() if x.notification is not None]
    last_read = 0
    for entry in sorted(entries, key=lambda x: x.timestamp, reverse=True):
        if entry.read_status == NC.NRS_LAST:
            last_read = entry.read_timestamp
            break
    for entry in entries:
        if entry.read_status in (NC.NRS_LAST, NC.NRS_READ):
            entry.is_read = True
        else:
            entry.is_read = (entry.read_timestamp or entry.timestamp) < last_read


def apply_local_read_status(params: KeeperParams, uids: Iterable[str], status: int) -> None:
    # The server does not echo this device's own read marks back in sync, so apply them locally.
    now = int(datetime.datetime.now().timestamp())
    for uid in uids:
        entry = params.notification_cache.get(uid)
        if entry:
            entry.read_status = status
            entry.read_timestamp = now
    update_read_statuses(params)


def get_notifications(params: KeeperParams) -> List[NotificationEntry]:
    entries = [x for x in params.notification_cache.values() if x.notification is not None]
    entries.sort(key=lambda x: x.timestamp, reverse=True)
    return entries


def type_name(notification_type: int) -> str:
    try:
        return NC.NotificationType.Name(notification_type)
    except ValueError:
        return str(notification_type)


def approval_status_name(status: int) -> str:
    if status == NC.NAS_UNSPECIFIED:
        return ''
    try:
        return NC.NotificationApprovalStatus.Name(status)[4:].replace('_', ' ').lower()
    except ValueError:
        return str(status)


def is_actionable(entry: NotificationEntry) -> bool:
    return entry.notification.type in ACTION_TYPES and entry.approval_status == NC.NAS_UNSPECIFIED


def status_label(entry: NotificationEntry) -> str:
    return approval_status_name(entry.approval_status) or ('pending' if is_actionable(entry) else '')


def get_ref(notification: NotificationCenter_pb2.Notification, ref_type: int) -> Optional[GraphSync_pb2.GraphSyncRef]:
    return next((x for x in notification.refs if x.type == ref_type), None)


def get_parameter(notification: NotificationCenter_pb2.Notification, key: str) -> Optional[bytes]:
    return next((x.data for x in notification.parameters if x.key == key), None)


def sender_name(notification: NotificationCenter_pb2.Notification) -> str:
    return notification.sender.name or notification.senderFullName


def record_title(params: KeeperParams, record_uid: str) -> Optional[str]:
    if record_uid in params.record_cache:
        from . import vault
        record = vault.KeeperRecord.load(params, record_uid)
        if record:
            return record.title
    return None


def record_key(params: KeeperParams, record_uid: str) -> Optional[bytes]:
    record = params.record_cache.get(record_uid)
    return record.get('record_key_unencrypted') if record else None


def team_name(params: KeeperParams, team_uid: str) -> Optional[str]:
    team = params.team_cache.get(team_uid)
    return team.get('name') if team else None


def decrypt_device_approval(params: KeeperParams, notification: NotificationCenter_pb2.Notification) -> Optional[Dict[str, Any]]:
    if not notification.encryptedData.data or not params.ecc_key:
        return None
    try:
        return json.loads(crypto.decrypt_ec(notification.encryptedData.data, params.ecc_key))
    except Exception as e:
        logging.debug('Decrypt device approval notification error: %s', e)
        return None


def decrypt_record_parameter(params: KeeperParams, notification: NotificationCenter_pb2.Notification, key: str) -> Optional[str]:
    # Workflow reason/ticket parameters are AES-GCM encrypted with the record key.
    data = get_parameter(notification, key)
    rec_ref = get_ref(notification, GraphSync_pb2.RFT_REC)
    if not data or not rec_ref:
        return None
    r_key = record_key(params, utils.base64_url_encode(rec_ref.value))
    if not r_key:
        return None
    try:
        return crypto.decrypt_aes_v2(data, r_key).decode('utf-8')
    except Exception as e:
        logging.debug('Decrypt notification parameter "%s" error: %s', key, e)
        return None


def get_pedm_approval(notification: NotificationCenter_pb2.Notification) -> Optional[pedm_pb2.ApprovalEnvelope]:
    # encryptedData.data holds a plain ApprovalEnvelope; the approval fields inside are encrypted with the MC agent key.
    if not notification.encryptedData.data:
        return None
    try:
        envelope = pedm_pb2.ApprovalEnvelope()
        envelope.ParseFromString(notification.encryptedData.data)
        return envelope
    except Exception as e:
        logging.debug('Parse EPM approval notification error: %s', e)
        return None


def _ref_number(value: bytes) -> int:
    return int.from_bytes(value, byteorder='big')


def get_message(params: KeeperParams, entry: NotificationEntry) -> str:
    n = entry.notification
    t = n.type
    sender = sender_name(n) or 'Someone'
    rec_ref = get_ref(n, GraphSync_pb2.RFT_REC)
    rec_uid = utils.base64_url_encode(rec_ref.value) if rec_ref else None
    rec_title = (record_title(params, rec_uid) or rec_uid) if rec_uid else None

    if t == NC.NT_DEVICE_APPROVAL:
        data = decrypt_device_approval(params, n) or {}
        return (f'{data.get("notification_device") or "A device"} is attempting to log in to your account from '
                f'{data.get("location") or "unknown location"} and IP address {data.get("ip_address") or "unknown"}.')
    if t == NC.NT_MASTER_PASS_UPDATED:
        return 'You have successfully updated your master password.'
    if t == NC.NT_SHARE_APPROVAL:
        return f'{sender} wants to establish a sharing relationship with you.'
    if t == NC.NT_SHARE_APPROVAL_APPROVED:
        return f'{sender} accepted your request for a sharing relationship.'
    if t == NC.NT_SHARE_APPROVAL_DENIED:
        return f'{sender} denied your request for a sharing relationship.'
    if t == NC.NT_SHARED:
        if rec_uid:
            return f'{sender} has shared a record with you: {rec_title}'
        folder_ref = get_ref(n, GraphSync_pb2.RFT_FOLDER)
        if folder_ref:
            folder_uid = utils.base64_url_encode(folder_ref.value)
            folder = params.folder_cache.get(folder_uid) if params.folder_cache else None
            return f'{sender} has shared a folder with you: {folder.name if folder else folder_uid}'
        team_ref = get_ref(n, GraphSync_pb2.RFT_TEAM)
        if team_ref:
            team_uid = utils.base64_url_encode(team_ref.value)
            return f'{sender} added you to team: {team_name(params, team_uid) or team_uid}'
        return f'{sender} has shared with you.'
    if t == NC.NT_TRANSFERRED:
        return f'{sender} transferred ownership of a record to you: {rec_title or "unknown record"}'
    if t == NC.NT_APPROVAL_REQUEST:
        text = f'{n.senderFullName or sender} requests to access {rec_title or "unknown resource"}'
        if get_parameter(n, 'escalated') is not None:
            text += ' (escalated)'
        return text
    if t == NC.NT_APPROVED_RESPONSE:
        return f'{n.senderFullName or sender} approved your request to access {rec_title or "unknown resource"}'
    if t == NC.NT_DENIED_RESPONSE:
        text = f'{n.senderFullName or sender} denied your request to access {rec_title or "unknown resource"}'
        reason = decrypt_record_parameter(params, n, 'reason')
        if reason:
            text += f': {reason}'
        return text
    if t == NC.NT_2FA_CONFIGURED:
        return 'You have successfully configured two-factor authentication.'
    if t in (NC.NT_SSL_CERTIFICATE_EXPIRES_SOON, NC.NT_SSL_CERTIFICATE_EXPIRED):
        bindings = {x.name: x.value for x in n.refs if x.type == GraphSync_pb2.RFT_GENERAL}
        provider = bindings.get('XXX', b'').decode('utf-8', 'replace') or 'unknown provider'
        days = _ref_number(bindings['ZZZ']) if 'ZZZ' in bindings else None
        if t == NC.NT_SSL_CERTIFICATE_EXPIRED:
            return f'SSL certificate for {provider} expired {days} day(s) ago' if days is not None else f'SSL certificate for {provider} expired'
        return f'SSL certificate for {provider} expires in {days} day(s)' if days is not None else f'SSL certificate for {provider} expires soon'
    if t == NC.NT_RECORD_REMINDER:
        return f'Reminder for record: {rec_title or "unknown record"}'
    if t == NC.NT_PEDM_APPROVAL_REQUEST:
        envelope = get_pedm_approval(n)
        if not envelope:
            return f'{sender} requests endpoint privilege elevation'
        return (f'{sender} requests {pedm_shared.approval_type_to_name(envelope.approval.approvalType)} approval '
                f'{utils.base64_url_encode(envelope.approval.approvalUid)}')
    return TYPE_TITLES.get(t) or type_name(t)
