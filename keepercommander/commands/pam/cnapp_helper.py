#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CNAPP integration helpers
# Copyright 2026 Keeper Security Inc.
#
"""Thin wrappers over `_post_request_to_router` for the krouter CNAPP REST endpoints.

Each helper accepts already-parsed Python types (str UIDs, ints, enums) and is responsible
for building the protobuf request, dispatching to krouter, and decoding the typed response.
Callers (commands, tests) should treat these as the single source of truth for the wire
contract — everything CLI-visible lives one layer up in `cnapp_commands.py`.

Mapping to krouter routes (all rooted under `/api/user/cnapp/`):

    Configuration:
        configuration/set            -> set_cnapp_configuration
        configuration/test           -> test_cnapp_configuration
        configuration/test-encrypter -> test_cnapp_encrypter
        configuration/read           -> read_cnapp_configuration
        configuration/delete         -> delete_cnapp_configuration

    Queue:
        queue                        -> list_cnapp_queue
        queue/associate              -> associate_cnapp_record
        queue/remediate              -> remediate_cnapp_queue_item
        queue/set-status             -> set_cnapp_queue_status
        queue/delete                 -> delete_cnapp_queue_item

Failures from the helper layer bubble up as Python exceptions raised by the underlying
HTTP/proto plumbing; callers convert them to user-readable output.
"""

import json

from typing import List, Optional

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from ... import crypto
from ...params import KeeperParams
from ...proto import cnapp_pb2


# NOTE: `router_helper` is imported lazily inside `_post_request_to_router` below.
# Importing it at module top creates this import-time chain:
#     cnapp_helper -> router_helper -> gateway_helper
#         -> keepercommander.commands.utils -> commands.ksm
#         -> commands.record -> commands.ksm  (ksm still partially loaded — crash)
# That `record <-> ksm` cycle is pre-existing and only works because production
# code paths load `record` first. Tests that import `cnapp_helper` cold hit the
# cycle directly. TODO(KC-1290): break the record↔ksm cycle so this wrapper can be removed.
def _post_request_to_router(params, endpoint, **kwargs):
    """Lazy proxy to `router_helper._post_request_to_router`.

    Defined as a module-level function so callers (and `unittest.mock.patch.object`)
    can keep referring to `cnapp_helper._post_request_to_router` as if it were the
    original symbol."""
    from .router_helper import _post_request_to_router as _real_post
    return _real_post(params, endpoint, **kwargs)


# Public re-exports — let commands/tests reach proto types via the helper module so they
# don't need to know the on-disk proto path.
CnappProvider = cnapp_pb2.CnappProvider
CnappRemediationAction = cnapp_pb2.CnappRemediationAction


# ---------------------------------------------------------------------------
# Conversion utilities
# ---------------------------------------------------------------------------

def _to_uid_bytes(uid):  # type: (Optional[str]) -> bytes
    """Convert a base64url-encoded UID string to bytes; empty/None -> empty bytes."""
    if not uid:
        return b''
    if isinstance(uid, bytes):
        return uid
    return url_safe_str_to_bytes(uid)


def build_encrypted_remediations(params, network_uid, group_names, role_names):
    # type: (KeeperParams, str, Optional[List[str]], Optional[List[str]]) -> bytes
    """Encrypt the REMOVE_STANDING_PRIVILEGE remediation params with the network record key.

    The gateway expects a JSON map `{"groupNames": [...], "roleNames": [...]}` encrypted
    AES-256-GCM with the PAM configuration (network) record key; krouter relays the
    ciphertext opaquely, so the group/role names never transit in the clear."""
    record = params.record_cache.get(network_uid) if params.record_cache else None
    if not record or 'record_key_unencrypted' not in record:
        raise ValueError(f'PAM configuration record "{network_uid}" not found in the local cache. '
                         f'Run "sync-down" and verify the network record UID.')
    plaintext = json.dumps({
        'groupNames': list(group_names or []),
        'roleNames': list(role_names or []),
    }).encode('utf-8')
    return crypto.encrypt_aes_v2(plaintext, record['record_key_unencrypted'])


def provider_from_name(name):  # type: (str) -> int
    """Resolve a human-typed provider name (e.g. "wiz") to a CnappProvider enum value.

    Accepts the bare provider keyword ("wiz") or the full proto symbol
    ("CNAPP_PROVIDER_WIZ"); case-insensitive. Raises ValueError on unknown input."""
    if not name:
        return cnapp_pb2.CNAPP_PROVIDER_UNSPECIFIED
    normalized = name.strip().upper()
    if not normalized.startswith('CNAPP_PROVIDER_'):
        normalized = 'CNAPP_PROVIDER_' + normalized
    try:
        return cnapp_pb2.CnappProvider.Value(normalized)
    except ValueError as e:
        valid = [n for n in cnapp_pb2.CnappProvider.keys() if n != 'CNAPP_PROVIDER_UNSPECIFIED']
        raise ValueError(f"Unknown CNAPP provider '{name}'. Valid options: {', '.join(valid)}") from e


def action_from_name(name):  # type: (str) -> int
    """Resolve a remediation action name to its enum int. Case-insensitive; accepts the
    short keyword (e.g. "rotate_credentials") or the full proto symbol."""
    if not name:
        return cnapp_pb2.UNSPECIFIED
    normalized = name.strip().upper().replace('-', '_')
    try:
        return cnapp_pb2.CnappRemediationAction.Value(normalized)
    except ValueError as e:
        valid = [n for n in cnapp_pb2.CnappRemediationAction.keys() if n != 'UNSPECIFIED']
        raise ValueError(f"Unknown remediation action '{name}'. Valid options: {', '.join(valid)}") from e


# ---------------------------------------------------------------------------
# Configuration endpoints
# ---------------------------------------------------------------------------

def _build_configuration(network_uid, provider, client_id=None, client_secret=None,
                         api_endpoint_url=None, cnapp_config_record_uid=None,
                         auth_endpoint_url=None):
    # type: (str, int, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]) -> cnapp_pb2.CnappConfiguration
    rq = cnapp_pb2.CnappConfiguration()
    rq.networkUid = _to_uid_bytes(network_uid)
    rq.provider = provider
    if client_id:
        rq.clientId = client_id
    if client_secret:
        rq.clientSecret = client_secret
    if api_endpoint_url:
        rq.apiEndpointUrl = api_endpoint_url
    if cnapp_config_record_uid:
        rq.cnappConfigRecordUid = _to_uid_bytes(cnapp_config_record_uid)
    if auth_endpoint_url:
        rq.authEndpointUrl = auth_endpoint_url
    return rq


def set_cnapp_configuration(params, network_uid, provider, client_id, client_secret,
                            api_endpoint_url, cnapp_config_record_uid, auth_endpoint_url=None):
    # type: (KeeperParams, str, int, str, str, str, str, Optional[str]) -> cnapp_pb2.CnappConfiguration
    """Create or update the CNAPP provider configuration on a network.

    krouter validates the credentials against the provider before persisting; an empty
    `client_secret` tells krouter to keep the previously stored value (useful for edits
    that only change the endpoint or record UID).

    `auth_endpoint_url` is the provider's OAuth2 token endpoint, letting customers point
    at their own tenant/region (e.g. EU vs US Wiz auth host) without a code change."""
    rq = _build_configuration(network_uid, provider, client_id, client_secret,
                              api_endpoint_url, cnapp_config_record_uid, auth_endpoint_url)
    return _post_request_to_router(params, 'cnapp/configuration/set', rq_proto=rq,
                                   rs_type=cnapp_pb2.CnappConfiguration)


def test_cnapp_configuration(params, network_uid, provider, client_id, client_secret,
                             api_endpoint_url, auth_endpoint_url=None):
    # type: (KeeperParams, str, int, str, str, str, Optional[str]) -> None
    """Probe the provider with the supplied credentials without persisting anything.

    Returns None on success; raises on validation failure (RRC_BAD_REQUEST with the
    provider's reason in the message)."""
    rq = _build_configuration(network_uid, provider, client_id, client_secret,
                              api_endpoint_url, cnapp_config_record_uid=None,
                              auth_endpoint_url=auth_endpoint_url)
    return _post_request_to_router(params, 'cnapp/configuration/test', rq_proto=rq)


def test_cnapp_encrypter(params, url_base_encrypter):
    # type: (KeeperParams, str) -> None
    """Issue a `GET <url>/health` against the customer-deployed Encrypter via krouter.

    Used by the UI/CLI to check that the Encrypter URL is reachable before saving a
    configuration that references it. Raises on non-200 or transport error."""
    rq = cnapp_pb2.CnappTestEncrypterRequest()
    rq.urlBaseEncrypter = url_base_encrypter
    return _post_request_to_router(params, 'cnapp/configuration/test-encrypter', rq_proto=rq)


def read_cnapp_configuration(params, network_uid, provider):
    # type: (KeeperParams, str, int) -> cnapp_pb2.CnappConfiguration
    """Read the persisted CNAPP configuration for a network. Note: krouter never returns
    the `clientSecret` field — only the endpoint, client id and config record UID."""
    rq = _build_configuration(network_uid, provider)
    return _post_request_to_router(params, 'cnapp/configuration/read', rq_proto=rq,
                                   rs_type=cnapp_pb2.CnappConfiguration)


def delete_cnapp_configuration(params, network_uid):
    # type: (KeeperParams, str) -> None
    """Remove the CNAPP configuration on a network. Raises RRC_BAD_STATE if none exists."""
    rq = cnapp_pb2.CnappDeleteConfigurationRequest()
    rq.networkUid = _to_uid_bytes(network_uid)
    return _post_request_to_router(params, 'cnapp/configuration/delete', rq_proto=rq)


# ---------------------------------------------------------------------------
# Queue endpoints
# ---------------------------------------------------------------------------

def list_cnapp_queue(params, network_uid, status_filter=0):
    # type: (KeeperParams, str, int) -> cnapp_pb2.CnappQueueListResponse
    """List queued CNAPP issues for a network. `status_filter=0` returns all statuses."""
    rq = cnapp_pb2.CnappQueueListRequest()
    rq.networkUid = _to_uid_bytes(network_uid)
    rq.statusFilter = int(status_filter) if status_filter is not None else 0
    return _post_request_to_router(params, 'cnapp/queue', rq_proto=rq,
                                   rs_type=cnapp_pb2.CnappQueueListResponse)


def associate_cnapp_record(params, cnapp_queue_id, record_uid):
    # type: (KeeperParams, int, str) -> None
    """Attach a vault record to a queue item — required before remediation."""
    rq = cnapp_pb2.CnappAssociateRequest()
    rq.cnappQueueId = int(cnapp_queue_id)
    rq.recordUid = _to_uid_bytes(record_uid)
    return _post_request_to_router(params, 'cnapp/queue/associate', rq_proto=rq)


def remediate_cnapp_queue_item(params, cnapp_queue_id, action_type, resource_ref=None,
                               pwd_complexity=None, controller_uid=None, message_uid=None,
                               encrypted_remediations=None, auto_remediate=False):
    # type: (KeeperParams, int, int, Optional[str], Optional[str], Optional[str], Optional[str], Optional[bytes], bool) -> cnapp_pb2.CnappRemediateResponse
    """Trigger a remediation action against the gateway for a queued issue.

    krouter dispatches `ROTATE_CREDENTIALS` and `REMOVE_STANDING_PRIVILEGE`; other
    actions return RRC_BAD_REQUEST. `encrypted_remediations` carries the
    REMOVE_STANDING_PRIVILEGE group/role targets (see `build_encrypted_remediations`);
    empty means the gateway falls back to the record's JIT settings. `auto_remediate`
    registers an auto-remediation rule for the item's control hash — krouter accepts it
    only with ROTATE_CREDENTIALS on items that carry a control hash.

    The proto's `provider` and `cnappConfigurationRecordUid` fields are deprecated
    (krouter reads both from its own DB) and deliberately never sent."""
    rq = cnapp_pb2.CnappRemediateRequest()
    rq.cnappQueueId = int(cnapp_queue_id)
    rq.actionType = int(action_type)
    if resource_ref:
        rq.resourceRef = _to_uid_bytes(resource_ref)
    if pwd_complexity:
        rq.pwdComplexity = pwd_complexity
    if controller_uid:
        rq.controllerUid = controller_uid
    if message_uid:
        rq.messageUid = _to_uid_bytes(message_uid)
    if encrypted_remediations:
        rq.encryptedRemediations = encrypted_remediations
    rq.autoRemediateInFuture = bool(auto_remediate)
    return _post_request_to_router(params, 'cnapp/queue/remediate', rq_proto=rq,
                                   rs_type=cnapp_pb2.CnappRemediateResponse)


def set_cnapp_queue_status(params, cnapp_queue_id, cnapp_queue_status_id, reason=None):
    # type: (KeeperParams, int, int, Optional[str]) -> cnapp_pb2.CnappSetStatusResponse
    """Set the local status on a queue item; krouter best-effort notifies the provider."""
    rq = cnapp_pb2.CnappSetStatusRequest()
    rq.cnappQueueId = int(cnapp_queue_id)
    rq.cnappQueueStatusId = int(cnapp_queue_status_id)
    if reason:
        rq.reason = reason
    return _post_request_to_router(params, 'cnapp/queue/set-status', rq_proto=rq,
                                   rs_type=cnapp_pb2.CnappSetStatusResponse)


def delete_cnapp_queue_item(params, cnapp_queue_id):
    # type: (KeeperParams, int) -> None
    """Remove a queue item entirely. Raises RRC_BAD_REQUEST if the queue id is unknown."""
    rq = cnapp_pb2.CnappDeleteQueueItemRequest()
    rq.cnappQueueId = int(cnapp_queue_id)
    return _post_request_to_router(params, 'cnapp/queue/delete', rq_proto=rq)
