"""Tunnel setup helpers for batch PAM import (shared deferred TunnelDAG; no pte.execute)."""
from __future__ import annotations

import base64
import logging
import os
from typing import Any, Optional

from ... import vault
from ...record_management import update_record
from ..tunnel.port_forward.TunnelGraph import TunnelDAG
from .base import PamRemoteBrowserObject, PamSettingsFieldData, parse_command_options
from .batch_nsf import sync_down_after_batch

_SEED_RECORD_TYPES = frozenset({
    'pamdatabase', 'pamdirectory', 'pammachine', 'pamremotebrowser', 'pamcloudresource',
})


def ensure_traffic_encryption_seed_on_typed_record(record: vault.TypedRecord) -> bool:
    """Ensure ``trafficEncryptionSeed`` on a TypedRecord before Step 1a create.

    Mirrors ``PAMTunnelEditCommand`` seed generation; never overwrites a non-empty seed.
    Returns True when a new seed was written on the in-memory record.
    """
    rt = (record.type_name or '').lower()
    if rt not in _SEED_RECORD_TYPES:
        return False
    existing = record.get_typed_field('trafficEncryptionSeed')
    if existing and existing.value:
        return False
    seed_b64 = base64.b64encode(os.urandom(32)).decode()
    field = vault.TypedField.new_field('trafficEncryptionSeed', seed_b64, '')
    if existing:
        existing.value = [seed_b64]
    elif record.get_record_type() in _SEED_RECORD_TYPES:
        record.fields.append(field)
    else:
        record.custom.append(field)
    return True


def merge_initial_pam_settings_on_record(record: vault.TypedRecord, obj) -> bool:
    """Coerce pamSettings / pamRemoteBrowserSettings structure at Step 1a (pte parity).

    Ensures ``connection`` / ``portForward`` subdicts exist as dicts before first
    ``records_add`` — same normalization ``PAMTunnelEditCommand`` would apply later.
    """
    from ..tunnel_and_connections import _coerce_settings_subdicts

    modified = False
    if isinstance(obj, PamRemoteBrowserObject):
        field = record.get_typed_field('pamRemoteBrowserSettings')
        if not field or not field.value or not isinstance(field.value, list):
            return False
        root = field.value[0]
        if not isinstance(root, dict):
            field.value[0] = {'connection': {}}
            modified = True
            root = field.value[0]
        if _coerce_settings_subdicts(root, 'connection'):
            modified = True
        return modified

    ps = getattr(obj, 'pam_settings', None)
    if not ps or not isinstance(ps, PamSettingsFieldData):
        return False
    field = record.get_typed_field('pamSettings')
    if not field:
        return False
    if not field.value or not isinstance(field.value, list) or not field.value:
        return False
    root = field.value[0]
    if not isinstance(root, dict):
        allow = True if ps.allowSupplyHost is True else False
        field.value[0] = {'allowSupplyHost': allow, 'portForward': {}, 'connection': {}}
        modified = True
        root = field.value[0]
    if _coerce_settings_subdicts(root, 'connection', 'portForward'):
        modified = True
    return modified


def _tunneling_flag_from_args(tunnel_args: dict) -> Optional[bool]:
    if tunnel_args.get('enable_tunneling'):
        return True
    if tunnel_args.get('disable_tunneling'):
        return False
    return None


def _connections_flag_from_args(tunnel_args: dict) -> Optional[bool]:
    if tunnel_args.get('enable_connections'):
        return True
    if tunnel_args.get('disable_connections'):
        return False
    return None


def validate_tunneling_for_resource(
    tdag: TunnelDAG,
    tunnel_args: dict,
    *,
    resource_uid: str = '',
    silent: bool = True,
) -> bool:
    """Read-only PAM config check (shared ``tdag``; no save)."""
    enable_tunneling = _tunneling_flag_from_args(tunnel_args)
    enable_connections = _connections_flag_from_args(tunnel_args)
    if tdag.check_tunneling_enabled_config(
        enable_connections=enable_connections,
        enable_tunneling=enable_tunneling,
    ):
        return True
    label = resource_uid or tunnel_args.get('record', '')
    msg = (
        f'Step 2 tunnel settings denied by PAM configuration for resource {label}. '
        f'Enable the requested features on the PAM configuration record.'
    )
    if silent:
        logging.warning(msg)
    else:
        logging.error(msg)
    return False


def queue_resource_config_link(tdag: TunnelDAG, resource_uid: str) -> None:
    """Queue resource↔config LINK on the shared deferred ``tdag`` (idempotent)."""
    if resource_uid and not tdag.is_tunneling_config_set_up(resource_uid):
        tdag.link_resource_to_config(resource_uid)


def apply_tunnel_setup_batch(
    params,
    tdag: TunnelDAG,
    mach,
    pam_cfg_uid: str,
    *,
    silent: bool = True,
) -> bool:
    """Step 2 tunnel validation + config link on shared ``tdag`` (no ``pte.execute``).

    Vault record prep (seed, pamSettings stubs) is done at Step 1a create.
    ``link_resource_to_config`` is typically called before this in ``run_step2_full``;
    this call is idempotent.
    """
    _ = params, pam_cfg_uid  # reserved for future batched record-update fallback
    tunnel_args = parse_command_options(mach, True)
    if not validate_tunneling_for_resource(
        tdag, tunnel_args, resource_uid=getattr(mach, 'uid', '') or '', silent=silent,
    ):
        return False
    queue_resource_config_link(tdag, mach.uid)
    return True


def ensure_traffic_encryption_seed_on_record(params, record_uid: str) -> None:
    """Fallback: ensure seed exists on a vault record after Step 1a (if still empty)."""
    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord):
        return
    if not ensure_traffic_encryption_seed_on_typed_record(record):
        return
    update_record(params, record)
    sync_down_after_batch(params)
