#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""Enforcement helpers for MCP tool calls: scope, self-protection, and guardrails."""

from typing import List, Optional, Set

from .config import CapabilityGrant, MCPConfig
from ..params import KeeperParams


class MCPAccessError(Exception):
    """Raised when a tool call is denied by scope, self-protection, or a guardrail."""
    pass


def assert_not_config_record(config, record_uid):  # type: (MCPConfig, Optional[str]) -> None
    """Self-protection: tools may never operate on the MCP config record itself."""
    if record_uid and config.config_record_uid and record_uid == config.config_record_uid:
        raise MCPAccessError('Access to the MCP configuration record is not permitted.')


def _expand_folders(params, folder_uids):  # type: (KeeperParams, Set[str]) -> Set[str]
    """Expand a set of folder UIDs to include all descendant folders."""
    result = set(folder_uids)
    pending = list(folder_uids)
    while pending:
        uid = pending.pop()
        node = params.folder_cache.get(uid)
        if node:
            for child in node.subfolders:
                if child not in result:
                    result.add(child)
                    pending.append(child)
    return result


def record_in_scope(params, grant, record_uid):  # type: (KeeperParams, CapabilityGrant, str) -> bool
    """Return True if a record is within the capability's scope.

    Scope can be expressed as allowed records and/or allowed folders (with descendants).
    An empty scope means the capability is unscoped (all records allowed).
    """
    scope = grant.scope or {}
    allowed_records = set(scope.get('records') or [])
    allowed_folders = set(scope.get('folders') or [])
    if not allowed_records and not allowed_folders:
        return True
    if record_uid in allowed_records:
        return True
    if allowed_folders:
        for folder_uid in _expand_folders(params, allowed_folders):
            if record_uid in params.subfolder_record_cache.get(folder_uid, set()):
                return True
    return False


def assert_record_in_scope(params, grant, record_uid):
    # type: (KeeperParams, CapabilityGrant, str) -> None
    if not record_in_scope(params, grant, record_uid):
        raise MCPAccessError(f'Record {record_uid} is outside the allowed scope for this capability.')


def folder_in_scope(params, grant, folder_uid):  # type: (KeeperParams, CapabilityGrant, str) -> bool
    scope = grant.scope or {}
    allowed_folders = set(scope.get('folders') or [])
    if not allowed_folders:
        return True
    return folder_uid in _expand_folders(params, allowed_folders)


def assert_folder_in_scope(params, grant, folder_uid):
    # type: (KeeperParams, CapabilityGrant, str) -> None
    if not folder_in_scope(params, grant, folder_uid):
        raise MCPAccessError(f'Folder {folder_uid} is outside the allowed scope for this capability.')


def is_dry_run_only(grant):  # type: (CapabilityGrant) -> bool
    return bool((grant.guardrails or {}).get('dry_run_only'))


def host_allowlist(grant):  # type: (CapabilityGrant) -> List[str]
    return list((grant.guardrails or {}).get('host_allowlist') or [])


def assert_host_allowed(grant, host):  # type: (CapabilityGrant, str) -> None
    allow = host_allowlist(grant)
    if allow and host not in allow:
        raise MCPAccessError(f'Host "{host}" is not in the guardrail allowlist for this capability.')
