#  _  __
# | |/ /_____ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""Thycotic to NSF role mapping for Nested Share Folder ACL."""

from typing import Optional, Dict, Tuple, List, Any, Set
import logging

ROLE_MATRIX = {
    ('owner', 'owner'): 'full-manager',
    ('owner', 'edit'): 'full-manager',
    ('edit', 'owner'): 'content-manager',
    ('edit', 'edit'): 'content-manager',
    ('add secret', 'owner'): 'content-manager',
    ('view', 'view'): 'viewer',
}

def _permission_principal_key(perm_row):
    # type: (Dict[str, Any]) -> Optional[Tuple[str, int]]
    user_id = perm_row.get('userId') or 0
    group_id = perm_row.get('groupId') or 0
    if user_id > 0:
        return ('user', user_id)
    if group_id > 0:
        return ('group', group_id)
    return None


def permission_grant_signature(perm_rows):
    # type: (List[Dict[str, Any]]) -> Set[Tuple[Tuple[str, int], str]]
    """Stable set of (principal, secretAccessRoleName) for ACL comparison."""
    sig = set()  # type: Set[Tuple[Tuple[str, int], str]]
    for row in perm_rows or []:
        principal = _permission_principal_key(row)
        secret_role = row.get('secretAccessRoleName')
        if not principal or not secret_role:
            continue
        sig.add((principal, secret_role.strip().lower()))
    return sig


def secret_acl_differs_from_folder_rows(secret_perm_rows, folder_perm_rows):
    # type: (List[Dict[str, Any]], List[Dict[str, Any]]) -> bool
    """True when secret-level grants differ from folder-level grants (override)."""
    secret_sig = permission_grant_signature(secret_perm_rows)
    if not secret_sig:
        return False
    folder_sig = permission_grant_signature(folder_perm_rows)
    return secret_sig != folder_sig


def parse_secret_inherit_permissions(secret):
    # type: (Dict[str, Any]) -> bool
    """
    Return True if the secret inherits folder permissions (Delinea default).

    Checks several API field names; missing field means inherit.
    """
    for key in ('inheritPermissions', 'inheritSecretPermissions', 'inheritsPermissions'):
        if key not in secret:
            continue
        raw = secret.get(key)
        if raw is None:
            continue
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            return raw.strip().lower() in ('true', '1', 'yes')
        return bool(raw)
    return True


def thycotic_roles_to_nsf_role(folder_access_role_name, secret_access_role_name):
    # type: (Optional[str], Optional[str]) -> Optional[str]
    """
    Map Delinea folder + secret access roles to NSF role.

    Args:
        folder_access_role_name: Delinea folder access role (e.g., 'Owner', 'Edit', 'View', 'List')
        secret_access_role_name: Delinea secret access role (e.g., 'Owner', 'Edit', 'View', 'List')

    Returns:
        NSF role name or None if no grant is warranted.
    """
    if not secret_access_role_name:
        return None

    folder_role = folder_access_role_name.lower() if folder_access_role_name else ''
    secret_role = secret_access_role_name.lower()

    # Lookup in existing mapping
    if (folder_role, secret_role) in ROLE_MATRIX:
        return ROLE_MATRIX.get((folder_role, secret_role))

    # Dynamic rule: Secret role wins when View folder has elevated secret access
    if folder_role == 'view' and secret_role in ('edit', 'owner'):
        return thycotic_secret_role_to_nsf_role(secret_access_role_name)

    # Dynamic Rule: no folder access (None or empty) + any secret role → use secret role
    if not folder_role:
        return thycotic_secret_role_to_nsf_role(secret_access_role_name)

    # Any folder + List secret → requestor
    if secret_role == 'list':
        return 'requestor'

    # No secret access → no grant
    return None


def thycotic_secret_role_to_nsf_role(secret_access_role_name):
    # type: (Optional[str]) -> Optional[str]
    """
    Map Delinea secret-only access role to NSF role (for secret-level overrides).

    Args:
        secret_access_role_name: Delinea secret access role

    Returns:
        NSF role name or None.
    """
    if not secret_access_role_name:
        return None

    role = secret_access_role_name.lower()

    if role == 'list':
        return 'requestor'
    elif role == 'view':
        return 'viewer'
    elif role == 'edit':
        return 'content-manager'
    elif role == 'owner':
        return 'full-manager'

    return None


def is_lossy_folder_secret_pair(folder_access_role_name, secret_access_role_name):
    # type: (Optional[str], Optional[str]) -> bool
    """
    Check if folder + secret ACL pair is lossy (information loss in NSF role mapping).

    Lossy: Owner/Edit folder but View secret (grants only viewer, loses folder permission).
    """
    if not folder_access_role_name or not secret_access_role_name:
        return False

    folder_role = folder_access_role_name.lower()
    secret_role = secret_access_role_name.lower()

    return folder_role in ('owner', 'edit') and secret_role == 'view'


def diff_secret_acl(folder_roles_by_email, secret_roles_by_email):
    # type: (Dict[str, str], Dict[str, str]) -> List[Tuple[str, str]]
    """
    Find secrets where the NSF role differs from the folder role.

    Args:
        folder_roles_by_email: {email: nsf_role} from folder grants
        secret_roles_by_email: {email: nsf_role} from secret-only grants

    Returns:
        [(email, nsf_role), ...] where secret role differs from folder role (skip no-ops).
    """
    deltas = []

    for email, secret_role in secret_roles_by_email.items():
        folder_role = folder_roles_by_email.get(email)

        if secret_role != folder_role:
            deltas.append((email, secret_role))

    return deltas


def secret_owner_emails_from_perm_rows(perm_rows, users_by_id, old_domain=None, new_domain=None):
    # type: (List[Dict], Dict[int, Dict], Optional[str], Optional[str]) -> set
    """Emails granted Delinea secretAccessRoleName Owner on a secret (any co-owner)."""
    from ..importer import replace_email_domain

    owners = set()
    users_by_id = users_by_id or {}
    for perm in perm_rows or []:
        if (perm.get('secretAccessRoleName') or '').strip().lower() != 'owner':
            continue
        user_id = perm.get('userId') or 0
        if user_id <= 0 or user_id not in users_by_id:
            continue
        email = users_by_id[user_id].get('emailAddress')
        if email:
            owners.add(replace_email_domain(email, old_domain, new_domain))
    return owners


def nsf_record_shares_for_secret_acl(secret_roles_by_email, folder_roles_by_email,
                                     secret_inherits_folder_permissions=True):
    # type: (Dict[str, str], Dict[str, str], bool) -> List[Tuple[str, str]]
    """
    Build NSF direct record shares from Delinea secret permission rows.

    When the secret's ``inheritPermissions`` is false (Delinea Sharing tab:
    "Inherit permissions" unchecked), every mapped secret grant becomes a
    direct record share. When the secret inherits folder permissions, only
    roles that differ from the folder baseline are returned (deltas).
    """
    if secret_inherits_folder_permissions is False:
        return list(secret_roles_by_email.items())
    return diff_secret_acl(folder_roles_by_email or {}, secret_roles_by_email)


def nsf_acl_log(message, *args, **kwargs):
    # type: (str, Any, Any) -> None
    """NSF ACL trace (visible when logging level is DEBUG)."""
    logging.debug('[NSF-ACL] ' + message, *args, **kwargs)
