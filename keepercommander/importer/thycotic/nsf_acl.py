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

FOLDER_ROLE_MAP = {
    'owner': 'full-manager',
    'edit': 'content-manager',
    'add secret': 'content-manager',
    'view': 'viewer',
}

SECRET_ROLE_MAP = {
    'list': 'viewer',
    'view': 'viewer',
    'edit': 'content-manager',
    'owner': 'full-manager',
}

# Higher wins when the same email appears more than once (user rows and groups).
ROLE_WEIGHT = {
    'full-manager': 3,
    'content-manager': 2,
    'viewer': 1,
}


def thycotic_folder_role_to_nsf_role(folder_access_role_name):
    # type: (Optional[str]) -> Optional[str]
    """Map a Delinea folder access role (folder permission only) to an NSF folder role."""
    if not folder_access_role_name:
        return None
    return FOLDER_ROLE_MAP.get(folder_access_role_name.strip().lower())


def thycotic_secret_role_to_nsf_role(secret_access_role_name):
    # type: (Optional[str]) -> Optional[str]
    """Map Delinea secret access role to NSF role (secret-level overrides).

    API returns Owner/Edit/View/List only; extended flags are separate fields.
    List maps to viewer. Unknown roles return None (no viewer fallback).
    """
    if not secret_access_role_name:
        return None
    return SECRET_ROLE_MAP.get(secret_access_role_name.strip().lower())


def _keep_highest_role(roles, email, role):
    # type: (Dict[str, str], str, str) -> None
    """Keep the higher-weight role for *email* (no downgrade)."""
    current = roles.get(email)
    if current is None or ROLE_WEIGHT.get(role, 0) > ROLE_WEIGHT.get(current, 0):
        roles[email] = role


def _roles_by_email(perm_rows, role_of, users_by_id, groups_by_id, group_filter=None,
                    old_domain=None, new_domain=None):
    # type: (List[Dict], Any, Dict[int, Dict], Dict[int, Dict], Any, Optional[str], Optional[str]) -> Dict[str, str]
    from ..importer import replace_email_domain

    users_by_id = users_by_id or {}
    groups_by_id = groups_by_id or {}
    group_roles = {}  # type: Dict[str, str]
    user_roles = {}  # type: Dict[str, str]
    for row in perm_rows or []:
        role = role_of(row)
        if not role:
            continue
        user_id = row.get('userId') or 0
        group_id = row.get('groupId') or 0
        if user_id > 0:
            email = (users_by_id.get(user_id) or {}).get('emailAddress')
            if email:
                email_normalized = replace_email_domain(email, old_domain, new_domain).lower()
                _keep_highest_role(user_roles, email_normalized, role)
        elif group_id > 0 and group_id in groups_by_id:
            group = groups_by_id[group_id]
            if group_filter is not None and not group_filter(group):
                continue
            for member_id in group.get('users', []) or []:
                email = (users_by_id.get(member_id) or {}).get('emailAddress')
                if email:
                    email_normalized = replace_email_domain(email, old_domain, new_domain).lower()
                    _keep_highest_role(group_roles, email_normalized, role)
    # Merge: highest role wins; on a tie, a direct user row beats a group grant.
    for email, role in user_roles.items():
        current = group_roles.get(email)
        if current is None or ROLE_WEIGHT.get(role, 0) >= ROLE_WEIGHT.get(current, 0):
            group_roles[email] = role
    return group_roles


def folder_roles_by_email(perm_rows, users_by_id, groups_by_id, group_filter=None,
                          old_domain=None, new_domain=None):
    # type: (List[Dict], Dict[int, Dict], Dict[int, Dict], Any, Optional[str], Optional[str]) -> Dict[str, str]
    """{email: NSF folder role} from Delinea folder permission rows (folderAccessRoleName only)."""
    return _roles_by_email(
        perm_rows, lambda r: thycotic_folder_role_to_nsf_role(r.get('folderAccessRoleName')),
        users_by_id, groups_by_id, group_filter, old_domain, new_domain)


def record_roles_by_email(perm_rows, users_by_id, groups_by_id, old_domain=None, new_domain=None,
                          group_filter=None):
    # type: (List[Dict], Dict[int, Dict], Dict[int, Dict], Optional[str], Optional[str], Any) -> Dict[str, str]
    """{email: NSF record role} from Delinea permission rows (secretAccessRoleName only)."""
    return _roles_by_email(
        perm_rows, lambda r: thycotic_secret_role_to_nsf_role(r.get('secretAccessRoleName')),
        users_by_id, groups_by_id, group_filter, old_domain, new_domain)


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

    Secret Server exposes this as ``enableInheritPermissions`` on
    ``/v1/secrets/{id}`` and ``/v2/secrets/{id}``. Older field names are
    still checked. Missing field means inherit.
    """
    for key in (
        'enableInheritPermissions',
        'inheritPermissions',
        'inheritSecretPermissions',
        'inheritsPermissions',
    ):
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


def diff_secret_acl(folder_roles_by_email, secret_roles_by_email):
    # type: (Dict[str, str], Dict[str, str]) -> List[Tuple[str, str]]
    """Return [(email, nsf_role), ...] where the secret role differs from the folder role."""
    deltas = []
    for email, secret_role in secret_roles_by_email.items():
        if secret_role != folder_roles_by_email.get(email):
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
            owners.add(replace_email_domain(email, old_domain, new_domain).lower())
    return owners


def nsf_record_shares_for_secret_acl(record_roles_by_email, folder_roles_by_email):
    # type: (Dict[str, str], Dict[str, str]) -> List[Tuple[str, str]]
    """Direct shares where the record role differs from the folder role (or no folder role)."""
    return diff_secret_acl(folder_roles_by_email or {}, record_roles_by_email or {})


def nsf_acl_log(message, *args, **kwargs):
    # type: (str, Any, Any) -> None
    """NSF ACL trace (visible when logging level is DEBUG)."""
    logging.debug('[NSF-ACL] ' + message, *args, **kwargs)
