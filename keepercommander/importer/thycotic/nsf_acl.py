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

from typing import Optional, Dict, Tuple, List
import logging


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
    if not folder_access_role_name or not secret_access_role_name:
        return None

    folder_role = folder_access_role_name.lower()
    secret_role = secret_access_role_name.lower()

    # Owner folder + (Owner or Edit) secret → full-manager
    if folder_role == 'owner' and secret_role in ('owner', 'edit'):
        return 'full-manager'

    # (Edit or Add Secret) folder + (Owner or Edit) secret → content-manager
    if folder_role in ('edit', 'add secret') and secret_role in ('owner', 'edit'):
        return 'content-manager'

    # Owner or Edit folder + View secret → viewer (lossy, log warning)
    if folder_role in ('owner', 'edit') and secret_role == 'view':
        return 'viewer'

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
