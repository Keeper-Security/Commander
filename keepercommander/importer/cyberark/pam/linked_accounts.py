#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import logging
import re
from typing import Dict, List, Optional, Tuple

from .client import CyberArkPVWAClient

def resolve_linked_accounts(client: 'CyberArkPVWAClient',
                            account: dict) -> List[dict]:
    """Resolve linked accounts (logon, reconcile, enable) for an account.

    Fetches the full account details to get linkedAccounts, then fetches
    each linked account and maps it as a pamUser record.

    Returns list of pamUser dicts with role annotations.
    """
    account_id = account.get("id", "")
    details = client.fetch_account_details(account_id)
    if not details:
        return []

    linked = details.get("linkedAccounts") or {}
    if not isinstance(linked, dict):
        logging.warning('Unexpected linkedAccounts type: %s for account %s',
                        type(linked).__name__, account_id)
        return []
    result = []

    for role, link_data in linked.items():
        if not isinstance(link_data, dict) or not link_data.get("id"):
            continue
        role_name = role.replace("Account", "").lower()  # logonAccount → logon

        # Fetch the linked account's password
        linked_id = link_data["id"]
        # Validate linked account ID format (same check as fetch_account_details)
        if not re.match(r'^[a-zA-Z0-9_]+$', str(linked_id)):
            logging.warning('Invalid linked account ID: %s — skipping',
                            re.sub(r'[^a-zA-Z0-9_]', '?', str(linked_id)))
            continue
        linked_name = link_data.get("name", "")
        linked_safe = link_data.get("safeName", account.get("safeName", ""))
        # Note: skip_all dict not passed here — linked account password
        # failures don't share the "Skip All" state with the main loop.
        # This is acceptable since linked accounts are typically few per resource.
        password = client.retrieve_password(linked_id, linked_name, linked_safe)

        # Build pamUser record for the linked account
        user_title = f"{linked_name} ({role_name} account)"
        linked_user = {
            "type": "pamUser",
            "title": user_title,
            "login": link_data.get("userName", linked_name),
            "password": password or "",
            "notes": f"CyberArk role: {role_name} account\n"
                     f"Linked to: {account.get('name', account_id)}\n"
                     f"Source safe: {linked_safe}",
            "_ca_role": role_name,  # Internal: logon, reconcile, or enable
            "_ca_id": str(linked_id),  # Internal: used by idempotency layer
            "_ca_safe": linked_safe,   # Internal: used by idempotency layer
        }
        # Embed CyberArk identity marker so re-imports can match this
        # linked account to the existing Keeper record.  The linked
        # account has its own CyberArk id distinct from the master
        # account it decorates, so we tag with ``linked_id`` (not the
        # outer ``account_id``).
        try:
            from .idempotency import annotate_record_with_marker
            annotate_record_with_marker(linked_user, str(linked_id), linked_safe)
        except Exception:  # noqa: BLE001 — never block linked-account resolution on annotation failure
            logging.debug("Failed to annotate linked account %s with CyberArk-ID marker", linked_id)
        result.append(linked_user)
        logging.info('Resolved linked %s account: %s', role_name, user_title)

    return result


def pick_launch_credentials(linked_users: List[dict]) -> Optional[str]:
    """Pick which linked account populates Keeper's launch_credentials slot.

    CyberArk PSM uses the logonAccount to establish the initial connection
    (e.g. SSH as a less-privileged service account), then switches (sudo/su)
    to the target account. Keeper's launch_credentials is the connection
    credential, so the logon account is its natural fit when present.

    Returns the logon account's title, or None if no logon is linked.
    """
    for lu in linked_users:
        if lu.get("_ca_role") == "logon":
            return lu.get("title")
    return None


def pick_admin_credentials(linked_users: List[dict]) -> Tuple[Optional[str], Optional[str]]:
    """Pick which linked account populates Keeper's administrative_credentials slot.

    CyberArk has three linked-account roles (logon, reconcile, enable) but
    Keeper resources have only one administrative_credentials slot. Reconcile
    is preferred because it is the account CyberArk CPM uses for password
    rotation recovery — the most common privileged-management path. Enable
    is used as a fallback when no reconcile account is linked.

    Returns (title, role) of the chosen account, or (None, None) if none present.
    """
    for lu in linked_users:
        if lu.get("_ca_role") == "reconcile":
            return lu.get("title"), "reconcile"
    for lu in linked_users:
        if lu.get("_ca_role") == "enable":
            return lu.get("title"), "enable"
    return None, None


def detect_dual_account(account: dict) -> Optional[Dict[str, str]]:
    """Detect if an account is part of a dual-account/rotational group.

    CyberArk dual accounts have VirtualUserName and/or GroupPlatformID
    in their platformAccountProperties.

    Returns dict of custom fields to add, or None if not a dual account.
    """
    if not isinstance(account, dict):
        return None
    props = account.get("platformAccountProperties") or {}
    virtual_user = props.get("VirtualUserName", "")
    group_platform = props.get("GroupPlatformID", "")
    index = props.get("Index", "")

    if not virtual_user and not group_platform:
        return None

    fields = {}
    if virtual_user:
        fields["ca_virtual_username"] = virtual_user
    if group_platform:
        fields["ca_dual_account_group"] = group_platform
    if index:
        fields["ca_dual_account_index"] = index

    return fields
