#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import logging
from typing import List

class PermissionMapper:
    """Maps CyberArk safe member permissions to Keeper shared folder permission tiers.

    CyberArk has 24 granular boolean permissions per safe member (ark-sdk-python).
    Keeper has 4 permission levels: manage_users, manage_records, can_edit, can_share.

    Mapping tiers (cumulative):
      Tier 1 (view):   useAccounts + retrieveAccounts + listAccounts
      Tier 2 (edit):   + addAccounts + updateAccountContent + updateAccountProperties
                        + renameAccounts + deleteAccounts
      Tier 3 (manage): + manageSafe + manageSafeMembers + viewSafeMembers

    Mapped but not tier-affecting (absorbed into higher tiers):
      viewAuditLog, backupSafe, unlockAccounts,
      initiateCPMAccountManagementOperations, specifyNextAccountContent,
      createFolders, deleteFolders, moveAccountsAndFolders

    UNMAPPED permissions (no Keeper equivalent — logged in report):
      accessWithoutConfirmation, requestsAuthorizationLevel1/2
    """

    # All 24 CyberArk permissions from ark-sdk-python ArkPCloudSafeMemberPermissions
    ALL_PERMISSIONS = {
        # Tier 1 — View
        "useAccounts", "retrieveAccounts", "listAccounts",
        # Tier 2 — Edit
        "addAccounts", "updateAccountContent", "updateAccountProperties",
        "renameAccounts", "deleteAccounts",
        # Tier 3 — Manage
        "manageSafe", "manageSafeMembers", "viewSafeMembers",
        # Absorbed into tiers (not tier-determining but tracked)
        "viewAuditLog", "backupSafe", "unlockAccounts",
        "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
        "createFolders", "deleteFolders", "moveAccountsAndFolders",
        # Unmapped — no Keeper equivalent
        "accessWithoutConfirmation",
        "requestsAuthorizationLevel1", "requestsAuthorizationLevel2",
        # CyberArk 13+ additions
        "isExpiredMembershipEnable", "isReadOnly",
    }

    # Permissions that have no Keeper equivalent
    UNMAPPED_PERMISSIONS = {
        "accessWithoutConfirmation",
        "requestsAuthorizationLevel1",
        "requestsAuthorizationLevel2",
    }

    @staticmethod
    def map_permissions(perms: dict) -> dict:
        """Map CyberArk permission booleans to Keeper shared folder permissions.

        Returns dict with keys: manage_users, manage_records, can_edit, can_share.
        """
        if not isinstance(perms, dict):
            return {"manage_users": False, "manage_records": False,
                    "can_edit": False, "can_share": False}

        # Tier 1: View — can list and use accounts
        has_view = (perms.get("useAccounts", False)
                    and perms.get("listAccounts", False))

        # Tier 2: Edit — can modify account content
        has_edit = (has_view
                    and perms.get("addAccounts", False)
                    and (perms.get("updateAccountContent", False)
                         or perms.get("updateAccountProperties", False)))

        # Tier 3: Manage — full safe administration
        has_manage = (has_edit
                      and perms.get("manageSafe", False)
                      and perms.get("manageSafeMembers", False))

        return {
            "manage_users": has_manage,
            "manage_records": has_edit or has_manage,
            "can_edit": has_edit or has_manage,
            "can_share": has_manage,
        }

    @staticmethod
    def get_unmapped_permissions(perms: dict) -> List[str]:
        """Return list of CyberArk permissions that have no Keeper equivalent."""
        if not isinstance(perms, dict):
            return []
        return [
            p for p in PermissionMapper.UNMAPPED_PERMISSIONS
            if perms.get(p, False)
        ]

    @staticmethod
    def map_member(member: dict) -> dict:
        """Map a CyberArk safe member to a Keeper shared folder permission entry.

        Returns dict with: name, member_type ('user'|'team'), permissions dict,
        unmapped list, and the raw memberName for matching.
        """
        name = member.get("memberName", "")
        member_type = member.get("memberType", "User")
        perms = member.get("permissions", {})

        # Warn on unexpected member types (CyberArk currently uses "User" and "Group")
        if member_type not in ("User", "Group"):
            logging.warning('Unexpected member type "%s" for member "%s" — treating as user',
                            member_type, name)

        keeper_perms = PermissionMapper.map_permissions(perms)
        unmapped = PermissionMapper.get_unmapped_permissions(perms)

        return {
            "name": name,
            "member_type": "team" if member_type == "Group" else "user",
            "permissions": keeper_perms,
            "unmapped_permissions": unmapped,
        }

