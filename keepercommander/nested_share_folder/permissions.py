"""
Nested Share Folder — role matrices, permission helpers, enum wrappers.

Open/Closed: new roles can be added to the matrices without changing
any consumer code.
"""

from typing import Dict

from ..proto import folder_pb2


class FolderUsageType:
    NORMAL = folder_pb2.UT_NORMAL


class SetBooleanValue:
    BOOLEAN_NO_CHANGE = folder_pb2.BOOLEAN_NO_CHANGE
    BOOLEAN_TRUE = folder_pb2.BOOLEAN_TRUE
    BOOLEAN_FALSE = folder_pb2.BOOLEAN_FALSE


_FOLDER_ROLE_PERMISSIONS: Dict[int, Dict[str, bool]] = {
    0: {  # NAVIGATOR
        'canAdd': False, 'canRemove': False, 'canDelete': False,
        'canListAccess': False, 'canUpdateAccess': False, 'canChangeOwnership': False,
        'canEditRecords': False, 'canViewRecords': False,
        'canApproveAccess': False, 'canRequestAccess': False,
        'canUpdateSetting': False, 'canListRecords': False, 'canListFolders': True,
    },
    1: {  # REQUESTOR
        'canAdd': False, 'canRemove': False, 'canDelete': False,
        'canListAccess': False, 'canUpdateAccess': False, 'canChangeOwnership': False,
        'canEditRecords': False, 'canViewRecords': False,
        'canApproveAccess': False, 'canRequestAccess': True,
        'canUpdateSetting': False, 'canListRecords': True, 'canListFolders': True,
    },
    2: {  # VIEWER
        'canAdd': False, 'canRemove': False, 'canDelete': False,
        'canListAccess': True, 'canUpdateAccess': False, 'canChangeOwnership': False,
        'canEditRecords': False, 'canViewRecords': True,
        'canApproveAccess': False, 'canRequestAccess': False,
        'canUpdateSetting': False, 'canListRecords': True, 'canListFolders': True,
    },
    3: {  # SHARED_MANAGER
        'canAdd': False, 'canRemove': False, 'canDelete': False,
        'canListAccess': True, 'canUpdateAccess': True, 'canChangeOwnership': False,
        'canEditRecords': False, 'canViewRecords': True,
        'canApproveAccess': True, 'canRequestAccess': False,
        'canUpdateSetting': False, 'canListRecords': True, 'canListFolders': True,
    },
    4: {  # CONTENT_MANAGER
        'canAdd': True, 'canRemove': False, 'canDelete': False,
        'canListAccess': True, 'canUpdateAccess': False, 'canChangeOwnership': False,
        'canEditRecords': True, 'canViewRecords': True,
        'canApproveAccess': False, 'canRequestAccess': False,
        'canUpdateSetting': False, 'canListRecords': True, 'canListFolders': True,
    },
    5: {  # CONTENT_SHARE_MANAGER
        'canAdd': True, 'canRemove': True, 'canDelete': False,
        'canListAccess': True, 'canUpdateAccess': True, 'canChangeOwnership': False,
        'canEditRecords': True, 'canViewRecords': True,
        'canApproveAccess': True, 'canRequestAccess': False,
        'canUpdateSetting': True, 'canListRecords': True, 'canListFolders': True,
    },
    6: {  # MANAGER
        'canAdd': True, 'canRemove': True, 'canDelete': True,
        'canListAccess': True, 'canUpdateAccess': True, 'canChangeOwnership': True,
        'canEditRecords': True, 'canViewRecords': True,
        'canApproveAccess': True, 'canRequestAccess': False,
        'canUpdateSetting': True, 'canListRecords': True, 'canListFolders': True,
    },
}

_RECORD_ROLE_PERMISSIONS: Dict[int, Dict[str, bool]] = {
    0: {
        'can_view_title': False, 'can_edit': False, 'can_view': False,
        'can_list_access': False, 'can_update_access': False, 'can_delete': False,
        'can_change_ownership': False, 'can_request_access': False, 'can_approve_access': False,
    },
    1: {
        'can_view_title': True, 'can_edit': False, 'can_view': False,
        'can_list_access': False, 'can_update_access': False, 'can_delete': False,
        'can_change_ownership': False, 'can_request_access': True, 'can_approve_access': False,
    },
    2: {
        'can_view_title': True, 'can_edit': False, 'can_view': True,
        'can_list_access': True, 'can_update_access': False, 'can_delete': False,
        'can_change_ownership': False, 'can_request_access': False, 'can_approve_access': False,
    },
    3: {
        'can_view_title': True, 'can_edit': False, 'can_view': True,
        'can_list_access': True, 'can_update_access': True, 'can_delete': False,
        'can_change_ownership': False, 'can_request_access': False, 'can_approve_access': True,
    },
    4: {
        'can_view_title': True, 'can_edit': True, 'can_view': True,
        'can_list_access': True, 'can_update_access': False, 'can_delete': False,
        'can_change_ownership': False, 'can_request_access': False, 'can_approve_access': False,
    },
    5: {
        'can_view_title': True, 'can_edit': True, 'can_view': True,
        'can_list_access': True, 'can_update_access': True, 'can_delete': False,
        'can_change_ownership': False, 'can_request_access': False, 'can_approve_access': True,
    },
    6: {
        'can_view_title': True, 'can_edit': True, 'can_view': True,
        'can_list_access': True, 'can_update_access': True, 'can_delete': True,
        'can_change_ownership': True, 'can_request_access': False, 'can_approve_access': True,
    },
}

ROLE_NAME_MAP: Dict[str, int] = {
    'contributor':           1,
    'requestor':             1,
    'viewer':                2,
    'shared_manager':        3,
    'share-manager':         3,
    'share_manager':         3,
    'content_manager':       4,
    'content-manager':       4,
    'content_share_manager': 5,
    'content-share-manager': 5,
    'full-manager':          6,
    'full_manager':          6,
}


def classic_shared_folder_permissions_to_nsf_role(manage_users=False,
                                                   manage_records=False):
    """Map Classic Shared Folder membership permissions to an NSF folder role."""
    can_manage_shares = bool(manage_users)
    can_manage_content = bool(manage_records)
    if can_manage_shares and can_manage_content:
        return 'content-share-manager'
    if can_manage_content:
        return 'content-manager'
    if can_manage_shares:
        return 'share-manager'
    return 'viewer'


def classic_record_permissions_to_nsf_role(can_edit=False, can_share=False):
    """Map one Classic Shared Folder record's permissions to an NSF record role."""
    can_manage_shares = bool(can_share)
    can_manage_content = bool(can_edit)
    if can_manage_shares and can_manage_content:
        return 'content-share-manager'
    if can_manage_content:
        return 'content-manager'
    if can_manage_shares:
        return 'share-manager'
    return 'viewer'


def merge_record_access_roles(*roles):
    """Return the least-privileged record role that includes all supplied roles."""
    required = {field: False for field in _RECORD_ROLE_PERMISSIONS[0]}
    for role in roles:
        if role is None:
            continue
        if isinstance(role, int):
            role_type = role
        else:
            role_name = role.strip().lower().replace('-', '_')
            role_type = ROLE_NAME_MAP.get(role_name)
            if role_type is None:
                try:
                    role_type = folder_pb2.AccessRoleType.Value(role_name.upper())
                except ValueError as exc:
                    raise ValueError(f"Unknown NSF record role '{role}'") from exc
        permissions = get_record_permissions_for_role(role_type)
        for field, value in permissions.items():
            required[field] |= value

    candidates = []
    for role_type in _RECORD_ROLE_PERMISSIONS:
        permissions = get_record_permissions_for_role(role_type)
        if all(not value or permissions[field] for field, value in required.items()):
            candidates.append((sum(permissions.values()), role_type))
    if not candidates:
        return 'full-manager'
    role_type = min(candidates)[1]
    return {
        0: 'navigator',
        1: 'requestor',
        2: 'viewer',
        3: 'share-manager',
        4: 'content-manager',
        5: 'content-share-manager',
        6: 'full-manager',
    }[role_type]


def get_folder_permissions_for_role(role_type: int) -> 'folder_pb2.FolderPermissions':
    perms_dict = _FOLDER_ROLE_PERMISSIONS.get(role_type)
    if perms_dict is None:
        raise ValueError(
            f"Unknown AccessRoleType {role_type}. "
            f"Expected one of {list(_FOLDER_ROLE_PERMISSIONS.keys())}.")
    perms = folder_pb2.FolderPermissions()
    for field, value in perms_dict.items():
        setattr(perms, field, value)
    return perms


def get_record_permissions_for_role(role_type: int) -> Dict[str, bool]:
    perms_dict = _RECORD_ROLE_PERMISSIONS.get(role_type)
    if perms_dict is None:
        raise ValueError(
            f"Unknown AccessRoleType {role_type}. "
            f"Expected one of {list(_RECORD_ROLE_PERMISSIONS.keys())}.")
    return dict(perms_dict)


def resolve_role_name(role: str) -> int:
    normalised = role.strip().lower()
    value = ROLE_NAME_MAP.get(normalised)
    if value is None:
        raise ValueError(
            f"Invalid role '{role}'. "
            f"Accepted values: {', '.join(sorted(set(ROLE_NAME_MAP.keys())))}.")
    return value
