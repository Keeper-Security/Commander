"""
KeeperDrive API package — single public facade.

Every symbol that the commands layer (or any external consumer) needs is
available here via ``from keepercommander import keeper_drive as _kd``.

Imports are **lazy** (using module-level ``__getattr__``) to avoid circular
dependencies during early module loading (e.g. ``api.py`` → ``sync_down.py``
→ this package → submodules that import ``api``).
"""

import importlib as _importlib

_SUBMODULE_MAP = {
    'permissions': [
        'FolderUsageType', 'SetBooleanValue', 'ROLE_NAME_MAP',
        'get_folder_permissions_for_role', 'get_record_permissions_for_role',
        'resolve_role_name',
    ],
    'common': [
        'get_folder_key', 'get_record_key', 'get_user_public_key',
        'get_record_from_cache', 'parse_sharing_status', 'get_record_key_type',
        'encrypt_record_key_for_folder', 'encrypt_for_recipient',
        'handle_share_invite', 'resolve_user_uid_bytes',
        'load_user_public_key', 'parse_folder_access_result',
    ],
    'folder_api': [
        'create_folder_data', 'encrypt_folder_key',
        'folder_add_v3', 'create_folder_v3', 'create_folders_batch_v3',
        'folder_access_update_v3', 'grant_folder_access_v3',
        'update_folder_access_v3', 'revoke_folder_access_v3',
        'manage_folder_access_batch_v3',
        'folder_update_v3', 'resolve_folder_identifier',
        'update_folder_v3', 'update_folders_batch_v3',
        'get_folder_access_v3',
    ],
    'record_api': [
        'create_record_data_v3', 'record_add_v3', 'record_update_v3',
        'create_record_v3', 'update_record_v3', 'create_records_batch_v3',
        'get_record_details_v3', 'get_record_accesses_v3',
        'share_record_v3', 'update_record_share_v3', 'unshare_record_v3',
        'transfer_record_ownership_v3', 'transfer_records_ownership_batch_v3',
    ],
    'folder_record_api': [
        'folder_record_update_v3',
        'add_record_to_folder_v3', 'update_record_in_folder_v3',
        'remove_record_from_folder_v3',
        'move_record_v3', 'manage_folder_records_batch_v3',
    ],
    'removal_api': [
        'remove_record_v3', 'remove_folder_v3',
        'find_kd_folders_for_record',
        'resolve_kd_record_uid', 'resolve_kd_folder_uid',
    ],
}

_LAZY_REGISTRY = {}
for _mod, _names in _SUBMODULE_MAP.items():
    for _name in _names:
        _LAZY_REGISTRY[_name] = _mod


def __getattr__(name):
    if name in _LAZY_REGISTRY:
        submod = _LAZY_REGISTRY[name]
        mod = _importlib.import_module(f'.{submod}', __name__)
        val = getattr(mod, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return list(globals().keys()) + list(_LAZY_REGISTRY.keys())
