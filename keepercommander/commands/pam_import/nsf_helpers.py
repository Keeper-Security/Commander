#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from __future__ import annotations

import logging
from typing import List, Optional

from .record_loader import iter_accessible_record_uids, load_pam_record
from ... import api, vault
from ...error import CommandError


def is_nsf_folder_uid(params, folder_uid: str) -> bool:
    """Return True when *folder_uid* is a Nested Shared Folder."""
    if not folder_uid:
        return False
    nsf_folders = getattr(params, 'nested_share_folders', None) or {}
    if folder_uid in nsf_folders:
        return True
    subfolder = (getattr(params, 'subfolder_cache', None) or {}).get(folder_uid) or {}
    return subfolder.get('source') == 'nested_share_folder'


def find_pam_configuration(params, config_name: str) -> Optional[vault.TypedRecord]:
    """Resolve a PAM configuration record by UID or title (classic + NSF)."""
    config_name = (config_name or '').strip()
    if not config_name:
        return None

    rec = load_pam_record(params, config_name)
    if rec and isinstance(rec, vault.TypedRecord) and rec.version == 6:
        return rec

    l_name = config_name.casefold()
    for uid in iter_accessible_record_uids(params):
        if uid == config_name:
            continue
        rec = load_pam_record(params, uid)
        if not rec or not isinstance(rec, vault.TypedRecord) or rec.version != 6:
            continue
        if rec.title and rec.title.casefold() == l_name:
            return rec
    return None


def get_ksm_app_folders(params, ksm_app_uid: str) -> List[dict]:
    """Return KSM-application folder roots (classic shared folders and NSF)."""
    from ..ksm import KSMCommand
    from ... import utils as keeper_utils
    from ...proto import APIRequest_pb2

    folders = []
    try:
        app_info_list = KSMCommand.get_app_info(params, ksm_app_uid)
        if not app_info_list:
            return folders
        app_info = app_info_list[0]
        shares = [x for x in app_info.shares if x.shareType == APIRequest_pb2.SHARE_TYPE_FOLDER]  # pylint: disable=no-member
        for share in shares:
            folder_uid = keeper_utils.base64_url_encode(share.secretUid)
            is_editable = share.editable if hasattr(share, 'editable') else False
            entry = _folder_entry_for_uid(params, folder_uid, is_editable)
            if entry:
                folders.append(entry)
    except Exception as exc:
        logging.error('Could not retrieve KSM application shares: %s', exc)
    return folders


def _folder_entry_for_uid(params, folder_uid: str, is_editable: bool) -> Optional[dict]:
    if folder_uid in getattr(params, 'shared_folder_cache', {}):
        cached_sf = params.shared_folder_cache[folder_uid]
        return {
            'uid': folder_uid,
            'name': cached_sf.get('name_unencrypted', 'Unknown'),
            'editable': is_editable,
            'permissions': 'Editable' if is_editable else 'Read-Only',
            'source': 'classic',
        }
    nsf_folders = getattr(params, 'nested_share_folders', None) or {}
    if folder_uid in nsf_folders:
        return {
            'uid': folder_uid,
            'name': nsf_folders[folder_uid].get('name', 'Unknown'),
            'editable': is_editable,
            'permissions': 'Editable' if is_editable else 'Read-Only',
            'source': 'nested',
        }
    return None


def build_folder_tree(params, folder_uid: str) -> dict:
    """Build a nested folder tree under *folder_uid* (classic or NSF)."""
    if is_nsf_folder_uid(params, folder_uid):
        return _build_nsf_folder_tree(params, folder_uid)
    return _build_classic_folder_tree(params, folder_uid)


def _build_classic_folder_tree(params, folder_uid: str) -> dict:
    tree = {}
    folder = params.folder_cache.get(folder_uid)
    if not folder:
        return tree
    for subfolder_uid in folder.subfolders:
        subfolder = params.folder_cache.get(subfolder_uid)
        if not subfolder:
            continue
        folder_name = subfolder.name or ''
        tree[folder_name] = {
            'uid': subfolder.uid,
            'name': folder_name,
            'subfolders': _build_classic_folder_tree(params, subfolder.uid),
        }
    return tree


def _build_nsf_folder_tree(params, root_uid: str) -> dict:
    nsf_folders = getattr(params, 'nested_share_folders', None) or {}

    def children_of(parent_uid: str) -> dict:
        kids = {}
        for fuid, finfo in nsf_folders.items():
            raw_parent = finfo.get('parent_uid') or ''
            if raw_parent != parent_uid:
                continue
            name = finfo.get('name') or fuid
            kids[name] = {
                'uid': fuid,
                'name': name,
                'subfolders': children_of(fuid),
            }
        return kids

    return children_of(root_uid)


def get_folder_record_uids(params, folder_uid: str) -> set:
    """Return record UIDs directly associated with a folder."""
    record_uids = set()
    subfolder_record_cache = getattr(params, 'subfolder_record_cache', None) or {}
    nsf_folder_records = getattr(params, 'nested_share_folder_records', None) or {}
    if folder_uid in subfolder_record_cache:
        record_uids.update(subfolder_record_cache[folder_uid])
    if folder_uid in nsf_folder_records:
        record_uids.update(nsf_folder_records[folder_uid])
    return record_uids


def get_records_in_folder(params, folder_uid: str) -> list:
    """Return (uid, title, record_type, login) tuples for records in *folder_uid*."""
    result = []
    for ruid in get_folder_record_uids(params, folder_uid):
        try:
            rec = load_pam_record(params, ruid)
            if not rec:
                continue
            title = getattr(rec, 'title', '') or ''
            rtype = getattr(rec, 'record_type', '') or ''
            login = ''
            fields = getattr(rec, 'fields', None)
            if isinstance(fields, list):
                field = next((x for x in fields if getattr(x, 'type', '') == 'login'), None)
                if field and hasattr(field, 'get_default_value'):
                    login = (field.get_default_value() or '') or ''
            result.append((ruid, title, rtype, login))
        except Exception:
            continue
    return result


def snapshot_nsf_folder_keys(params) -> dict:
    out = {}
    for uid, info in (getattr(params, 'nested_share_folders', None) or {}).items():
        key = info.get('folder_key_unencrypted') if isinstance(info, dict) else None
        if not key:
            continue
        out[uid] = {
            'name': info.get('name') or uid,
            'parent_uid': info.get('parent_uid'),
            'folder_key_unencrypted': key,
        }
    return out


def restore_nsf_folder_keys(params, snapshot: Optional[dict]) -> None:
    for uid, info in (snapshot or {}).items():
        seed_nsf_folder_cache(
            params,
            uid,
            info.get('name') or uid,
            info.get('parent_uid'),
            info.get('folder_key_unencrypted'),
        )


def sync_down_preserving_nsf_keys(params) -> None:
    preserved = snapshot_nsf_folder_keys(params)
    api.sync_down(params)
    restore_nsf_folder_keys(params, preserved)


def seed_nsf_folder_cache(params, folder_uid: str, name: str,
                          parent_uid: Optional[str] = None,
                          folder_key: Optional[bytes] = None) -> None:
    """Keep local NSF caches consistent right after folder creation.
    """
    if not folder_uid:
        return

    normalized_parent = parent_uid or None
    nsf = getattr(params, 'nested_share_folders', None)
    if nsf is None:
        params.nested_share_folders = {}
        nsf = params.nested_share_folders
    entry = dict(nsf.get(folder_uid) or {})
    entry['name'] = name
    entry['parent_uid'] = normalized_parent
    if folder_key:
        entry['folder_key_unencrypted'] = folder_key
    nsf[folder_uid] = entry

    subfolder_cache = getattr(params, 'subfolder_cache', None)
    if subfolder_cache is None:
        params.subfolder_cache = {}
        subfolder_cache = params.subfolder_cache
    sf_entry = dict(subfolder_cache.get(folder_uid) or {})
    sf_entry.update({
        'folder_uid': folder_uid,
        'type': 'user_folder',
        'name': name,
        'parent_uid': normalized_parent,
        'source': 'nested_share_folder',
    })
    if folder_key:
        sf_entry['folder_key_unencrypted'] = folder_key
    subfolder_cache[folder_uid] = sf_entry

    # Folder nodes used by find_folders / NSF project discovery.
    from ...subfolder import NestedShareFolderNode
    folder_cache = getattr(params, 'folder_cache', None)
    if isinstance(folder_cache, dict):
        node = folder_cache.get(folder_uid)
        if not isinstance(node, NestedShareFolderNode):
            node = NestedShareFolderNode()
            node.uid = folder_uid
            node.subfolders = []
            folder_cache[folder_uid] = node
        node.name = name
        node.parent_uid = normalized_parent
        if normalized_parent and normalized_parent in folder_cache:
            parent = folder_cache[normalized_parent]
            kids = getattr(parent, 'subfolders', None)
            if kids is None:
                parent.subfolders = [folder_uid]
            elif folder_uid not in kids:
                kids.append(folder_uid)

    env = getattr(params, 'environment_variables', None)
    if isinstance(env, dict):
        env['last_folder_uid'] = folder_uid


def create_nsf_subfolder(params, folder_name: str, parent_uid: str = '',
                         folder_uid: Optional[str] = None) -> str:
    """Create an NSF subfolder; returns folder UID."""
    from ...nested_share_folder.folder_api import _prepare_folder_for_creation, folder_add_v3
    from ..nested_share_folder.helpers import command_error_handler, check_result
    from ...proto import folder_pb2

    name = str(folder_name or '').strip()
    if not name:
        raise CommandError('pam project extend', 'NSF subfolder name is required')
    if not folder_uid:
        folder_uid = api.generate_record_uid()

    parent = parent_uid or None
    if parent:
        nsf_folders = getattr(params, 'nested_share_folders', None) or {}
        folder_cache = getattr(params, 'folder_cache', None) or {}
        if parent not in nsf_folders and parent not in folder_cache:
            raise CommandError('pam project extend', f'Parent folder "{parent_uid}" not found')

    with command_error_handler('pam project extend'):
        fd, folder_key = _prepare_folder_for_creation(
            params, folder_uid, name, parent, None, True,
        )
        response = folder_add_v3(params, [fd])
        if not response.folderAddResults:
            raise CommandError('pam project extend', 'No results from NSF folder creation')
        r = response.folderAddResults[0]
        check_result({
            'success': r.status == folder_pb2.SUCCESS,
            'message': r.message,
        }, 'pam project extend')

    seed_nsf_folder_cache(params, folder_uid, name, parent_uid, folder_key)
    return folder_uid


def extend_create_record(params, obj, folder_uid: str) -> Optional[str]:
    """Create a PAM import record in a classic or NSF folder."""
    return obj.create_record(params, folder_uid)
