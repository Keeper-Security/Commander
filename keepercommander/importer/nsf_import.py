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
"""Nested Share Folder helpers for the general vault import pipeline."""

from __future__ import annotations

import logging
import time
from typing import Dict, Iterable, List, Optional, Tuple

from .importer import (
    Folder as ImportFolder,
    PathDelimiter,
    Permission as ImportPermission,
    Record as ImportRecord,
    SharedFolder as ImportSharedFolder,
    path_components,
)
from .. import utils
from ..error import CommandError, KeeperApiError
from ..params import KeeperParams
from ..subfolder import BaseFolderNode


NSF_RECORD_BATCH = 1000
NSF_FOLDER_BATCH = 100
_THROTTLE_BASE_WAIT = 10.0
_THROTTLE_MULTIPLIER = 1.5
_THROTTLE_MAX_RETRIES = 5


def is_nsf_folder(params, folder_uid):  # type: (KeeperParams, Optional[str]) -> bool
    """Return True when *folder_uid* is a Nested Share Folder."""
    if not folder_uid:
        return False
    if folder_uid in (getattr(params, 'nested_share_folders', None) or {}):
        return True
    subfolder = (getattr(params, 'subfolder_cache', None) or {}).get(folder_uid) or {}
    if subfolder.get('source') == 'nested_share_folder':
        return True
    folder = (getattr(params, 'folder_cache', None) or {}).get(folder_uid)
    return bool(folder and getattr(folder, 'type', None) == BaseFolderNode.NestedShareFolderType)


def resolve_nsf_folder(params, identifier):  # type: (KeeperParams, Optional[str]) -> Optional[str]
    """Resolve a folder name, path, or UID to an NSF folder UID."""
    if not identifier:
        return None
    from ..nested_share_folder.folder_api import resolve_folder_identifier

    for candidate in (identifier, identifier.replace('\\', '/')):
        uid = resolve_folder_identifier(params, candidate)
        if uid and is_nsf_folder(params, uid):
            return uid
    return None


def classic_perms_to_nsf_role(manage_users=False, manage_records=False,
                              can_edit=False, can_share=False):
    """Map classic shared-folder booleans to an NSF role name."""
    if manage_users and manage_records:
        return 'full-manager'
    if manage_records and can_share:
        return 'content-share-manager'
    if manage_records or can_edit:
        return 'content-manager'
    if can_share:
        return 'share-manager'
    return 'viewer'


def flatten_record_folder_paths(records):  # type: (List[ImportRecord]) -> None
    """Collapse domain + path into a single NSF path on each record folder."""
    for record in records:
        if not record.folders:
            continue
        for folder in record.folders:
            comps = []
            if folder.domain:
                comps.extend(path_components(folder.domain))
            if folder.path:
                comps.extend(path_components(folder.path))
            folder.domain = ''
            folder.path = PathDelimiter.join(
                [c.replace(PathDelimiter, 2 * PathDelimiter) for c in comps]
            ) if comps else ''


def ensure_nsf_record_folders(records, folders, default_name=None):
    # type: (List[ImportRecord], List[ImportSharedFolder], Optional[str]) -> str
    """Create SharedFolder targets for record folder paths."""
    name = (default_name or '').strip()
    existing = {(fol.path or '').lower() for fol in folders or [] if fol.path}

    def _add_shared(path):
        key = (path or '').lower()
        if not path or key in existing:
            return
        sf = ImportSharedFolder()
        sf.path = path
        folders.append(sf)
        existing.add(key)

    for rec in records or []:
        if not rec.folders:
            if not name:
                continue
            rec.folders = [ImportFolder()]
        for fol in rec.folders:
            if not (fol.path or fol.domain):
                if not name:
                    continue
                fol.path = name
            _add_shared(fol.path or fol.domain)
    return name


def find_nsf_child(params, folder_name, parent_uid):
    # type: (KeeperParams, str, Optional[str]) -> Optional[str]
    """Find an NSF child named *folder_name* under *parent_uid* (or vault root)."""
    from ..commands.nested_share_folder.helpers import normalize_parent_uid

    nsf_folders = getattr(params, 'nested_share_folders', None) or {}
    name_lower = (folder_name or '').lower()
    looking_for_root = not parent_uid
    for fuid, fobj in nsf_folders.items():
        if (fobj.get('name') or '').lower() != name_lower:
            continue
        raw_parent = fobj.get('parent_uid') or ''
        normalized = normalize_parent_uid(raw_parent)
        is_root_child = (
            normalized in ('', 'root')
            or (raw_parent and raw_parent not in nsf_folders)
        )
        if looking_for_root:
            if is_root_child:
                return fuid
        elif raw_parent == parent_uid:
            return fuid
    return None


def _is_throttle_error(exc):  # type: (BaseException) -> bool
    if isinstance(exc, KeeperApiError) and str(getattr(exc, 'result_code', '')).lower() in (
            'throttled', '429', 'too_many_requests'):
        return True
    text = str(getattr(exc, 'message', None) or exc).lower()
    return 'throttl' in text or 'too many' in text or 'rate limit' in text


def _call_with_throttle_retry(description, fn, *args, **kwargs):
    """Retry *fn* with progressive backoff when the API returns throttled."""
    wait = _THROTTLE_BASE_WAIT
    for attempt in range(1, _THROTTLE_MAX_RETRIES + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if not _is_throttle_error(exc) or attempt >= _THROTTLE_MAX_RETRIES:
                raise
            logging.warning(
                '%s throttled (attempt %d/%d); waiting %.0fs before retry',
                description, attempt, _THROTTLE_MAX_RETRIES, wait,
            )
            time.sleep(wait)
            wait *= _THROTTLE_MULTIPLIER


def create_nsf_folder(params, name, parent_uid=''):
    # type: (KeeperParams, str, Optional[str]) -> str
    """Create one NSF folder and seed local caches. Returns folder UID."""
    results = create_nsf_folders_batch(params, [(name, parent_uid or '')])
    if not results:
        raise CommandError('import', f'Failed to create NSF folder "{name}"')
    return results[0]


def create_nsf_folders_batch(params, folders):
    # type: (KeeperParams, List[Tuple[str, str]]) -> List[str]
    """Create many NSF folders that share the same depth (parents already exist).

    *folders* is a list of ``(name, parent_uid)`` pairs. Returns UIDs in the
    same order. Uses ``vault/folders/v3/add`` batches of up to 100 with
    throttle retries.
    """
    from ..nested_share_folder.folder_api import create_folders_batch_v3
    from ..commands.pam_import.nsf_helpers import seed_nsf_folder_cache

    if not folders:
        return []

    created_uids = []  # type: List[str]
    for start in range(0, len(folders), NSF_FOLDER_BATCH):
        chunk = folders[start:start + NSF_FOLDER_BATCH]
        specs = [
            {
                'name': name,
                'parent_uid': parent_uid or None,
                'inherit_permissions': True,
            }
            for name, parent_uid in chunk
        ]
        results = _call_with_throttle_retry(
            'NSF folder create',
            create_folders_batch_v3,
            params,
            specs,
        )
        if len(results) != len(chunk):
            raise CommandError(
                'import',
                f'NSF folder batch returned {len(results)} results for {len(chunk)} folders',
            )
        for (name, parent_uid), result in zip(chunk, results):
            if not isinstance(result, dict) or result.get('success') is False:
                message = (result or {}).get('message') if isinstance(result, dict) else None
                raise CommandError(
                    'import',
                    message or f'Failed to create NSF folder "{name}"',
                )
            folder_uid = result['folder_uid']
            seed_nsf_folder_cache(
                params, folder_uid, name, parent_uid or None,
                result.get('folder_key_unencrypted'),
            )
            created_uids.append(folder_uid)
    return created_uids


def ensure_nsf_path(params, comps, parent_uid=''):
    # type: (KeeperParams, Iterable[str], Optional[str]) -> str
    """Ensure path components exist under *parent_uid*; return leaf folder UID."""
    current = parent_uid or ''
    for comp in comps:
        if not comp:
            continue
        existing = find_nsf_child(params, comp, current)
        if existing:
            current = existing
            continue
        current = create_nsf_folder(params, comp, current)
    return current


def _folder_comp_lists(folders, records):
    # type: (List[ImportSharedFolder], List[ImportRecord]) -> List[Tuple[object, List[str]]]
    """Return ``(target, component_list)`` pairs for every folder to resolve."""
    targets = []  # type: List[Tuple[object, List[str]]]
    for fol in folders or []:
        comps = [c for c in path_components(fol.path or '') if c]
        if comps:
            targets.append((fol, comps))
    for rec in records or []:
        if not rec.folders:
            continue
        for fol in rec.folders:
            comps = []
            if fol.domain:
                comps.extend(path_components(fol.domain))
            if fol.path:
                comps.extend(path_components(fol.path))
            comps = [c for c in comps if c]
            targets.append((fol, comps))
    return targets


def prepare_nsf_folders(params, folders, records, base_parent_uid=''):
    # type: (KeeperParams, List[ImportSharedFolder], List[ImportRecord], str) -> int
    """Create NSF folder trees for import shared folders and record folders.

    Builds the full tree first, then creates missing folders **by depth** in
    batches of up to 100 (``vault/folders/v3/add``), with throttle retries.
    Sets ``uid`` on each resolved ``ImportSharedFolder`` / ``ImportFolder``.
    Returns the number of folders created.
    """
    before = set((getattr(params, 'nested_share_folders', None) or {}).keys())
    targets = _folder_comp_lists(folders, records)

    # path_tuple -> folder_uid
    uid_by_path = {}  # type: Dict[Tuple[str, ...], str]
    if base_parent_uid:
        uid_by_path[()] = base_parent_uid

    # Resolve / create level by level so parent keys exist for children.
    max_depth = max((len(comps) for _, comps in targets), default=0)
    for depth in range(1, max_depth + 1):
        pending = []  # type: List[Tuple[Tuple[str, ...], str, str]]
        seen = set()  # type: set
        for _, comps in targets:
            if len(comps) < depth:
                continue
            path_tuple = tuple(comps[:depth])
            if path_tuple in uid_by_path or path_tuple in seen:
                continue
            parent_tuple = path_tuple[:-1]
            if parent_tuple not in uid_by_path and parent_tuple != ():
                # Parent should have been resolved at previous depth.
                continue
            parent_uid = uid_by_path.get(parent_tuple, base_parent_uid or '')
            name = path_tuple[-1]
            existing = find_nsf_child(params, name, parent_uid)
            if existing:
                uid_by_path[path_tuple] = existing
                continue
            seen.add(path_tuple)
            pending.append((path_tuple, name, parent_uid))

        if not pending:
            continue

        batch_input = [(name, parent_uid) for _, name, parent_uid in pending]
        created_uids = create_nsf_folders_batch(params, batch_input)
        for (path_tuple, _name, _parent_uid), folder_uid in zip(pending, created_uids):
            uid_by_path[path_tuple] = folder_uid

    # Assign leaf UIDs back onto import objects.
    for target, comps in targets:
        if not comps:
            if base_parent_uid:
                target.uid = base_parent_uid
            else:
                target.uid = ''
            continue
        path_tuple = tuple(comps)
        target.uid = uid_by_path.get(path_tuple, '')

    after = set((getattr(params, 'nested_share_folders', None) or {}).keys())
    created = len(after - before)
    if created:
        logging.info('Created %d Nested Share Folder(s)', created)
    return created


def build_nsf_record_add(params, import_record, record_key, data):
    """Build a ``vault/records/v3/add`` RecordAdd."""
    from ..nested_share_folder.common import get_folder_key
    from ..nested_share_folder.record_api import create_record_data_v3

    folder_uid = ''
    if import_record.folders:
        folder_uid = import_record.folders[0].uid or ''
    folder_key = None
    if folder_uid:
        if not is_nsf_folder(params, folder_uid):
            raise CommandError('import', f'NSF folder not found for record "{import_record.title}"')
        folder_key = get_folder_key(params, folder_uid, raise_on_missing=True)
    return create_record_data_v3(
        record_uid=import_record.uid,
        record_key=record_key,
        data=data,
        folder_uid=folder_uid or None,
        folder_key=folder_key,
        data_key=params.data_key,
        client_modified_time=utils.current_milli_time(),
    )


def execute_nsf_records_add(params, record_adds):
    # type: (KeeperParams, list) -> list
    """Submit NSF record adds in batches of up to 1000 with throttle retries."""
    from ..nested_share_folder.record_api import record_add_v3

    results = []
    for start in range(0, len(record_adds), NSF_RECORD_BATCH):
        batch = record_adds[start:start + NSF_RECORD_BATCH]
        try:
            rs = _call_with_throttle_retry(
                'NSF record add',
                record_add_v3,
                params,
                batch,
            )
            results.extend(list(rs.records))
        except Exception as exc:
            logging.warning('NSF record add batch failed: %s', exc)
            for ra in batch:
                uid = utils.base64_url_encode(ra.recordUid)
                logging.warning('Failed to create NSF record %s', uid)
    return results


def apply_nsf_folder_permissions(params, folders, manage_users=False, manage_records=False,
                                 can_edit=False, can_share=False):
    # type: (KeeperParams, List[ImportSharedFolder], bool, bool, bool, bool) -> None
    """Grant NSF folder access from ImportSharedFolder.permissions.

    Each permission may specify an NSF ``role`` (viewer, content-manager,
    full-manager, …). When ``role`` is absent, classic manage_users /
    manage_records flags are mapped via ``classic_perms_to_nsf_role``.
    """
    from ..nested_share_folder.folder_api import grant_folder_access_v3
    from ..nested_share_folder.permissions import resolve_role_name

    default_role = classic_perms_to_nsf_role(
        manage_users, manage_records, can_edit, can_share)

    granted = 0
    for fol in folders or []:
        if not fol.uid or not is_nsf_folder(params, fol.uid):
            if not fol.uid and fol.path:
                comps = list(path_components(fol.path))
                parent = ''
                for comp in comps:
                    parent = find_nsf_child(params, comp, parent) or ''
                    if not parent:
                        break
                fol.uid = parent
            if not fol.uid or not is_nsf_folder(params, fol.uid):
                continue

        folder_role = classic_perms_to_nsf_role(
            fol.manage_users if fol.manage_users is not None else manage_users,
            fol.manage_records if fol.manage_records is not None else manage_records,
            fol.can_edit if fol.can_edit is not None else can_edit,
            fol.can_share if fol.can_share is not None else can_share,
        )

        for perm in fol.permissions or []:  # type: ImportPermission
            explicit_role = (getattr(perm, 'role', None) or '').strip()
            if explicit_role:
                try:
                    resolve_role_name(explicit_role)
                except ValueError as exc:
                    logging.warning(
                        'NSF permission for "%s" on "%s": %s',
                        perm.name or perm.uid, fol.path or fol.uid, exc)
                    continue
                role = explicit_role.strip().lower().replace('_', '-')
                if role == 'shared-manager':
                    role = 'share-manager'
                elif role == 'contributor':
                    role = 'requestor'
            else:
                role = classic_perms_to_nsf_role(
                    perm.manage_users if perm.manage_users is not None else False,
                    perm.manage_records if perm.manage_records is not None else False,
                )
                if role == 'viewer' and (manage_users or manage_records or can_edit or can_share):
                    role = folder_role if folder_role != 'viewer' else default_role

            name = perm.name or ''
            uid = perm.uid or ''
            recipient = name or uid
            if not recipient:
                continue
            if uid and '@' not in uid and (not name or '@' not in name):
                as_team = True
                recipient = uid
            elif name and '@' in name:
                as_team = False
                recipient = name
            elif name:
                as_team = False
                recipient = name
            else:
                as_team = False

            try:
                result = _call_with_throttle_retry(
                    'NSF folder permission',
                    grant_folder_access_v3,
                    params, fol.uid, recipient, role=role, as_team=as_team,
                )
                if result.get('success'):
                    granted += 1
                else:
                    logging.warning(
                        'NSF permission for "%s" on "%s": %s',
                        recipient, fol.path or fol.uid, result.get('message'))
            except Exception as exc:
                logging.warning(
                    'NSF permission for "%s" on "%s" failed: %s',
                    recipient, fol.path or fol.uid, exc)

    if granted:
        logging.info('Granted %d Nested Share Folder permission(s)', granted)
