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
from ...nested_share_folder.common import NSF_FOLDER_BATCH_SIZE
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


def get_record_summary(params, record_uid: str) -> Optional[tuple]:
    """Return (uid, title, record_type, login) for *record_uid*, or None when the record cannot be loaded."""
    try:
        rec = load_pam_record(params, record_uid)
        if not rec:
            return None
        title = getattr(rec, 'title', '') or ''
        rtype = getattr(rec, 'record_type', '') or ''
        login = ''
        fields = getattr(rec, 'fields', None)
        if isinstance(fields, list):
            field = next((x for x in fields if getattr(x, 'type', '') == 'login'), None)
            if field and hasattr(field, 'get_default_value'):
                login = (field.get_default_value() or '') or ''
        return (record_uid, title, rtype, login)
    except Exception:
        return None


def get_records_in_folder(params, folder_uid: str) -> list:
    """Return (uid, title, record_type, login) tuples for records in *folder_uid*."""
    result = []
    for ruid in get_folder_record_uids(params, folder_uid):
        summary = get_record_summary(params, ruid)
        if summary:
            result.append(summary)
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


def fetch_file_record_infos(params, file_uids) -> dict:
    """Name / size / mime type / time of file records the local caches do not hold.

    Found on QA 2026-11-19 (``resend_test/probe_file_records.py``): the files of a record in a Nested Share Folder are
    linked to it (the Web Vault shows them) but the sync does not deliver them to Commander - they are in no cache.
    ``vault/records/v3/details/data`` hands them out by uid (version 4 records; the key is encrypted with the data key,
    the data holds ``name``, ``size``, ``title``, ``type``, ``lastModified``). One request for all uids. Returns
    ``{uid: info}`` in the shape of ``record_state.file_record_info``; a uid the server does not give (or that cannot be
    decrypted) is simply absent, and a failing request returns ``{}`` - the caller then reports the file as unreadable.
    """
    import json
    from ... import crypto, utils
    from ...nested_share_folder.record_api import _try_decrypt_record_key
    from ...proto import record_details_pb2

    uids = [u for u in dict.fromkeys(file_uids or []) if u]
    if not uids:
        return {}
    rq = record_details_pb2.RecordDataRequest()
    for uid in uids:
        rq.recordUids.append(utils.base64_url_decode(uid))
    rq.clientTime = utils.current_milli_time()
    try:
        rs = api.communicate_rest(params, rq, 'vault/records/v3/details/data', rs_type=record_details_pb2.RecordDataResponse)
    except Exception as e:      # pylint: disable=broad-except
        logging.debug('file record fetch failed: %s', e)
        return {}
    out = {}
    for rd in rs.data:
        uid = utils.base64_url_encode(rd.recordUid)
        try:
            key = _try_decrypt_record_key(params, rd.recordKey, rd.recordKeyType, uid)
            enc = rd.encryptedRecordData
            enc = utils.base64_url_decode(enc) if isinstance(enc, str) else enc
            if not (key and enc):
                continue
            data = json.loads(crypto.decrypt_aes_v2(enc, key).decode().rstrip(' '))
        except Exception as e:      # pylint: disable=broad-except
            logging.debug('file record %s could not be decrypted: %s', uid, e)
            continue
        out[uid] = {'record_uid': uid, 'name': data.get('name') or data.get('title') or '', 'size': data.get('size'),
                    'mime_type': data.get('type') or '', 'last_modified': data.get('lastModified')}
    return out


def stale_nsf_records(params, record_uids) -> List[str]:
    """UIDs of the records whose local DATA is older than what the server has.

    Found on QA 2026-11-19 (``resend_test/probe_nsf_read.py --write``): after a ``records/v3/update`` an INCREMENTAL
    sync moves the revision in ``nested_share_records`` (here 6274004) and drops the NSF data copy
    (``nested_share_record_data[uid]['data_json']``), but the classic ``record_cache`` copy keeps the OLD data and the
    OLD revision (6273968), and ``load_pam_record`` then returns the old data. Only a full sync (revision 0, no token)
    brings the new data. Such a record must not be read for a comparison, nor be the base of an update.
    """
    nsf_records = getattr(params, 'nested_share_records', None) or {}
    nsf_data = getattr(params, 'nested_share_record_data', None) or {}
    classic = getattr(params, 'record_cache', None) or {}
    stale = []
    for uid in record_uids:
        nsf = nsf_records.get(uid)
        if not nsf:
            continue                                  # a classic record: the normal sync is enough
        nsf_rev = int(nsf.get('revision') or 0)
        copy = classic.get(uid)
        if copy is not None:
            if int(copy.get('revision') or 0) < nsf_rev:
                stale.append(uid)
        elif not (nsf_data.get(uid) or {}).get('data_json'):
            stale.append(uid)                         # known to the NSF cache but no data at all
    return stale


def refresh_stale_nsf_records(params, record_uids) -> int:
    """Full sync when ``stale_nsf_records`` finds any; returns how many records were stale (0 = no sync was made)."""
    stale = stale_nsf_records(params, record_uids)
    if stale:
        logging.debug('%d NSF record(s) have stale local data (first: %s): full sync', len(stale), stale[0])
        params.revision = 0
        params.sync_down_token = b''
        sync_down_preserving_nsf_keys(params)
    return len(stale)


def nsf_record_can_edit(params, record_uid: str) -> Optional[bool]:
    """Can the current user edit this Nested Share Folder record? ``None`` = not known.

    Reads the access rows that sync stores in ``params.nested_share_record_accesses`` (the current user's rows, direct
    or inherited): an OWNER row or a row with ``can_edit`` grants, a row that is ``denied_access`` does not. ``True``
    when any of the user's rows grants, ``False`` when the user has rows and none grants (a viewer, for example).
    ``None`` for a record that is not an NSF record, for a record without access rows (a partial first sync) and for
    rows that cannot be matched to the user: the server stays the source of truth there and rejects the write, which
    is better than a wrong refusal in the plan.
    """
    if record_uid not in (getattr(params, 'nested_share_records', None) or {}):
        return None
    accesses = (getattr(params, 'nested_share_record_accesses', None) or {}).get(record_uid) or []
    if not accesses:
        return None
    from ..nested_share_folder.helpers import _current_user_account_uid, _is_current_user_access
    me = _current_user_account_uid(params)
    mine = [a for a in accesses if _is_current_user_access(a, params, me)]
    if not mine:
        return None
    return any((a.get('owner') or a.get('can_edit')) and not a.get('denied_access') for a in mine)


def collect_nsf_subtree_uids(params, root_uid: str) -> List[str]:
    """Return *root_uid* plus every NSF folder nested underneath it.

    Breadth-first so parents are granted before their children; dedup'd and
    cycle-safe.
    """
    root_uid = (root_uid or '').strip()
    if not root_uid:
        return []

    children = {}
    for folder_uid, info in (getattr(params, 'nested_share_folders', None) or {}).items():
        parent_uid = (info.get('parent_uid') if isinstance(info, dict) else None) or ''
        if parent_uid:
            children.setdefault(parent_uid, []).append(folder_uid)

    ordered = [root_uid]
    seen = {root_uid}
    queue = [root_uid]
    while queue:
        current = queue.pop(0)
        for child_uid in children.get(current, []):
            if child_uid in seen:
                continue
            seen.add(child_uid)
            ordered.append(child_uid)
            queue.append(child_uid)
    return ordered


def grant_nsf_folders_to_ksm_app(params, app_uid: str, folder_uids, editable: bool = True) -> List[str]:
    """Register NSF folders on a KSM application.

    KSM and the Gateway only see records in folders carrying a direct
    ``AT_APPLICATION`` grant - unlike classic shared-folder children, NSF
    children have their own folder key and inherit nothing from the parent.

    One batched ``secret add`` is attempted first; on failure the UIDs are
    retried one at a time so a single unshareable folder does not lose the
    rest. Returns the UIDs that were granted.
    """
    from ..ksm import KSMCommand

    app_uid = (app_uid or '').strip()
    if not app_uid:
        return []

    uids: List[str] = []
    seen = set()
    for folder_uid in folder_uids or []:
        folder_uid = (folder_uid or '').strip()
        if not folder_uid or folder_uid in seen:
            continue
        seen.add(folder_uid)
        uids.append(folder_uid)
    if not uids:
        return []

    # add_app_share ends in a sync_down that drops the NSF folder keys, so
    # restore them before every call - not just once at the end.
    preserved = snapshot_nsf_folder_keys(params)
    try:
        try:
            KSMCommand().execute(params, command=('secret', 'add'), app=app_uid,
                                 secret=list(uids), editable=editable)
            return uids
        except Exception as exc:
            if len(uids) == 1:
                logging.warning('Could not register folder %s on KSM application %s: %s',
                                uids[0], app_uid, exc)
                return []
            logging.debug('Batch KSM share of %d folders failed (%s) - retrying one at a time',
                          len(uids), exc)

        granted: List[str] = []
        for folder_uid in uids:
            restore_nsf_folder_keys(params, preserved)
            try:
                KSMCommand().execute(params, command=('secret', 'add'), app=app_uid,
                                     secret=[folder_uid], editable=editable)
                granted.append(folder_uid)
            except Exception as exc:
                logging.warning('Could not register folder %s on KSM application %s: %s',
                                folder_uid, app_uid, exc)
        return granted
    finally:
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


def create_nsf_folders_batch(params, folder_specs: List[dict], *,
                             sync: bool = True,
                             command: str = 'pam') -> List[dict]:
    """Create NSF folders via ``vault/folders/v3/add`` in chunks of 100.

    Each *folder_specs* entry is ``{'name': str, 'parent_uid': str|None}``.
    Returns the batch API result list (same order as *folder_specs*).
    Seeds local NSF caches after each successful create; optionally syncs once
    at the end so callers avoid one round-trip per folder.
    """
    from ...nested_share_folder.folder_api import create_folders_batch_v3

    if not folder_specs:
        return []

    results: List[dict] = []
    for start in range(0, len(folder_specs), NSF_FOLDER_BATCH_SIZE):
        chunk = folder_specs[start:start + NSF_FOLDER_BATCH_SIZE]
        try:
            chunk_results = create_folders_batch_v3(params, chunk)
        except Exception as exc:
            raise CommandError(command, f'NSF folder batch create failed: {exc}') from exc

        if len(chunk_results) != len(chunk):
            raise CommandError(
                command,
                f'NSF folder batch returned {len(chunk_results)} results for {len(chunk)} folders',
            )

        for spec, result in zip(chunk, chunk_results):
            if not result.get('success'):
                name = spec.get('name') or '?'
                raise CommandError(
                    command,
                    result.get('message') or f'Failed to create Nested Share Folder: {name}',
                )
            folder_uid = result.get('folder_uid')
            if not folder_uid:
                raise CommandError(
                    command,
                    f"Nested Share Folder creation did not return UID: {spec.get('name')}",
                )
            seed_nsf_folder_cache(
                params,
                folder_uid,
                spec.get('name') or '',
                spec.get('parent_uid') or None,
                result.get('folder_key_unencrypted'),
            )
            results.append(result)

    if sync:
        sync_down_preserving_nsf_keys(params)
    return results


def extend_create_record(params, obj, folder_uid: str) -> Optional[str]:
    """Create a PAM import record in a classic or NSF folder."""
    return obj.create_record(params, folder_uid)
