import json
import logging
from typing import List, Dict

import google

from .. import utils, crypto
from ..params import RecordOwner
from ..proto import folder_pb2, record_pb2


def _ensure_nested_share_folder_attrs(params):
    """Ensure Nested Share Folder caches exist on params, even for older sessions."""
    if params is None:
        return
    if not hasattr(params, 'nested_share_folders'):
        params.nested_share_folders = {}
    if not hasattr(params, 'nested_share_folder_keys'):
        params.nested_share_folder_keys = {}
    if not hasattr(params, 'nested_share_folder_accesses'):
        params.nested_share_folder_accesses = {}
    if not hasattr(params, 'nested_share_records'):
        params.nested_share_records = {}
    if not hasattr(params, 'nested_share_record_data'):
        params.nested_share_record_data = {}
    if not hasattr(params, 'nested_share_record_keys'):
        params.nested_share_record_keys = {}
    if not hasattr(params, 'nested_share_record_accesses'):
        params.nested_share_record_accesses = {}
    if not hasattr(params, 'nested_share_folder_records'):
        params.nested_share_folder_records = {}
    if not hasattr(params, 'nested_share_folder_sharing_states'):
        params.nested_share_folder_sharing_states = {}
    if not hasattr(params, 'nested_share_record_sharing_states'):
        params.nested_share_record_sharing_states = {}
    if not hasattr(params, 'nested_share_record_links'):
        params.nested_share_record_links = {}
    if not hasattr(params, 'nested_share_raw_dag_data'):
        params.nested_share_raw_dag_data = []


def create_accumulator():
    return {
        'folders': [],
        'folder_keys': [],
        'folder_accesses': [],
        'revoked_folder_accesses': [],
        'denied_folder_accesses': [],
        'record_data': [],
        'record_keys': [],
        'record_accesses': [],
        'revoked_record_accesses': [],
        'records': [],
        'folder_records': [],
        'removed_folders': [],
        'removed_folder_records': [],
        'users': [],
        'folder_sharing_states': [],
        'record_sharing_states': [],
        'record_links': [],
        'removed_record_links': [],
        'record_rotations': [],
        'raw_dag_data': [],
    }


def clear_caches(params):
    _ensure_nested_share_folder_attrs(params)
    params.nested_share_folders.clear()
    params.nested_share_folder_keys.clear()
    params.nested_share_folder_accesses.clear()
    params.nested_share_records.clear()
    params.nested_share_record_data.clear()
    params.nested_share_record_keys.clear()
    params.nested_share_record_accesses.clear()
    params.nested_share_folder_records.clear()
    params.nested_share_folder_sharing_states.clear()
    params.nested_share_record_sharing_states.clear()
    params.nested_share_record_links.clear()
    params.nested_share_raw_dag_data.clear()
    # nested_share_folder_trashed_folders is intentionally NOT cleared here.
    # The server keeps sending trashed folders in every sync_down response
    # (including full/CLEAR syncs), so the trashed-UID filter must survive
    # cache clears. The set is persisted to disk and reloaded on session start.


def collect_from_response(acc, response, resp_bw_recs, resp_sec_data_recs, resp_sec_scores, record_rotation_items):
    if not response.HasField('keeperDriveData'):
        return
    nsf_data = response.keeperDriveData
    if len(nsf_data.folders) > 0:
        acc['folders'].extend(nsf_data.folders)
    if len(nsf_data.folderKeys) > 0:
        acc['folder_keys'].extend(nsf_data.folderKeys)
    if len(nsf_data.folderAccesses) > 0:
        acc['folder_accesses'].extend(nsf_data.folderAccesses)
    if len(nsf_data.revokedFolderAccesses) > 0:
        acc['revoked_folder_accesses'].extend(nsf_data.revokedFolderAccesses)
    dfa_attr = getattr(nsf_data, 'deniedFolderAccesses', None)
    if dfa_attr:
        acc['denied_folder_accesses'].extend(dfa_attr)
    if len(nsf_data.recordData) > 0:
        acc['record_data'].extend(nsf_data.recordData)
    # recordKeys does not exist as a top-level field in Nested Share FolderData;
    # record keys are embedded in folderRecords[].recordMetadata.encryptedRecordKey
    # and are extracted during _process_nested_share_folder_sync. Use getattr defensively
    # so that if the field is ever added to the proto it is collected automatically.
    rk_attr = getattr(nsf_data, 'recordKeys', None)
    if rk_attr:
        acc['record_keys'].extend(rk_attr)
    if len(nsf_data.recordAccesses) > 0:
        acc['record_accesses'].extend(nsf_data.recordAccesses)
    if len(nsf_data.revokedRecordAccesses) > 0:
        acc['revoked_record_accesses'].extend(nsf_data.revokedRecordAccesses)
    if len(nsf_data.records) > 0:
        acc['records'].extend(nsf_data.records)
    if len(nsf_data.folderRecords) > 0:
        acc['folder_records'].extend(nsf_data.folderRecords)
    if len(nsf_data.removedFolders) > 0:
        acc['removed_folders'].extend(nsf_data.removedFolders)
    if len(nsf_data.removedFolderRecords) > 0:
        acc['removed_folder_records'].extend(nsf_data.removedFolderRecords)

    users_attr = getattr(nsf_data, 'users', None)
    if users_attr:
        acc['users'].extend(users_attr)
    fss_attr = getattr(nsf_data, 'folderSharingState', None)
    if fss_attr:
        acc['folder_sharing_states'].extend(fss_attr)
    rss_attr = getattr(nsf_data, 'recordSharingStates', None)
    if rss_attr:
        acc['record_sharing_states'].extend(rss_attr)
    rl_attr = getattr(nsf_data, 'recordLinks', None)
    if rl_attr:
        acc['record_links'].extend(rl_attr)
    rrl_attr = getattr(nsf_data, 'removedRecordLinks', None)
    if rrl_attr:
        acc['removed_record_links'].extend(rrl_attr)
    rrd_attr = getattr(nsf_data, 'recordRotationData', None)
    if rrd_attr:
        acc['record_rotations'].extend(rrd_attr)
    dag_attr = getattr(nsf_data, 'rawDagData', None)
    if dag_attr:
        acc['raw_dag_data'].extend(dag_attr)
    bw_attr = getattr(nsf_data, 'breachWatchRecords', None)
    if bw_attr:
        resp_bw_recs.extend(bw_attr)
    bws_attr = getattr(nsf_data, 'breachWatchSecurityData', None)
    if bws_attr:
        resp_sec_data_recs.extend(bws_attr)
    ssd_attr = getattr(nsf_data, 'securityScoreData', None)
    if ssd_attr:
        resp_sec_scores.extend(ssd_attr)
    if acc['record_rotations']:
        record_rotation_items.extend(acc['record_rotations'])


def has_data(acc):
    return any(len(v) > 0 for v in acc.values())


def process(params, acc):
    if not has_data(acc):
        return
    _ensure_nested_share_folder_attrs(params)

    _process_nested_share_folder_sync(params, acc)


def _process_nested_share_folder_sync(params, acc):
    """Process Nested Share Folder atomic sync objects and store in caches.
    """
    folders = acc.get('folders') or []
    folder_keys = acc.get('folder_keys') or []
    folder_accesses = acc.get('folder_accesses') or []
    revoked_folder_accesses = acc.get('revoked_folder_accesses') or []
    denied_folder_accesses = acc.get('denied_folder_accesses') or []
    records = acc.get('records') or []
    record_data_list = acc.get('record_data') or []
    record_keys = acc.get('record_keys') or []
    record_accesses = acc.get('record_accesses') or []
    revoked_record_accesses = acc.get('revoked_record_accesses') or []
    folder_records = acc.get('folder_records') or []
    removed_folders = acc.get('removed_folders') or []
    removed_folder_records = acc.get('removed_folder_records') or []
    users = acc.get('users') or []
    folder_sharing_states = acc.get('folder_sharing_states') or []
    record_sharing_states = acc.get('record_sharing_states') or []
    record_links = acc.get('record_links') or []
    removed_record_links = acc.get('removed_record_links') or []
    raw_dag_data = acc.get('raw_dag_data') or []

    _process_users(params, users)
    _process_folders(params, folders)
    _process_folder_keys(params, folder_keys)
    _process_folder_accesses(params, folder_accesses)
    _process_revoked_folder_accesses(params, revoked_folder_accesses)
    _process_denied_folder_accesses(params, denied_folder_accesses)
    _process_folder_sharing_states(params, folder_sharing_states)

    _process_records(params, records)
    _process_record_data(params, record_data_list)
    _process_record_keys(params, record_keys)
    _process_record_accesses(params, record_accesses)
    _process_revoked_record_accesses(params, revoked_record_accesses)
    _process_record_sharing_states(params, record_sharing_states)

    _process_record_links(params, record_links)
    _process_removed_record_links(params, removed_record_links)

    _process_folder_records(params, folder_records)
    _process_removed_folder_records(params, removed_folder_records)

    _process_removed_folders(params, removed_folders)
    _purge_orphaned_records(params)
    _process_raw_dag_data(params, raw_dag_data)

    _decrypt_nested_share_folder_keys(params)
    _reconstruct_nested_share_folder_entities(params)



def _process_users(params, users):
    """Populate ``params.user_cache`` from Nested Share Folder ``Users`` records."""
    for user in users:
        account_uid = utils.base64_url_encode(user.accountUid)
        params.user_cache[account_uid] = user.username


def _process_folders(params, folders):
    """Store base folder objects (encrypted; keys/data decrypted later)."""
    for folder_data in folders:
        folder_uid = utils.base64_url_encode(folder_data.folderUid)
        folder_obj = {
            'folder_uid': folder_uid,
            'folder_type': folder_data.type if folder_data.type else 0,
            'parent_uid': utils.base64_url_encode(folder_data.parentUid) if folder_data.parentUid else None,
            'data': folder_data.data,
            'inherit_user_permissions': folder_data.inheritUserPermissions if folder_data.inheritUserPermissions else 0,
        }
        if folder_data.folderKey:
            folder_obj['folder_key'] = folder_data.folderKey
        if folder_data.dateCreated:
            folder_obj['date_created'] = folder_data.dateCreated
        if folder_data.lastModified:
            folder_obj['last_modified'] = folder_data.lastModified
        if folder_data.HasField('ownerInfo'):
            folder_obj['owner_account_uid'] = utils.base64_url_encode(folder_data.ownerInfo.accountUid)
            folder_obj['owner_username'] = folder_data.ownerInfo.username
        params.nested_share_folders[folder_uid] = folder_obj


def _process_folder_keys(params, folder_keys):
    """Store encrypted folder keys grouped by folder UID."""
    for fk in folder_keys:
        folder_uid = utils.base64_url_encode(fk.folderUid)
        if folder_uid not in params.nested_share_folder_keys:
            params.nested_share_folder_keys[folder_uid] = []
        params.nested_share_folder_keys[folder_uid].append({
            'folder_uid': folder_uid,
            'parent_uid': utils.base64_url_encode(fk.parentUid) if fk.parentUid else None,
            'encrypted_key': fk.folderKey,
            'key_type': fk.encryptedBy,
        })


def _process_folder_accesses(params, folder_accesses):
    """Store folder access entries grouped by folder UID."""
    for fa in folder_accesses:
        folder_uid = utils.base64_url_encode(fa.folderUid)
        if folder_uid not in params.nested_share_folder_accesses:
            params.nested_share_folder_accesses[folder_uid] = []
        access_uid = utils.base64_url_encode(fa.accessTypeUid)
        username = params.user_cache.get(access_uid) if hasattr(params, 'user_cache') else None
        fa_obj = {
            'folder_uid': folder_uid,
            'access_type_uid': access_uid,
            'access_type': fa.accessType,
            'access_role_type': fa.accessRoleType if fa.accessRoleType else 0,
            'inherited': fa.inherited if fa.inherited else False,
            'hidden': fa.hidden if fa.hidden else False,
            'date_created': fa.dateCreated if fa.dateCreated else 0,
            'last_modified': fa.lastModified if fa.lastModified else 0,
        }
        if username:
            fa_obj['username'] = username
        if fa.HasField('folderKey'):
            fa_obj['folder_key'] = {
                'encrypted_key': fa.folderKey.encryptedKey,
                'encrypted_key_type': fa.folderKey.encryptedKeyType,
            }
        if fa.HasField('tlaProperties'):
            fa_obj['tla_properties'] = google.protobuf.json_format.MessageToDict(
                fa.tlaProperties, preserving_proto_field_name=True
            )
        if fa.HasField('permissions'):
            p = fa.permissions
            fa_obj['permissions'] = {
                'can_add':              p.canAdd,
                'can_remove':           p.canRemove,
                'can_delete':           p.canDelete,
                'can_list_access':      p.canListAccess,
                'can_update_access':    p.canUpdateAccess,
                'can_change_ownership': p.canChangeOwnership,
                'can_edit_records':     p.canEditRecords,
                'can_view_records':     p.canViewRecords,
                'can_approve_access':   p.canApproveAccess,
                'can_request_access':   p.canRequestAccess,
                'can_update_setting':   p.canUpdateSetting,
                'can_list_records':     p.canListRecords,
                'can_list_folders':     p.canListFolders,
            }
        params.nested_share_folder_accesses[folder_uid].append(fa_obj)


def _process_folder_sharing_states(params, folder_sharing_states):
    """Store the per-folder sharing state from sync-down.

    Each ``FolderSharingState`` carries ``shared`` (bool) and ``count``
    (number of accessors aside from the current user). This is the only
    reliable signal in the sync response that tells us whether a folder
    the current user owns has been shared with someone else, because the
    ``folderAccesses`` list only contains the current user's own entry.
    """
    for fss in folder_sharing_states:
        try:
            folder_uid = utils.base64_url_encode(fss.folderUid)
        except Exception:
            continue
        params.nested_share_folder_sharing_states[folder_uid] = {
            'shared': bool(fss.shared),
            'count': int(fss.count) if fss.count else 0,
        }


def _process_revoked_folder_accesses(params, revoked_folder_accesses):
    """Drop folder access entries that the server explicitly revoked."""
    for rfa in revoked_folder_accesses:
        folder_uid = utils.base64_url_encode(rfa.folderUid)
        actor_uid = utils.base64_url_encode(rfa.actorUid)
        if folder_uid in params.nested_share_folder_accesses:
            params.nested_share_folder_accesses[folder_uid] = [
                fa for fa in params.nested_share_folder_accesses[folder_uid]
                if fa['access_type_uid'] != actor_uid
            ]


def _process_denied_folder_accesses(params, denied_folder_accesses):
    """Treat denied folder accesses as inaccessible: clear access + cached key."""
    for dfa in denied_folder_accesses:
        try:
            folder_uid = utils.base64_url_encode(dfa.folderUid)
            actor_uid = utils.base64_url_encode(dfa.actorUid)
            if folder_uid in params.nested_share_folder_accesses:
                params.nested_share_folder_accesses[folder_uid] = [
                    fa for fa in params.nested_share_folder_accesses[folder_uid]
                    if fa['access_type_uid'] != actor_uid
                ]
            if folder_uid in params.nested_share_folders:
                folder_obj = params.nested_share_folders[folder_uid]
                folder_obj.pop('folder_key_unencrypted', None)
                folder_obj['denied'] = True
                logging.debug('Folder %s access denied for actor %s', folder_uid, actor_uid)
        except Exception as e:
            logging.debug('Failed to process denied folder access: %s', e)


def _process_records(params, records):
    """Store DriveRecord metadata (no encrypted content)."""
    for record in records:
        record_uid = utils.base64_url_encode(record.recordUid)
        record_obj = {
            'record_uid': record_uid,
            'revision': record.revision,
            'version': record.version,
            'shared': record.shared if record.shared else False,
            'client_modified_time': record.clientModifiedTime if record.clientModifiedTime else 0,
        }
        if record.fileSize:
            record_obj['file_size'] = record.fileSize
        if record.thumbnailSize:
            record_obj['thumbnail_size'] = record.thumbnailSize
        params.nested_share_records[record_uid] = record_obj


def _process_record_data(params, record_data_list):
    """Store record data blobs (decrypted later in ``_decrypt_*``)."""
    for rd in record_data_list:
        record_uid = utils.base64_url_encode(rd.recordUid)
        rd_obj = {
            'record_uid': record_uid,
            'data': rd.data,
        }
        if rd.HasField('user'):
            rd_obj['user_account_uid'] = utils.base64_url_encode(rd.user.accountUid)
            rd_obj['user_username'] = rd.user.username
        params.nested_share_record_data[record_uid] = rd_obj


def _process_record_keys(params, record_keys):
    """Store standalone encrypted record keys grouped by record UID."""
    for rk in record_keys:
        record_uid = utils.base64_url_encode(rk.record_uid)
        if record_uid not in params.nested_share_record_keys:
            params.nested_share_record_keys[record_uid] = []
        params.nested_share_record_keys[record_uid].append({
            'record_uid': record_uid,
            'user_uid': utils.base64_url_encode(rk.user_uid),
            'record_key': rk.record_key,
            'encrypted_key_type': rk.encrypted_key_type,
        })


def _process_record_accesses(params, record_accesses):
    """Store record access entries grouped by record UID."""
    for ra in record_accesses:
        record_uid = utils.base64_url_encode(ra.recordUid)
        if record_uid not in params.nested_share_record_accesses:
            params.nested_share_record_accesses[record_uid] = []
        access_uid = utils.base64_url_encode(ra.accessTypeUid)
        username = params.user_cache.get(access_uid) if hasattr(params, 'user_cache') else None
        ra_obj = {
            'record_uid': record_uid,
            'access_uid': access_uid,
            'access_type': ra.accessType,
            'access_role_type': ra.accessRoleType,
            'owner': ra.owner if hasattr(ra, 'owner') else False,
            'inherited': ra.inherited if hasattr(ra, 'inherited') else False,
            'hidden': ra.hidden if hasattr(ra, 'hidden') else False,
            'denied_access': ra.deniedAccess if hasattr(ra, 'deniedAccess') else False,
            'can_view_title': ra.can_view_title if hasattr(ra, 'can_view_title') and ra.can_view_title else False,
            'can_edit': ra.can_edit if hasattr(ra, 'can_edit') and ra.can_edit else False,
            'can_view': ra.can_view if hasattr(ra, 'can_view') and ra.can_view else False,
            'can_list_access': ra.can_list_access if hasattr(ra, 'can_list_access') and ra.can_list_access else False,
            'can_update_access': ra.can_update_access if hasattr(ra, 'can_update_access') and ra.can_update_access else False,
            'can_delete': ra.can_delete if hasattr(ra, 'can_delete') and ra.can_delete else False,
            'can_change_ownership': ra.can_change_ownership if hasattr(ra, 'can_change_ownership') and ra.can_change_ownership else False,
            'can_request_access': ra.can_request_access if hasattr(ra, 'can_request_access') and ra.can_request_access else False,
            'can_approve_access': ra.can_approve_access if hasattr(ra, 'can_approve_access') and ra.can_approve_access else False,
            'date_created': ra.dateCreated if hasattr(ra, 'dateCreated') else 0,
            'last_modified': ra.lastModified if hasattr(ra, 'lastModified') else 0,
        }
        if username:
            ra_obj['username'] = username
        if hasattr(ra, 'tlaProperties') and ra.HasField('tlaProperties'):
            ra_obj['tla_properties'] = google.protobuf.json_format.MessageToDict(
                ra.tlaProperties, preserving_proto_field_name=True
            )
        params.nested_share_record_accesses[record_uid].append(ra_obj)


def _process_revoked_record_accesses(params, revoked_record_accesses):
    """Drop record access entries that the server explicitly revoked."""
    for rra in revoked_record_accesses:
        record_uid = utils.base64_url_encode(rra.recordUid)
        actor_uid = utils.base64_url_encode(rra.actorUid)
        if record_uid in params.nested_share_record_accesses:
            params.nested_share_record_accesses[record_uid] = [
                ra for ra in params.nested_share_record_accesses[record_uid]
                if ra['access_uid'] != actor_uid
            ]


def _process_record_sharing_states(params, record_sharing_states):
    """Update each record's effective ``shared`` flag from sharing state."""
    for rss in record_sharing_states:
        record_uid = utils.base64_url_encode(rss.recordUid)
        state_obj = {
            'record_uid': record_uid,
            'is_directly_shared': rss.isDirectlyShared,
            'is_indirectly_shared': rss.isIndirectlyShared,
            'is_shared': rss.isShared,
        }
        params.nested_share_record_sharing_states[record_uid] = state_obj
        if record_uid in params.nested_share_records:
            record_obj = params.nested_share_records[record_uid]
            record_obj['shared'] = record_obj.get('shared', False) or state_obj['is_shared']


def _process_record_links(params, record_links):
    """Store parent/child record link relationships and surface their keys."""
    for rl in record_links:
        child_uid = utils.base64_url_encode(rl.childRecordUid) if rl.childRecordUid else None
        parent_uid = utils.base64_url_encode(rl.parentRecordUid) if rl.parentRecordUid else None
        if not child_uid:
            continue
        link_obj = {
            'record_uid': child_uid,
            'parent_uid': parent_uid,
            'record_key': rl.recordKey,
        }
        if child_uid not in params.nested_share_record_links:
            params.nested_share_record_links[child_uid] = []
        existing_keys = [lk.get('record_key') for lk in params.nested_share_record_links[child_uid]]
        if rl.recordKey not in existing_keys:
            params.nested_share_record_links[child_uid].append(link_obj)

        # Record links carry encrypted record keys — feed them into record_keys
        # so the decrypt pass can pick them up.
        if rl.recordKey:
            if child_uid not in params.nested_share_record_keys:
                params.nested_share_record_keys[child_uid] = []
            params.nested_share_record_keys[child_uid].append({
                'record_uid': child_uid,
                'parent_uid': parent_uid,
                'record_key': rl.recordKey,
                'encrypted_key_type': folder_pb2.encrypted_by_data_key_gcm,
                'source': 'record_link',
            })


def _process_removed_record_links(params, removed_record_links):
    """Remove link entries that the server marked deleted."""
    for rrl in removed_record_links:
        child_uid = utils.base64_url_encode(rrl.childRecordUid) if rrl.childRecordUid else None
        if not child_uid:
            continue
        if child_uid in params.nested_share_record_links:
            if rrl.recordKey:
                params.nested_share_record_links[child_uid] = [
                    lk for lk in params.nested_share_record_links[child_uid]
                    if lk.get('record_key') != rrl.recordKey
                ]
            else:
                del params.nested_share_record_links[child_uid]


def _process_folder_records(params, folder_records):
    """Store folder ↔ record associations and per-folder record keys."""
    for fr in folder_records:
        folder_uid = utils.base64_url_encode(fr.folderUid)
        record_uid = utils.base64_url_encode(fr.recordMetadata.recordUid)
        if folder_uid not in params.nested_share_folder_records:
            params.nested_share_folder_records[folder_uid] = set()
        params.nested_share_folder_records[folder_uid].add(record_uid)

        has_key = (hasattr(fr.recordMetadata, 'encryptedRecordKey')
                   and fr.recordMetadata.encryptedRecordKey)
        if not has_key:
            continue

        if record_uid not in params.nested_share_record_keys:
            params.nested_share_record_keys[record_uid] = []
        rk_obj = {
            'record_uid': record_uid,
            'folder_uid': folder_uid,
            'record_key': fr.recordMetadata.encryptedRecordKey,
            'encrypted_key_type': fr.recordMetadata.encryptedRecordKeyType,
            # ENCRYPTED_BY_USER_KEY (0) → record key encrypted with user data_key
            # ENCRYPTED_BY_PARENT_KEY (1) → record key encrypted with the folder key
            'folder_key_encryption_type': int(fr.folderKeyEncryptionType),
        }
        if fr.recordMetadata.HasField('tlaProperties'):
            rk_obj['tla_properties'] = google.protobuf.json_format.MessageToDict(
                fr.recordMetadata.tlaProperties, preserving_proto_field_name=True
            )
        params.nested_share_record_keys[record_uid].append(rk_obj)


def _process_removed_folder_records(params, removed_folder_records):
    """Remove folder ↔ record associations marked as deleted."""
    for rfr in removed_folder_records:
        folder_uid = utils.base64_url_encode(rfr.folder_uid)
        record_uid = utils.base64_url_encode(rfr.record_uid)
        if folder_uid in params.nested_share_folder_records:
            params.nested_share_folder_records[folder_uid].discard(record_uid)


def _process_removed_folders(params, removed_folders):
    """Drop folders flagged as removed in this sync batch.

    Applied after all folder/record additions so removals always win.
    """
    for rf in removed_folders:
        folder_uid = utils.base64_url_encode(rf.folder_uid)
        logging.debug('Removing Nested Share Folder from cache: %s', folder_uid)

        params.nested_share_folders.pop(folder_uid, None)
        params.nested_share_folder_keys.pop(folder_uid, None)
        params.nested_share_folder_accesses.pop(folder_uid, None)
        params.nested_share_folder_sharing_states.pop(folder_uid, None)
        params.nested_share_folder_records.pop(folder_uid, None)
        params.subfolder_cache.pop(folder_uid, None)
        params.subfolder_record_cache.pop(folder_uid, None)


def _purge_orphaned_records(params):
    """Drop records that no longer belong to any folder.

    Without this pass, records removed via folder deletion would still appear
    in ``nsf-list`` after a successful removal + sync_down.
    """
    all_folder_record_uids = {
        uid
        for rec_set in params.nested_share_folder_records.values()
        for uid in rec_set
    }
    orphaned = [uid for uid in list(params.nested_share_records)
                if uid not in all_folder_record_uids]
    for uid in orphaned:
        params.nested_share_records.pop(uid, None)
        params.nested_share_record_data.pop(uid, None)
        params.nested_share_record_keys.pop(uid, None)
        params.nested_share_record_accesses.pop(uid, None)
        params.nested_share_record_sharing_states.pop(uid, None)
        params.nested_share_record_links.pop(uid, None)
        params.record_cache.pop(uid, None)
        params.meta_data_cache.pop(uid, None)
        params.record_owner_cache.pop(uid, None)
        logging.debug('Purged orphaned Nested Share Record from cache: %s', uid)


def _process_raw_dag_data(params, raw_dag_data):
    """Convert raw DAG protobuf entries to dicts and append to the cache."""
    if not raw_dag_data:
        return
    for dag_entry in raw_dag_data:
        try:
            dag_dict = google.protobuf.json_format.MessageToDict(
                dag_entry, preserving_proto_field_name=True
            )
        except Exception as e:
            logging.debug(f"Failed to parse Nested Share Folder DAG data: {e}")
            dag_dict = {'error': str(e)}
        params.nested_share_raw_dag_data.append(dag_dict)


def _try_decrypt_symmetric(enc_key, sym_key):
    """Try AES-256-GCM then AES-256-CBC with *sym_key*. Returns plaintext or None."""
    for fn in (crypto.decrypt_aes_v2, crypto.decrypt_aes_v1):
        try:
            result = fn(enc_key, sym_key)
            if result:
                return result
        except Exception:
            pass
    return None


def _try_decrypt_with_user_keys(enc_key, params):
    """Try every available user key (symmetric then asymmetric). Returns plaintext or None."""
    result = _try_decrypt_symmetric(enc_key, params.data_key)
    if result:
        return result
    if params.rsa_key2:
        try:
            result = crypto.decrypt_rsa(enc_key, params.rsa_key2)
            if result:
                return result
        except Exception:
            pass
    if params.ecc_key:
        try:
            result = crypto.decrypt_ec(enc_key, params.ecc_key)
            if result:
                return result
        except Exception:
            pass
    return None


def _decrypt_nested_share_folder_keys(params):
    """Decrypt Nested Share Folder folder and record keys."""
    newly_decrypted = True
    
    while newly_decrypted:
        newly_decrypted = False
        
        for folder_uid, folder_obj in params.nested_share_folders.items():
            if 'folder_key_unencrypted' in folder_obj:
                continue

            folder_key = None

            if folder_uid in params.nested_share_folder_keys:
                for fk in params.nested_share_folder_keys[folder_uid]:
                    enc_key = fk['encrypted_key']
                    try:
                        if fk['key_type'] == folder_pb2.ENCRYPTED_BY_USER_KEY:
                            # FolderKeyEncryptionType only tells us the KEY SOURCE (user vs parent),
                            # not the encryption algorithm.  Try all algorithms in likelihood order:
                            #   AES-256-GCM (60 B) — modern default
                            #   AES-256-CBC (48 B) — legacy
                            #   RSA-2048    (256 B) — shared folder re-encrypted for this user
                            #   ECC                — EC-based key wrap
                            folder_key = _try_decrypt_with_user_keys(enc_key, params)
                            if folder_key:
                                break
                        elif fk['key_type'] == folder_pb2.ENCRYPTED_BY_PARENT_KEY:
                            parent_uid = folder_obj.get('parent_uid')
                            if parent_uid and parent_uid in params.nested_share_folders:
                                parent_folder = params.nested_share_folders[parent_uid]
                                if 'folder_key_unencrypted' in parent_folder:
                                    parent_key = parent_folder['folder_key_unencrypted']
                                    folder_key = _try_decrypt_symmetric(enc_key, parent_key)
                                    if folder_key:
                                        break
                    except Exception as e:
                        logging.debug(f"Failed to decrypt folder key for {folder_uid}: {e}")

            # Fallback: try from folder access data (EncryptedDataKey — has explicit algorithm)
            if not folder_key and folder_uid in params.nested_share_folder_accesses:
                for fa in params.nested_share_folder_accesses[folder_uid]:
                    if 'folder_key' not in fa:
                        continue

                    try:
                        encrypted_key = fa['folder_key']['encrypted_key']
                        key_type = fa['folder_key']['encrypted_key_type']

                        if key_type == folder_pb2.encrypted_by_data_key_gcm:
                            folder_key = crypto.decrypt_aes_v2(encrypted_key, params.data_key)
                        elif key_type == folder_pb2.encrypted_by_data_key:
                            folder_key = crypto.decrypt_aes_v1(encrypted_key, params.data_key)
                        elif key_type == folder_pb2.encrypted_by_public_key:
                            if params.rsa_key2:
                                folder_key = crypto.decrypt_rsa(encrypted_key, params.rsa_key2)
                        elif key_type == folder_pb2.encrypted_by_public_key_ecc:
                            if params.ecc_key:
                                folder_key = crypto.decrypt_ec(encrypted_key, params.ecc_key)
                        else:
                            # Unknown type — try all user keys as a last resort
                            folder_key = _try_decrypt_with_user_keys(encrypted_key, params)

                        if folder_key:
                            break
                    except Exception as e:
                        logging.debug(f"Failed to decrypt folder key for {folder_uid} from access data: {e}")

            if folder_key:
                folder_obj['folder_key_unencrypted'] = folder_key
                newly_decrypted = True

                if 'data' in folder_obj and folder_obj['data']:
                    try:
                        data_bytes = crypto.decrypt_aes_v2(folder_obj['data'], folder_key)
                        data_json = json.loads(data_bytes.decode('utf-8'))
                        folder_obj['name'] = data_json.get('name', 'Unnamed Folder')
                        if 'color' in data_json:
                            folder_obj['color'] = data_json['color']
                    except Exception as e:
                        logging.debug(f"Failed to decrypt folder data for {folder_uid}: {e}")

    _decrypt_nested_share_record_keys(params)


def _try_decrypt_record_key(rk, params):
    """Try all applicable methods to decrypt a single record key entry.
    Returns decrypted key bytes or None."""
    encrypted_key = rk['record_key']
    key_type = rk.get('encrypted_key_type', 0)
    folder_uid = rk.get('folder_uid')
    parent_uid = rk.get('parent_uid')

    # 1. Try public key decryption (works regardless of source)
    if key_type == folder_pb2.encrypted_by_public_key:
        if params.rsa_key2:
            try:
                return crypto.decrypt_rsa(encrypted_key, params.rsa_key2)
            except Exception as e:
                logging.debug(f"RSA decrypt failed: {e}")
        return None
    if key_type == folder_pb2.encrypted_by_public_key_ecc:
        if params.ecc_key:
            try:
                return crypto.decrypt_ec(encrypted_key, params.ecc_key)
            except Exception as e:
                logging.debug(f"EC decrypt failed: {e}")
        return None

    # 2. For record-link keys, try parent record key then data key
    if rk.get('source') == 'record_link' and parent_uid:
        if parent_uid in params.nested_share_records:
            parent_obj = params.nested_share_records[parent_uid]
            if 'record_key_unencrypted' in parent_obj:
                try:
                    return crypto.decrypt_aes_v2(encrypted_key, parent_obj['record_key_unencrypted'])
                except Exception:
                    pass
                try:
                    return crypto.decrypt_aes_v1(encrypted_key, parent_obj['record_key_unencrypted'])
                except Exception:
                    pass

    # Build ordered list of keys to try.
    # Use folderKeyEncryptionType when available to prefer the correct key source:
    #   ENCRYPTED_BY_USER_KEY (0) → data_key should come first
    #   ENCRYPTED_BY_PARENT_KEY (1) → folder key should come first (default / unknown)
    fket = rk.get('folder_key_encryption_type')
    folder_key_val = None
    if folder_uid and folder_uid in params.nested_share_folders:
        folder_obj = params.nested_share_folders[folder_uid]
        if 'folder_key_unencrypted' in folder_obj:
            folder_key_val = folder_obj['folder_key_unencrypted']

    keys_to_try = []
    if fket == int(folder_pb2.ENCRYPTED_BY_USER_KEY):
        # Record key was encrypted directly with the user's data key
        keys_to_try.append(('data', params.data_key))
        if folder_key_val is not None:
            keys_to_try.append(('folder', folder_key_val))
    else:
        # Record key was encrypted with the parent folder key (or unknown — try folder first)
        if folder_key_val is not None:
            keys_to_try.append(('folder', folder_key_val))
        keys_to_try.append(('data', params.data_key))

    # 3. Symmetric decryption with candidate keys
    for label, dec_key in keys_to_try:
        if key_type == folder_pb2.encrypted_by_data_key_gcm:
            try:
                return crypto.decrypt_aes_v2(encrypted_key, dec_key)
            except Exception:
                continue
        elif key_type == folder_pb2.encrypted_by_data_key:
            try:
                return crypto.decrypt_aes_v1(encrypted_key, dec_key)
            except Exception:
                continue
        else:
            try:
                return crypto.decrypt_aes_v2(encrypted_key, dec_key)
            except Exception:
                pass
            try:
                return crypto.decrypt_aes_v1(encrypted_key, dec_key)
            except Exception:
                continue

    return None


def _decrypt_record_data(record_uid, record_key, params):
    """Decrypt record data using the record key and store data_json."""
    if record_uid not in params.nested_share_record_data:
        return
    rd_obj = params.nested_share_record_data[record_uid]
    if 'data_json' in rd_obj:
        return
    if 'data' not in rd_obj or not rd_obj['data']:
        return
    try:
        try:
            data_bytes = crypto.decrypt_aes_v2(rd_obj['data'], record_key)
        except Exception:
            data_bytes = crypto.decrypt_aes_v1(rd_obj['data'], record_key)
        data_json = json.loads(data_bytes.decode('utf-8'))
        rd_obj['data_json'] = data_json
    except Exception as e:
        logging.warning(f"Failed to decrypt record data for {record_uid}: {e}")


def _decrypt_nested_share_record_keys(params):
    """Decrypt all Nested Share Folder record keys, trying multiple sources."""

    # Pass 0: check if record keys were already decrypted by the regular vault
    # sync (via recordMetaData or record_cache in SyncDownResponse). This is
    # the primary path for records shared with the current user.
    for record_uid, record_obj in params.nested_share_records.items():
        if 'record_key_unencrypted' in record_obj:
            continue
        # Check meta_data_cache (decrypted record metadata from regular sync)
        if record_uid in params.meta_data_cache:
            meta = params.meta_data_cache[record_uid]
            if 'record_key_unencrypted' in meta:
                record_obj['record_key_unencrypted'] = meta['record_key_unencrypted']
                _decrypt_record_data(record_uid, meta['record_key_unencrypted'], params)
                logging.debug(f"Record {record_uid}: key obtained from meta_data_cache")
                continue
        # Check record_cache (records already processed by regular vault sync)
        if record_uid in params.record_cache:
            cached = params.record_cache[record_uid]
            if 'record_key_unencrypted' in cached:
                record_obj['record_key_unencrypted'] = cached['record_key_unencrypted']
                _decrypt_record_data(record_uid, cached['record_key_unencrypted'], params)
                logging.debug(f"Record {record_uid}: key obtained from record_cache")

    # Pass 1: decrypt from nested_share_record_keys entries
    for record_uid, record_keys_list in params.nested_share_record_keys.items():
        if record_uid not in params.nested_share_records:
            continue
        record_obj = params.nested_share_records[record_uid]
        if 'record_key_unencrypted' in record_obj:
            continue

        for rk in record_keys_list:
            try:
                record_key = _try_decrypt_record_key(rk, params)
                if record_key:
                    record_obj['record_key_unencrypted'] = record_key
                    _decrypt_record_data(record_uid, record_key, params)
                    break
            except Exception as e:
                logging.debug(f"Failed to decrypt record key for {record_uid}: {e}")

    # Pass 2: for records still without keys, try all available decryption keys
    # against the record data directly. This catches records whose keys weren't
    # delivered through the expected folderRecords/recordKeys channels.
    undecrypted = [
        uid for uid, obj in params.nested_share_records.items()
        if 'record_key_unencrypted' not in obj
        and uid in params.nested_share_record_data
        and params.nested_share_record_data[uid].get('data')
    ]
    if undecrypted:
        logging.debug(f"Pass 2: {len(undecrypted)} record(s) still need decryption")

    for record_uid in undecrypted:
        record_obj = params.nested_share_records[record_uid]
        rd_obj = params.nested_share_record_data[record_uid]
        record_key = None

        # Try record link keys with parent record key, then data key
        if record_uid in params.nested_share_record_links:
            for link in params.nested_share_record_links[record_uid]:
                enc_key = link.get('record_key')
                if not enc_key:
                    continue
                parent = link.get('parent_uid')
                if parent and parent in params.nested_share_records:
                    parent_obj = params.nested_share_records[parent]
                    if 'record_key_unencrypted' in parent_obj:
                        try:
                            record_key = crypto.decrypt_aes_v2(enc_key, parent_obj['record_key_unencrypted'])
                        except Exception:
                            try:
                                record_key = crypto.decrypt_aes_v1(enc_key, parent_obj['record_key_unencrypted'])
                            except Exception:
                                pass
                if not record_key:
                    try:
                        record_key = crypto.decrypt_aes_v2(enc_key, params.data_key)
                    except Exception:
                        try:
                            record_key = crypto.decrypt_aes_v1(enc_key, params.data_key)
                        except Exception:
                            pass
                if not record_key and params.rsa_key2:
                    try:
                        record_key = crypto.decrypt_rsa(enc_key, params.rsa_key2)
                    except Exception:
                        pass
                if not record_key and params.ecc_key:
                    try:
                        record_key = crypto.decrypt_ec(enc_key, params.ecc_key)
                    except Exception:
                        pass
                if record_key:
                    break

        # Try decrypting record data directly with folder keys as a last resort.
        # If the record data was encrypted with a folder key (instead of a per-record key),
        # this will succeed and we use the folder key as the effective record key.
        if not record_key:
            candidate_folder_keys = set()
            for folder_uid, rec_set in params.nested_share_folder_records.items():
                if record_uid in rec_set and folder_uid in params.nested_share_folders:
                    fobj = params.nested_share_folders[folder_uid]
                    if 'folder_key_unencrypted' in fobj:
                        candidate_folder_keys.add(id(fobj['folder_key_unencrypted']))
                        try:
                            data_bytes = crypto.decrypt_aes_v2(rd_obj['data'], fobj['folder_key_unencrypted'])
                            data_json = json.loads(data_bytes.decode('utf-8'))
                            rd_obj['data_json'] = data_json
                            record_obj['record_key_unencrypted'] = fobj['folder_key_unencrypted']
                            logging.debug(f"Record {record_uid}: decrypted data directly with folder key {folder_uid}")
                            record_key = fobj['folder_key_unencrypted']
                            break
                        except Exception:
                            pass

        if record_key and 'record_key_unencrypted' not in record_obj:
            record_obj['record_key_unencrypted'] = record_key
            _decrypt_record_data(record_uid, record_key, params)

    # Log remaining undecrypted records
    still_undecrypted = [
        uid for uid, obj in params.nested_share_records.items()
        if 'record_key_unencrypted' not in obj
    ]
    if still_undecrypted:
        logging.debug(
            f"Nested Share Folder: {len(still_undecrypted)} record(s) could not be decrypted: "
            f"{still_undecrypted[:5]}{'...' if len(still_undecrypted) > 5 else ''}"
        )


def _reconstruct_nested_share_folder_entities(params):
    """Reconstruct complete Nested Share Folder entities from atomic objects."""
    for folder_uid, folder_obj in params.nested_share_folders.items():
        if 'folder_key_unencrypted' not in folder_obj:
            continue

        user_folder = {
            'folder_uid': folder_uid,
            'type': 'user_folder',
            'name': folder_obj.get('name', 'Unnamed Folder'),
            'folder_key_unencrypted': folder_obj['folder_key_unencrypted'],
            'source': 'nested_share_folder',
        }

        if 'parent_uid' in folder_obj and folder_obj['parent_uid']:
            user_folder['parent_uid'] = folder_obj['parent_uid']

        if 'color' in folder_obj:
            user_folder['color'] = folder_obj['color']

        params.subfolder_cache[folder_uid] = user_folder

    for folder_uid, record_uids in params.nested_share_folder_records.items():
        # Replace (not additive) so that records removed from a folder are
        # evicted from the subfolder_record_cache on the very next sync.
        params.subfolder_record_cache[folder_uid] = set(record_uids)

    for record_uid, record_obj in params.nested_share_records.items():
        if 'record_key_unencrypted' not in record_obj:
            continue

        if record_uid not in params.nested_share_record_data:
            continue

        rd_obj = params.nested_share_record_data[record_uid]
        if 'data_json' not in rd_obj:
            continue

        record_entry = {
            'record_uid': record_uid,
            'revision': record_obj.get('revision', 0),
            'version': record_obj.get('version', 0),
            'shared': record_obj.get('shared', False),
            'record_key_unencrypted': record_obj['record_key_unencrypted'],
            'data_unencrypted': json.dumps(rd_obj['data_json']).encode('utf-8'),
            'extra_unencrypted': None,
            'udata': {},
            'source': 'nested_share_folder',
        }

        params.record_cache[record_uid] = record_entry

        if record_uid not in params.meta_data_cache:
            meta_data = {
                'record_uid': record_uid,
                'record_key_unencrypted': record_obj['record_key_unencrypted'],
                'can_share': True,
                'can_edit': True,
            }
            if 'user_account_uid' in rd_obj:
                meta_data['owner_account_uid'] = rd_obj['user_account_uid']
                if rd_obj['user_account_uid'] in params.user_cache:
                    meta_data['owner_username'] = params.user_cache[rd_obj['user_account_uid']]
            params.meta_data_cache[record_uid] = meta_data

        if record_uid not in params.record_owner_cache:
            if 'user_account_uid' in rd_obj:
                is_owner = (rd_obj['user_account_uid'] == utils.base64_url_encode(params.account_uid_bytes))
                params.record_owner_cache[record_uid] = RecordOwner(
                    is_owner,
                    rd_obj['user_account_uid']
                )