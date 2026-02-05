import json
import logging
from typing import List, Dict

import google

from . import utils, crypto
from .params import RecordOwner
from .proto import folder_pb2, record_pb2


def _ensure_keeper_drive_attrs(params):
    """Ensure Keeper Drive caches exist on params, even for older sessions."""
    if params is None:
        return
    if not hasattr(params, 'keeper_drive_folders'):
        params.keeper_drive_folders = {}
    if not hasattr(params, 'keeper_drive_folder_keys'):
        params.keeper_drive_folder_keys = {}
    if not hasattr(params, 'keeper_drive_folder_accesses'):
        params.keeper_drive_folder_accesses = {}
    if not hasattr(params, 'keeper_drive_records'):
        params.keeper_drive_records = {}
    if not hasattr(params, 'keeper_drive_record_data'):
        params.keeper_drive_record_data = {}
    if not hasattr(params, 'keeper_drive_record_keys'):
        params.keeper_drive_record_keys = {}
    if not hasattr(params, 'keeper_drive_record_accesses'):
        params.keeper_drive_record_accesses = {}
    if not hasattr(params, 'keeper_drive_folder_records'):
        params.keeper_drive_folder_records = {}
    if not hasattr(params, 'keeper_drive_record_sharing_states'):
        params.keeper_drive_record_sharing_states = {}
    if not hasattr(params, 'keeper_drive_record_links'):
        params.keeper_drive_record_links = {}
    if not hasattr(params, 'keeper_drive_raw_dag_data'):
        params.keeper_drive_raw_dag_data = []


def create_accumulator():
    return {
        'folders': [],
        'folder_keys': [],
        'folder_accesses': [],
        'revoked_folder_accesses': [],
        'record_data': [],
        'record_keys': [],
        'record_accesses': [],
        'revoked_record_accesses': [],
        'records': [],
        'folder_records': [],
        'removed_folder_records': [],
        'users': [],
        'record_sharing_states': [],
        'record_links': [],
        'removed_record_links': [],
        'record_rotations': [],
        'raw_dag_data': [],
    }


def clear_caches(params):
    _ensure_keeper_drive_attrs(params)
    params.keeper_drive_folders.clear()
    params.keeper_drive_folder_keys.clear()
    params.keeper_drive_folder_accesses.clear()
    params.keeper_drive_records.clear()
    params.keeper_drive_record_data.clear()
    params.keeper_drive_record_keys.clear()
    params.keeper_drive_record_accesses.clear()
    params.keeper_drive_folder_records.clear()
    params.keeper_drive_record_sharing_states.clear()
    params.keeper_drive_record_links.clear()
    params.keeper_drive_raw_dag_data.clear()


def collect_from_response(acc, response, resp_bw_recs, resp_sec_data_recs, resp_sec_scores, record_rotation_items):
    if not response.HasField('keeperDriveData'):
        return
    kd_data = response.keeperDriveData
    if len(kd_data.folders) > 0:
        acc['folders'].extend(kd_data.folders)
    if len(kd_data.folderKeys) > 0:
        acc['folder_keys'].extend(kd_data.folderKeys)
    if len(kd_data.folderAccesses) > 0:
        acc['folder_accesses'].extend(kd_data.folderAccesses)
    if len(kd_data.revokedFolderAccesses) > 0:
        acc['revoked_folder_accesses'].extend(kd_data.revokedFolderAccesses)
    if len(kd_data.recordData) > 0:
        acc['record_data'].extend(kd_data.recordData)
    if len(kd_data.recordKeys) > 0:
        acc['record_keys'].extend(kd_data.recordKeys)
    if len(kd_data.recordAccesses) > 0:
        acc['record_accesses'].extend(kd_data.recordAccesses)
    if len(kd_data.revokedRecordAccesses) > 0:
        acc['revoked_record_accesses'].extend(kd_data.revokedRecordAccesses)
    if len(kd_data.records) > 0:
        acc['records'].extend(kd_data.records)
    if len(kd_data.folderRecords) > 0:
        acc['folder_records'].extend(kd_data.folderRecords)
    if len(kd_data.removedFolderRecords) > 0:
        acc['removed_folder_records'].extend(kd_data.removedFolderRecords)

    users_attr = getattr(kd_data, 'users', None)
    if users_attr:
        acc['users'].extend(users_attr)
    rss_attr = getattr(kd_data, 'recordSharingStates', None)
    if rss_attr:
        acc['record_sharing_states'].extend(rss_attr)
    rl_attr = getattr(kd_data, 'recordLinks', None)
    if rl_attr:
        acc['record_links'].extend(rl_attr)
    rrl_attr = getattr(kd_data, 'removedRecordLinks', None)
    if rrl_attr:
        acc['removed_record_links'].extend(rrl_attr)
    rrd_attr = getattr(kd_data, 'recordRotationData', None)
    if rrd_attr:
        acc['record_rotations'].extend(rrd_attr)
    dag_attr = getattr(kd_data, 'rawDagData', None)
    if dag_attr:
        acc['raw_dag_data'].extend(dag_attr)
    bw_attr = getattr(kd_data, 'breachWatchRecords', None)
    if bw_attr:
        resp_bw_recs.extend(bw_attr)
    bws_attr = getattr(kd_data, 'breachWatchSecurityData', None)
    if bws_attr:
        resp_sec_data_recs.extend(bws_attr)
    ssd_attr = getattr(kd_data, 'securityScoreData', None)
    if ssd_attr:
        resp_sec_scores.extend(ssd_attr)
    if acc['record_rotations']:
        record_rotation_items.extend(acc['record_rotations'])


def has_data(acc):
    return any(len(v) > 0 for v in acc.values())


def process(params, acc):
    if not has_data(acc):
        return
    _ensure_keeper_drive_attrs(params)
    logging.debug(
        'Processing Keeper Drive sync data: folders=%d folder_records=%d records=%d record_keys=%d',
        len(acc['folders']), len(acc['folder_records']), len(acc['records']), len(acc['record_keys'])
    )
    _process_keeper_drive_sync(
        params,
        acc['folders'],
        acc['folder_keys'],
        acc['folder_accesses'],
        acc['revoked_folder_accesses'],
        acc['records'],
        acc['record_data'],
        acc['record_keys'],
        acc['record_accesses'],
        acc['revoked_record_accesses'],
        acc['folder_records'],
        acc['removed_folder_records'],
        acc['users'],
        acc['record_sharing_states'],
        acc['record_links'],
        acc['removed_record_links'],
        acc['raw_dag_data'],
    )


def _process_keeper_drive_sync(params, folders, folder_keys, folder_accesses, revoked_folder_accesses,
                                records, record_data_list, record_keys, record_accesses, revoked_record_accesses,
                                folder_records, removed_folder_records, users,
                                record_sharing_states, record_links, removed_record_links, raw_dag_data):
    """Process Keeper Drive atomic sync objects and store in caches."""

    record_sharing_states = record_sharing_states or []
    record_links = record_links or []
    removed_record_links = removed_record_links or []
    raw_dag_data = raw_dag_data or []

    # Store users in user_cache
    for user in users:
        account_uid = utils.base64_url_encode(user.accountUid)
        params.user_cache[account_uid] = user.username

    # Process folders
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
        params.keeper_drive_folders[folder_uid] = folder_obj

    # Process folder keys (group by folder_uid)
    for fk in folder_keys:
        folder_uid = utils.base64_url_encode(fk.folderUid)
        if folder_uid not in params.keeper_drive_folder_keys:
            params.keeper_drive_folder_keys[folder_uid] = []
        fk_obj = {
            'folder_uid': folder_uid,
            'parent_uid': utils.base64_url_encode(fk.parentUid) if fk.parentUid else None,
            'encrypted_key': fk.folderKey,
            'key_type': fk.encryptedBy,
        }
        params.keeper_drive_folder_keys[folder_uid].append(fk_obj)

    # Process folder accesses (group by folder_uid)
    for fa in folder_accesses:
        folder_uid = utils.base64_url_encode(fa.folderUid)
        if folder_uid not in params.keeper_drive_folder_accesses:
            params.keeper_drive_folder_accesses[folder_uid] = []
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
            fa_obj['permissions'] = {
                'can_add_users': fa.permissions.canAddUsers if fa.permissions.canAddUsers else False,
                'can_remove_users': fa.permissions.canRemoveUsers if fa.permissions.canRemoveUsers else False,
                'can_add_records': fa.permissions.canAddRecords if fa.permissions.canAddRecords else False,
                'can_remove_records': fa.permissions.canRemoveRecords if fa.permissions.canRemoveRecords else False,
                'can_delete_records': fa.permissions.canDeleteRecords if fa.permissions.canDeleteRecords else False,
                'can_create_folders': fa.permissions.canCreateFolders if fa.permissions.canCreateFolders else False,
                'can_delete_folders': fa.permissions.canDeleteFolders if fa.permissions.canDeleteFolders else False,
                'can_change_user_permissions': fa.permissions.canChangeUserPermissions if fa.permissions.canChangeUserPermissions else False,
                'can_change_record_permissions': fa.permissions.canChangeRecordPermissions if fa.permissions.canChangeRecordPermissions else False,
                'can_change_folder_ownership': fa.permissions.canChangeFolderOwnership if fa.permissions.canChangeFolderOwnership else False,
                'can_change_record_ownership': fa.permissions.canChangeRecordOwnership if fa.permissions.canChangeRecordOwnership else False,
                'can_edit_records': fa.permissions.canEditRecords if fa.permissions.canEditRecords else False,
                'can_view_records': fa.permissions.canViewRecords if fa.permissions.canViewRecords else False,
                'can_reshare_records': fa.permissions.canReshareRecords if fa.permissions.canReshareRecords else False,
            }
        params.keeper_drive_folder_accesses[folder_uid].append(fa_obj)

    # Process revoked folder accesses
    for rfa in revoked_folder_accesses:
        folder_uid = utils.base64_url_encode(rfa.folderUid)
        actor_uid = utils.base64_url_encode(rfa.actorUid)
        if folder_uid in params.keeper_drive_folder_accesses:
            params.keeper_drive_folder_accesses[folder_uid] = [
                fa for fa in params.keeper_drive_folder_accesses[folder_uid]
                if fa['access_type_uid'] != actor_uid
            ]

    # Process records (DriveRecord metadata)
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
        params.keeper_drive_records[record_uid] = record_obj

    # Process record data (encrypted content)
    for rd in record_data_list:
        record_uid = utils.base64_url_encode(rd.recordUid)
        rd_obj = {
            'record_uid': record_uid,
            'data': rd.data,
        }
        if rd.HasField('user'):
            rd_obj['user_account_uid'] = utils.base64_url_encode(rd.user.accountUid)
            rd_obj['user_username'] = rd.user.username
        params.keeper_drive_record_data[record_uid] = rd_obj

    # Process record keys (group by record_uid)
    for rk in record_keys:
        record_uid = utils.base64_url_encode(rk.record_uid)
        if record_uid not in params.keeper_drive_record_keys:
            params.keeper_drive_record_keys[record_uid] = []
        rk_obj = {
            'record_uid': record_uid,
            'user_uid': utils.base64_url_encode(rk.user_uid),
            'record_key': rk.record_key,
            'encrypted_key_type': rk.encrypted_key_type,
        }
        params.keeper_drive_record_keys[record_uid].append(rk_obj)

    # Process record accesses (group by record_uid)
    for ra in record_accesses:
        record_uid = utils.base64_url_encode(ra.recordUid)
        if record_uid not in params.keeper_drive_record_accesses:
            params.keeper_drive_record_accesses[record_uid] = []
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
            'can_edit': ra.can_edit if hasattr(ra, 'can_edit') and ra.can_edit else False,
            'can_view': ra.can_view if hasattr(ra, 'can_view') and ra.can_view else False,
            'can_share': ra.can_share if hasattr(ra, 'can_share') and ra.can_share else False,
            'can_delete': ra.can_delete if hasattr(ra, 'can_delete') and ra.can_delete else False,
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
        params.keeper_drive_record_accesses[record_uid].append(ra_obj)

    # Process revoked record accesses
    for rra in revoked_record_accesses:
        record_uid = utils.base64_url_encode(rra.recordUid)
        actor_uid = utils.base64_url_encode(rra.actorUid)
        if record_uid in params.keeper_drive_record_accesses:
            params.keeper_drive_record_accesses[record_uid] = [
                ra for ra in params.keeper_drive_record_accesses[record_uid]
                if ra['access_uid'] != actor_uid
            ]

    # Process record sharing states
    for rss in record_sharing_states:
        record_uid = utils.base64_url_encode(rss.recordUid)
        state_obj = {
            'record_uid': record_uid,
            'is_directly_shared': rss.isDirectlyShared,
            'is_indirectly_shared': rss.isIndirectlyShared,
            'is_shared': rss.isShared,
        }
        params.keeper_drive_record_sharing_states[record_uid] = state_obj
        if record_uid in params.keeper_drive_records:
            record_obj = params.keeper_drive_records[record_uid]
            record_obj['shared'] = record_obj.get('shared', False) or state_obj['is_shared']

    # Process record links
    for rl in record_links:
        record_uid = utils.base64_url_encode(rl.record_uid)
        link_obj = {
            'record_uid': record_uid,
            'record_key': rl.record_key,
        }
        if record_uid not in params.keeper_drive_record_links:
            params.keeper_drive_record_links[record_uid] = []
        existing_keys = [lk.get('record_key') for lk in params.keeper_drive_record_links[record_uid]]
        if rl.record_key not in existing_keys:
            params.keeper_drive_record_links[record_uid].append(link_obj)

    for rrl in removed_record_links:
        record_uid = utils.base64_url_encode(rrl.record_uid)
        if record_uid in params.keeper_drive_record_links:
            if rrl.record_key:
                params.keeper_drive_record_links[record_uid] = [
                    lk for lk in params.keeper_drive_record_links[record_uid]
                    if lk.get('record_key') != rrl.record_key
                ]
            else:
                del params.keeper_drive_record_links[record_uid]

    # Process folder records (associations)
    for fr in folder_records:
        folder_uid = utils.base64_url_encode(fr.folderUid)
        record_uid = utils.base64_url_encode(fr.recordMetadata.recordUid)
        if folder_uid not in params.keeper_drive_folder_records:
            params.keeper_drive_folder_records[folder_uid] = set()
        params.keeper_drive_folder_records[folder_uid].add(record_uid)

        has_key = hasattr(fr.recordMetadata, 'encryptedRecordKey') and fr.recordMetadata.encryptedRecordKey

        if has_key:
            if record_uid not in params.keeper_drive_record_keys:
                params.keeper_drive_record_keys[record_uid] = []
            rk_obj = {
                'record_uid': record_uid,
                'folder_uid': folder_uid,
                'record_key': fr.recordMetadata.encryptedRecordKey,
                'encrypted_key_type': fr.recordMetadata.encryptedRecordKeyType,
            }
            if fr.recordMetadata.HasField('tlaProperties'):
                rk_obj['tla_properties'] = google.protobuf.json_format.MessageToDict(
                    fr.recordMetadata.tlaProperties, preserving_proto_field_name=True
                )
            params.keeper_drive_record_keys[record_uid].append(rk_obj)

    # Process removed folder records
    for rfr in removed_folder_records:
        folder_uid = utils.base64_url_encode(rfr.folder_uid)
        record_uid = utils.base64_url_encode(rfr.record_uid)
        if folder_uid in params.keeper_drive_folder_records:
            params.keeper_drive_folder_records[folder_uid].discard(record_uid)

    if raw_dag_data:
        for dag_entry in raw_dag_data:
            try:
                dag_dict = google.protobuf.json_format.MessageToDict(
                    dag_entry, preserving_proto_field_name=True
                )
            except Exception as e:
                logging.debug(f"Failed to parse Keeper Drive DAG data: {e}")
                dag_dict = {'error': str(e)}
            params.keeper_drive_raw_dag_data.append(dag_dict)

    _decrypt_keeper_drive_keys(params)
    _reconstruct_keeper_drive_entities(params)


def _decrypt_keeper_drive_keys(params):
    """Decrypt Keeper Drive folder and record keys."""
    newly_decrypted = True
    
    while newly_decrypted:
        newly_decrypted = False
        
        for folder_uid, folder_obj in params.keeper_drive_folders.items():
            if 'folder_key_unencrypted' in folder_obj:
                continue

            folder_key = None

            if folder_uid in params.keeper_drive_folder_keys:
                for fk in params.keeper_drive_folder_keys[folder_uid]:
                    try:
                        if fk['key_type'] == folder_pb2.ENCRYPTED_BY_USER_KEY:
                            
                            folder_key = crypto.decrypt_aes_v2(fk['encrypted_key'], params.data_key)
                            break
                        elif fk['key_type'] == folder_pb2.ENCRYPTED_BY_PARENT_KEY:
                            parent_uid = folder_obj.get('parent_uid')
                            if parent_uid and parent_uid in params.keeper_drive_folders:
                                parent_folder = params.keeper_drive_folders[parent_uid]
                                if 'folder_key_unencrypted' in parent_folder:
                                    parent_key = parent_folder['folder_key_unencrypted']
                                    folder_key = crypto.decrypt_aes_v2(fk['encrypted_key'], parent_key)
                                    break
                    except Exception as e:
                        logging.debug(f"Failed to decrypt folder key for {folder_uid}: {e}")

            # Fallback: try from folder access data
            if not folder_key and folder_uid in params.keeper_drive_folder_accesses:
                for fa in params.keeper_drive_folder_accesses[folder_uid]:
                    if 'folder_key' not in fa:
                        continue

                    try:
                        encrypted_key = fa['folder_key']['encrypted_key']
                        key_type = fa['folder_key']['encrypted_key_type']

                        if key_type == folder_pb2.encrypted_by_data_key_gcm:
                            folder_key = crypto.decrypt_aes_v2(encrypted_key, params.data_key)
                            break
                        elif key_type == folder_pb2.encrypted_by_data_key:
                            folder_key = crypto.decrypt_aes_v1(encrypted_key, params.data_key)
                            break
                        elif key_type == folder_pb2.encrypted_by_public_key:
                            folder_key = crypto.decrypt_rsa(encrypted_key, params.rsa_key2)
                            break
                        elif key_type == folder_pb2.encrypted_by_public_key_ecc:
                            folder_key = crypto.decrypt_ec(encrypted_key, params.ecc_key)
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

    for record_uid, record_keys_list in params.keeper_drive_record_keys.items():
        if record_uid in params.keeper_drive_records:
            record_obj = params.keeper_drive_records[record_uid]
            if 'record_key_unencrypted' in record_obj:
                continue

            record_key = None
            for rk in record_keys_list:
                try:
                    if 'folder_uid' in rk:
                        folder_uid = rk['folder_uid']
                        
                        if rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key_gcm:
                            try:
                                record_key = crypto.decrypt_aes_v2(rk['record_key'], params.data_key)
                                logging.debug(f"Record {record_uid}: decrypted with data key (GCM) from folderRecord")
                                break
                            except Exception as e:
                                logging.debug(f"Record {record_uid}: data key decrypt failed, trying folder key: {e}")
                        elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key:
                            try:
                                record_key = crypto.decrypt_aes_v1(rk['record_key'], params.data_key)
                                logging.debug(f"Record {record_uid}: decrypted with data key (CBC) from folderRecord")
                                break
                            except Exception as e:
                                logging.debug(f"Record {record_uid}: data key decrypt failed, trying folder key: {e}")
                        
                        if not record_key and folder_uid in params.keeper_drive_folders:
                            folder_obj = params.keeper_drive_folders[folder_uid]
                            if 'folder_key_unencrypted' in folder_obj:
                                folder_key = folder_obj['folder_key_unencrypted']
                                if rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key_gcm:
                                    record_key = crypto.decrypt_aes_v2(rk['record_key'], folder_key)
                                elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key:
                                    record_key = crypto.decrypt_aes_v1(rk['record_key'], folder_key)
                                else:
                                    try:
                                        record_key = crypto.decrypt_aes_v2(rk['record_key'], folder_key)
                                    except:
                                        record_key = crypto.decrypt_aes_v1(rk['record_key'], folder_key)
                                if record_key:
                                    break
                    else:
                        if rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key_gcm:
                            record_key = crypto.decrypt_aes_v2(rk['record_key'], params.data_key)
                            break
                        elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key:
                            record_key = crypto.decrypt_aes_v1(rk['record_key'], params.data_key)
                            break
                        elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_public_key:
                            if params.rsa_key2:
                                record_key = crypto.decrypt_rsa(rk['record_key'], params.rsa_key2)
                                break
                        elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_public_key_ecc:
                            if params.ecc_key:
                                record_key = crypto.decrypt_ec(rk['record_key'], params.ecc_key)
                                break
                        elif rk['encrypted_key_type'] == folder_pb2.no_key or rk['encrypted_key_type'] == 0:
                            try:
                                record_key = crypto.decrypt_aes_v2(rk['record_key'], params.data_key)
                                break
                            except:
                                try:
                                    record_key = crypto.decrypt_aes_v1(rk['record_key'], params.data_key)
                                    break
                                except:
                                    logging.debug(f"Record {record_uid}: failed to decrypt with data key (type=0)")
                except Exception as e:
                    logging.debug(f"Failed to decrypt record key for {record_uid}: {e}")

            if record_key:
                record_obj['record_key_unencrypted'] = record_key

                if record_uid in params.keeper_drive_record_data:
                    rd_obj = params.keeper_drive_record_data[record_uid]
                    if 'data' in rd_obj and rd_obj['data']:
                        try:
                            try:
                                data_bytes = crypto.decrypt_aes_v2(rd_obj['data'], record_key)
                            except:
                                data_bytes = crypto.decrypt_aes_v1(rd_obj['data'], record_key)

                            data_json = json.loads(data_bytes.decode('utf-8'))
                            rd_obj['data_json'] = data_json
                        except Exception as e:
                            logging.warning(f"Failed to decrypt record data for {record_uid}: {e}")


def _reconstruct_keeper_drive_entities(params):
    """Reconstruct complete Keeper Drive entities from atomic objects."""
    for folder_uid, folder_obj in params.keeper_drive_folders.items():
        if 'folder_key_unencrypted' not in folder_obj:
            continue

        user_folder = {
            'folder_uid': folder_uid,
            'type': 'user_folder',
            'name': folder_obj.get('name', 'Unnamed Folder'),
            'folder_key_unencrypted': folder_obj['folder_key_unencrypted'],
        }

        if 'parent_uid' in folder_obj and folder_obj['parent_uid']:
            user_folder['parent_uid'] = folder_obj['parent_uid']

        if 'color' in folder_obj:
            user_folder['color'] = folder_obj['color']

        params.subfolder_cache[folder_uid] = user_folder

    for folder_uid, record_uids in params.keeper_drive_folder_records.items():
        if folder_uid not in params.subfolder_record_cache:
            params.subfolder_record_cache[folder_uid] = set()
        for record_uid in record_uids:
            params.subfolder_record_cache[folder_uid].add(record_uid)

    for record_uid, record_obj in params.keeper_drive_records.items():
        if 'record_key_unencrypted' not in record_obj:
            continue

        if record_uid not in params.keeper_drive_record_data:
            continue

        rd_obj = params.keeper_drive_record_data[record_uid]
        if 'data_json' not in rd_obj:
            continue

        record_entry = {
            'record_uid': record_uid,
            'revision': record_obj.get('revision', 0),
            'version': record_obj.get('version', 0),
            'shared': record_obj.get('shared', False),
            'record_key_unencrypted': record_obj['record_key_unencrypted'],
            'data_unencrypted': json.dumps(rd_obj['data_json']).encode('utf-8'),
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

    logging.info(f"Reconstructed {len(params.keeper_drive_folders)} Keeper Drive folder(s) and {len(params.keeper_drive_records)} record(s)")
