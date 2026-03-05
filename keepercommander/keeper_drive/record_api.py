"""
KeeperDrive — record CRUD, sharing, and ownership transfer.
"""

import json
import logging
import os
from typing import Optional, List, Dict, Any

from .. import utils, crypto, api
from ..params import KeeperParams
from ..proto import record_pb2, folder_pb2, record_endpoints_pb2, record_details_pb2, record_sharing_pb2
from ..error import KeeperApiError
from ..api import pad_aes_gcm

from .common import (
    get_folder_key, get_record_key, get_record_from_cache,
    get_user_public_key, encrypt_for_recipient, handle_share_invite,
    parse_sharing_status,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════
# Low-level protobuf builder
# ══════════════════════════════════════════════════════════════════════════

def create_record_data_v3(record_uid, record_key, data,
                           non_shared_data=None, folder_uid=None,
                           folder_key=None, record_key_type=None,
                           client_modified_time=None, data_key=None):
    ra = record_endpoints_pb2.RecordAdd()
    ra.recordUid = utils.base64_url_decode(record_uid)

    if folder_uid and folder_key:
        ra.recordKey = crypto.encrypt_aes_v2(record_key, folder_key)
        ra.folderUid = utils.base64_url_decode(folder_uid)
        ra.folderKey = crypto.encrypt_aes_v2(record_key, folder_key)
    elif folder_uid and not folder_key:
        raise ValueError("folder_key required when folder_uid is provided")
    else:
        if data_key is None:
            raise ValueError("data_key required when creating at vault root")
        ra.recordKey = crypto.encrypt_aes_v2(record_key, data_key)

    ra.recordKeyType = (record_key_type if record_key_type is not None
                        else folder_pb2.encrypted_by_data_key_gcm)

    data_json = pad_aes_gcm(json.dumps(data))
    data_bytes = data_json.encode() if isinstance(data_json, str) else data_json
    ra.data = crypto.encrypt_aes_v2(data_bytes, record_key)

    if non_shared_data:
        ns = pad_aes_gcm(json.dumps(non_shared_data))
        ns_bytes = ns.encode() if isinstance(ns, str) else ns
        ra.nonSharedData = crypto.encrypt_aes_v2(ns_bytes, record_key)
    if client_modified_time:
        ra.clientModifiedTime = client_modified_time
    return ra


# ══════════════════════════════════════════════════════════════════════════
# Transport: record_add_v3 / record_update_v3
# ══════════════════════════════════════════════════════════════════════════

def record_add_v3(params, records, client_time=None, security_data_key_type=None):
    if not records or len(records) > 1000:
        raise ValueError("Provide 1..1000 records")
    rq = record_endpoints_pb2.RecordsAddRequest()
    rq.records.extend(records)
    if client_time:
        rq.clientTime = client_time
    if security_data_key_type:
        rq.securityDataKeyType = security_data_key_type
    return api.communicate_rest(params, rq, 'vault/records/v3/add',
                                rs_type=record_pb2.RecordsModifyResponse)


def record_update_v3(params, records, client_time=None, security_data_key_type=None):
    if not records or len(records) > 1000:
        raise ValueError("Provide 1..1000 records")
    rq = record_pb2.RecordsUpdateRequest()
    rq.records.extend(records)
    if client_time:
        rq.client_time = client_time
    if security_data_key_type:
        rq.security_data_key_type = security_data_key_type
    return api.communicate_rest(params, rq, 'vault/records/v3/update',
                                rs_type=record_pb2.RecordsModifyResponse)


# ══════════════════════════════════════════════════════════════════════════
# High-level: create / update / batch
# ══════════════════════════════════════════════════════════════════════════

def create_record_v3(params, record_type='', title='', fields=None,
                     folder_uid=None, notes=None, custom_fields=None,
                     record_data=None):
    uid = utils.generate_uid()
    rk = os.urandom(32)

    if record_data is not None:
        data = record_data
    else:
        data = {'type': record_type, 'title': title, 'fields': []}
        if fields:
            for ft, fv in fields.items():
                data['fields'].append({'type': ft, 'value': fv if isinstance(fv, list) else [fv]})
        if notes is not None:
            data['notes'] = notes
        if custom_fields:
            data['fields'].extend(custom_fields)

    fk = get_folder_key(params, folder_uid, raise_on_missing=True) if folder_uid else None

    ra = create_record_data_v3(
        record_uid=uid, record_key=rk, data=data,
        folder_uid=folder_uid, folder_key=fk,
        data_key=params.data_key, client_modified_time=utils.current_milli_time())
    response = record_add_v3(params, [ra])

    if response.records:
        r = response.records[0]
        return {
            'record_uid': uid,
            'status': record_pb2.RecordModifyResult.Name(r.status),
            'message': r.message,
            'success': r.status == record_pb2.RS_SUCCESS,
            'revision': getattr(response, 'revision', 0),
        }
    raise KeeperApiError('no_results', 'No results from record creation')


def update_record_v3(params, record_uid, data=None, title=None,
                     record_type=None, fields=None, notes=None,
                     non_shared_data=None, revision=None):
    if record_uid not in params.record_cache:
        from .. import sync_down
        sync_down.sync_down(params)
        if record_uid not in params.record_cache:
            raise ValueError(f"Record {record_uid} not found")

    rec = params.record_cache[record_uid]
    rk = rec.get('record_key_unencrypted')
    if not rk:
        raise ValueError(f"Record key not available for {record_uid}")

    if data is None:
        existing = None
        if 'data_unencrypted' in rec:
            raw = rec['data_unencrypted']
            if isinstance(raw, bytes):
                existing = json.loads(raw.decode())
        data = existing.copy() if existing else {'fields': []}
        if title is not None:
            data['title'] = title
        if record_type is not None:
            data['type'] = record_type
        if fields is not None:
            by_type = {}
            for ef in data.get('fields', []):
                by_type.setdefault(ef.get('type'), []).append(ef)
            for ft, fv in fields.items():
                fv = fv if isinstance(fv, list) else [fv]
                if ft in by_type and by_type[ft]:
                    by_type[ft][0]['value'] = fv
                else:
                    data.setdefault('fields', []).append({'type': ft, 'value': fv})
        if notes is not None:
            data['notes'] = notes

    ru = record_pb2.RecordUpdate()
    ru.record_uid = utils.base64_url_decode(record_uid)
    ru.client_modified_time = utils.current_milli_time()
    ru.revision = revision if revision is not None else rec.get('revision', 0)

    dj = pad_aes_gcm(json.dumps(data))
    db = dj.encode() if isinstance(dj, str) else dj
    ru.data = crypto.encrypt_aes_v2(db, rk)

    if non_shared_data:
        nsj = pad_aes_gcm(json.dumps(non_shared_data))
        nsb = nsj.encode() if isinstance(nsj, str) else nsj
        ru.non_shared_data = crypto.encrypt_aes_v2(nsb, rk)

    response = record_update_v3(params, [ru])
    if response.records:
        r = response.records[0]
        return {
            'record_uid': record_uid,
            'status': record_pb2.RecordModifyResult.Name(r.status),
            'message': r.message,
            'success': r.status == record_pb2.RS_SUCCESS,
            'revision': getattr(response, 'revision', 0),
        }
    raise KeeperApiError('no_results', 'No results from record update')


def create_records_batch_v3(params, record_specs):
    if len(record_specs) > 1000:
        raise ValueError("Maximum 1000 records at a time")
    adds, uid_map = [], {}
    for idx, spec in enumerate(record_specs):
        uid = utils.generate_uid()
        uid_map[idx] = uid
        rk = os.urandom(32)
        data = {'type': spec['type'], 'title': spec['title'], 'fields': []}
        for ft, fv in spec.get('fields', {}).items():
            data['fields'].append({'type': ft, 'value': fv if isinstance(fv, list) else [fv]})
        if spec.get('notes') is not None:
            data['notes'] = spec['notes']
        if spec.get('custom_fields'):
            data['fields'].extend(spec['custom_fields'])

        fuid = spec.get('folder_uid')
        fk = get_folder_key(params, fuid) if fuid else None
        adds.append(create_record_data_v3(
            record_uid=uid, record_key=rk, data=data,
            folder_uid=fuid, folder_key=fk,
            data_key=params.data_key, client_modified_time=utils.current_milli_time()))

    response = record_add_v3(params, adds)
    return [{
        'record_uid': uid_map.get(i, utils.base64_url_encode(r.record_uid)),
        'title': record_specs[i].get('title'),
        'status': record_pb2.RecordModifyResult.Name(r.status),
        'message': r.message,
        'success': r.status == record_pb2.RS_SUCCESS,
        'revision': getattr(response, 'revision', 0),
    } for i, r in enumerate(response.records)]


# ══════════════════════════════════════════════════════════════════════════
# Record details / access
# ══════════════════════════════════════════════════════════════════════════

def get_record_details_v3(params, record_uids, client_time=None):
    if not record_uids:
        raise ValueError("At least one record UID required")
    rq = record_details_pb2.RecordDataRequest()
    for uid in record_uids:
        rq.recordUids.append(utils.base64_url_decode(uid))
    rq.clientTime = client_time or utils.current_milli_time()

    rs = api.communicate_rest(params, rq, 'vault/records/v3/details/data',
                              rs_type=record_details_pb2.RecordDataResponse)
    result = {'data': [], 'forbidden_records': []}

    for rd in rs.data:
        uid = utils.base64_url_encode(getattr(rd, 'recordUid', getattr(rd, 'record_uid', b'')))
        title, rtype = 'Unknown', 'Unknown'
        try:
            title, rtype = _decrypt_record_data(params, rd, uid)
        except Exception:
            pass
        result['data'].append({
            'record_uid': uid, 'title': title, 'type': rtype,
            'revision': getattr(rd, 'revision', 0),
            'version': getattr(rd, 'version', 0),
        })
    for fu in rs.forbiddenRecords:
        result['forbidden_records'].append(utils.base64_url_encode(fu))
    return result


def _decrypt_record_data(params, rd, uid):
    rk_val = getattr(rd, 'recordKey', getattr(rd, 'record_key', None))
    if not rk_val:
        raise ValueError("No record key")
    enc_rk = utils.base64_url_decode(rk_val) if isinstance(rk_val, str) else rk_val
    rk_type = getattr(rd, 'recordKeyType', getattr(rd, 'record_key_type', None))

    drk = _try_decrypt_record_key(params, enc_rk, rk_type, uid)
    enc_data = getattr(rd, 'encryptedRecordData', getattr(rd, 'encrypted_record_data', None))
    if drk and enc_data:
        raw = utils.base64_url_decode(enc_data) if isinstance(enc_data, str) else enc_data
        dec = crypto.decrypt_aes_v2(raw, drk)
        dj = json.loads(dec.decode().rstrip(' '))
        return dj.get('title', 'Unknown'), dj.get('type', 'Unknown')
    return 'Unknown', 'Unknown'


def _try_decrypt_record_key(params, enc_rk, rk_type, uid):
    drk = None
    if rk_type in (record_pb2.ENCRYPTED_BY_DATA_KEY, 'ENCRYPTED_BY_DATA_KEY'):
        try: drk = crypto.decrypt_aes_v1(enc_rk, params.data_key)
        except Exception: pass
    elif rk_type in (record_pb2.ENCRYPTED_BY_DATA_KEY_GCM, 'ENCRYPTED_BY_DATA_KEY_GCM', None):
        try: drk = crypto.decrypt_aes_v2(enc_rk, params.data_key)
        except Exception: pass
    elif rk_type in (record_pb2.ENCRYPTED_BY_PUBLIC_KEY, 'ENCRYPTED_BY_PUBLIC_KEY'):
        drk = crypto.decrypt_rsa(enc_rk, params.rsa_key2)
    elif rk_type in (record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC, 'ENCRYPTED_BY_PUBLIC_KEY_ECC'):
        drk = crypto.decrypt_ec(enc_rk, params.ecc_key)

    if not drk and uid in getattr(params, 'keeper_drive_record_keys', {}):
        for rk_entry in params.keeper_drive_record_keys[uid]:
            fuid = rk_entry.get('folder_uid')
            if fuid:
                fobj = getattr(params, 'keeper_drive_folders', {}).get(fuid, {})
                fk = fobj.get('folder_key_unencrypted')
                if fk:
                    try: drk = crypto.decrypt_aes_v2(enc_rk, fk); break
                    except Exception:
                        try: drk = crypto.decrypt_aes_v1(enc_rk, fk); break
                        except Exception: pass
    return drk


def get_record_accesses_v3(params, record_uids):
    if not record_uids:
        raise ValueError("At least one record UID required")
    rq = record_details_pb2.RecordAccessRequest()
    for uid in record_uids:
        rq.recordUids.append(utils.base64_url_decode(uid))

    rs = api.communicate_rest(params, rq, 'vault/records/v3/details/access',
                              rs_type=record_details_pb2.RecordAccessResponse)
    result = {'record_accesses': [], 'forbidden_records': []}
    for ra in rs.recordAccesses:
        d = ra.data
        ai = ra.accessorInfo
        ao = {
            'record_uid': utils.base64_url_encode(d.recordUid),
            'accessor_name': ai.name,
            'access_type': folder_pb2.AccessType.Name(d.accessType) if hasattr(d, 'accessType') else 'UNKNOWN',
            'access_type_uid': utils.base64_url_encode(d.accessTypeUid),
            'owner': getattr(d, 'owner', False),
        }
        for flag in ('can_view_title', 'can_edit', 'can_view', 'can_list_access',
                     'can_update_access', 'can_delete', 'can_change_ownership',
                     'can_request_access', 'can_approve_access'):
            ao[flag] = getattr(d, flag, False)
        result['record_accesses'].append(ao)
    for fu in rs.forbiddenRecords:
        result['forbidden_records'].append(utils.base64_url_encode(fu))
    return result


# ══════════════════════════════════════════════════════════════════════════
# Record sharing  (Strategy: share / update / revoke)
# ══════════════════════════════════════════════════════════════════════════

def _build_share_permissions(params, record_uid, recipient_email, access_role_type,
                              expiration_timestamp, include_role):
    """Build a Permissions protobuf for share/update — single source of truth."""
    from .. import sync_down as sd
    sd.sync_down(params)

    rec = get_record_from_cache(params, record_uid)
    if not rec:
        raise ValueError(f"Record {record_uid} not found in cache")
    rk = rec.get('record_key_unencrypted')
    if not rk:
        raise ValueError(f"Record {record_uid} has no decrypted key")

    pub_key, use_ecc, uid_bytes, needs_invite = get_user_public_key(params, recipient_email)
    if not pub_key:
        handle_share_invite(params, recipient_email, needs_invite)
        raise ValueError(f"User {recipient_email} has no public key")
    if not uid_bytes:
        raise ValueError(f"User {recipient_email} not found")

    enc_rk = encrypt_for_recipient(rk, pub_key, use_ecc)
    uid_b = utils.base64_url_decode(record_uid)

    perm = record_sharing_pb2.Permissions()
    perm.recipientUid = uid_bytes
    perm.recordUid = uid_b
    perm.recordKey = enc_rk
    perm.useEccKey = use_ecc

    perm.rules.accessTypeUid = uid_bytes
    perm.rules.accessType = folder_pb2.AT_USER
    perm.rules.recordUid = uid_b
    perm.rules.owner = False
    if include_role and access_role_type is not None:
        perm.rules.accessRoleType = access_role_type
    if expiration_timestamp:
        perm.rules.tlaProperties.expiration = expiration_timestamp
    return perm


def share_record_v3(params, record_uid, recipient_email, access_role_type,
                    expiration_timestamp=None):
    perm = _build_share_permissions(params, record_uid, recipient_email,
                                     access_role_type, expiration_timestamp,
                                     include_role=True)
    rq = record_sharing_pb2.Request()
    rq.createSharingPermissions.append(perm)
    rs = api.communicate_rest(params, rq, 'vault/records/v3/share',
                              rs_type=record_sharing_pb2.Response)
    results = [parse_sharing_status(s) for s in rs.createdSharingStatus]
    return {'results': results, 'success': all(r['success'] for r in results)}


def update_record_share_v3(params, record_uid, recipient_email,
                            access_role_type=None, expiration_timestamp=None):
    perm = _build_share_permissions(params, record_uid, recipient_email,
                                     access_role_type, expiration_timestamp,
                                     include_role=True)
    rq = record_sharing_pb2.Request()
    rq.updateSharingPermissions.append(perm)
    rs = api.communicate_rest(params, rq, 'vault/records/v3/share',
                              rs_type=record_sharing_pb2.Response)
    results = [parse_sharing_status(s) for s in rs.updatedSharingStatus]
    return {'results': results, 'success': all(r['success'] for r in results)}


def unshare_record_v3(params, record_uid, recipient_email):
    from .. import sync_down as sd
    sd.sync_down(params)

    rec = get_record_from_cache(params, record_uid)
    if not rec:
        raise ValueError(f"Record {record_uid} not found in cache")
    _, _, uid_bytes, _ = get_user_public_key(params, recipient_email)
    if not uid_bytes:
        raise ValueError(f"User {recipient_email} not found")

    uid_b = utils.base64_url_decode(record_uid)
    perm = record_sharing_pb2.Permissions()
    perm.recipientUid = uid_bytes
    perm.recordUid = uid_b
    perm.rules.accessTypeUid = uid_bytes
    perm.rules.accessType = folder_pb2.AT_USER
    perm.rules.recordUid = uid_b

    rq = record_sharing_pb2.Request()
    rq.revokeSharingPermissions.append(perm)
    rs = api.communicate_rest(params, rq, 'vault/records/v3/share',
                              rs_type=record_sharing_pb2.Response)
    results = [parse_sharing_status(s) for s in rs.revokedSharingStatus]
    return {'results': results, 'success': all(r['success'] for r in results)}


# ══════════════════════════════════════════════════════════════════════════
# Ownership transfer
# ══════════════════════════════════════════════════════════════════════════

def _build_transfer_record(params, record_uid, new_owner_email, require_uid=False):
    rec = get_record_from_cache(params, record_uid) or params.record_cache.get(record_uid)
    if not rec:
        return None
    rk = rec.get('record_key_unencrypted')
    if not rk:
        return None

    pub_key, use_ecc, _, _ = get_user_public_key(params, new_owner_email, require_uid=require_uid)
    if not pub_key:
        return None
    enc_rk = encrypt_for_recipient(rk, pub_key, use_ecc)

    tr = record_pb2.TransferRecord()
    tr.username = new_owner_email
    tr.recordUid = utils.base64_url_decode(record_uid)
    tr.recordKey = enc_rk
    tr.useEccKey = use_ecc
    return tr


def transfer_record_ownership_v3(params, record_uid, new_owner_email):
    from .. import sync_down as sd
    sd.sync_down(params)

    tr = _build_transfer_record(params, record_uid, new_owner_email, require_uid=False)
    if not tr:
        raise ValueError(f"Cannot prepare transfer for record {record_uid}")

    rq = record_pb2.RecordsOnwershipTransferRequest()
    rq.transferRecords.append(tr)
    rs = api.communicate_rest(params, rq, 'vault/records/v3/transfer',
                              rs_type=record_pb2.RecordsOnwershipTransferResponse)
    results = [{
        'record_uid': utils.base64_url_encode(s.recordUid),
        'username': s.username, 'status': s.status, 'message': s.message,
        'success': 'success' in s.status.lower(),
    } for s in rs.transferRecordStatus]
    params.sync_data = True
    return {'results': results, 'success': all(r['success'] for r in results)}


def transfer_records_ownership_batch_v3(params, transfers):
    from .. import sync_down as sd
    sd.sync_down(params)

    trs = []
    for spec in transfers:
        tr = _build_transfer_record(params, spec['record_uid'], spec['new_owner_email'])
        if tr:
            trs.append(tr)
    if not trs:
        raise ValueError("No valid transfer records to process")

    rq = record_pb2.RecordsOnwershipTransferRequest()
    rq.transferRecords.extend(trs)
    rs = api.communicate_rest(params, rq, 'vault/records/v3/transfer',
                              rs_type=record_pb2.RecordsOnwershipTransferResponse)
    results = [{
        'record_uid': utils.base64_url_encode(s.recordUid),
        'username': s.username, 'status': s.status, 'message': s.message,
        'success': 'success' in s.status.lower(),
    } for s in rs.transferRecordStatus]
    params.sync_data = True
    ok = sum(1 for r in results if r['success'])
    return {'results': results, 'success': all(r['success'] for r in results),
            'total': len(results), 'successful': ok, 'failed': len(results) - ok}
