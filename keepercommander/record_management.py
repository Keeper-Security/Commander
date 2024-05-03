#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import enum
import json
import logging
from typing import Optional, Union

from keepercommander.breachwatch import BreachWatch

from . import api, subfolder, utils, crypto, vault, vault_extensions
from .error import KeeperApiError
from .params import KeeperParams
from .proto import record_pb2


def add_record_to_folder(params, record, folder_uid=None):
    # type: (KeeperParams, vault.KeeperRecord, Optional[str]) -> None
    if not record.record_uid:
        record.record_uid = utils.generate_uid()
    if not record.record_key:
        record.record_key = utils.generate_aes_key()

    folder = params.folder_cache.get(folder_uid)    # type: Union[None, subfolder.BaseFolderNode]
    folder_key = None      # type: Optional[bytes]
    if isinstance(folder, subfolder.SharedFolderFolderNode):
        shared_folder_uid = folder.shared_folder_uid
    elif isinstance(folder, subfolder.SharedFolderNode):
        shared_folder_uid = folder.uid
    else:
        shared_folder_uid = None
    if shared_folder_uid and shared_folder_uid in params.shared_folder_cache:
        shared_folder = params.shared_folder_cache.get(shared_folder_uid)
        folder_key = shared_folder.get('shared_folder_key_unencrypted')

    if isinstance(record, vault.PasswordRecord):
        rq = {
            'command': 'record_add',
            'record_uid': record.record_uid,
            'record_key': utils.base64_url_encode(
                crypto.encrypt_aes_v1(record.record_key, params.data_key)),
            'record_type': 'password',
            'folder_type': folder.type if folder else 'user_folder',
            'how_long_ago': 0,
        }
        if folder:
            rq['folder_uid'] = folder.uid
        if folder_key:
            rq['folder_key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(record.record_key, folder_key))
        data = vault_extensions.extract_password_record_data(record)
        rq['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode(), record.record_key))
        extra = vault_extensions.extract_password_record_extras(record)
        rq['extra'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(extra).encode(), record.record_key))
        file_ids = []
        if record.attachments:
            for atta in record.attachments:
                file_ids.append(atta.id)
                if atta.thumbnails:
                    for thumb in atta.thumbnails:
                        file_ids.append(thumb.id)
        rq['file_ids'] = file_ids

        rs = api.communicate(params, rq)
        record.revision = rs.get('revision', 0)
        add_record_audit_data(params, record)
        if record.attachments:
            for atta in record.attachments:
                params.queue_audit_event(
                    'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=atta.id)

    elif isinstance(record, vault.TypedRecord):
        add_record = record_pb2.RecordAdd()
        add_record.record_uid = utils.base64_url_decode(record.record_uid)
        add_record.record_key = crypto.encrypt_aes_v2(record.record_key, params.data_key)
        add_record.client_modified_time = utils.current_milli_time()
        add_record.folder_type = record_pb2.user_folder
        if folder:
            add_record.folder_uid = utils.base64_url_decode(folder.uid)
            if folder.type == 'shared_folder':
                add_record.folder_type = record_pb2.shared_folder
            elif folder.type == 'shared_folder_folder':
                add_record.folder_type = record_pb2.shared_folder_folder
            if folder_key:
                add_record.folder_key = crypto.encrypt_aes_v2(record.record_key, folder_key)

        data = vault_extensions.extract_typed_record_data(record)
        json_data = api.get_record_data_json_bytes(data)
        add_record.data = crypto.encrypt_aes_v2(json_data, record.record_key)

        refs = vault_extensions.extract_typed_record_refs(record)
        for ref in refs:
            ref_record_key = None    # type: Optional[bytes]
            if record.linked_keys:
                ref_record_key = record.linked_keys.get(ref)
            if not ref_record_key:
                ref_record = vault.KeeperRecord.load(params, ref)
                if ref_record:
                    ref_record_key = ref_record.record_key

            if ref_record_key:
                link = record_pb2.RecordLink()
                link.record_uid = utils.base64_url_decode(ref)
                link.record_key = crypto.encrypt_aes_v2(ref_record_key, record.record_key)
                add_record.record_links.append(link)

        if params.enterprise_ec_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                add_record.audit.version = 0
                add_record.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

        rq = record_pb2.RecordsAddRequest()
        rq.client_time = utils.current_milli_time()
        rq.records.append(add_record)
        rs = api.communicate_rest(params, rq, 'vault/records_add', rs_type=record_pb2.RecordsModifyResponse)
        record_rs = next((x for x in rs.records if utils.base64_url_encode(x.record_uid) == record.record_uid), None)
        if record_rs:
            if record_rs.status != record_pb2.RS_SUCCESS:
                raise KeeperApiError(record_rs.status, rs.message)
        record.revision = rs.revision
        if record.linked_keys:
            for file_uid in record.linked_keys:
                params.queue_audit_event(
                    'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=file_uid)
    else:
        raise ValueError('Unsupported Keeper record')


class RecordChangeStatus(enum.Flag):
    Title = enum.auto()
    RecordType = enum.auto()
    Username = enum.auto()
    Password = enum.auto()
    URL = enum.auto()


def compare_records(record1, record2):
    # type: (vault.KeeperRecord, vault.KeeperRecord) -> RecordChangeStatus
    status = RecordChangeStatus(0)

    if record1.title != record2.title:
        status = status | RecordChangeStatus.Title
    if BreachWatch.extract_password(record1) != BreachWatch.extract_password(record2):
        status = status | RecordChangeStatus.Password

    if isinstance(record1, vault.PasswordRecord) and isinstance(record2, vault.PasswordRecord):
        if record1.login != record2.login:
            status = status | RecordChangeStatus.Username
        if record1.link != record2.link:
            status = status | RecordChangeStatus.URL
    elif isinstance(record1, vault.TypedRecord) and isinstance(record2, vault.TypedRecord):
        if record1.record_type != record2.record_type:
            status = status | RecordChangeStatus.RecordType

        r_login = record1.get_typed_field('login') or record1.get_typed_field('email')
        e_login = record2.get_typed_field('login') or record2.get_typed_field('email')
        if r_login or e_login:
            if r_login and e_login:
                if r_login.get_external_value() or '' != e_login.get_external_value() or '':
                    status = status | RecordChangeStatus.Username
            else:
                status = status | RecordChangeStatus.Username

        r_url = record1.get_typed_field('url')
        e_url = record2.get_typed_field('url')
        if r_url or e_url:
            if r_url and e_url:
                if r_url.get_external_value() or '' != e_url.get_external_value() or '':
                    status = status | RecordChangeStatus.URL
            else:
                status = status | RecordChangeStatus.URL

    return status


def update_record(params, record, skip_extra=False):
    # type: (KeeperParams, vault.KeeperRecord, bool) -> None
    storage_record = params.record_cache.get(record.record_uid)
    if not storage_record:
        raise Exception(f'Record Update: {record.record_uid} not found.')

    existing_record = vault.KeeperRecord.load(params, storage_record)
    if type(existing_record) != type(record):
        raise Exception(f'Record {record.record_uid}: Invalid record type.')

    record_change_status = compare_records(record, existing_record)

    if isinstance(record, vault.PasswordRecord) and isinstance(existing_record, vault.PasswordRecord):
        record_object = {
            'record_uid': record.record_uid,
            'version': 2,
            'revision': existing_record.revision,
            'client_modified_time': utils.current_milli_time(),
        }
        path = api.resolve_record_write_path(params, record.record_uid)
        if path:
            record_object.update(path)

        data = vault_extensions.extract_password_record_data(record)
        record_object['data'] = utils.base64_url_encode(
            crypto.encrypt_aes_v1(json.dumps(data).encode(), record.record_key))

        if not skip_extra:
            existing_extra = None
            try:
                if 'extra_unencrypted' in storage_record:
                    existing_extra = json.loads(storage_record['extra_unencrypted'])
            except Exception as e:
                logging.warning('Decrypt record %s extra error: %s', record.record_uid, e)

            extra = vault_extensions.extract_password_record_extras(record, existing_extra)
            extra_str = json.dumps(extra)
            record_object['extra'] = utils.base64_url_encode(
                crypto.encrypt_aes_v1(extra_str.encode('utf-8'), record.record_key))

            if 'udata' in storage_record:
                u = storage_record['udata']
                if isinstance(u, dict):
                    udata = u
                elif isinstance(u, (str, bytes)):
                    udata = json.loads(u)
                else:
                    udata = {}
            else:
                udata = {}

            file_ids = []
            udata['file_ids'] = file_ids
            if record.attachments:
                for atta in record.attachments:
                    file_ids.append(atta.id)
                    if atta.thumbnails:
                        for thumb in atta.thumbnails:
                            file_ids.append(thumb.id)
            record_object['udata'] = udata

        rq = {
            "command": "record_update",
            "client_time": utils.current_milli_time(),
            'update_records': [record_object]
        }
        rs = api.communicate(params, rq)
        status = next((x for x in rs.get('update_records', []) if x.get('record_uid') == record.record_uid), None)
        if status:
            record_status = status.get('status', 'success')
            if record_status != 'success':
                raise KeeperApiError(record_status, status.get('message', ''))

        record.revision = rs.get('revision', record.revision)
        add_record_audit_data(params, record)
        prev_file_refs = set((x.id for x in existing_record.attachments or []))
        new_file_refs = set((x.id for x in record.attachments or []))
        for file_id in new_file_refs.difference(prev_file_refs):
            params.queue_audit_event(
                'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=file_id)
        for file_id in prev_file_refs.difference(new_file_refs):
            params.queue_audit_event(
                'file_attachment_deleted', record_uid=record.record_uid, attachment_id=file_id)

    elif isinstance(record, vault.TypedRecord) and isinstance(existing_record, vault.TypedRecord):
        record_uid_bytes = utils.base64_url_decode(record.record_uid)
        ru = record_pb2.RecordUpdate()
        ru.record_uid = record_uid_bytes
        ru.client_modified_time = utils.current_milli_time()
        ru.revision = existing_record.revision

        data = vault_extensions.extract_typed_record_data(record)
        json_data = api.get_record_data_json_bytes(data)
        ru.data = crypto.encrypt_aes_v2(json_data, record.record_key)

        existing_refs = vault_extensions.extract_typed_record_refs(existing_record)
        refs = vault_extensions.extract_typed_record_refs(record)
        for ref in refs.difference(existing_refs):
            ref_record_key = None
            if record.linked_keys and ref in record.linked_keys:
                ref_record_key = record.linked_keys[ref]
            if not ref_record_key:
                ref_record = vault.KeeperRecord.load(params, ref)
                if ref_record:
                    ref_record_key = ref_record.record_key
            if ref_record_key:
                link = record_pb2.RecordLink()
                link.record_uid = utils.base64_url_decode(ref)
                link.record_key = crypto.encrypt_aes_v2(ref_record_key, record.record_key)
                ru.record_links_add.append(link)
        for ref in existing_refs.difference(refs):
            ru.record_links_remove.append(utils.base64_url_decode(ref))

        if params.enterprise_ec_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                ru.audit.version = 0
                ru.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

        rq = record_pb2.RecordsUpdateRequest()
        rq.client_time = utils.current_milli_time()
        rq.records.append(ru)

        rs = api.communicate_rest(params, rq, 'vault/records_update', rs_type=record_pb2.RecordsModifyResponse)
        rs_status = next((x for x in rs.records if record_uid_bytes == x.record_uid), None)
        if rs_status and rs_status.status != record_pb2.RS_SUCCESS:
            raise KeeperApiError(record_pb2.RecordModifyResult.keys()[rs_status.status], rs_status.message)
        record.revision = rs.revision
        for file_id in refs.difference(existing_refs):
            params.queue_audit_event(
                'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=file_id)
        for file_id in existing_refs.difference(refs):
            params.queue_audit_event(
                'file_attachment_deleted', record_uid=record.record_uid, attachment_id=file_id)
    else:
        raise ValueError('Unsupported Keeper record')

    if bool(record_change_status & RecordChangeStatus.Password):
        params.queue_audit_event('record_password_change', record_uid=record.record_uid)
        BreachWatch.scan_and_update_security_data(params, record.record_uid, params.breach_watch)


def add_record_audit_data(params, record):   # type: (KeeperParams, vault.KeeperRecord) -> None
    if params.enterprise_ec_key:
        audit_data = vault_extensions.extract_audit_data(record)
        if audit_data:
            record_audit_rq = record_pb2.RecordAddAuditData()
            record_audit_rq.record_uid = utils.base64_url_decode(record.record_uid)
            record_audit_rq.revision = record.revision
            record_audit_rq.data = crypto.encrypt_ec(
                json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)
            audit_rq = record_pb2.AddAuditDataRequest()
            audit_rq.records.append(record_audit_rq)
            try:
                api.communicate_rest(params, audit_rq, 'vault/record_add_audit_data')
            except Exception as e:
                logging.info('Store audit data error: %s', e)
