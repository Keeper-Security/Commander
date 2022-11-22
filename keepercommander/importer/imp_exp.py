#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from typing import Iterator, List, Optional, Union, Dict, Tuple, Set

"""Import and export functionality."""
import abc
import base64
import collections
import copy
import hashlib
import json
import logging
import os
import re
import itertools
import math
import requests
import time

from .encryption_reader import EncryptionReader
from .importer import (importer_for_format, exporter_for_format, path_components, PathDelimiter, BaseExporter,
                       BaseImporter, Record as ImportRecord, RecordField as ImportRecordField, Folder as ImportFolder,
                       SharedFolder as ImportSharedFolder, Permission as ImportPermission, BytesAttachment,
                       Attachment as ImportAttachment, RecordSchemaField, File as ImportFile,
                       RecordReferences, FIELD_TYPE_ONE_TIME_CODE)
from .. import api
from .. import utils, crypto
from ..commands import base
from ..display import bcolors
from ..error import KeeperApiError, CommandError
from ..params import KeeperParams
from ..proto import record_pb2, folder_pb2
from ..recordv3 import RecordV3
from ..rest_api import CLIENT_VERSION  # pylint: disable=no-name-in-module
from ..subfolder import BaseFolderNode, SharedFolderFolderNode, find_folders, try_resolve_path

EMAIL_PATTERN = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
IV_LEN = 12
GCM_TAG_LEN = 16
RECORD_MAX_DATA_LEN = 32000
RECORD_MAX_DATA_WARN = 'Skipping record "{}": Data size of {} exceeds limit of {}'
LARGE_FIELD_MSG = 'This field is stored as attachment "{}" to avoid 32k record limit'
FILE_ATTACHMENT_CHUNK = 100


STANDARD_RECORD_TYPES = {
    'login', 'bankAccount', 'address', 'bankCard', 'birthCertificate', 'contact', 'driverLicense', 'encryptedNotes', 'file',
    'healthInsurance', 'membership', 'passport', 'photo', 'serverCredentials', 'softwareLicense', 'ssnCard', 'general', 'sshKeys',
    'databaseCredentials', 'wifiCredentials'}


def get_record_data_json_bytes(data):
    """Get serialized and utf-8 encoded record data with padding"""
    data_str = json.dumps(data)
    padding = int(math.ceil(max(384, len(data_str)) / 16) * 16)
    if padding:
        data_str = data_str.ljust(padding)
    return data_str.encode('utf-8')


def get_import_folder(params, folder_uid, record_uid):
    """Get a folder name from a folder uid (?)."""
    folder = ImportFolder()

    uid = folder_uid
    is_path = True
    while uid in params.folder_cache:
        f = params.folder_cache[uid]

        if f.type == 'shared_folder':
            is_path = False
            if f.uid in params.shared_folder_cache:
                sf = params.shared_folder_cache[f.uid]
                if 'records' in sf:
                    for sfr in sf['records']:
                        if sfr['record_uid'] == record_uid:
                            folder.can_share = sfr['can_share']
                            folder.can_edit = sfr['can_edit']
                            break

        name = f.name.replace(PathDelimiter, 2*PathDelimiter)
        if is_path:
            if folder.path:
                folder.path = name + PathDelimiter + folder.path
            else:
                folder.path = name
        else:
            if folder.domain:
                folder.domain = name + PathDelimiter + folder.domain
            else:
                folder.domain = name

        uid = f.parent_uid
        if not uid:
            break

    return folder


def get_folder_path(params, folder_uid):
    """Get the path corresponding to a folder uid."""
    uid = folder_uid
    path = ''
    while uid in params.folder_cache:
        f = params.folder_cache[uid]
        name = f.name.replace(PathDelimiter, 2*PathDelimiter)
        if path:
            path = name + PathDelimiter + path
        else:
            path = name

        uid = f.parent_uid
        if not uid:
            break

    return path


def convert_keeper_record(record, has_attachments=False):
    # type: (dict, bool) -> Optional[ImportRecord]
    record_uid = record.get('record_uid')
    if not record_uid:
        logging.debug('Invalid Keeper record: no record uid')
        return

    version = record.get('version') or 2
    if type(version) != int:
        try:
            version = int(version)
        except:
            logging.debug('Invalid Keeper record \"%s\" version: %s', record_uid, str(version))
            return
    if 'data_unencrypted' not in record:
        return

    data = json.loads(record['data_unencrypted'])
    rec = ImportRecord()
    rec.uid = record_uid
    rec.title = data.get('title') or ''
    rec.notes = data.get('notes') or ''
    if version == 2:
        rec.login = data.get('secret1') or ''
        rec.password = data.get('secret2') or ''
        rec.login_url = data.get('link')
        if 'custom' in data:
            for custom in data['custom'] or []:
                rf = ImportRecordField()
                rf.label = custom.get('name') or ''
                rf.value = custom.get('value') or ''
                rec.fields.append(rf)
        if 'extra_unencrypted' in record:
            extra = json.loads(record['extra_unencrypted'])
            if 'fields' in extra:
                for field in extra['fields']:
                    if field['field_type'] == 'totp':
                        rf = ImportRecordField()
                        rf.type = FIELD_TYPE_ONE_TIME_CODE
                        rf.value = field['data']
                        rec.fields.append(rf)

    elif version == 3 and 'type' in data:
        rec.type = data['type']
        schema_fields = []
        if 'fields' in data:
            for field in data['fields']:
                field_type = field.get('type') or ''
                if field_type:
                    schema_field = RecordSchemaField()
                    schema_field.ref = field_type
                    schema_field.label = field.get('label') or ''
                    schema_fields.append(schema_field)

        if rec.type not in STANDARD_RECORD_TYPES:
            rec.schema = schema_fields

        fields = data.get('fields') if 'fields' in data else []
        custom = data.get('custom') if 'custom' in data else []
        for field in itertools.chain(fields, custom):
            field_value = field.get('value') or ''
            if type(field_value) is list and len(field_value) == 1:
                field_value = field_value[0]
            field_type = field.get('type') or ''

            if field_type == 'login' and not rec.login and type(field_value) == str:
                rec.login = field_value
            elif field_type == 'password' and not rec.password and type(field_value) == str:
                rec.password = field_value
            elif field_type == 'url' and not field.get('label') and not rec.login_url and type(field_value) == str:
                rec.login_url = field_value
            elif field_type.endswith('Ref'):
                ref_type = field_type[:-3]
                if ref_type == 'file' and not has_attachments:
                    continue
                uids = field_value if isinstance(field_value, list) else [str(field_value)]
                uids = [x for x in uids if x]
                if uids:
                    references = RecordReferences()
                    references.type = ref_type
                    references.uids = uids
                    if not rec.references:
                        rec.references = []
                    rec.references.append(references)
            else:
                rf = ImportRecordField()
                rf.type = field_type
                rf.label = field['label'] if 'label' in field else ''
                rf.value = field_value
                if not rf.value:
                    base_field = next((x for x in schema_fields if x.ref == rf.type and x.label == rf.label), None)
                    if base_field:
                        continue
                rec.fields.append(rf)
    else:
        return

    return rec


def export(params, file_format, filename, **kwargs):
    # type: (KeeperParams, str, str, ...) -> None
    """Export data from Vault to a file in an assortment of formats."""
    api.sync_down(params)

    exporter = exporter_for_format(file_format)()  # type: BaseExporter
    if 'max_size' in kwargs:
        exporter.max_size = int(kwargs['max_size'])

    if not filename and not exporter.supports_stdout():
        raise CommandError('export', 'File name parameter is required.')

    folder_filter = None      # type: Optional[Set[str]]
    record_filter = None      # type: Optional[Set[str]]
    folder_path = kwargs.get('folder')
    if folder_path:
        folder = None    # type: Optional[BaseFolderNode]
        rs = try_resolve_path(params, folder_path)
        if rs:
            f, rest = rs
            if not rest:
                folder = f
        if not folder:
            logging.warning('Folder \"%s\" not found', folder_path)
            return
        folder_filter = set()
        record_filter = set()

        def on_folder(base_folder):   # type: (BaseFolderNode) -> None
            folder_filter.add(base_folder.uid)
            if base_folder.uid in params.subfolder_record_cache:
                record_filter.update(params.subfolder_record_cache[base_folder.uid])
        base.FolderMixin.traverse_folder_tree(params, folder.uid, on_folder)

    to_export = []
    if exporter.has_shared_folders():
        shfolders = [api.get_shared_folder(params, sf_uid) for sf_uid in params.shared_folder_cache]
        shfolders.sort(key=lambda x: x.name.lower(), reverse=False)
        for f in shfolders:
            if folder_filter:
                if f.shared_folder_uid not in folder_filter:
                    continue

            fol = ImportSharedFolder()
            fol.uid = f.shared_folder_uid
            fol.path = get_folder_path(params, f.shared_folder_uid)
            fol.manage_users = f.default_manage_users
            fol.manage_records = f.default_manage_records
            fol.can_edit = f.default_can_edit
            fol.can_share = f.default_can_share
            fol.permissions = []
            if f.teams:
                for team in f.teams:
                    perm = ImportPermission()
                    perm.uid = team['team_uid']
                    perm.name = team['name']
                    perm.manage_users = team['manage_users']
                    perm.manage_records = team['manage_records']
                    fol.permissions.append(perm)
            if f.users:
                for user in f.users:
                    perm = ImportPermission()
                    perm.name = user['username']
                    perm.manage_users = user['manage_users']
                    perm.manage_records = user['manage_records']
                    fol.permissions.append(perm)

            to_export.append(fol)
    sf_count = len(to_export)

    force = kwargs.get('force', False)
    if not force and not exporter.supports_v3_record():
        answer = base.user_choice(f'Export to {file_format} format may not support all custom fields, data will be exported as best effort\n\n'
                                  'Do you want to continue?', 'yn', 'n')
        if answer.lower() != 'y':
            return

    # # assign export record id`
    # external_ids = {}
    # ext_id = 0
    # for record_uid in params.record_cache.keys():
    #     ext_id += 1
    #     external_ids[record_uid] = ext_id
    for record_uid in params.record_cache:
        if record_filter:
            if record_uid not in record_filter:
                continue

        record = params.record_cache[record_uid]
        record_version = record.get('version') or 0
        if record_version == 2 or record_version == 3:
            rec = convert_keeper_record(record, exporter.has_attachments())
            if not rec:
                continue

            if exporter.has_attachments():
                if record_version == 2 and 'extra_unencrypted' in record:
                    extra = json.loads(record['extra_unencrypted'])
                    if 'files' in extra:
                        rec.attachments = []
                        names = set()
                        for a in extra['files']:
                            orig_name = a.get('title') or a.get('name') or 'attachment'
                            name = orig_name
                            counter = 0
                            while name in names:
                                counter += 1
                                name = "{0}-{1}".format(orig_name, counter)
                            names.add(name)
                            atta = KeeperV2Attachment(params, rec.uid, a['id'])
                            atta.name = name
                            atta.size = a['size']
                            atta.key = utils.base64_url_decode(a['key'])
                            atta.mime = a.get('type') or ''
                            rec.attachments.append(atta)
                elif record_version == 3:
                    if 'data_unencrypted' in record:
                        data = json.loads(record['data_unencrypted'])
                        file_ref = next((x.get('value') for x in data.get('fields', []) if x.get('type', '') == 'fileRef'), None)
                        if isinstance(file_ref, list) and len(file_ref) > 0:
                            rec.attachments = []
                            for file_uid in file_ref:
                                if file_uid in params.record_cache:
                                    file = params.record_cache[file_uid]
                                    if file.get('version') == 4:
                                        a = json.loads(file['data_unencrypted'])
                                        atta = KeeperV3Attachment(params, file_uid)
                                        atta.key = file['record_key_unencrypted']
                                        atta.name = a.get('name', '')
                                        atta.size = a.get('size', 0)
                                        atta.mime = a.get('type', '')
                                        rec.attachments.append(atta)

            for folder_uid in find_folders(params, record_uid):
                if folder_filter:
                    if folder_uid not in folder_filter:
                        continue
                if folder_uid in params.folder_cache:
                    export_folder = get_import_folder(params, folder_uid, record_uid)
                    if rec.folders is None:
                        rec.folders = []
                    rec.folders.append(export_folder)

            to_export.append(rec)
        # elif record_version == 4:
        #     if 'data_unencrypted' in record:
        #         data = json.loads(record['data_unencrypted'])
        #         file = ImportFile()
        #         file.file_id = record['record_uid']
        #         file.name = data.get('name')
        #         file.title = data.get('title')
        #         file.size = data.get('size')
        #         file.mime = data.get('type')
        #         to_export.append(file)

    rec_count = len(to_export) - sf_count

    if len(to_export) > 0:
        file_password = kwargs.get('keepass_file_password')
        exporter.execute(filename, to_export, file_password)
        params.queue_audit_event('exported_records', file_format=file_format)
        logging.info('%d records exported', rec_count)


def import_user_permissions(params, shared_folders):  # type: (KeeperParams, List[ImportSharedFolder]) -> None
    if not shared_folders:
        return

    folders = [x for x in shared_folders if isinstance(x, ImportSharedFolder) and x.permissions]
    if not folders:
        return

    api.sync_down(params)

    folder_lookup = {}
    if params.folder_cache:
        for f_uid in params.folder_cache:
            fol = params.folder_cache[f_uid]
            f_key = '{0}|{1}'.format((fol.name or '').casefold(), fol.parent_uid or '')
            folder_lookup[f_key] = f_uid, fol.type

    for fol in folders:
        comps = list(path_components(fol.path))
        parent_uid = ''
        for i in range(len(comps)):
            is_last = False
            if i == len(comps) - 1:
                is_last = True
            comp = comps[i]
            if not comp:
                continue
            f_key = '{0}|{1}'.format(comp.casefold(), parent_uid)
            if f_key in folder_lookup:
                parent_uid, fol_type = folder_lookup[f_key]
                if is_last and fol_type == BaseFolderNode.SharedFolderType:
                    fol.uid = parent_uid
            else:
                break

    folders = [x for x in folders if x.uid in params.shared_folder_cache]
    if folders:
        permissions = prepare_folder_permission(params, folders)
        if permissions:
            rs = api.execute_batch(params, permissions)
            api.sync_down(params)
            if rs:
                teams_added = 0
                users_added = 0
                for r in rs:
                    if 'add_teams' in r:
                        teams_added += len([x for x in r['add_teams'] if x.get('status') == 'success'])
                    if 'add_users' in r:
                        users_added += len([x for x in r['add_users'] if x.get('status') == 'success'])
                if teams_added > 0:
                    logging.info("%d team(s) added to shared folders", teams_added)
                if users_added > 0:
                    logging.info("%d user(s) added to shared folders", users_added)


def _import(params, file_format, filename, **kwargs):
    """Import records from one of a variety of sources."""
    shared = kwargs.get('shared') or False
    import_users = kwargs.get('users_only') or False
    old_domain = kwargs.get('old_domain')
    new_domain = kwargs.get('new_domain')
    tmpdir = kwargs.get('tmpdir')
    record_type = kwargs.get('record_type')

    import_into = kwargs.get('import_into') or ''
    if import_into:
        import_into = import_into.replace(PathDelimiter, 2*PathDelimiter)
    update_flag = kwargs['update_flag']

    importer = importer_for_format(file_format)()  # type: BaseImporter

    records_before = len(params.record_cache)

    folders = []        # type: List[ImportSharedFolder]
    records = []        # type: List[ImportRecord]
    files = []          # type: List[ImportFile]

    for x in importer.execute(filename, params=params, users_only=import_users,
                              old_domain=old_domain, new_domain=new_domain, tmpdir=tmpdir):
        if isinstance(x, ImportRecord):
            if shared or import_into:
                if not x.folders:
                    x.folders = [ImportFolder()]
                for f in x.folders:
                    if shared:
                        d_comps = list(path_components(f.domain)) if f.domain else []
                        p_comps = list(path_components(f.path)) if f.path else []
                        if len(d_comps) > 0:
                            f.domain = d_comps[0]
                            p_comps[0:0] = d_comps[1:]
                        elif len(p_comps) > 0:
                            f.domain = p_comps[0]
                            p_comps = p_comps[1:]
                        f.path = PathDelimiter.join([x.replace(PathDelimiter, 2*PathDelimiter) for x in p_comps])
                    if import_into:
                        if f.domain:
                            f.domain = PathDelimiter.join([import_into, f.domain])
                        elif f.path:
                            f.path = PathDelimiter.join([import_into, f.path])
                        else:
                            f.path = import_into

            if record_type and not x.type:
                x.type = record_type
            try:
                x.validate()
            except CommandError as ce:
                logging.info(ce.message)
            records.append(x)
        elif isinstance(x, ImportSharedFolder):
            if shared:
                continue
            x.validate()
            if import_into:
                if x.path:
                    x.path = PathDelimiter.join([import_into, x.path])

            folders.append(x)

    if import_users:
        import_user_permissions(params, folders)
        return

    api.sync_down(params)

    manage_users = kwargs.get('manage_users') or False
    manage_records = kwargs.get('manage_records') or False
    can_edit = kwargs.get('can_edit') or False
    can_share = kwargs.get('can_share') or False

    if shared:
        sfol = set()
        for r in records:
            if r.folders:
                for f in r.folders:
                    if f.domain:
                        sfol.add(f.domain)
        for x in sfol:
            sf = ImportSharedFolder()
            sf.path = x
            sf.manage_users = manage_users
            sf.manage_records = manage_records
            sf.can_edit = can_edit
            sf.can_share = can_share
            folders.append(sf)

    folder_add = prepare_folder_add(params, folders, records, manage_users, manage_records, can_edit, can_share)
    if folder_add:
        fol_rs, _ = execute_import_folder_record(params, folder_add, None)
        _ = fol_rs
        api.sync_down(params)

    if files:
        pass

    record_keys = {}
    audit_uids = []

    if records:  # create/update records
        records_v2_to_add = []      # type: List[folder_pb2.RecordRequest]
        records_v2_to_update = []   # type: List[dict]
        records_v3_to_add = []      # type: List[record_pb2.RecordAdd]
        records_v3_to_update = []   # type: List[record_pb2.RecordUpdate]
        import_uids = {}

        records_to_import, external_lookup = prepare_record_add_or_update(update_flag, params, records)

        reference_uids = set()
        for import_record in records_to_import:
            existing_record = params.record_cache.get(import_record.uid)
            record_key = existing_record['record_key_unencrypted'] if existing_record else utils.generate_aes_key()
            record_keys[import_record.uid] = record_key

            reference_uids.clear()
            if import_record.references:
                for ref in import_record.references:
                    reference_uids.update([x for x in ref.uids if x in params.record_cache])

            if import_record.type and import_record.fields:
                for field in import_record.fields:
                    if field.type in RecordV3.field_values:
                        type_value = RecordV3.field_values[field.type].get('value')
                        if type_value is None:
                            continue
                        field_type = type(type_value)
                        if isinstance(field.value, list):
                            field.value = [x for x in field.value if isinstance(x, field_type)]
                        else:
                            if not isinstance(field.value, field_type):
                                field.value = copy.deepcopy(type_value)

            if existing_record:
                version = existing_record.get('version', 0)
                if version == 3:   # V3
                    orig_data = json.loads(existing_record['data_unencrypted'])
                    if not import_record.type:
                        import_record.type = orig_data.get('type', 'login')
                    v3_upd_rq = record_pb2.RecordUpdate()
                    v3_upd_rq.record_uid = utils.base64_url_decode(import_record.uid)
                    import_uids[import_record.uid] = {'ver': 'v3', 'op': 'update'}
                    v3_upd_rq.client_modified_time = utils.current_milli_time()
                    v3_upd_rq.revision = existing_record.get('revision') or 0
                    data = _construct_record_v3_data(import_record, orig_data)
                    v3_upd_rq.data = crypto.encrypt_aes_v2(api.get_record_data_json_bytes(data), record_key)
                    data_size = len(v3_upd_rq.data)
                    if data_size > RECORD_MAX_DATA_LEN:
                        logging.warning(RECORD_MAX_DATA_WARN.format(data['title'], data_size, RECORD_MAX_DATA_LEN))
                        continue

                    orig_refs = set()
                    if 'fields' in orig_data:
                        for field in itertools.chain(orig_data['fields'], orig_data['custom'] if 'custom' in orig_data else []):
                            if 'type' in field and 'value' in field:
                                if field['type'].endswith('Ref'):
                                    uids = field['value']
                                    if type(uids) is not list:
                                        uids = [uids]
                                    for uid in uids:
                                        if uid in params.record_cache:
                                            orig_refs.add(uid)

                    for uid in orig_refs.difference(reference_uids):
                        v3_upd_rq.record_links_remove.append(utils.base64_url_decode(uid))

                    for uid in reference_uids.difference(orig_refs):
                        link = record_pb2.RecordLink()
                        link.record_uid = utils.base64_url_decode(uid)
                        v3_upd_rq.record_links_add.append(link)

                    records_v3_to_update.append(v3_upd_rq)
                elif version == 2:
                    orig_extra = json.loads(existing_record['extra_unencrypted']) if 'extra_unencrypted' in existing_record else None

                    data, extra = _construct_record_v2(import_record, orig_extra)
                    encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), record_key)
                    v2_upd_rq = {
                        'record_uid': import_record.uid,
                        'data': utils.base64_url_encode(encrypted_data),
                        'version': 2,
                        'client_modified_time': api.current_milli_time(),
                        'revision': existing_record.get('revision') or 0,
                    }
                    import_uids[import_record.uid] = {'ver': 'v2', 'op': 'update'}
                    if extra:
                        encrypted_extra = crypto.encrypt_aes_v1(json.dumps(extra).encode('utf-8'), record_key)
                        v2_upd_rq['extra'] = utils.base64_url_encode(encrypted_extra)

                    records_v2_to_update.append(v2_upd_rq)
            else:
                # pick a folder to insert the record
                folder_type = BaseFolderNode.UserFolderType
                folder_uid = ''
                shared_folder_key = b''
                if import_record.folders:
                    folder_uid = import_record.folders[0].uid
                if folder_uid in params.folder_cache:
                    folder = params.folder_cache[folder_uid]    # type: Union[BaseFolderNode, SharedFolderFolderNode]
                    folder_type = folder.type
                    if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        shared_folder_uid = folder.uid if folder.type == BaseFolderNode.SharedFolderType else folder.shared_folder_uid
                        shared_folder = params.shared_folder_cache[shared_folder_uid]
                        shared_folder_key = shared_folder.get('shared_folder_key_unencrypted')
                    else:
                        if folder.type == BaseFolderNode.RootFolderType:
                            folder_uid = ''

                if import_record.type:   # V3
                    v3_add_rq = record_pb2.RecordAdd()
                    v3_add_rq.record_uid = utils.base64_url_decode(import_record.uid)
                    import_uids[import_record.uid] = {'ver': 'v3', 'op': 'add'}
                    v3_add_rq.client_modified_time = utils.current_milli_time()
                    data = _construct_record_v3_data(import_record)
                    v3_add_rq.data = crypto.encrypt_aes_v2(api.get_record_data_json_bytes(data), record_key)
                    data_size = len(v3_add_rq.data)
                    if data_size > RECORD_MAX_DATA_LEN:
                        logging.warning(RECORD_MAX_DATA_WARN.format(data['title'], data_size, RECORD_MAX_DATA_LEN))
                        continue

                    v3_add_rq.record_key = crypto.encrypt_aes_v2(record_key, params.data_key)
                    v3_add_rq.folder_type = \
                        record_pb2.user_folder if folder_type == BaseFolderNode.UserFolderType else \
                        record_pb2.shared_folder if folder_type == BaseFolderNode.SharedFolderType else \
                        record_pb2.shared_folder_folder

                    if folder_uid:
                        v3_add_rq.folder_uid = utils.base64_url_decode(folder_uid)
                        if shared_folder_key:
                            v3_add_rq.folder_key = crypto.encrypt_aes_v2(record_key, shared_folder_key)
                    for uid in reference_uids:
                        link = record_pb2.RecordLink()
                        link.record_uid = utils.base64_url_decode(uid)
                        v3_add_rq.record_links.append(link)

                    if params.enterprise_ec_key:
                        audit_data = {
                            'title': import_record.title,
                            'record_type': import_record.type
                        }
                        if import_record.login_url:
                            audit_data['url'] = utils.url_strip(import_record.login_url)
                        v3_add_rq.audit.version = 0
                        v3_add_rq.audit.data = crypto.encrypt_ec(json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

                    records_v3_to_add.append(v3_add_rq)
                else:
                    v2_add_rq = folder_pb2.RecordRequest()
                    v2_add_rq.recordUid = utils.base64_url_decode(import_record.uid)
                    import_uids[import_record.uid] = {'ver': 'v2', 'op': 'add'}
                    v2_add_rq.recordType = 0
                    v2_add_rq.howLongAgo = 0
                    data, extra = _construct_record_v2(import_record)
                    v2_add_rq.recordData = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), record_key)
                    if extra:
                        v2_add_rq.extra = crypto.encrypt_aes_v1(json.dumps(extra).encode('utf-8'), record_key)
                    v2_add_rq.encryptedRecordKey = crypto.encrypt_aes_v1(record_key, params.data_key)
                    v2_add_rq.folderType = \
                        folder_pb2.user_folder if folder_type == BaseFolderNode.UserFolderType else \
                        folder_pb2.shared_folder if folder_type == BaseFolderNode.SharedFolderType else \
                        folder_pb2.shared_folder_folder
                    if folder_uid:
                        v2_add_rq.folderUid = utils.base64_url_decode(folder_uid)
                        if shared_folder_key:
                            v2_add_rq.encryptedRecordFolderKey = crypto.encrypt_aes_v1(record_key, shared_folder_key)

                    records_v2_to_add.append(v2_add_rq)
                    if params.enterprise_ec_key:
                        audit_uids.append(import_record.uid)

        for v3_add_rq in records_v3_to_add:
            record_uid = utils.base64_url_encode(v3_add_rq.record_uid)
            record_key = record_keys.get(record_uid)
            for link in v3_add_rq.record_links:
                link_uid = link.record_uid
                link_key = record_keys.get(link_uid)
                if record_key and link_key:
                    link.record_key = crypto.encrypt_aes_v2(link_key, record_key)

        for v3_upd_rq in records_v3_to_update:
            record_uid = utils.base64_url_encode(v3_upd_rq.record_uid)
            record_key = record_keys.get(record_uid)
            for link in v3_upd_rq.record_links_add:
                link_uid = link.record_uid
                link_key = record_keys.get(link_uid)
                if record_key and link_key:
                    link.record_key = crypto.encrypt_aes_v2(link_key, record_key)

        if records_v2_to_add:
            _, rec_rs = execute_import_folder_record(params, None, records_v2_to_add)
        if records_v3_to_add:
            rec_rs = execute_records_add(params, records_v3_to_add)
        if records_v2_to_update:
            execute_update_v2_record(params, records_v2_to_update)
        if records_v3_to_update:
            rec_rs = execute_records_update(params, records_v3_to_update)

        api.sync_down(params)

        # update audit data
        if audit_uids and params.enterprise_ec_key:
            audit_records = list(prepare_record_audit(params, audit_uids))
            while audit_records:
                try:
                    rq = record_pb2.AddAuditDataRequest()
                    rq.records.extend(audit_records[:999])
                    audit_records = audit_records[999:]
                    api.communicate_rest(params, rq, 'vault/record_add_audit_data')
                except Exception as e:
                    logging.debug('Update record audit error: %s', e)
            api.sync_down(params)

        # ensure records are linked to folders
        record_links = prepare_record_link(params, records)
        if record_links:
            api.execute_batch(params, record_links)
            api.sync_down(params)

        # adjust shared folder permissions
        shared_update = prepare_record_permission(params, records)
        if shared_update:
            api.execute_batch(params, shared_update)
            api.sync_down(params)

        # upload attachments
        v2_atts = []
        v3_atts = []
        for r in records:
            if r.attachments:
                if r.uid in import_uids:
                    ver = import_uids[r.uid]['ver']
                    if ver == 'v3':
                        v3_atts.append(r)
                    else:
                        for a in r.attachments:
                            v2_atts.append((r.uid, a))
                elif r.uid in external_lookup:
                    existing_record = params.record_cache[external_lookup[r.uid]]
                    existing_data = json.loads(existing_record['data_unencrypted'])
                    filerefs = [f for f in existing_data.get('fields', []) if f['type'] == 'fileRef']
                    if len(filerefs) > 0:
                        existing_attachments = [
                            params.record_cache[u] for u in filerefs[0].get('value') or [] if u in params.record_cache
                        ]
                        attachment_data = [json.loads(a['data_unencrypted']) for a in existing_attachments]
                    else:
                        attachment_data = []

                    found_attachments = []
                    missing_attachments = []
                    for a in r.attachments:
                        data = [
                            d for d in attachment_data if d.get('title') == a.name and d.get('size') == a.size
                        ]
                        if len(data) > 0:
                            found_attachments.append(a)
                        else:
                            missing_attachments.append(a)

                    if found_attachments:
                        found = len(found_attachments)
                        total = len(r.attachments)
                        print(f'Found {found} of {total} attachments in record {r.title}.')
                        if missing_attachments:
                            for a in found_attachments:
                                r.attachments.remove(a)

                    if missing_attachments:
                        r.uid = external_lookup[r.uid]
                        if r.type:
                            v3_atts.append(r)

        if len(v2_atts) > 0:
            upload_attachment(params, v2_atts)
        if len(v3_atts) > 0:
            upload_v3_attachments(params, v3_atts)

    if hasattr(importer, 'cleanup') and callable(importer.cleanup):
        importer.cleanup()

    records_after = len(params.record_cache)
    if records_after > records_before:
        params.queue_audit_event('imported_records', file_format=file_format.upper())
        logging.info("%d records imported successfully", records_after - records_before)


def report_statuses(status_type, status_iter):
    """Report status codes from list of folder_pb2.*Response."""
    counter = collections.Counter(element.lower() for element in status_iter)
    for status, count in sorted(counter.items()):
        logging.info('%-15s %-15s %d', status_type, status, count)


def chunks(list_, n):
    """
    Yield successive n-sized chunks from list_.

    Based on https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
    """
    for offset in range(0, len(list_), n):
        yield list_[offset:offset + n]


def execute_update_v2_record(params, records_to_update):
    """Interact with the API to update preexisting records: we only change the password(s)."""
    for chunk in chunks(records_to_update, 100):
        request = {
            'command': 'record_update',
            'username': params.user,
            'session_token': params.session_token,
            'client_version': CLIENT_VERSION,
            'locale': api.LOCALE,
            'pt': 'Commander',
            'client_time': api.current_milli_time(),
            'update_records': chunk,
            'device_id': 'Commander',
        }
        result = api.communicate(params, request)
        if isinstance(result, dict):
            if 'result' in result:
                # Note that this may appear more than once for an import with many password updates
                report_statuses('update', (element['status'] for element in result['update_records']))
            else:
                logging.info('overall operation failed')


def execute_import_folder_record(params, folders, records):
    """Interact with the API to import folders and records."""
    rs_folder = []
    rs_record = []
    while folders or records:
        rq = folder_pb2.ImportFolderRecordRequest()
        cap = 999
        if folders:
            chunk = folders[:cap]
            folders = folders[cap:]
            cap = cap - len(folders)
            for e in chunk:
                rq.folderRequest.append(e)
        if records and cap > 0:
            chunk = records[:cap]
            records = records[cap:]
            for e in chunk:
                rq.recordRequest.append(e)

        rs = api.communicate_rest(params, rq, "folder/import_folders_and_records")
        import_rs = folder_pb2.ImportFolderRecordResponse()
        import_rs.ParseFromString(rs)
        if len(import_rs.folderResponse) > 0:
            rs_folder.extend(import_rs.folderResponse)
        if len(import_rs.recordResponse) > 0:
            rs_record.extend(import_rs.recordResponse)
        if len(folders or []) > 0 or len(records or []) > 0:
            time.sleep(5)

    report_statuses('folder', (element.status for element in rs_folder))
    report_statuses('legacy record', (element.status for element in rs_record))

    return rs_folder, rs_record


def record_status_to_str(status):  # type: (record_pb2.RecordModifyStatus) -> str
    if status == record_pb2.RS_SUCCESS:
        return 'success'
    if status == record_pb2.RS_OUT_OF_SYNC:
        return 'out of sync'
    if status == record_pb2.RS_ACCESS_DENIED:
        return 'access denied'
    if status == record_pb2.RS_SHARE_DENIED:
        return 'share denied'
    if status == record_pb2.RS_RECORD_EXISTS:
        return 'record exists'
    if status == record_pb2.RS_OLD_RECORD_VERSION_TYPE:
        return 'old record version type'
    return str(status)


def execute_records_add(params, records):  # type: (KeeperParams, List[record_pb2.RecordAdd]) -> List[record_pb2.RecordModifyResult]
    rs_record = []
    while records:
        rq = record_pb2.RecordsAddRequest()
        rq.client_time = utils.current_milli_time()
        rq.records.extend(records[:999])
        records = records[999:]
        rs = api.communicate_rest(params, rq, 'vault/records_add', rs_type=record_pb2.RecordsModifyResponse)
        rs_record.extend(rs.records)

    report_statuses('record', (record_status_to_str(x.status) for x in rs_record))

    return rs_record


def execute_records_update(params, records):  # type: (KeeperParams, List[record_pb2.RecordUpdate]) -> List[record_pb2.RecordModifyResult]
    rs_record = []
    while records:
        rq = record_pb2.RecordsUpdateRequest()
        rq.client_time = utils.current_milli_time()
        rq.records.extend(records[:999])
        records = records[999:]
        rs = api.communicate_rest(params, rq, 'vault/records_update', rs_type=record_pb2.RecordsModifyResponse)
        rs_record.extend(rs.records)

    report_statuses('record', (record_status_to_str(x.status) for x in rs_record))

    return rs_record


def upload_v3_attachments(params, records_with_attachments):  # type: (KeeperParams, list) -> None
    """Interact with the API to upload v3 attachments"""
    print('Uploading v3 attachments:')

    while len(records_with_attachments) > 0:
        file_attachment_chunk = 0
        rq = record_pb2.FilesAddRequest()
        uid_to_attachment = {}
        for i, parent_record in enumerate(records_with_attachments):
            file_attachment_chunk += len(parent_record.attachments)
            if file_attachment_chunk > FILE_ATTACHMENT_CHUNK and i > 0:
                records_with_attachments = records_with_attachments[i:]
                break
            parent_uid = parent_record.uid
            existing_record = params.record_cache.get(parent_uid)
            for atta in parent_record.attachments:  # type: ImportAttachment
                if not existing_record:
                    parent_title = getattr(parent_record, 'title', '')
                    logging.warning(
                        f'Upload of {atta.name} failed: Parent record {parent_title} ({parent_uid}) is missing.'
                    )
                    continue

                atta.prepare()
                if isinstance(atta.size, int):
                    if atta.size > 100 * 2 ** 20:  # hard limit at 100MB for upload
                        logging.warning(
                            f'Upload of {atta.name} failed: File size of {atta.size} exceeds the 100MB maximum.'
                        )
                        continue

                file_data = {
                    'name': atta.name,
                    'size': atta.size,
                    'title': atta.name,
                    'lastModified': api.current_milli_time(),
                    'type': 'application/octet-stream'
                }
                rdata = json.dumps(file_data).encode('utf-8')

                file_key = utils.generate_aes_key()
                file_uid = utils.base64_url_decode(api.generate_record_uid())

                rf = record_pb2.File()
                rf.record_uid = file_uid
                rf.record_key = crypto.encrypt_aes_v2(file_key, params.data_key)
                rf.data = crypto.encrypt_aes_v2(rdata, file_key)
                rf.fileSize = IV_LEN + atta.size + GCM_TAG_LEN
                rq.files.append(rf)
                uid_to_attachment[file_uid] = (atta, parent_uid, file_key)

        else:  # for i, parent_record in enumerate(records_with_attachments)
            records_with_attachments = []

        rq.client_time = api.current_milli_time()
        rs = api.communicate_rest(params, rq, 'vault/files_add')
        files_add_rs = record_pb2.FilesAddResponse()
        files_add_rs.ParseFromString(rs)

        new_attachments_by_parent_uid = {}  # type: Dict[Tuple[ImportAttachment, bytes, bytes]]
        for f in files_add_rs.files:
            atta, parent_uid, file_key = uid_to_attachment[f.record_uid]
            status = record_pb2.FileAddResult.DESCRIPTOR.values_by_number[f.status].name
            success = (f.status == record_pb2.FileAddResult.DESCRIPTOR.values_by_name['FA_SUCCESS'].number)

            if not success:
                logging.warning(f'{bcolors.FAIL}Upload of {atta.name} failed with status: {status}{bcolors.ENDC}')
                continue

            with atta.open() as src:
                with EncryptionReader.get_buffered_reader(src, file_key) as encrypted_src:
                    form_files = {'file': (atta.name, encrypted_src, 'application/octet-stream')}
                    form_params = json.loads(f.parameters)
                    print(f'{atta.name} ... ', end='', flush=True)
                    response = requests.post(f.url, data=form_params, files=form_files)

            if str(response.status_code) == form_params.get('success_action_status'):
                print('Done')
                new_attachments = new_attachments_by_parent_uid.get(parent_uid)
                if new_attachments:
                    new_attachments.append((atta, f.record_uid, file_key))
                else:
                    new_attachments_by_parent_uid[parent_uid] = [(atta, f.record_uid, file_key)]
            else:
                print('Failed')

        rec_list = []
        record_links_add = {}
        for parent_uid, attachments in new_attachments_by_parent_uid.items():
            new_attachments_uids = [utils.base64_url_encode(a[1]) for a in attachments]

            record_data = params.record_cache[parent_uid].get('data_unencrypted')
            if record_data:
                if isinstance(record_data, bytes):
                    record_data = record_data.decode('utf-8')
                data = json.loads(record_data.strip())
            else:
                data = {}
            if 'fields' not in data:
                data['fields'] = []

            # find first fileRef or create new fileRef if missing
            file_ref = next((ft for ft in data['fields'] if ft['type'] == 'fileRef'), None)
            if file_ref:
                file_ref['value'] = file_ref.get('value', []) + new_attachments_uids
            else:
                data['fields'].append({'type': 'fileRef', 'value': new_attachments_uids})

            new_data = json.dumps(data)
            params.record_cache[parent_uid]['data_unencrypted'] = new_data
            params.sync_data = True
            rec = api.get_record(params, parent_uid)
            rec_list.append(rec)

            parent_key = params.record_cache[parent_uid]['record_key_unencrypted']
            record_links_add[parent_uid] = [
                {'record_uid': a[1], 'record_key': crypto.encrypt_aes_v2(a[2], parent_key)} for a in attachments
            ]

        api.update_records_v3(params, rec_list, record_links_by_uid={'record_links_add': record_links_add}, silent=True)


def upload_attachment(params, attachments):
    """
    Interact with the API to upload attachments.

    :param attachments:
    :type attachments: [(str, ImportAttachment)]
    """
    print('Uploading attachments:')
    while len(attachments) > 0:
        chunk = attachments[:90]
        attachments = attachments[90:]

        uploads = None

        file_no = 0
        file_size = 0
        for _, att in chunk:
            file_no += 1
            file_size += att.size or 0

        # TODO check storage subscription
        rq = {
            'command': 'request_upload',
            'file_count': file_no
        }
        try:
            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                uploads = rs['file_uploads']
        except Exception as e:
            logging.error(e)
            return

        uploaded = {}
        crypter = crypto.StreamCrypter()
        crypter.is_gcm = False
        for record_id, atta in chunk:
            if not uploads:
                break

            try:
                upload = uploads.pop()
                key = utils.generate_aes_key()
                crypter.key = key
                with atta.open() as plain, crypter.set_stream(plain, True) as encypted:
                    files = {
                        upload['file_parameter']: (atta.name, encypted, 'application/octet-stream')
                    }
                    print('{0} ... '.format(atta.name), end='', flush=True)
                    response = requests.post(upload['url'], files=files, data=upload['parameters'])
                    if response.status_code == upload['success_status_code']:
                        if record_id not in uploaded:
                            uploaded[record_id] = []
                        uploaded[record_id].append({
                            'key': utils.base64_url_encode(key),
                            'name': atta.name,
                            'file_id': upload['file_id'],
                            'size': crypter.bytes_read
                        })
                        print('Done')
                    else:
                        print('Failed')

            except Exception as e:
                logging.warning(e)

        if len(uploaded) > 0:
            rq = {
                'command': 'record_update',
                'pt': 'Commander',
                'device_id': 'Commander',
                'client_time': api.current_milli_time(),
                'update_records': []
            }
            for record_id in uploaded:
                if record_id in params.record_cache:
                    rec = params.record_cache[record_id]
                    extra = json.loads(rec['extra_unencrypted'].decode('utf-8')) if 'extra' in rec else {}
                    files = extra.get('files')
                    if files is None:
                        files = []
                        extra['files'] = files
                    udata = rec['udata'] if 'udata' in rec else {}
                    file_ids = udata.get('file_ids')
                    if file_ids is None:
                        file_ids = []
                        udata['file_ids'] = file_ids
                    for atta in uploaded[record_id]:
                        file_ids.append(atta['file_id'])
                        files.append({
                            'id': atta['file_id'],
                            'name': atta['name'],
                            'size': atta['size'],
                            'key': atta['key']
                        })

                    ru = {
                        'record_uid': record_id,
                        'version': 2,
                        'client_modified_time': api.current_milli_time(),
                        'extra': api.encrypt_aes(json.dumps(extra).encode('utf-8'), rec['record_key_unencrypted']),
                        'udata': udata,
                        'revision': rec['revision']
                    }
                    api.resolve_record_access_path(params, record_id, path=ru)
                    rq['update_records'].append(ru)
            try:
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    api.sync_down(params)
            except Exception as e:
                logging.debug(e)


def prepare_folder_add(params, folders, records, manage_users, manage_records, can_edit, can_share):
    """Find what folders to import (?)."""
    folder_hash = {}
    for f_uid in params.folder_cache:
        fol = params.folder_cache[f_uid]
        h = hashlib.md5()
        hs = '{0}|{1}'.format((fol.name or '').lower(), fol.parent_uid or '')
        h.update(hs.encode())
        shared_folder_key = None
        if fol.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            sf_uid = fol.shared_folder_uid if fol.type == BaseFolderNode.SharedFolderFolderType else fol.uid
            if sf_uid in params.shared_folder_cache:
                shared_folder_key = params.shared_folder_cache[sf_uid]['shared_folder_key_unencrypted']
        folder_hash[h.hexdigest()] = f_uid, fol.type, shared_folder_key

    folder_add = []      # type: [folder_pb2.FolderRequest]
    if folders:
        for fol in folders:
            skip_folder = False
            parent_uid = ''
            comps = list(path_components(fol.path))
            for i in range(len(comps)):
                comp = comps[i]
                h = hashlib.md5()
                hs = '{0}|{1}'.format(comp.lower(), parent_uid)
                h.update(hs.encode())
                digest = h.hexdigest()

                is_last = False
                if i == len(comps) - 1:
                    is_last = True

                if digest not in folder_hash:
                    folder_uid = api.generate_record_uid()
                    folder_type = 'shared_folder' if is_last else 'user_folder'

                    fol_req = folder_pb2.FolderRequest()
                    fol_req.folderUid = base64.urlsafe_b64decode(folder_uid + '==')
                    fol_req.folderType = 2 if folder_type == 'shared_folder' else 1

                    if parent_uid:
                        fol_req.parentFolderUid = base64.urlsafe_b64decode(parent_uid + '==')

                    folder_key = os.urandom(32)
                    fol_req.encryptedFolderKey = base64.urlsafe_b64decode(api.encrypt_aes(folder_key, params.data_key) + '==')

                    data = {'name': comp}
                    string = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)
                    fol_req.folderData = base64.urlsafe_b64decode(string + '==')

                    if folder_type == 'shared_folder':
                        string2 = api.encrypt_aes(comp.encode('utf-8'), folder_key)
                        fol_req.sharedFolderFields.encryptedFolderName = base64.urlsafe_b64decode(string2 + '==')
                        fol_req.sharedFolderFields.manageUsers = fol.manage_users or manage_users
                        fol_req.sharedFolderFields.manageRecords = fol.manage_records or manage_records
                        fol_req.sharedFolderFields.canEdit = fol.can_edit or can_edit
                        fol_req.sharedFolderFields.canShare = fol.can_share or can_share

                    folder_add.append(fol_req)
                    folder_hash[digest] = folder_uid, folder_type, folder_key if folder_type == 'shared_folder' else None
                else:
                    folder_uid, folder_type, folder_key = folder_hash[digest]
                    if is_last:
                        skip_folder = folder_type != 'shared_folder'
                    else:
                        skip_folder = folder_type != 'user_folder'

                parent_uid = folder_uid
                if skip_folder:
                    break

    if records:
        for rec in records:
            if rec.folders:
                for fol in rec.folders:
                    parent_uid = ''
                    parent_shared_folder_uid = None
                    parent_shared_folder_key = None
                    parent_type = ''
                    for is_domain in [True, False]:
                        path = fol.domain if is_domain else fol.path
                        if not path:
                            continue

                        comps = list(path_components(path))
                        for i in range(len(comps)):
                            comp = comps[i]
                            h = hashlib.md5()
                            hs = '{0}|{1}'.format(comp.lower(), parent_uid)
                            h.update(hs.encode())
                            digest = h.hexdigest()

                            if digest not in folder_hash:
                                is_shared = False
                                if i == len(comps) - 1:
                                    is_shared = is_domain

                                folder_uid = api.generate_record_uid()
                                if not parent_type or parent_type == 'user_folder':
                                    folder_type = 'shared_folder' if is_shared else 'user_folder'
                                else:
                                    folder_type = 'shared_folder_folder'

                                fol_req = folder_pb2.FolderRequest()
                                fol_req.folderUid = base64.urlsafe_b64decode(folder_uid + '==')
                                fol_req.folderType = 2 \
                                    if folder_type == 'shared_folder' \
                                    else 3 \
                                    if folder_type == 'shared_folder_folder' \
                                    else 1

                                if parent_uid:
                                    fol_req.parentFolderUid = base64.urlsafe_b64decode(parent_uid + '==')
                                    if folder_type == 'shared_folder_folder' and parent_uid == parent_shared_folder_uid:
                                        fol_req.parentFolderUid = b''

                                folder_key = os.urandom(32)
                                if folder_type == 'shared_folder_folder':
                                    string3 = api.encrypt_aes(folder_key, parent_shared_folder_key or params.data_key)
                                    fol_req.encryptedFolderKey = base64.urlsafe_b64decode(string3 + '==')
                                else:
                                    string4 = api.encrypt_aes(folder_key, params.data_key)
                                    fol_req.encryptedFolderKey = base64.urlsafe_b64decode(string4 + '==')

                                data = {'name': comp}
                                string5 = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)
                                fol_req.folderData = base64.urlsafe_b64decode(string5 + '==')

                                if folder_type == 'shared_folder':
                                    string6 = api.encrypt_aes(comp.encode('utf-8'), folder_key)
                                    fol_req.sharedFolderFields.encryptedFolderName = base64.urlsafe_b64decode(string6 + '==')

                                    parent_shared_folder_key = folder_key
                                    parent_shared_folder_uid = folder_uid

                                elif folder_type == 'shared_folder_folder':
                                    if parent_shared_folder_uid:
                                        fol_req.sharedFolderFolderFields.sharedFolderUid = \
                                            base64.urlsafe_b64decode(parent_shared_folder_uid + '==')

                                folder_add.append(fol_req)
                                folder_hash[digest] = folder_uid, folder_type, parent_shared_folder_key
                            else:
                                folder_uid, folder_type, parent_shared_folder_key = folder_hash[digest]

                            if folder_type == 'shared_folder':
                                parent_shared_folder_uid = folder_uid

                            parent_uid = folder_uid
                            parent_type = folder_type

                    fol.uid = parent_uid

    return folder_add


def prepare_record_audit(params, uids):
    # type: (KeeperParams, Iterator[str]) -> Iterator[record_pb2.RecordAddAuditData]
    if not params.enterprise_ec_key:
        return
    for uid in uids:
        if uid in params.record_cache:
            keeper_record = params.record_cache[uid]
            import_record = convert_keeper_record(keeper_record)
            if import_record and import_record.title:
                title = import_record.title
                if len(title) > 900:
                    title = title[:900]
                record_type = import_record.type
                audit_data = {
                    'title': title,
                    'record_type': import_record.type
                }
                if import_record.login_url:
                    audit_data['url'] = utils.url_strip(import_record.login_url)
                record_audit_rq = record_pb2.RecordAddAuditData()
                record_audit_rq.record_uid = utils.base64_url_decode(uid)
                record_audit_rq.revision = 0
                record_audit_rq.data = crypto.encrypt_ec(json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)
                yield record_audit_rq


RECORD_FIELD_TYPES = {'login', 'password', 'url'}
IGNORABLE_FIELD_TYPES = {'text', 'fileRef', 'cardRef', 'oneTimeCode'}


def value_to_token(value): # type: (any) -> str
    if not value:
        return ''
    if type(value) == str:
        return value
    if type(value) == list:
        return ','.join((value_to_token(x) for x in value))
    if type(value) == dict:
        pairs = [x for x in value.items()]
        pairs.sort(key=lambda x: x[0])
        return ';'.join(f'{k}={value_to_token(v)}' for k, v in pairs)
    return str(value)


def tokenize_record_key(record):   # type: (ImportRecord) -> Iterator[str]
    """
    Turn a record-to-import into an iterable of str's for hashing.  This is really about import --update.

    Examine just the relevant parts of the record.
    """
    record_type = record.type or ""
    yield f'$type:{record_type}'
    yield f'$title:{record.title or ""}'
    yield f'$login:{record.login or ""}'
    yield f'$url:{record.login_url or ""}'

    if record_type in {'', 'login'}:
        return

    excluded = {x for x in RECORD_FIELD_TYPES}
    excluded.update(IGNORABLE_FIELD_TYPES)
    fields = {x.name_key(): x.value for x in record.fields if x.type and x.type not in excluded}
    if record.type == 'bankCard':
        if '$paymentcard' in fields:
            payment_card = fields.pop('$paymentcard')
        else:
            payment_card = {}
        yield '$paymentcard:' + value_to_token(payment_card.get('cardNumber'))
    elif record.type == 'bankAccount':
        yield value_to_token(fields.get('bankAccount'))
        yield value_to_token(fields.get('name'))
    elif record.type == 'address':
        yield value_to_token(fields.get('address'))
    else:
        fields = [x for x in record.fields if x.type not in excluded]
        fields.sort(key=ImportRecordField.name_key, reverse=False)
        for field in fields:
            hash_value = field.hash_key()
            if hash_value:
                yield hash_value


def tokenize_full_import_record(record):   # type: (ImportRecord) -> Iterator[str]
    """
    Turn a record-to-import into an iterable of str's for hashing.

    Examine the entire record.
    """
    yield f'$type:{record.type or ""}'
    yield f'$title:{record.title or ""}'
    yield f'$login:{record.login or ""}'
    yield f'$password:{record.password or ""}'
    yield f'$url:{record.login_url or ""}'
    yield f'$notes:{record.notes or ""}'

    fields = [x for x in record.fields]
    fields.sort(key=ImportRecordField.name_key, reverse=False)
    for field in fields:
        hash_key = field.hash_key()
        if hash_key:
            yield hash_key


def _construct_record_v2(rec_to_import, orig_extra=None):  # type: (ImportRecord, Optional[dict]) -> (dict, dict)
    totp = None
    custom_fields = []
    for field in rec_to_import.fields:
        value = ''
        if type(field.value) == str:
            value = field.value
        elif type(field.value) == list:
            value = field.value[0]
        elif field.value:
            value = str(value)

        if field.type == FIELD_TYPE_ONE_TIME_CODE:
            if value:
                totp = value
        else:
            name = field.label or field.type or ''
            custom_fields.append({
                'type': 'text',
                'name': name,
                'value': value
            })

    data = {
        'title': rec_to_import.title or '',
        'secret1': rec_to_import.login or '',
        'secret2': rec_to_import.password or '',
        'link': rec_to_import.login_url or '',
        'notes': rec_to_import.notes or '',
        'custom': custom_fields
    }

    if totp and orig_extra:
        if 'fields' in orig_extra:
            orig_totp = next((x.get('data') for x in orig_extra['fields'] if x.get('field_type') == 'totp'), None)
            if orig_totp == totp:
                totp = None

    extra = None
    if totp:
        extra = orig_extra or {}
        if 'fields' in extra:
            fields = extra['fields']
        else:
            fields = []
            extra['fields'] = fields
        fields.append({
            'id': utils.generate_uid(),
            'field_type': 'totp',
            'field_title': 'Two-Factor Code',
            'type': 0,
            'data': totp
        })

    return data, extra


def _create_field_v3(schema, value):  # type: (RecordSchemaField, any) -> dict
    if value is None:
        value = ''
    field = {
        'type': schema.ref or 'text',
        'value': value if type(value) is list else [value]
    }
    if schema.label:
        field['label'] = schema.label
    return field


def _construct_record_v3_data(rec_to_import, orig_data=None, map_data_custom_to_rec_fields=None):
    # type: (ImportRecord, Optional[dict], Optional[dict]) -> dict
    data = {}
    if orig_data:
        data.update(orig_data)
    data['title'] = rec_to_import.title or ''
    data['type'] = rec_to_import.type or ''
    data['notes'] = rec_to_import.notes or ''
    record_fields = [x for x in rec_to_import.fields]
    record_refs = [x for x in rec_to_import.references or []]
    data['fields'] = []
    for field in rec_to_import.schema or []:
        if field.ref == 'login':
            data['fields'].append(_create_field_v3(field, rec_to_import.login))
            rec_to_import.login = ''
        elif field.ref == 'password':
            data['fields'].append(_create_field_v3(field, rec_to_import.password))
            rec_to_import.password = ''
        elif field.ref == 'url':
            data['fields'].append(_create_field_v3(field, rec_to_import.login_url))
            rec_to_import.login_url = ''
        else:
            index = -1
            if field.ref.endswith('Ref'):
                for i, ref_value in enumerate(record_refs):
                    if ref_value.type == field.ref:
                        index = i
                        break
                ref_value = record_fields.pop(index) if index >= 0 else None
                data['fields'].append(_create_field_v3(field, ref_value.value if ref_value else []))
            else:
                for i, field_value in enumerate(record_fields):
                    if field_value.type == field.ref and (field_value.label or '') == (field.label or ''):
                        index = i
                        break
                field_value = record_fields.pop(index) if index >= 0 else None
                data['fields'].append(_create_field_v3(field, field_value.value if field_value else []))

    data['custom'] = []
    if rec_to_import.login:
        field = RecordSchemaField()
        field.ref = 'login'
        data['custom'].append(_create_field_v3(field, rec_to_import.login))
        rec_to_import.login = ''

    if rec_to_import.password:
        field = RecordSchemaField()
        field.ref = 'password'
        data['custom'].append(_create_field_v3(field, rec_to_import.password))
        rec_to_import.password = ''

    if rec_to_import.login_url:
        field = RecordSchemaField()
        field.ref = 'url'
        data['custom'].append(_create_field_v3(field, rec_to_import.login_url))
        rec_to_import.login_url = ''

    for i, field_value in enumerate(record_fields):
        field = RecordSchemaField()
        field.ref = field_value.type or 'text'
        if field_value.label:
            field.label = field_value.label
        data['custom'].append(_create_field_v3(field, field_value.value))
        if map_data_custom_to_rec_fields is not None:
            map_data_custom_to_rec_fields[len(data['custom']) - 1] = i

    for reference in record_refs:
        field = RecordSchemaField()
        field.ref = reference.type + 'Ref'
        field.label = reference.label
        data['custom'].append(_create_field_v3(field, reference.uids))

    return data


def build_record_hash(tokens):    # type: (Iterator[str]) -> str
    """Build a sha256 hash of record using tokenize_gen."""
    hasher = hashlib.sha256()
    for token in tokens:
        hasher.update(token.encode())
    return hasher.hexdigest()


def prepare_record_add_or_update(update_flag, params, records):
    # type: (bool, KeeperParams, Iterator[ImportRecord]) -> Tuple[List[ImportRecord], dict]
    """
    Find what records to import or update.

    If update_flag is False:
        If a 100% match is found for a record, then just skip requesting anything; it doesn't need to be changed.
        Otherwise import the record, risking creating an almost-duplicate.
    If update_flag is True:
       if a unique field match (on title, login, and url) is found, then request a change in password only.
    """
    preexisting_entire_record_hash = {}
    preexisting_partial_record_hash = {}
    for record_uid in params.record_cache:
        import_record = convert_keeper_record(params.record_cache[record_uid])
        if import_record:
            record_hash = build_record_hash(tokenize_full_import_record(import_record))
            preexisting_entire_record_hash[record_hash] = record_uid
            if update_flag:
                record_hash = build_record_hash(tokenize_record_key(import_record))
                preexisting_partial_record_hash[record_hash] = record_uid
        else:
            pass

    record_to_import = []   # type: List[ImportRecord]
    record_uid_to_update = set()
    external_lookup = {}

    for import_record in records:
        if import_record.type:
            if len(import_record.notes or '') > RECORD_MAX_DATA_LEN - 2 * (2 ** 10):
                if import_record.attachments is None:
                    import_record.attachments = []
                atta = BytesAttachment(f'{import_record.title}_notes_field.txt', import_record.notes.encode('utf-8'))
                import_record.attachments.append(atta)
                import_record.notes = LARGE_FIELD_MSG.format(atta.name)

            for f in import_record.fields:
                if not f.value:
                    continue
                if isinstance(f.value, str):
                    if len(f.value) > RECORD_MAX_DATA_LEN - 2 * (2 ** 10):
                        if import_record.attachments is None:
                            import_record.attachments = []
                        atta = BytesAttachment(f'{import_record.title}_{f.type}_field.txt', f.value.encode('utf-8'))
                        import_record.attachments.append(atta)
                        f.value = LARGE_FIELD_MSG.format(atta.name)

        record_hash = build_record_hash(tokenize_full_import_record(import_record))
        if record_hash in preexisting_entire_record_hash:
            if import_record.uid:
                record_uid = preexisting_entire_record_hash[record_hash]
                external_lookup[import_record.uid] = record_uid
            continue

        if import_record.uid and import_record.uid in params.record_cache:
            record_uid_to_update.add(import_record.uid)
            record_to_import.append(import_record)
            continue
        elif update_flag:
            record_hash = build_record_hash(tokenize_record_key(import_record))
            if record_hash in preexisting_partial_record_hash:
                record_uid = preexisting_partial_record_hash[record_hash]
                if import_record.uid:
                    external_lookup[import_record.uid] = record_uid
                if record_uid not in record_uid_to_update:
                    record_uid_to_update.add(record_uid)
                    import_record.uid = record_uid
                    record_to_import.append(import_record)
                continue

        record_uid = utils.generate_uid()
        if import_record.uid:
            external_lookup[import_record.uid] = record_uid
        import_record.uid = record_uid
        record_to_import.append(import_record)

    record_types = {}
    if params.record_type_cache:
        for rts in params.record_type_cache.values():
            try:
                rto = json.loads(rts)
                if '$id' in rto:
                    record_types[rto['$id']] = rto
            except:
                pass

    for import_record in record_to_import:
        if not import_record.type:
            continue
        if import_record.schema:
            continue
        record_type = import_record.type
        if record_type in record_types:
            fields = record_types[record_type].get('fields') or []
            import_record.schema = []
            for field in fields:
                if '$ref' in field:
                    f = RecordSchemaField()
                    f.ref = field['$ref']
                    f.label = field.get('label') or ''
                    import_record.schema.append(f)

    for import_record in record_to_import:
        if import_record.references:
            for ref in import_record.references:
                ref.uids = [external_lookup[x] for x in ref.uids if x in external_lookup]

    return record_to_import, external_lookup


def prepare_record_link(params, records):
    """Prepare record links to folders."""
    record_folders = {}    # type: [str, [str]]
    record_links = []
    for rec in records:
        if rec.uid:
            if rec.uid in params.record_cache:
                if rec.uid in record_folders:
                    folder_ids = record_folders[rec.uid]
                else:
                    folder_ids = list(find_folders(params, rec.uid))
                    record_folders[rec.uid] = folder_ids
                record = params.record_cache[rec.uid]
                for fol in rec.folders or [None]:
                    folder_uid = fol.uid if fol else ''
                    if folder_uid and folder_uid not in params.folder_cache:
                        continue
                    if folder_uid in folder_ids:
                        continue
                    if len(folder_ids) > 0:
                        folder_ids.append(folder_uid)
                        src_folder = params.folder_cache[folder_ids[0]]
                        dst_folder = params.folder_cache[folder_uid] if folder_uid in params.folder_cache else params.root_folder
                        ft = dst_folder.type if dst_folder.type != BaseFolderNode.RootFolderType else BaseFolderNode.UserFolderType
                        req = {
                            'command': 'move',
                            'to_type': ft,
                            'link': True,
                            'move': [],
                            'transition_keys': []
                        }
                        if dst_folder.type != BaseFolderNode.RootFolderType:
                            req['to_uid'] = dst_folder.uid
                        ft = src_folder.type if src_folder.type != BaseFolderNode.RootFolderType else BaseFolderNode.UserFolderType
                        mo = {
                            'type': 'record',
                            'uid': rec.uid,
                            'from_type': ft,
                            'cascade': True
                        }
                        if src_folder.type != BaseFolderNode.RootFolderType:
                            mo['from_uid'] = src_folder.uid
                        req['move'].append(mo)

                        transition_key = None
                        record_key = record['record_key_unencrypted']
                        if src_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                            if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                                ssf_uid = src_folder.uid if src_folder.type == BaseFolderNode.SharedFolderType else \
                                    src_folder.shared_folder_uid
                                dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                                    dst_folder.shared_folder_uid
                                if ssf_uid != dsf_uid:
                                    shf = params.shared_folder_cache[dsf_uid]
                                    transition_key = api.encrypt_aes(record_key, shf['shared_folder_key_unencrypted'])
                            else:
                                transition_key = api.encrypt_aes(record_key, params.data_key)
                        else:
                            if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                                dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                                    dst_folder.shared_folder_uid
                                shf = params.shared_folder_cache[dsf_uid]
                                transition_key = api.encrypt_aes(record_key, shf['shared_folder_key_unencrypted'])
                        if transition_key is not None:
                            req['transition_keys'].append({
                                'uid': rec.uid,
                                'key': transition_key
                            })
                        record_links.append(req)
    return record_links


def prepare_folder_permission(params, folders):    # type: (KeeperParams, list) -> list
    """Prepare a list of API interactions for changes to folder permissions."""
    shared_folder_lookup = {}
    api.load_available_teams(params)
    for shared_folder_uid in params.shared_folder_cache:
        path = get_folder_path(params, shared_folder_uid)
        if path:
            shared_folder_lookup[path] = shared_folder_uid

    email_pattern = re.compile(EMAIL_PATTERN)
    emails = set()
    teams = set()
    for fol in folders:
        shared_folder_uid = shared_folder_lookup.get(fol.path)
        if not shared_folder_uid:
            continue
        shared_folder = params.shared_folder_cache.get(shared_folder_uid)
        if not shared_folder:
            continue
        shared_folder_key = shared_folder.get('shared_folder_key_unencrypted')
        if not shared_folder_key:
            continue

        if fol.permissions:
            for perm in fol.permissions:
                if perm.uid:
                    if 'teams' in shared_folder:
                        found = next((True for x in shared_folder['teams'] if x['team_uid'] == perm.uid), False)
                        if found:
                            continue
                    teams.add(perm.uid)
                    if perm.name:
                        teams.add(perm.name)
                elif perm.name:
                    lower_name = perm.name.casefold()
                    match = email_pattern.match(perm.name)
                    if match:
                        if perm.name == params.user:
                            continue
                        if 'users' in shared_folder:
                            found = next((True for x in shared_folder['users'] if x['username'].lower() == lower_name), False)
                            if found:
                                continue
                        emails.add(perm.name.lower())
                    else:
                        if 'teams' in shared_folder:
                            found = next((True for x in shared_folder['teams'] if x['name'].lower() == lower_name), False)
                            if found:
                                continue
                        teams.add(perm.name)

    if len(emails) > 0:
        api.load_user_public_keys(params, list(emails))

    if len(teams) > 0:
        team_uids = set()
        for t in teams:
            team_uid = next((
                x.get('team_uid') for x in (params.available_team_cache or []) if x.get('team_uid') == t or x.get('team_name').casefold() == t.casefold()
                ), None)
            if team_uid:
                team_uids.add(team_uid)
        if len(team_uids) > 0:
            api.load_team_keys(params, list(team_uids))

    folder_permissions = []
    for fol in folders:
        shared_folder_uid = shared_folder_lookup.get(fol.path)
        if not shared_folder_uid:
            continue
        shared_folder = params.shared_folder_cache.get(shared_folder_uid)
        if not shared_folder:
            continue
        shared_folder_key = shared_folder.get('shared_folder_key_unencrypted')
        if not shared_folder_key:
            continue

        if fol.permissions:
            add_users = []
            add_teams = []
            for perm in fol.permissions:
                team_uid = None
                username = None
                try:
                    if perm.uid and any(True for x in params.available_team_cache if x.get('team_uid') == perm.uid):
                        team_uid = perm.uid
                    elif perm.name:
                        name = perm.name.casefold()
                        team_uid = next((x.get('team_uid') for x in params.available_team_cache if x.get('team_name').casefold() == name), None)
                        if team_uid is None:
                            username = name

                    if team_uid:
                        if 'teams' in shared_folder:
                            found = next((True for x in shared_folder['teams'] if x['team_uid'] == team_uid), False)
                            if found:
                                continue
                        rq = {
                            'team_uid': team_uid,
                            'manage_users': perm.manage_users,
                            'manage_records': perm.manage_records,
                        }
                        if team_uid in params.team_cache:
                            team = params.team_cache[team_uid]
                            if 'team_key_unencrypted' in team:
                                team_key = team['team_key_unencrypted']
                                rq['shared_folder_key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(shared_folder_key, team_key))
                                add_teams.append(rq)
                        elif team_uid in params.key_cache:
                            team_keys = params.key_cache[team_uid]
                            if team_keys.rsa:
                                rsa_key = crypto.load_rsa_public_key(team_keys.rsa)
                                rq['shared_folder_key'] = utils.base64_url_encode(crypto.encrypt_rsa(shared_folder_key, rsa_key))
                                add_teams.append(rq)
                        continue

                    if username:
                        if username in params.key_cache:
                            if 'users' in shared_folder:
                                found = next((True for x in shared_folder['users'] if x['username'].lower() == username), False)
                                if found:
                                    continue

                            public_keys = params.key_cache[username]
                            if public_keys.rsa:
                                rsa_key = crypto.load_rsa_public_key(public_keys.rsa)
                                rq = {
                                    'username': username,
                                    'manage_users': perm.manage_users,
                                    'manage_records': perm.manage_records,
                                    'shared_folder_key': utils.base64_url_encode(crypto.encrypt_rsa(shared_folder_key, rsa_key))
                                }
                                add_users.append(rq)
                        continue
                except Exception as e:
                    logging.debug(e)

            while len(add_teams) > 0 or len(add_users) > 0:
                team_chunk = add_teams[:400]
                add_teams = add_teams[400:]
                user_chunk = add_users[:400]
                add_users = add_users[400:]
                request = {
                    'command': 'shared_folder_update',
                    'operation': 'update',
                    'pt': 'Commander',
                    'shared_folder_uid': shared_folder_uid,
                    'force_update': True,
                    'add_teams': team_chunk,
                    'add_users': user_chunk,
                }
                folder_permissions.append(request)

    return folder_permissions


def prepare_record_permission(params, records):
    """Prepare a list of API interactions for changes to record permissions."""
    shared_update = []
    for rec in records:
        if rec.folders and rec.uid:
            if rec.uid in params.record_cache:
                for fol in rec.folders:
                    if fol.can_edit is None and fol.can_share is None:
                        continue

                    if fol.uid and fol.uid in params.folder_cache:
                        folder = params.folder_cache[fol.uid]
                        if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                            sf_uid = \
                                folder.shared_folder_uid \
                                if folder.type == BaseFolderNode.SharedFolderFolderType \
                                else folder.uid
                            if sf_uid in params.shared_folder_cache:
                                sf = params.shared_folder_cache[sf_uid]
                                if 'records' in sf:
                                    for sfr in sf['records']:
                                        if sfr['record_uid'] == rec.uid:
                                            if sfr['can_share'] != fol.can_share or sfr['can_edit'] != fol.can_edit:
                                                req = {
                                                    'command': 'shared_folder_update',
                                                    'pt': 'Commander',
                                                    'operation': 'update',
                                                    'shared_folder_uid': sf_uid,
                                                    'force_update': True,
                                                    'update_records': [{
                                                        'record_uid': rec.uid,
                                                        'shared_folder_uid': sf_uid,
                                                        'can_edit': fol.can_edit or False,
                                                        'can_share': fol.can_share or False
                                                    }]
                                                }
                                                shared_update.append(req)
                                            break
    return shared_update


class KeeperBaseAttachment(ImportAttachment, crypto.StreamCrypter, abc.ABC):
    def __init__(self, params):
        super().__init__()
        self.params = params


class KeeperV2Attachment(KeeperBaseAttachment):
    def __init__(self, params, record_uid, file_id):
        super().__init__(params)
        self.file_id = file_id
        self.record_uid = record_uid
        self.is_gcm = False

    def open(self):
        rq = {
            'command': 'request_download',
            'file_ids': [self.file_id],
        }
        api.resolve_record_access_path(self.params, self.record_uid, path=rq)
        rs = api.communicate(self.params, rq)
        dl = rs['downloads'][0]
        rs_http = requests.get(dl['url'], proxies=self.params.rest_context.proxies, stream=True)
        return self.set_stream(rs_http.raw, for_encrypt=False)


class KeeperV3Attachment(KeeperBaseAttachment):
    def __init__(self, params, file_uid):
        super().__init__(params)
        self.file_uid = file_uid

    def open(self):
        rq = record_pb2.FilesGetRequest()
        rq.record_uids.append(utils.base64_url_decode(self.file_uid))
        rq.for_thumbnails = False
        rs = api.communicate_rest(self.params, rq, 'vault/files_download', rs_type=record_pb2.FilesGetResponse)
        file = rs.files[0]
        if file.status != record_pb2.FG_SUCCESS:
            raise KeeperApiError('access_denied', 'Attachment: access denied')
        self.is_gcm = file.fileKeyType == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM
        url = file.url
        rs_http = requests.get(url, proxies=self.params.rest_context.proxies, stream=True)
        if rs_http.status_code != file.success_status_code:
            raise KeeperApiError('file_not_found', 'Attachment: file not found')
        return self.set_stream(rs_http.raw, for_encrypt=False)
