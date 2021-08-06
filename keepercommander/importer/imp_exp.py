#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2017 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Import and export functionality."""

from contextlib import contextmanager
import collections
import base64
import hashlib
import io
import json
import logging
import os
import re

from Cryptodome.Cipher import AES
import requests

from keepercommander import api
from keepercommander.rest_api import CLIENT_VERSION  # pylint: disable=no-name-in-module
from ..params import KeeperParams

from .importer import importer_for_format, exporter_for_format, path_components, PathDelimiter, BaseExporter, \
    Record as ImportRecord, Folder as ImportFolder, SharedFolder as ImportSharedFolder,  Permission as ImportPermission,\
    Attachment as ImportAttachment, BaseImporter
from ..subfolder import BaseFolderNode, find_folders
from .. import folder_pb2
from ..record import Record

TWO_FACTOR_CODE = 'TFC:Keeper'
EMAIL_PATTERN = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"


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


def export(params, file_format, filename, **export_args):
    """Export data from Vault to a file in an assortment of formats."""
    api.sync_down(params)

    exporter = exporter_for_format(file_format)()  # type: BaseExporter
    if export_args:
        if 'max_size' in export_args:
            exporter.max_size = int(export_args['max_size'])

    to_export = []
    if exporter.has_shared_folders():
        shfolders = [api.get_shared_folder(params, sf_uid) for sf_uid in params.shared_folder_cache]
        shfolders.sort(key=lambda x: x.name.lower(), reverse=False)
        for f in shfolders:
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

    records = [api.get_record(params, record_uid) for record_uid in params.record_cache]
    records.sort(key=lambda x: x.title.lower(), reverse=False)

    for r in records:
        rec = ImportRecord()
        rec.uid = r.record_uid
        rec.title = r.title.strip('\x00') if r.title else ''
        rec.login = r.login.strip('\x00') if r.login else ''
        rec.password = r.password.strip('\x00') if r.password else ''
        rec.login_url = r.login_url.strip('\x00') if r.login_url else ''
        rec.notes = r.notes.strip('\x00') if r.notes else ''
        for cf in r.custom_fields:
            name = cf.get('name')
            value = cf.get('value')
            if name and value:
                rec.custom_fields[name] = value
        if r.totp:
            rec.custom_fields[TWO_FACTOR_CODE] = r.totp

        for folder_uid in find_folders(params, r.record_uid):
            if folder_uid in params.folder_cache:
                folder = get_import_folder(params, folder_uid, r.record_uid)
                if rec.folders is None:
                    rec.folders = []
                rec.folders.append(folder)
        if exporter.has_attachments() and r.attachments:
            rec.attachments = []
            names = set()
            for a in r.attachments:
                orig_name = a.get('title') or a.get('name') or 'attachment'
                name = orig_name
                counter = 0
                while name in names:
                    counter += 1
                    name = "{0}-{1}".format(orig_name, counter)
                names.add(name)
                atta = KeeperAttachment(params, rec.uid)
                atta.file_id = a['id']
                atta.name = name
                atta.size = a['size']
                atta.key = base64.urlsafe_b64decode(a['key'] + '==')
                atta.mime = a.get('type') or ''
                rec.attachments.append(atta)

        to_export.append(rec)
    rec_count = len(to_export) - sf_count

    if len(to_export) > 0:
        file_password = export_args.get('keepass_file_password') if export_args else None
        exporter.execute(filename, to_export, file_password)
        params.queue_audit_event('exported_records', file_format=file_format)
        logging.info('%d records exported', rec_count)


def _import(params, file_format, filename, **kwargs):
    """Import records from one of a variety of sources."""
    api.sync_down(params)

    shared = kwargs.get('shared') or False
    import_into = kwargs.get('import_into') or ''
    if import_into:
        import_into = import_into.replace(PathDelimiter, 2*PathDelimiter)
    update_flag = kwargs['update_flag']

    importer = importer_for_format(file_format)()  # type: BaseImporter

    records_before = len(params.record_cache)

    folders = []  # type: [ImportSharedFolder]
    records = []  # type: [ImportRecord]
    for x in importer.execute(filename):
        if type(x) is ImportRecord:
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

            x.validate()
            records.append(x)
        elif type(x) is ImportSharedFolder:
            if shared:
                continue
            x.validate()
            if import_into:
                if x.path:
                    x.path = PathDelimiter.join([import_into, x.path])

            folders.append(x)

    if shared:
        manage_users = kwargs.get('manage_users') or False
        manage_records = kwargs.get('manage_records') or False
        can_edit = kwargs.get('can_edit') or False
        can_share = kwargs.get('can_share') or False

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

    folder_add = prepare_folder_add(params, folders, records)
    if folder_add:
        fol_rs, _ = execute_import_folder_record(params, folder_add, None)
        _ = fol_rs
        api.sync_down(params)

    if folders:
        permissions = prepare_folder_permission(params, folders)
        if permissions:
            api.execute_batch(params, permissions)
            api.sync_down(params)

    if records:
        # create/update records
        records_to_add, records_to_update = prepare_record_add_or_update(update_flag, params, records)
        if records_to_add:
            _, rec_rs = execute_import_folder_record(params, None, records_to_add)
            _ = rec_rs
            api.sync_down(params)
        if records_to_update:
            execute_update_record(params, records_to_update)
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
        atts = []
        for r in records:
            if r.attachments:
                r_uid = r.uid
                for a in r.attachments:
                    atts.append((r_uid, a))
        if len(atts) > 0:
            upload_attachment(params, atts)

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


def execute_update_record(params, records_to_update):
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

    report_statuses('folder', (element.status for element in rs_folder))
    report_statuses('record', (element.status for element in rs_record))

    return rs_folder, rs_record


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
        for record_id, atta in chunk:
            if not uploads:
                break

            try:
                upload = uploads.pop()
                buffer = io.BytesIO()
                cipher = None
                key = atta.key
                if not key:
                    key = os.urandom(32)
                    iv = os.urandom(16)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    buffer.write(iv)
                with atta.open() as s:
                    finished = False
                    while not finished:
                        chunk = s.read(10240)
                        if len(chunk) > 0:
                            if cipher is not None:
                                if len(chunk) < 10240:
                                    finished = True
                                    chunk = api.pad_binary(chunk)
                                chunk = cipher.encrypt(chunk)
                            buffer.write(chunk)
                        else:
                            finished = True
                size = buffer.tell() - 16
                if size > 0:
                    buffer.seek(0, io.SEEK_SET)
                    files = {
                        upload['file_parameter']: (atta.name, buffer, 'application/octet-stream')
                    }
                    print('{0} ... '.format(atta.name), end='', flush=True)
                    response = requests.post(upload['url'], files=files, data=upload['parameters'])
                    if response.status_code == upload['success_status_code']:
                        if record_id not in uploaded:
                            uploaded[record_id] = []
                        uploaded[record_id].append({
                            'key': base64.urlsafe_b64encode(key).decode().rstrip('='),
                            'name': atta.name,
                            'file_id': upload['file_id'],
                            'size': size
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


def prepare_folder_add(params, folders, records):
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
                        fol_req.sharedFolderFields.manageUsers = fol.manage_users
                        fol_req.sharedFolderFields.manageRecords = fol.manage_records
                        fol_req.sharedFolderFields.canEdit = fol.can_edit
                        fol_req.sharedFolderFields.canShare = fol.can_share

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


def tokenize_partial_import_record(record):   # type: (ImportRecord) -> [str]
    """
    Turn a record-to-import into an iterable of str's for hashing.  This is really about import --update.

    Examine just the relevant parts of the record.
    """
    yield record.title or ''
    yield record.login or ''
    yield record.login_url or ''


def tokenize_partial_preexisting_record(record):   # type: (Record) -> [str]
    """
    Turn a preexisting record into an iterable of str's for hashing.

    Examine just the relevant parts of the record.

    For now at least, this is the same as tokenize_partial_import_record().
    """
    return tokenize_partial_import_record(record)


def tokenize_full_import_record(record):   # type: (ImportRecord) -> [str]
    """
    Turn a record-to-import into an iterable of str's for hashing.

    Examine the entire record.
    """
    yield record.title or ''
    yield record.login or ''
    yield record.password or ''
    yield record.login_url or ''
    yield record.notes or ''

    if len(record.custom_fields) > 0:
        keys = list(record.custom_fields.keys())
        keys.sort()
        for key in keys:
            yield key + ':' + record.custom_fields[key]


def tokenize_full_preexisting_record(record):   # type: (Record) -> [str]
    """Turn a preexisting record into an iterable of str's for hashing."""
    yield record.title or ''
    yield record.login or ''
    yield record.password or ''
    yield record.login_url or ''
    yield record.notes or ''

    custom = {}
    if record.custom_fields:
        for cf in record.custom_fields:
            if cf.get('name') and cf.get('value'):
                custom[cf.get('name')] = cf.get('value')
    if record.totp:
        custom[TWO_FACTOR_CODE] = record.totp
    if len(custom) > 0:
        keys = list(custom.keys())
        keys.sort()
        for key in keys:
            yield key + ':' + custom[key]


def construct_import_rec_req(params, preexisting_record_hash, rec_to_import):
    """Build a rec_req for rec_to_import."""
    r_hash = build_record_hash(record=rec_to_import, tokenize_gen=tokenize_full_import_record)

    if r_hash in preexisting_record_hash:
        # Nothing to do.  We already have this identical record.
        return None
    else:
        rec_to_import.uid = api.generate_record_uid()
        preexisting_record_hash[r_hash] = rec_to_import.uid
        record_key = os.urandom(32)
        rec_req = folder_pb2.RecordRequest()
        rec_req.recordUid = base64.urlsafe_b64decode(rec_to_import.uid + '==')
        rec_req.recordType = 0
        rec_req.encryptedRecordKey = base64.urlsafe_b64decode(api.encrypt_aes(record_key, params.data_key) + '==')
        rec_req.howLongAgo = 0
        rec_req.folderType = 1

        folder_uid = None
        if rec_to_import.folders:
            folder_uid = rec_to_import.folders[0].uid
        if folder_uid:
            if folder_uid in params.folder_cache:
                folder = params.folder_cache[folder_uid]
                if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    rec_req.folderUid = base64.urlsafe_b64decode(folder.uid + '==')
                    rec_req.folderType = 2 if folder.type == BaseFolderNode.SharedFolderType else 3

                    sh_uid = folder.uid if folder.type == BaseFolderNode.SharedFolderType else folder.shared_folder_uid
                    sf = params.shared_folder_cache[sh_uid]
                    rec_req.encryptedRecordFolderKey = base64.urlsafe_b64decode(
                        api.encrypt_aes(record_key, sf['shared_folder_key_unencrypted']) + '=='
                    )
                else:
                    rec_req.folderType = 1
                    if folder.type != BaseFolderNode.RootFolderType:
                        rec_req.folderUid = base64.urlsafe_b64decode(folder.uid + '==')

        custom_fields = []
        totp = None
        if rec_to_import.custom_fields:
            for cf in rec_to_import.custom_fields:
                if cf == TWO_FACTOR_CODE:
                    totp = rec_to_import.custom_fields[cf]
                else:
                    custom_fields.append({
                        'name': cf,
                        'value': rec_to_import.custom_fields[cf]
                    })

        data = {
            'title': rec_to_import.title or '',
            'secret1': rec_to_import.login or '',
            'secret2': rec_to_import.password or '',
            'link': rec_to_import.login_url or '',
            'notes': rec_to_import.notes or '',
            'custom': custom_fields
        }
        rec_req.recordData = base64.urlsafe_b64decode(api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key) + '==')
        if totp:
            extra = {
                'fields': [
                    {
                        'id': api.generate_record_uid(),
                        'field_type': 'totp',
                        'field_title': 'Two-Factor Code',
                        'type': 0,
                        'data': totp
                    }]
            }
            rec_req.extra = base64.urlsafe_b64decode(api.encrypt_aes(json.dumps(extra).encode('utf-8'), record_key) + '==')
        return rec_req


def construct_update_rec_req(params, preexisting_record_hash, rec_to_update):
    """
    Build a rec_req for rec_to_import.

    Based on https://keeper.atlassian.net/wiki/spaces/KA/pages/13238307/record+update+-+deprecated
    and upload_attachment(params, attachments), which appears elsewhere in this file.

    We're not doing records_update yet, because it requires v3 and we don't do v3 yet.
    """
    # FIXME: This assert probably can be sorted out during code review.
    assert len(rec_to_update.folders) == 1, "What should we do with records that aren't in exactly one folder?"
    data = {
        'folder': rec_to_update.folders[0].get_folder_path(),
        'title': rec_to_update.title,
        'secret1': rec_to_update.login,
        'secret2': rec_to_update.password,
        'link': rec_to_update.login_url,
        # We add notes and custom a little later.
    }

    current_rec = params.record_cache[rec_to_update.uid]
    # This should always exist, because this is an import --update.
    preexisting_record = params.record_cache[rec_to_update.uid]

    preexisting_record_fields_str = preexisting_record['data_unencrypted'].decode('utf-8')
    preexisting_record_fields_dict = json.loads(preexisting_record_fields_str)

    # These fields need to be preserved - per our design.
    field_tuple = ('notes', 'custom')
    for field_name in field_tuple:
        # these need to be preserved
        if field_name in preexisting_record_fields_dict:
            data[field_name] = preexisting_record_fields_dict[field_name]

    unencrypted_key = preexisting_record['record_key_unencrypted']

    encrypted_data = api.encrypt_aes(json.dumps(data).encode('utf-8'), unencrypted_key)
    record_key = api.encrypt_aes(unencrypted_key, params.data_key)
    one_rec_req = {
        'record_uid': rec_to_update.uid,
        'record_key': record_key,
        'record_key_unencrypted': base64.urlsafe_b64encode(unencrypted_key).decode('utf-8'),
        'data': encrypted_data,
        'version': 2,
        'client_modified_time': api.current_milli_time(),
        'revision': current_rec['revision']
    }
    return one_rec_req


def build_record_hash(record, tokenize_gen):
    """Build a sha256 hash of record using tokenize_gen."""
    hasher = hashlib.sha256()
    for token in tokenize_gen(record):
        hasher.update(token.encode())
    return hasher.hexdigest()


def build_hash_dict(params, tokenize_gen):
    """Return a dict of hashes to record uid's with a parameterized tokenizing generator."""
    preexisting_record_hash = {}
    for preexisting_r_uid in params.record_cache:
        preexisting_rec = api.get_record(params, preexisting_r_uid)
        preexisting_record_hash[build_record_hash(preexisting_rec, tokenize_gen)] = preexisting_r_uid
    return preexisting_record_hash


def prepare_record_add_or_update(update_flag, params, records):
    """
    Find what records to import or update.

    If update_flag is False:
        If a 100% match is found for a record, then just skip requesting anything; it doesn't need to be changed.
        Otherwise import the record, risking creating an almost-duplicate.
    If update_flag is True:
       if a unique field match (on title, login, and url) is found, then request a change in password only.
       Do not update the TOTP custom field, even if it exists.
    """
    recs_to_import_or_update = records
    del records
    preexisting_entire_record_hash = build_hash_dict(params, tokenize_full_preexisting_record)
    preexisting_partial_record_hash = build_hash_dict(params, tokenize_partial_preexisting_record)

    record_adds = []
    record_updates = []
    for rec_to_import_or_update in recs_to_import_or_update:
        perform_import_or_update = 'neither'

        full_hash_of_cur_rec = build_record_hash(rec_to_import_or_update, tokenize_full_import_record)
        partial_hash_of_cur_rec = build_record_hash(rec_to_import_or_update, tokenize_partial_import_record)
        # Decide what kind of operation is needed.
        if full_hash_of_cur_rec in preexisting_entire_record_hash:
            # We do not need to do a record update; we already have this record in its entirety.
            pass
        elif partial_hash_of_cur_rec in preexisting_partial_record_hash and update_flag:
            # This is a record to update instead of importing it.
            rec_to_import_or_update.uid = preexisting_partial_record_hash[partial_hash_of_cur_rec]
            perform_import_or_update = 'update'
        else:
            # Create a new UID for the new record, and signal that we need to do the import.
            # We do this conditionally for --update, and unconditionally for import without --update.
            rec_to_import_or_update.uid = api.generate_record_uid()
            perform_import_or_update = 'import'

        # Act on the selected operation.
        if perform_import_or_update == 'update':
            rec_req = construct_update_rec_req(params, preexisting_partial_record_hash, rec_to_import_or_update)
            # Schedule the record for later batch-update.
            record_updates.append(rec_req)
        elif perform_import_or_update == 'import':
            rec_req = construct_import_rec_req(params, preexisting_entire_record_hash, rec_to_import_or_update)
            # Schedule the record for later batch-addition.
            record_adds.append(rec_req)
        elif perform_import_or_update == 'neither':
            # Nothing to do.
            pass
        else:
            raise AssertionError('perform_import_or_update has a strange value: {}'.format(perform_import_or_update))

    return record_adds, record_updates


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
    for shared_folder_uid in params.shared_folder_cache:
        path = get_folder_path(params, shared_folder_uid)
        if path:
            shared_folder_lookup[path] = shared_folder_uid

    email_pattern = re.compile(EMAIL_PATTERN)
    emails = set()
    teams = set()
    for fol in folders:
        if fol.permissions:
            for perm in fol.permissions:
                if perm.uid:
                    teams.add(perm.uid)
                    if perm.name:
                        teams.add(perm.name)
                elif perm.name:
                    match = email_pattern.match(perm.name)
                    if match:
                        if perm.name != params.user:
                            emails.add(perm.name.lower())
                    else:
                        teams.add(perm.name)

    if len(emails) > 0:
        api.load_user_public_keys(params, list(emails))

    if len(teams) > 0:
        api.load_available_teams(params)
        team_uids = set()
        for t in teams:
            team_uid = next(
                (
                    x.get('team_uid')
                    for x in params.available_team_cache
                    if x.get('team_uid') == t or x.get('team_name').casefold() == t.casefold()
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
                try:
                    if perm.uid:
                        if perm.uid in params.key_cache:
                            team_key = params.key_cache[perm.uid]
                            rq = {
                                'team_uid': perm.uid,
                                'manage_users': perm.manage_users,
                                'manage_records': perm.manage_records,
                            }
                            if type(team_key) == bytes:
                                rq['shared_folder_key'] = api.encrypt_aes(shared_folder_key, team_key)
                            else:
                                rq['shared_folder_key'] = api.encrypt_rsa(shared_folder_key, team_key)
                            add_teams.append(rq)
                            continue

                    if perm.name:
                        name = perm.name.casefold()
                        if name in params.key_cache:
                            rsa_key = params.key_cache[name]
                            rq = {
                                'username': name,
                                'manage_users': perm.manage_users,
                                'manage_records': perm.manage_records,
                                'shared_folder_key': api.encrypt_rsa(shared_folder_key, rsa_key)
                            }
                            add_users.append(rq)
                            continue

                        team_uid = next((x.get('team_uid') for x in params.available_team_cache
                                         if x.get('team_name').casefold() == name), None)
                        if team_uid in params.key_cache:
                            team_key = params.key_cache[team_uid]
                            rq = {
                                'team_uid': team_uid,
                                'manage_users': perm.manage_users,
                                'manage_records': perm.manage_records,
                            }
                            if type(team_key) == bytes:
                                rq['shared_folder_key'] = api.encrypt_aes(shared_folder_key, team_key)
                            else:
                                rq['shared_folder_key'] = api.encrypt_rsa(shared_folder_key, team_key)
                            add_teams.append(rq)
                            continue

                except Exception as e:
                    logging.debug(e)

            if add_teams or add_users:
                request = {
                    'command': 'shared_folder_update',
                    'operation': 'update',
                    'pt': 'Commander',
                    'shared_folder_uid': shared_folder_uid,
                    'force_update': True,
                    'add_teams': add_teams,
                    'add_users': add_users,
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


class KeeperAttachment(ImportAttachment):
    """
    Allow opening an attachment.

    Note that this may be a duplicate of keepercommander/importer/commands.py's KeeperAttachment.
    """

    def __init__(self, params, record_uid,):
        """Initialize."""
        ImportAttachment.__init__(self)
        self.params = params
        self.record_uid = record_uid

    @contextmanager
    def open(self):
        """Open an attachment."""
        rq = {
            'command': 'request_download',
            'file_ids': [self.file_id],
        }
        api.resolve_record_access_path(self.params, self.record_uid, path=rq)

        rs = api.communicate(self.params, rq)
        if rs['result'] == 'success':
            dl = rs['downloads'][0]
            if 'url' in dl:
                with requests.get(dl['url'], stream=True) as rq_http:
                    yield rq_http.raw
