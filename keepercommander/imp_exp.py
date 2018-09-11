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

import os
import json
import hashlib
import base64
import requests
import io

from contextlib import contextmanager
from email.utils import parseaddr
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES

from . import api

from .shared_folder import SharedFolder
from .importer.importer import importer_for_format, exporter_for_format, path_components, PathDelimiter, BaseExporter, \
    Record as ImportRecord, Folder as ImportFolder, SharedFolder as ImportSharedFolder, Permission as ImportPermission,\
    Attachment as ImportAttachment
from .subfolder import BaseFolderNode, find_folders


def get_import_folder(params, folder_uid, record_uid):
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


def export(params, file_format, filename):
    api.sync_down(params)

    exporter = exporter_for_format(file_format)()  # type: BaseExporter

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
        for folder_uid in find_folders(params, r.record_uid):
            if folder_uid in params.folder_cache:
                folder = get_import_folder(params, folder_uid, r.record_uid)
                if rec.folders is None:
                    rec.folders = []
                rec.folders.append(folder)
        if exporter.has_attachments() and r.attachments:
            rec.attachments = []
            for a in r.attachments:
                atta = KeeperAttachment(params, rec.uid)
                atta.file_id = a['id']
                atta.name = a['name']
                atta.size = a['size']
                atta.key = base64.urlsafe_b64decode(a['key'] + '==')
                atta.mime = a['type']
                rec.attachments.append(atta)

        to_export.append(rec)
    rec_count = len(to_export) - sf_count

    if len(to_export) > 0:
        exporter.execute(filename, to_export)
        api.print_info('{0} records exported'.format(rec_count))


def _import(params, file_format, filename, **kwargs):
    api.sync_down(params)

    shared = kwargs.get('shared') or False

    importer = importer_for_format(file_format)()
    """:type : BaseImporter"""

    records_before = len(params.record_cache)

    folders = []  # type: [ImportSharedFolder]
    records = []  # type: [ImportRecord]
    for x in importer.execute(filename):
        if type(x) is ImportRecord:
            if shared:
                if x.folders:
                    for f in x.folders:
                        d_comps = list(path_components(f.domain)) if f.domain else []
                        p_comps = list(path_components(f.path)) if f.path else []
                        if len(d_comps) > 0:
                            f.domain = d_comps[0]
                            p_comps[0:0] = d_comps[1:]
                        elif len(p_comps) > 0:
                            f.domain = p_comps[0]
                            p_comps = p_comps[1:]
                        f.path = PathDelimiter.join([x.replace(PathDelimiter, 2*PathDelimiter) for x in p_comps])

            records.append(x)
        elif type(x) is ImportSharedFolder:
            if shared:
                continue
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

    if folders:
        shared_folder_add = prepare_shared_folder_add(params, folders)
        execute_batch(params, shared_folder_add)

    if records:
        # create folders
        folder_add = prepare_folder_add(params, records)
        execute_batch(params, folder_add)

        # create records
        record_adds = prepare_record_add(params, records)
        execute_batch(params, record_adds)

        # ensure records are linked to folders
        record_links = prepare_record_link(params, records)
        execute_batch(params, record_links)

        # adjust shared folder permissions
        shared_update = prepare_record_permission(params, records)
        execute_batch(params, shared_update)

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
        print("{0} records imported successfully".format(records_after - records_before))


def upload_attachment(params, attachments):
    '''
    :param attachments:
    :type attachments: [(str, ImportAttachment)]
    '''

    if len(attachments) > 0:
        print('Uploading attachments:')
        uploads = None

        file_no = 0
        file_size = 0
        for _, att in attachments:
            file_no += 1
            file_size += att.size or 0

        #TODO check storage subscription
        rq = {
            'command': 'request_upload',
            'file_count': file_no
        }
        try:
            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                uploads = rs['file_uploads']
        except Exception as e:
            print(e)
            return

        uploaded = {}
        for record_id, atta in attachments:
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
                pass

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
                    extra = json.loads(rec['extra'].decode('utf-8')) if 'extra' in rec else {}
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
                        'data': api.encrypt_aes(rec['data'], rec['record_key_unencrypted']),
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

            except:
                pass


def prepare_shared_folder_add(params, folders):
    folder_hash = {}
    for f_uid in params.folder_cache:
        fol = params.folder_cache[f_uid]
        h = hashlib.md5()
        hs = '{0}|{1}'.format((fol.name or '').lower(), fol.parent_uid or '')
        h.update(hs.encode())
        shared_folder_key = None
        if fol.type in { BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            sf_uid = fol.shared_folder_uid if fol.type == BaseFolderNode.SharedFolderFolderType else fol.uid
            if sf_uid in params.shared_folder_cache:
                shared_folder_key = params.shared_folder_cache[sf_uid]['shared_folder_key']
        folder_hash[h.hexdigest()] = f_uid, fol.type, shared_folder_key

    # public keys
    emails = {}
    for fol in folders:
        if fol.permissions:
            for perm in fol.permissions:
                if perm.name not in emails:
                    _, email = parseaddr(perm.name)
                    if email:
                        if email != params.user:
                            emails[email.lower()] = None
    if emails:
        request = {
            'command': "public_keys",
            'key_owners': list(emails.keys())
        }
        try:
            rs = api.communicate(params, request)
            if 'public_keys' in rs:
                for pk in rs['public_keys']:
                    if 'public_key' in pk:
                        emails[pk['key_owner']] = pk['public_key']
        except Exception as e:
            if params.debug: print(e)

    shared_folder_add = []
    for fol in folders:
        skip_folder = False
        parent_uid = ''
        parent_type = ''
        parent_key = None
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
                request = {
                    'command': 'folder_add',
                    'folder_uid': folder_uid
                }
                folder_type = 'shared_folder' if is_last else 'user_folder'
                request['folder_type'] = folder_type

                encryption_key = params.data_key
                folder_key = os.urandom(32)
                request['key'] = api.encrypt_aes(folder_key, encryption_key)
                if parent_uid:
                    request['parent_uid'] = parent_uid
                if folder_type == 'shared_folder':
                    request['name'] = api.encrypt_aes(comp.encode('utf-8'), folder_key)

                data = {'name': comp}
                request['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)

                shared_folder_add.append(request)
                parent_uid = folder_uid
                parent_type = folder_type
                parent_key = folder_key
                folder_hash[digest] = folder_uid, folder_type, folder_key if folder_type == 'shared_folder' else None
            else:
                parent_uid, parent_type, parent_key = folder_hash[digest]
                if is_last:
                    skip_folder = parent_type != 'shared_folder'
                else:
                    skip_folder = parent_type != 'user_folder'
            if skip_folder:
                break

        if not skip_folder and parent_type == 'shared_folder':
            request = {
                'command': 'shared_folder_update',
                'operation': 'update',
                'pt': 'Commander',
                'shared_folder_uid': parent_uid,
                'force_update': True,
                'default_manage_users': fol.manage_users,
                'default_manage_records': fol.manage_records,
                'default_can_edit': fol.can_edit,
                'default_can_share': fol.can_share
            }
            if fol.permissions:
                for perm in fol.permissions:
                    is_team = False
                    if perm.uid and params.team_cache:
                        is_team = perm.uid in params.team_cache
                    else:
                        _, email = parseaddr(perm.name)
                        if not email:
                            is_team = True
                        if is_team:
                            perm.uid = None
                            for team in params.team_cache:
                                if team['name'].lower() == perm.name.lower():
                                    perm.uid = team['team_uid']
                                    break
                    if is_team:
                        if perm.uid and perm.uid in params.team_cache:
                            if 'add_teams' not in request:
                                request['add_teams'] = []
                            team = params.team_cache[perm.uid]
                            request['add_teams'].append({
                                'team_uid': perm.uid,
                                'manage_users': perm.manage_users,
                                'manage_records': perm.manage_records,
                                'shared_folder_key': api.encrypt_aes(parent_key, team['team_key'])
                            })
                    else:
                        if 'add_users' not in request:
                            request['add_users'] = []
                        email = perm.name.lower()
                        if email == params.user.lower():
                            request['add_users'].append({
                                'username': email,
                                'manage_users': perm.manage_users,
                                'manage_records': perm.manage_records,
                                'shared_folder_key': api.encrypt_aes(parent_key, params.data_key)
                            })
                        elif email in emails:
                            public_key = emails[email]
                            if public_key:
                                try:
                                    rsa_key = RSA.importKey(base64.urlsafe_b64decode(public_key + '=='))
                                    request['add_users'].append({
                                        'username': email,
                                        'manage_users': perm.manage_users,
                                        'manage_records': perm.manage_records,
                                        'shared_folder_key': api.encrypt_rsa(parent_key, rsa_key)
                                    })
                                except:
                                    pass
            shared_folder_add.append(request)

    return shared_folder_add


def prepare_folder_add(params, records):
    folder_hash = {}
    for f_uid in params.folder_cache:
        fol = params.folder_cache[f_uid]
        h = hashlib.md5()
        hs = '{0}|{1}'.format((fol.name or '').lower(), fol.parent_uid or '')
        h.update(hs.encode())
        shared_folder_key = None
        if fol.type in { BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            sf_uid = fol.shared_folder_uid if fol.type == BaseFolderNode.SharedFolderFolderType else fol.uid
            if sf_uid in params.shared_folder_cache:
                shared_folder_key = params.shared_folder_cache[sf_uid]['shared_folder_key']
        folder_hash[h.hexdigest()] = f_uid, fol.type, shared_folder_key

    folder_add = []

    for rec in records:
        if rec.folders:
            for fol in rec.folders:
                parent_uid = ''
                parent_shared_folder_uid = None
                parent_shared_folder_key = None
                parent_type = BaseFolderNode.RootFolderType
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
                            request = {
                                'command': 'folder_add',
                                'folder_uid': folder_uid
                            }
                            if parent_type in {BaseFolderNode.UserFolderType, BaseFolderNode.RootFolderType}:
                                folder_type = 'shared_folder' if is_shared else 'user_folder'
                            else:
                                folder_type = 'shared_folder_folder'
                            request['folder_type'] = folder_type

                            encryption_key = params.data_key
                            if request['folder_type'] == 'shared_folder_folder' and parent_shared_folder_uid and parent_shared_folder_key:
                                encryption_key = parent_shared_folder_key
                                request['shared_folder_uid'] = parent_shared_folder_uid

                            folder_key = os.urandom(32)
                            request['key'] = api.encrypt_aes(folder_key, encryption_key)
                            if parent_type not in {BaseFolderNode.RootFolderType, BaseFolderNode.SharedFolderType}:
                                request['parent_uid'] = parent_uid

                            if request['folder_type'] == 'shared_folder':
                                request['name'] = api.encrypt_aes(comp.encode('utf-8'), folder_key)
                                parent_shared_folder_key = folder_key

                            data = {'name': comp}
                            request['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)
                            folder_add.append(request)
                            parent_uid = folder_uid
                            parent_type = folder_type
                            folder_hash[digest] = parent_uid, parent_type, parent_shared_folder_key
                        else:
                            parent_uid, parent_type, parent_shared_folder_key = folder_hash[digest]

                        if parent_type == BaseFolderNode.SharedFolderType:
                            parent_shared_folder_uid = parent_uid
                fol.uid = parent_uid

    return folder_add


def prepare_record_add(params, records):
    record_hash = {}
    for r_uid in params.record_cache:
        rec = api.get_record(params, r_uid)
        h = hashlib.md5()
        hs = '{0}|{1}|{2}'.format(rec.title or '', rec.login or '', rec.password or '')
        h.update(hs.encode())
        record_hash[h.hexdigest()] = r_uid

    record_adds = []
    for rec in records:
        h = hashlib.md5()
        hs = '{0}|{1}|{2}'.format(rec.title or '', rec.login or '', rec.password or '')
        h.update(hs.encode())
        rec_hash = h.hexdigest()

        record_uid = record_hash.get(rec_hash)
        if record_uid is None:
            record_key = os.urandom(32)
            record_uid = api.generate_record_uid()
            req = {
                'command': 'record_add',
                'record_uid': record_uid,
                'record_type': 'password',
                'record_key': api.encrypt_aes(record_key, params.data_key),
                'how_long_ago': 0,
                'folder_type': 'user_folder'
            }
            folder_uid = None
            if rec.folders:
                if len(rec.folders) > 0:
                    folder_uid = rec.folders[0].uid
            if folder_uid:
                if folder_uid in params.folder_cache:
                    folder = params.folder_cache[folder_uid]
                    if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        req['folder_uid'] = folder.uid
                        req['folder_type'] = 'shared_folder' if folder.type == BaseFolderNode.SharedFolderType else 'shared_folder_folder'

                        sh_uid = folder.uid if folder.type == BaseFolderNode.SharedFolderType else folder.shared_folder_uid
                        sf = params.shared_folder_cache[sh_uid]
                        req['folder_key'] = api.encrypt_aes(record_key, sf['shared_folder_key'])
                        if 'key_type' not in sf:
                            if 'teams' in sf:
                                for team in sf['teams']:
                                    req['team_uid'] = team['team_uid']
                                    if team['manage_records']:
                                        break
                    else:
                        req['folder_type'] = 'user_folder'
                        if folder.type != BaseFolderNode.RootFolderType:
                            req['folder_uid'] = folder.uid

            custom_fields = []
            if rec.custom_fields:
                for cf in rec.custom_fields:
                    custom_fields.append({
                        'name': cf,
                        'value': rec.custom_fields[cf]
                    })

            data = {
                'title': rec.title or '',
                'secret1': rec.login or '',
                'secret2': rec.password or '',
                'link': rec.login_url or '',
                'notes': rec.notes or '',
                'custom': custom_fields
            }
            req['data'] =  api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key)
            record_adds.append(req)

        rec.uid = record_uid

    return record_adds


def prepare_record_link(params, records):
    record_links = []
    for rec in records:
        if rec.folders and rec.uid:
            if rec.uid in params.record_cache:
                record = params.record_cache[rec.uid]
                folder_ids = list(find_folders(params, rec.uid))
                for fol in rec.folders:
                    if fol.uid and fol.uid in params.folder_cache:
                        if len(folder_ids) > 0:
                            if fol.uid not in folder_ids:
                                src_folder =  params.folder_cache[folder_ids[0]]
                                dst_folder = params.folder_cache[fol.uid]
                                req = {
                                    'command': 'move',
                                    'to_type': dst_folder.type if dst_folder.type != BaseFolderNode.RootFolderType else BaseFolderNode.UserFolderType,
                                    'link': True,
                                    'move': [],
                                    'transition_keys': []
                                }
                                if dst_folder.type != BaseFolderNode.RootFolderType:
                                    req['to_uid'] = dst_folder.uid
                                mo = {
                                    'type': 'record',
                                    'uid': rec.uid,
                                    'from_type': src_folder.type if src_folder.type != BaseFolderNode.RootFolderType else BaseFolderNode.UserFolderType,
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
                                            transition_key = api.encrypt_aes(record_key, shf['shared_folder_key'])
                                    else:
                                        transition_key = api.encrypt_aes(record_key, params.data_key)
                                else:
                                    if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                                        dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                                            dst_folder.shared_folder_uid
                                        shf = params.shared_folder_cache[dsf_uid]
                                        transition_key = api.encrypt_aes(record_key, shf['shared_folder_key'])
                                if transition_key is not None:
                                    req['transition_keys'].append({
                                        'uid': rec.uid,
                                        'key': transition_key
                                    })
                                record_links.append(req)
    return record_links


def prepare_record_permission(params, records):
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
                            sf_uid = folder.shared_folder_uid if folder.type == BaseFolderNode.SharedFolderFolderType else folder.uid
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


def execute_batch(params, requests):
    if not requests:
        return

    chunk_size = 100
    queue = requests.copy()
    while len(queue) > 0:
        chunk = queue[:chunk_size]
        queue = queue[chunk_size:]

        rq = {
            'command': 'execute',
            'requests': chunk
        }
        try:
            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                if 'results' in rs:
                    results = rs['results']
                    if len(results) > 0:
                        if params.debug:
                            pos = len(results) - 1
                            req = chunk[pos]
                            res = results[pos]
                            if res['result'] != 'success':
                                print('execute failed: command {0}: {1})'.format(req.get('command'), res.get('message')))
                        if len(results) < len(chunk):
                            queue = chunk[len(results):] + queue

        except Exception as e:
            if params.debug:
                print(e)
    api.sync_down(params)


def parse_sf_json(json):
    sf = SharedFolder()
    sf.default_manage_records = json['default_manage_records']
    sf.default_manage_users = json['default_manage_users']
    sf.default_can_edit = json['default_can_edit']
    sf.default_can_share = json['default_can_share']
    sf.name = json['name']
    sf.records = json['records'] if 'records' in json else []
    sf.users = json['users'] if 'users' in json else []
    sf.teams = json['teams'] if 'teams' in json else []
    return sf


def create_sf(params, filename):
    api.sync_down(params)

    def read_json():
        with open(filename, mode="rt", encoding="utf8") as f:
            return json.load(f)

    print('Creating shared folder(s)...')
    num_success = 0
    add_records_success = []
    user_success = []

    for json_sf in read_json():
        print('Preparing shared folder in read_json')
        my_shared_folder = api.prepare_shared_folder(params, parse_sf_json(json_sf))
        request = api.make_request(params, 'shared_folder_update')

        request.update(my_shared_folder)

        if params.debug: print('Sending request')
        response_json = api.communicate(params, request)

        if 'add_users' in response_json:
            user_success = [info for info in response_json['add_users'] if info['status'] == 'success']
            if len(user_success) > 0:
                print("{0} users added successfully".format(len(user_success)))

            user_failures = [info for info in response_json['add_users'] if info['status'] != 'success']
            if len(user_failures) > 0:
                print("{0} users failed to get added".format(len(user_failures)))

        if 'add_records' in response_json:
            add_records_success = [info for info in response_json['add_records'] if info['status'] == 'success']
            if len(add_records_success) > 0:
                print("{0} records added successfully".format(len(add_records_success)))

            add_records_failures = [info for info in response_json['add_records'] if info['status'] != 'success']
            if len(add_records_failures) > 0:
                print("{0} records failed to get added".format(len(add_records_failures)))

        if len(user_success)+len(add_records_success) > 0:
            num_success += 1
            print('Created shared folder ' + request['shared_folder_uid'] + 'with success')

    if num_success > 0:
        print('Successfully created ['+str(num_success)+'] shared folders')


def delete_all(params):
    api.sync_down(params)
    if len(params.record_cache) == 0:
        print('No records to delete')
        return
    request = api.make_request(params, 'record_update')
    print('removing {0} records from Keeper'.format(len(params.record_cache)))
    request['delete_records'] = [key for key in params.record_cache.keys()]
    response_json = api.communicate(params, request)
    success = [info for info in response_json['delete_records'] if info['status'] == 'success']
    if len(success) > 0:
        print("{0} records deleted successfully".format(len(success)))
    failures = [info for info in response_json['delete_records'] if info['status'] != 'success']
    if len(failures) > 0:
        print("{0} records failed to delete".format(len(failures)))


class KeeperAttachment(ImportAttachment):
    def __init__(self, params, record_uid,):
        ImportAttachment.__init__(self)
        self.params = params
        self.record_uid = record_uid

    @contextmanager
    def open(self):
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

