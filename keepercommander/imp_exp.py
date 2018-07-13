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

from . import api
from .importer.importer import importer_for_format, exporter_for_format, path_components, PathDelimiter, \
    Record as ImportRecord, Folder as ImportFolder
from .subfolder import BaseFolderNode, find_folders


def get_import_folder(params, folder_uid, record_uid):
    folder = ImportFolder()

    uid = folder_uid
    while uid in params.folder_cache:
        f = params.folder_cache[uid]
        name = f.name.replace(PathDelimiter, 2*PathDelimiter)
        if folder.path:
            folder.path = name + PathDelimiter + folder.path
        else:
            folder.path = name

        if f.type == 'shared_folder':
            folder.domain = folder.path
            folder.path = None
            if f.uid in params.shared_folder_cache:
                sf = params.shared_folder_cache[f.uid]
                if 'records' in sf:
                    for sfr in sf['records']:
                        if sfr['record_uid'] == record_uid:
                            folder.can_share = sfr['can_share']
                            folder.can_edit = sfr['can_edit']
                            break

        uid = f.parent_uid
        if not uid:
            break

    return folder


def export(params, file_format, filename):
    api.sync_down(params)

    records = [api.get_record(params, record_uid) for record_uid in params.record_cache]
    records.sort(key=lambda x: ((x.folder if x.folder else ' ') + x.title).lower(), reverse=False)

    exporter = exporter_for_format(file_format)()
    """:type : BaseExporter"""

    recs = []
    for r in records:
        rec = ImportRecord()
        rec.title = r.title
        rec.login = r.login
        rec.password = r.password
        rec.login_url = r.login_url
        rec.notes = r.notes
        rec.custom_fields.extend(r.custom_fields)
        for folder_uid in find_folders(params, r.record_uid):
            if folder_uid in params.folder_cache:
                folder = get_import_folder(params, folder_uid, r.record_uid)
                if rec.folders is None:
                    rec.folders = []
                rec.folders.append(folder)
        recs.append(rec)

    if len(recs) > 0:
        exporter.execute(filename, recs)
        print('{0} records exported'.format(len(recs)))


def _import(params, file_format, filename):
    api.login(params)
    api.sync_down(params)

    importer = importer_for_format(file_format)()
    """:type : BaseImporter"""

    records_before = len(params.record_cache)

    records = []  # type: [ImportRecord]
    for x in importer.execute(filename):
        if type(x) is ImportRecord:
            records.append(x)

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

    records_after = len(params.record_cache)
    if records_after > records_before:
        print("{0} records imported successfully".format(records_after - records_before))


def prepare_folder_add(params, records):
    folder_hash = {}
    for f_uid in params.folder_cache:
        fol = params.folder_cache[f_uid]
        h = hashlib.md5()
        hs = '{0}|{1}'.format((fol.name or '').lower(), fol.parent_uid or '')
        h.update(hs.encode())
        folder_hash[h.hexdigest()] = f_uid, fol.type

    folder_add = []
    for rec in records:
        if rec.folders:
            for fol in rec.folders:
                parent_uid = ''
                parent_shared_folder_uid = None
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
                            if request['folder_type'] == 'shared_folder_folder' and parent_shared_folder_uid:
                                sf = params.shared_folder_cache[parent_shared_folder_uid]
                                encryption_key = sf['shared_folder_key']
                                request['shared_folder_uid'] = parent_shared_folder_uid

                            folder_key = os.urandom(32)
                            request['key'] = api.encrypt_aes(folder_key, encryption_key)
                            if parent_type not in {BaseFolderNode.RootFolderType, BaseFolderNode.SharedFolderType}:
                                request['parent_uid'] = parent_uid

                            if request['folder_type'] == 'shared_folder':
                                request['name'] = api.encrypt_aes(comp.encode('utf-8'), folder_key)
                                request['manage_users'] = True
                                request['manage_records'] = True

                            data = {'name': comp}
                            request['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)
                            folder_add.append(request)
                            parent_uid = folder_uid
                            parent_type = folder_type
                            folder_hash[digest] = parent_uid, parent_type
                        else:
                            parent_uid, parent_type = folder_hash[digest]

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

            data = {
                'title': rec.title or '',
                'secret1': rec.login or '',
                'secret2': rec.password or '',
                'link': rec.login_url or '',
                'notes': rec.notes or '',
                'custom': rec.custom_fields or []
            }
            req['data'] =  api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key)
            record_adds.append(req)

        rec.record_uid = record_uid

    return record_adds


def prepare_record_link(params, records):
    record_links = []
    for rec in records:
        if rec.folders and rec.record_uid:
            if rec.record_uid in params.record_cache:
                folder_ids = list(find_folders(params, rec.record_uid))
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
                                    'uid': rec.record_uid,
                                    'from_type': src_folder.type if src_folder.type != BaseFolderNode.RootFolderType else BaseFolderNode.UserFolderType,
                                    'cascade': True
                                }
                                if src_folder.type != BaseFolderNode.RootFolderType:
                                    mo['from_uid'] = src_folder.uid
                                req['move'].append(mo)

                                transition_key = None
                                record_key = rec['record_key_unencrypted']
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
                                        'uid': rec.record_uid,
                                        'key': transition_key
                                    })
                                record_links.append(req)
    return record_links


def prepare_record_permission(params, records):
    shared_update = []
    for rec in records:
        if rec.folders and rec.record_uid:
            if rec.record_uid in params.record_cache:
                for fol in rec.folders:
                    if fol.uid and fol.uid in params.folder_cache:
                        folder = params.folder_cache[fol.uid]
                        if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                            sf_uid = folder.shared_folder_uid if folder.type == BaseFolderNode.SharedFolderFolderType else folder.uid
                            if sf_uid in params.shared_folder_cache:
                                sf = params.shared_folder_cache[sf_uid]
                                if 'records' in sf:
                                    for sfr in sf['records']:
                                        if sfr['record_uid'] == rec.record_uid:
                                            if sfr['can_share'] != fol.can_share or sfr['can_edit'] != fol.can_edit:
                                                req = {
                                                    'command': 'shared_folder_update',
                                                    'pt': 'Commander',
                                                    'operation': 'update',
                                                    'shared_folder_uid': sf_uid,
                                                    'force_update': True,
                                                    'update_records': [{
                                                        'record_uid': rec.record_uid,
                                                        'shared_folder_uid': sf_uid,
                                                        'can_edit': fol.can_edit,
                                                        'can_share': fol.can_share
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
