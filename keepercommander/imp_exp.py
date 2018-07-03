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
from keepercommander import api
from keepercommander.importer.importer import importer_for_format, exporter_for_format, path_components, PathDelimiter, BaseImporter, BaseExporter, Record as ImportRecord
from keepercommander.subfolder import BaseFolderNode, find_folders, get_folder_path


def export(params, format, filename):
    api.sync_down(params)

    records = [api.get_record(params, record_uid) for record_uid in params.record_cache]
    records.sort(key=lambda x: ((x.folder if x.folder else ' ') + x.title).lower(), reverse=False)

    exporter = exporter_for_format(format)()
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
        fols = find_folders(params, r.record_uid)
        for x in fols:
            if len(x) > 0:
                rec.folder = get_folder_path(params, x, delimiter=PathDelimiter)
                break
        recs.append(rec)

    if len(recs) > 0:
        exporter.execute(filename, recs)


def _import(params, format, filename):
    api.login(params)
    api.sync_down(params)

    importer = importer_for_format(format)()
    """:type : BaseImporter"""

    success = 0
    record_hash = {}
    for r_uid in params.record_cache:
        rec = api.get_record(params, r_uid)
        h = hashlib.md5()
        hs = '{0}|{1}|{2}'.format(rec.title or '', rec.login or '', rec.password or '')
        h.update(hs.encode())
        record_hash[h.hexdigest()] = r_uid

    for x in importer.execute(filename):
        if type(x) is ImportRecord:
            h = hashlib.md5()
            hs = '{0}|{1}|{2}'.format(x.title or '', x.login or '', x.password or '')
            h.update(hs.encode())
            hash = h.hexdigest()
            if hash in record_hash:
                continue

            folder_uid = resolve_folder(params, x.folder)
            record_key = os.urandom(32)
            data = {
                'title': x.title or '',
                'secret1': x.login or '',
                'secret2': x.password or '',
                'link': x.login_url or '',
                'notes': x.notes or '',
                'custom': x.custom_fields
            }
            rq = {
                'command': 'record_add',
                'record_uid': api.generate_record_uid(),
                'record_type': 'password',
                'record_key': api.encrypt_aes(record_key, params.data_key),
                'folder_type': 'user_folder',
                'how_long_ago': 0,
                'data': api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key)
            }
            key_encryption_key = params.data_key
            if folder_uid:
                if folder_uid in params.folder_cache:
                    folder = params.folder_cache[folder_uid]
                    if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        rq['folder_uid'] = folder.uid
                        rq['folder_type'] = 'shared_folder' if folder.type == BaseFolderNode.SharedFolderType else 'shared_folder_folder'
                        sh_uid = folder.uid if folder.type == BaseFolderNode.SharedFolderType else folder.shared_folder_uid
                        sf = params.shared_folder_cache[sh_uid]
                        rq['folder_key'] = api.encrypt_aes(record_key, sf['shared_folder_key'])
                        if 'key_type' not in sf:
                            if 'teams' in sf:
                                for team in sf['teams']:
                                    rq['team_uid'] = team['team_uid']
                                    if team['manage_records']:
                                        break
                    else:
                        rq['folder_uid'] = folder.uid

            try:
                rs = api.communicate(params, rq)
                success = success + 1
            except Exception as e:
                print(e)

        api.sync_down(params)

    if success > 0:
        print("{0} records imported successfully".format(success))


'''
####### create_sf
@click.command('create_sf', help='Create shared folders from JSON input file')
@click.pass_obj
@click.argument('filename')
def create_sf(params, filename):
    try:
        prompt_for_credentials(params)
        imp_exp.create_sf(params, filename)
    except Exception as e:
        raise click.ClickException(e)


def parse_line(line):
    fields = line.split('\t')
    record = Record()
    record.folder = fields[0]
    record.title = fields[1]
    record.login = fields[2]
    record.password = fields[3]
    record.login_url = fields[4]
    record.notes = fields[5].replace('\\\\n', '\n')
    record.custom_fields = [{'name': fields[i], 'value': fields[i + 1], 'type': 'text'} for i in
                            range(6, len(fields) - 1, 2)]
    return record


def parse_record_json(record_json):
    record = Record()
    record.folder = record_json['folder']
    record.title = record_json['title']
    record.login = record_json['login']
    record.password = record_json['password']
    record.login_url = record_json['login_url']
    record.notes = record_json['notes']
    record.custom_fields = record_json['custom_fields']
    return record


def parse_sf_json(sf_json):
    sf = SharedFolder()
    sf.default_manage_records = sf_json['default_manage_records']
    sf.default_manage_users = sf_json['default_manage_users']
    sf.default_can_edit = sf_json['default_can_edit']
    sf.default_can_share = sf_json['default_can_share']
    sf.name = sf_json['name']
    sf.records = sf_json['records']
    sf.users = sf_json['users']
    sf.teams = sf_json['teams']
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
'''


def delete_all(params):
    api.sync_down(params)
    if (len(params.record_cache) == 0):
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


def resolve_folder(params, path):
    folders = path_components(path)
    folder_uid = ''
    for comp in folders:
        fn = comp
        shared_props = None
        if fn.endswith('$'):
            fn = fn[:-1].strip()
            shared_props = {}
            has_flag = True
            while has_flag:
                has_flag = False
                for fl in ['edit', 'reshare']:
                    flag = '#' + fl
                    if fn.endswith('#'+flag):
                        fn = fn[:-len(flag)]
                        shared_props[fl] = True
                        has_flag = True
                        break

        if len(fn) > 0:
            found = False
            folder = params.folder_cache[folder_uid] if len(folder_uid) > 0 else params.root_folder
            for fuid in folder.subfolders:
                f = params.folder_cache[fuid]
                if f.name.lower() == fn.lower():
                    folder_uid = f.uid
                    found = True
                    break
            if not found:
                request = {"command": "folder_add"}
                fuid = api.generate_record_uid()
                request['folder_uid'] = fuid
                if folder.type in {BaseFolderNode.UserFolderType, BaseFolderNode.RootFolderType}:
                    request['folder_type'] = 'user_folder' if shared_props is None else 'shared_folder'
                else:
                    request['folder_type'] = 'shared_folder_folder'
                folder_key = os.urandom(32)
                encryption_key = params.data_key
                if request['folder_type'] == 'shared_folder_folder':
                    sf_uid = folder.shared_folder_uid if folder.type == BaseFolderNode.SharedFolderFolderType else folder.uid
                    sf = params.shared_folder_cache[sf_uid]
                    encryption_key = sf['shared_folder_key']
                    request['shared_folder_uid'] = sf_uid

                request['key'] = api.encrypt_aes(folder_key, encryption_key)
                if folder.type not in {BaseFolderNode.RootFolderType, BaseFolderNode.SharedFolderType}:
                    request['parent_uid'] = folder.uid

                if request['folder_type'] == 'shared_folder':
                    request['name'] = api.encrypt_aes(fn.encode('utf-8'), folder_key)
                    if shared_props is not None:
                        if 'edit' in shared_props:
                            request['can_edit'] = True
                        if 'reshare' in shared_props:
                            request['can_share'] = True
                        #request['manage_users'] = True
                        #request['manage_records'] = True

                data = {'name': fn}
                request['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)

                try:
                    rs = api.communicate(params, request)
                    api.sync_down(params)
                    folder_uid = fuid
                except Exception as e:
                    print(e)
                    break

    return folder_uid
