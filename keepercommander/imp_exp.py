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

import json
from keepercommander import api
from keepercommander.record import Record
from keepercommander.shared_folder import SharedFolder


def export(params, format, filename):
    api.sync_down(params)

    records = [api.get_record(params, record_uid) for record_uid in params.record_cache]

    records.sort(key=lambda x: ((x.folder if x.folder else ' ') + x.title).lower(), reverse=False)

    if format == 'json':
        with open(filename, 'w') as f:
            json.dump([record.to_dictionary() for record in records], f, indent=2, ensure_ascii=False)
    else:
        with open(filename, 'wt') as f:
            for record in records:
                f.write(record.to_tab_delimited() + '\n')
            print('{0} records exported to {1}'.format(len(records), filename))


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

def parse_record_json(json):
    record = Record()
    record.folder = json['folder']
    record.title = json['title']
    record.login = json['login']
    record.password = json['password']
    record.login_url = json['login_url']
    record.notes = json['notes']
    record.custom_fields = json['custom_fields']
    return record

def parse_sf_json(json):
    sf = SharedFolder()
    sf.default_manage_records = json['default_manage_records']
    sf.default_manage_users = json['default_manage_users']
    sf.default_can_edit = json['default_can_edit']
    sf.default_can_share = json['default_can_share']
    sf.name = json['name']
    sf.records = json['records']
    sf.users = json['users']
    sf.teams = json['teams']
    return sf

def _import(params, format, filename):
    api.login(params)

    if format == 'json':
        def read_json():
            with open(filename, 'rt') as f:
                return json.load(f)

        records_to_add = [api.prepare_record(params, parse_record_json(json)) for json in read_json()]
    else:
        def read_lines():
            with open(filename, 'rt') as f:
                return f.readlines()

        records_to_add = [api.prepare_record(params, parse_line(line)) for line in read_lines()]

    if (len(records_to_add) == 0):
        print('No records to import')
        return

    request = api.make_request(params, 'record_update')
    print('importing {0} records to Keeper'.format(len(records_to_add)))
    request['add_records'] = records_to_add
    response_json = api.communicate(params, request)
    success = [info for info in response_json['add_records'] if info['status'] == 'success']
    if len(success) > 0:
        print("{0} records imported successfully".format(len(success)))
    failures = [info for info in response_json['add_records'] if info['status'] != 'success']
    if len(failures) > 0:
        print("{0} records failed to import".format(len(failures)))


def create_sf(params, filename):
    api.sync_down(params)

    def read_json():
        with open(filename, 'rt') as f:
            return json.load(f)

    print('Creating shared folder(s)...')
    num_success = 0

    for json_sf in read_json():
        print('Preparing shared folder')
        my_shared_folder = api.prepare_shared_folder(params, parse_sf_json(json_sf))
        request = api.make_request(params, 'shared_folder_update')

        request.update(my_shared_folder)

        if params.debug: print('Sending request')
        response_json = api.communicate(params, request)

        user_success = [info for info in response_json['add_users'] if info['status'] == 'success']
        if len(user_success) > 0:
            print("{0} users added successfully".format(len(user_success)))

        user_failures = [info for info in response_json['add_users'] if info['status'] != 'success']
        if len(user_failures) > 0:
            print("{0} users failed to get added".format(len(user_failures)))

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
