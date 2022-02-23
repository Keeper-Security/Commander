#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# This example also pulls configuration
# from config.json or writes the config file if it does not exist.
#
# Usage:
#    python aging_report.py

import base64
import datetime
import getpass
import getopt
import json
import os
import sqlite3
import sys

from keepercommander import api, utils, crypto
from keepercommander.commands.aram import AuditReportCommand
from keepercommander.params import KeeperParams
from keepercommander.proto import enterprise_pb2
from keepercommander.commands.base import dump_report_data


def read_config_file(params):
    params.config_filename = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.isfile(params.config_filename):
        with open(params.config_filename, 'r') as f:
            params.config = json.load(f)
            if 'user' in params.config:
                params.user = params.config['user']

            if 'password' in params.config:
                params.password = params.config['password']

            if 'mfa_token' in params.config:
                params.mfa_token = params.config['mfa_token']

            if 'server' in params.config:
                params.server = params.config['server']

            if 'device_id' in params.config:
                device_id = base64.urlsafe_b64decode(params.config['device_id'] + '==')
                params.rest_context.device_id = device_id


def connect():
    my_params = KeeperParams()
    read_config_file(my_params)

    while not my_params.user:
        my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

    while not my_params.password:
        my_params.password = getpass.getpass(prompt='Master Password: ', stream=None)

    api.login(my_params)
    api.sync_down(my_params)
    api.query_enterprise(my_params)
    return my_params


def prepare_database(params):
    user_lookup = {x['username']: x['enterprise_user_id'] for x in params.enterprise['users']}
    last_audit_time = 0

    # get SOX data
    with sqlite3.connect(os.path.join(os.path.dirname(__file__), f'sox_data.db')) as connection:
        rs = connection.execute('pragma table_info(\'audit_data\')').fetchall()
        if rs:
            rs = connection.execute('select max(time) from audit_data where time is not null').fetchall()
            try:
                if rs[0][0] is not None:
                    last_audit_time = rs[0][0]
            except:
                pass

        else:
            connection.execute('create table audit_data (record_uid TEXT NOT NULL, user INTEGER NOT NULL, encrypted_data TEXT NOT NULL, '
                               'shared INTEGER NOT NULL, time INTEGER NULL, primary key (record_uid))')
            connection.execute('create index audit_data_user_idx on audit_data(user)')
            connection.execute('create index audit_data_time_idx on audit_data(time)')

            print('Loading record information.')
            user_ids = list(user_lookup.values())
            loaded = 0
            while user_ids:
                continuation_token = b''
                chunk = user_ids[:999]
                user_ids = user_ids[999:]
                rq = enterprise_pb2.PreliminaryComplianceDataRequest()
                rq.enterpriseUserIds.extend(chunk)
                rq.includeNonShared = True
                has_more = True
                total_records = 0
                while has_more:
                    if continuation_token:
                        rq.continuationToken = continuation_token
                    rs = api.communicate_rest(params, rq, 'enterprise/get_preliminary_compliance_data',
                                              rs_type=enterprise_pb2.PreliminaryComplianceDataResponse)
                    has_more = rs.hasMore
                    continuation_token = rs.continuationToken
                    if rs.totalMatchingRecords:
                        total_records = rs.totalMatchingRecords
                    for user in rs.auditUserData:
                        loaded += len(user.auditUserRecords)
                    print(f'{loaded} of {total_records} records      \r', end='')

                    def get_audit_data():
                        for user in rs.auditUserData:
                            if user.status == enterprise_pb2.OK:
                                for record in user.auditUserRecords:
                                    yield (utils.base64_url_encode(record.recordUid), user.enterpriseUserId,
                                           1 if record.shared else 0, utils.base64_url_encode(record.encryptedData))

                        connection.executemany('insert into audit_data (record_uid, user, shared, encrypted_data) values (?, ?, ?, ?) ' +
                                               'on conflict (record_uid) do update set ' +
                                               'user=excluded.user, shared=excluded.shared, encrypted_data=excluded.encrypted_data',
                                               get_audit_data())

                    connection.commit()
            print('')

        report_command = AuditReportCommand()
        has_more = True
        if last_audit_time == 0:
            from_date = datetime.datetime.now()
            from_date = from_date.replace(year=(from_date.year - 5))
            last_audit_time = from_date.timestamp()
        loaded = 0
        while has_more:
            has_more = False
            report_data = report_command.execute(params, report_type='span', columns=['record_uid'], aggregate=['last_created'], order='asc', limit=1000,
                                                 created=f'> {int(last_audit_time)}', event_type='record_password_change', format='json')
            data = json.loads(report_data)
            if not data:
                break
            if loaded == 0:
                print('Loading record password change information.')
            loaded += len(data)
            print(f'{loaded}      \r', end='')
            if len(data) == 1000:
                last_event = data[-1]
                from_date = datetime.datetime.strptime(last_event['last_created'], '%Y-%m-%dT%H:%M:%S%z')
                last_audit_time = from_date.timestamp()
                has_more = True

            def get_password_data():
                for event in data:
                    last_created = event['last_created']
                    dt = datetime.datetime.strptime(last_created, '%Y-%m-%dT%H:%M:%S%z')
                    yield int(dt.timestamp()), event['record_uid']

            connection.executemany('update or ignore audit_data set time = ? where record_uid = ?', get_password_data())
            connection.commit()
        print('')


if __name__ == '__main__':
    params = connect()
    prepare_database(params)
    period = ''
    output_format = 'table'
    opts, args = getopt.getopt(sys.argv[1:], 'p:f:', ['period=', 'format='])
    for o, v in opts:
        if o in {'-p', '--period'}:
            period = v
        elif o in {'-f', '--format'}:
            if v in {'table', 'json', 'csv'}:
                output_format = v

    dt = datetime.datetime.now()
    if not period:
        period = '3m'

    co = period[-1]
    va = 0
    try:
        va = abs(int(period[:-1]))
    except:
        print(f'Invalid period: {period}')
        exit(-1)

    if co == 'd':
        dt = dt - datetime.timedelta(days=-va)
    elif co == 'm':
        month = dt.month
        year = dt.year
        month -= va
        while month < 1:
            month += 12
            year -= 1
        dt = dt.replace(month=month, year=year)
    elif co == 'y':
        dt = dt.replace(year=dt.year-va)
    else:
        print(f'Invalid period: {period}')
        exit(-1)

    user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise['users']}
    tree_key = params.enterprise['unencrypted_tree_key']
    ecc_key = utils.base64_url_decode(params.enterprise['keys']['ecc_encrypted_private_key'])
    ecc_key = crypto.decrypt_aes_v2(ecc_key, tree_key)
    ec_private_key = crypto.load_ec_private_key(ecc_key)

    error_count = 0
    table = []
    columns = ['owner', 'title', 'password_changed', 'shared', 'record_url'] if output_format == 'json' else \
        ['Owner', 'Record Title', 'Last Password Change', 'Shared', 'Record URL']
    with sqlite3.connect(os.path.join(os.path.dirname(__file__), f'sox_data.db')) as connection:
        cursor = connection.execute('select record_uid, user, time, shared, encrypted_data from audit_data where time is not null and time < ?', (int(dt.timestamp()),))
        for record_uid, user_id, timestamp, shared, encrypted_data in cursor:
            if user_id not in user_lookup:
                continue

            try:
                audit_json = crypto.decrypt_ec(utils.base64_url_decode(encrypted_data), ec_private_key)
                audit = json.loads(audit_json.decode())
                row = [user_lookup[user_id], audit.get('title', record_uid), datetime.datetime.fromtimestamp(timestamp), True if shared > 0 else False,
                       f'https://{params.server}/vault/#detail/{record_uid}']
                table.append(row)
            except:
                error_count += 1

    report = dump_report_data(table, columns, fmt=output_format)
    if report:
        print(report)






