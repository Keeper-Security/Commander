# -*- coding: utf-8 -*-
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

import argparse
import itertools
import json
import logging
from typing import Tuple, List, Optional, Set

from .base import user_choice, dump_report_data, Command
from .. import api, crypto, utils, vault, error
from ..proto import record_pb2
from ..record import get_totp_code


verify_shared_folders_parser = argparse.ArgumentParser(prog='verify-shared-folders')
verify_shared_folders_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                                          help='Display the the found problems without fixing')
verify_shared_folders_parser.add_argument('target', nargs='*', help='Shared folder UID or name.')


class VerifySharedFoldersCommand(Command):
    def get_parser(self):
        return verify_shared_folders_parser

    def execute(self, params, **kwargs):
        shared_folders = None    # type: Optional[Set[str]]
        target = kwargs.get('target')
        if isinstance(target, list) and len(target) > 0:
            shared_folders = set()
            sf_names = {x['name_unencrypted'].lower(): x['shared_folder_uid']
                        for x in params.shared_folder_cache.values()}
            for name in target:
                if name in params.shared_folder_cache:
                    shared_folders.add(name)
                else:
                    sf_name = name.lower()
                    if sf_name in sf_names:
                        shared_folders.add(sf_names[sf_name])
                    else:
                        raise error.CommandError('shared_folders', f'Shared folder \"{name}\" not found')

        rq = {
            'command': 'sync_down',
            'revision': 0,
            'include': ['shared_folder', 'sfheaders', 'sfusers', 'sfrecords', 'explicit']
        }
        rs = api.communicate(params, rq)
        sf_v3_keys = []     # type: List[Tuple[str, str]]  # (record_uid, shared_folder_uid)
        sf_v2_keys = []     # type: List[Tuple[str, str]]  # (record_uid, shared_folder_uid)
        if 'shared_folders' in rs:
            for sf in rs['shared_folders']:
                shared_folder_uid = sf['shared_folder_uid']
                if 'records' in sf:
                    for rec in sf['records']:
                        record_uid = rec['record_uid']
                        record = params.record_cache.get(record_uid)
                        if not record:
                            continue
                        if 'record_key' not in rec:
                            continue
                        record_key = utils.base64_url_decode(rec['record_key'])
                        version = record.get('version', 0)
                        if version == 3:
                            if len(record_key) != 60:
                                if shared_folders is None or shared_folder_uid in shared_folders:
                                    sf_v3_keys.append((record_uid, shared_folder_uid))
                        elif version == 2:
                            if len(record_key) == 60:
                                if shared_folders is None or shared_folder_uid in shared_folders:
                                    sf_v2_keys.append((record_uid, shared_folder_uid))

        if not sf_v3_keys and not sf_v2_keys:
            if kwargs.get('dry_run'):
                print(f'There are no record keys to be corrected')
            return

        if len(sf_v3_keys) > 0:
            record_uids = list({x[0] for x in sf_v3_keys})
            print(f'There {("are" if len(record_uids) > 1 else "is")} {len(record_uids)} V3 record key(s) to be corrected')
            try:
                for record_uid in record_uids[:99]:
                    record = vault.KeeperRecord.load(params, record_uid)
                    print(f' {record_uid}  {record.title}')
                if len(record_uids) > 99:
                    print(f' {(len(record_uids) - 99)} more ...')
            except:
                pass

        if len(sf_v2_keys) > 0:
            record_uids = list({x[0] for x in sf_v2_keys})
            print(f'There {("are" if len(record_uids) > 1 else "is")} {len(record_uids)} V2 record key(s) to be corrected')
            try:
                for record_uid in record_uids[:99]:
                    record = vault.KeeperRecord.load(params, record_uid)
                    print(f' {record_uid}  {record.title}')
                if len(record_uids) > 99:
                    print(f' {(len(record_uids) - 99)} more ...')
            except:
                pass

        if kwargs.get('dry_run'):
            return

        answer = user_choice('Do you want to proceed?', 'yn', 'n')
        if answer.lower() == 'y':
            sf_v3_keys.sort(key=lambda x: x[0])
            while sf_v3_keys:
                chunk = sf_v3_keys[:999]
                sf_v3_keys = sf_v3_keys[999:]

                record_convert = None
                last_record_uid = ''
                rq = record_pb2.RecordsConvertToV3Request()
                for record_uid, shared_folder_uid in chunk:
                    if shared_folder_uid not in params.shared_folder_cache:
                        continue
                    if record_uid not in params.record_cache:
                        continue

                    record = params.record_cache[record_uid]
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    if last_record_uid != record_uid:
                        if record_convert:
                            rq.records.append(record_convert)
                        last_record_uid = record_uid
                        record_convert = record_pb2.RecordConvertToV3()
                        record_convert.record_uid = utils.base64_url_decode(record_uid)
                        record_convert.client_modified_time = utils.current_milli_time()
                        record_convert.revision = record['revision']
                        record_convert.data = utils.base64_url_decode(record['data'])
                        if params.enterprise_ec_key:
                            rec = vault.KeeperRecord.load(params, record_uid)
                            if isinstance(rec, vault.TypedRecord):
                                audit_data = {
                                    'title': rec.title or '',
                                    'record_type': rec.record_type,
                                }
                                field = rec.get_typed_field('url')
                                if field:
                                    default_value = field.get_default_value(str)
                                    if default_value:
                                        audit_data['url'] = utils.url_strip(default_value)
                                record_convert.audit.data = crypto.encrypt_ec(json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

                    fk = record_pb2.RecordFolderForConversion()
                    fk.folder_uid = utils.base64_url_decode(shared_folder_uid)
                    fk.record_folder_key = crypto.encrypt_aes_v2(record['record_key_unencrypted'], shared_folder['shared_folder_key_unencrypted'])
                    record_convert.folder_key.append(fk)

                if record_convert:
                    rq.records.append(record_convert)

                rs = api.communicate_rest(params, rq, 'vault/records_convert3', rs_type=record_pb2.RecordsModifyResponse)
                if rs:
                    pass

            if sf_v2_keys:
                sf_v2_keys.sort(key=lambda x: x[1])
                rqs = []
                rq = None
                for record_uid, shared_folder_uid in sf_v2_keys:
                    record = params.record_cache[record_uid]
                    record_key = record['record_key_unencrypted']
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    shared_folder_key = shared_folder['shared_folder_key_unencrypted']
                    if not rq or rq['shared_folder_uid'] != shared_folder_uid or len(rq['add_records']) > 95:
                        if rq and len(rq['add_records']) > 0:
                            rqs.append(rq)
                        rq = {
                            'command': 'shared_folder_update',
                            'pt': 'Commander',
                            'operation': 'update',
                            'shared_folder_uid': shared_folder_uid,
                            'name': shared_folder['name'],
                            'revision': shared_folder['revision'],
                            'add_records': []
                        }
                    rq['add_records'].append({
                        'record_uid': record_uid,
                        'record_key': utils.base64_url_encode(crypto.encrypt_aes_v1(record_key, shared_folder_key)),
                        'can_edit': False,
                        'can_share': False,
                    })
                if rq:
                    rqs.append(rq)

                rss = api.execute_batch(params, rqs)
                results = []
                for i, rs in enumerate(rss):
                    shared_folder_uid = rqs[i].get('shared_folder_uid')
                    if rs.get('result') != 'success':
                        results.append([shared_folder_uid, '', '', rs.get('result_code')])
                    elif 'add_records' in rs:
                        if shared_folder_uid:
                            for status in rs['add_records']:
                                if status.get('status') != 'success':
                                    record_uid = status.get('record_uid')
                                    if record_uid:
                                        api.get_record_shares(params, [record_uid])
                                        owner = ''
                                        rec = params.record_cache.get(record_uid)
                                        if rec and 'shares' in rec:
                                            shares = rec['shares']
                                            if 'user_permissions' in shares:
                                                owner = next((x.get('username') for x in shares['user_permissions'] if x.get('owner')))
                                        results.append([shared_folder_uid, record_uid, owner, status.get('status')])
                if results:
                    headers = ['Shared Folder UID', 'Record UID', 'Record Owner', 'Error code']
                    dump_report_data(results, headers=headers, title='V2 Record key errors')

            params.sync_data = True


class VerifyRecordsCommand(Command):
    def execute(self, params, **kwargs):
        records_v3_to_fix = {}
        records_v2_to_fix = {}
        records_to_delete = set()
        for record_uid in params.record_cache:
            record = params.record_cache[record_uid]
            if 'data_unencrypted' not in record:
                continue

            try:
                data = json.loads(record['data_unencrypted'])
            except:
                records_to_delete.add(record_uid)
                continue
            version = record.get('version', 0)

            if version == 3:
                is_broken = False
                # both fields and custom
                for field in itertools.chain(data.get('fields', []), data.get('custom', [])):
                    value = field.get('value')
                    # value is not list
                    if not isinstance(value, list):
                        is_broken = True
                        if value:
                            value = [value]
                        else:
                            value = []
                        field['value'] = value
                    # fix credit card expiration on paymentCard
                    if field.get('type', '') == 'paymentCard':
                        for card in field['value']:
                            if isinstance(card, dict):
                                if 'cardExpirationDate' in card:
                                    exp = card['cardExpirationDate']
                                    if isinstance(exp, str):
                                        if exp:
                                            month, sep, year = exp.partition('/')
                                            if not month.isnumeric() or not year.isnumeric():
                                                is_broken = True
                                                card['cardExpirationDate'] = ""
                                    else:
                                        is_broken = True
                                        card['cardExpirationDate'] = ""

                            else:
                                field['value'] = []
                                break
                    # date field type should contain int value
                    if field.get('type', '') == 'date':
                        orig_dates = field['value']
                        tested_dates = [x for x in orig_dates if isinstance(x, int)]
                        if len(tested_dates) < len(orig_dates):
                            field['value'] = tested_dates
                            is_broken = True

                # custom only
                for field in data.get('custom', []):
                    # OTP URL scheme should have oneTimeCode
                    if field.get('type', '') != 'oneTimeCode' and field.get('value'):
                        value = field.get('value')
                        if isinstance(value, list) and len(value) == 1:
                            value = value[0]
                            if isinstance(value, str) and value.startswith('otpauth'):
                                try:
                                    code, _, _ = get_totp_code(value)
                                    if code:
                                        field['type'] = 'oneTimeCode'
                                        is_broken = True
                                except:
                                    pass

                has_unknown_type = any((x for x in data.get('custom', []) if x.get('type') == 'unknownType'))
                if has_unknown_type:
                    data['custom'] = [x for x in data['custom'] if x.get('type') != 'unknownType']
                    is_broken = True

                # login record type should have oneTimeCode on fields rather than custom
                if data.get('type') in {'login'} and 'fields' in data and 'custom' in data:
                    fields_otp = next((x for x in data.get('fields') if x.get('type') == 'oneTimeCode'), None)
                    if not fields_otp or not fields_otp.get('value'):
                        custom_otp = next((x for x in data.get('custom', []) if x.get('type') == 'oneTimeCode'), None)
                        if custom_otp and custom_otp.get('value'):
                            if fields_otp:
                                fields_otp['value'] = custom_otp['value']
                            else:
                                data['fields'].append(custom_otp)
                            try:
                                data['custom'].remove(custom_otp)
                            except:
                                custom_otp['value'] = []
                            is_broken = True

                if is_broken:
                    records_v3_to_fix[record_uid] = data
            elif version == 2:
                is_broken = False
                for field in ('title', 'secret1', 'secret2', 'link', 'notes'):
                    if field in data:
                        value = data[field]
                        if not isinstance(value, str):
                            if value is None:
                                data[field] = ''
                            else:
                                data[field] = str(value)
                            is_broken = True
                    else:
                        data[field] = ''
                        is_broken = True
                if is_broken:
                    records_v2_to_fix[record_uid] = data

        if len(records_v2_to_fix) > 0 or len(records_v3_to_fix) > 0:
            total_records = len(records_v2_to_fix) + len(records_v3_to_fix)
            print(f'There are {total_records} record(s) to be corrected')
            answer = user_choice('Do you want to proceed?', 'yn', 'n')
            if answer.lower() == 'y':
                success = 0
                failed = []

                if len(records_v2_to_fix) > 0:
                    record_uids = list(records_v2_to_fix.keys())
                    while len(record_uids) > 0:
                        chunk = record_uids[:99]
                        record_uids = record_uids[99:]
                        rq = {
                            'command': 'record_update',
                            'client_time': utils.current_milli_time(),
                            'pt': 'Commander',
                            'update_records': []
                        }
                        for record_uid in chunk:
                            record = params.record_cache[record_uid]
                            record_key = record['record_key_unencrypted']
                            revision = record.get('revision') or 0
                            data = records_v2_to_fix[record_uid]
                            encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key)
                            rq['update_records'].append({
                                'record_uid': record_uid,
                                'version': 2,
                                'data': utils.base64_url_encode(encrypted_data),
                                'client_modified_time': utils.current_milli_time(),
                                'revision': revision,
                            })
                            rs = api.communicate(params, rq)
                            for rs_status in rs.get('update_records') or []:
                                record_uid = rs_status['record_uid']
                                status = rs_status.get('status')
                                if status == 'success':
                                    success += 1
                                else:
                                    failed.append(f'{record_uid}: {rs_status.get("message", status)}')

                if len(records_v3_to_fix) > 0:
                        rq = record_pb2.RecordsUpdateRequest()
                        rq.client_time = utils.current_milli_time()
                        for record_uid in records_v3_to_fix:
                            record = params.record_cache[record_uid]
                            record_key = record['record_key_unencrypted']
                            upd_rq = record_pb2.RecordUpdate()
                            upd_rq.record_uid = utils.base64_url_decode(record_uid)
                            upd_rq.client_modified_time = utils.current_milli_time()
                            upd_rq.revision = record.get('revision') or 0
                            data = records_v3_to_fix[record_uid]
                            upd_rq.data = crypto.encrypt_aes_v2(api.get_record_data_json_bytes(data), record_key)
                            rq.records.append(upd_rq)
                            if len(rq.records) >= 999:
                                break
                        rs = api.communicate_rest(params, rq, 'vault/records_update', rs_type=record_pb2.RecordsModifyResponse)
                        for status in rs.records:
                            if status.status == record_pb2.RS_SUCCESS:
                                success += 1
                            else:
                                record_uid = utils.base64_url_encode(status.record_uid)
                                failed.append(f'{record_uid}: {status.message}')

                if success > 0:
                    logging.info('Successfully corrected %d record(s)', success)
                if len(failed) > 0:
                    logging.warning('Failed to correct %d record(s)', len(failed))
                    logging.info('\n'.join(failed))

                    params.sync_data = True

