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

from .base import user_choice, Command
from .. import api, crypto, utils, vault, error
from ..proto import record_pb2
from ..record import get_totp_code


verify_shared_folders_parser = argparse.ArgumentParser(prog='verify-shared-folders')
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
        sf_keys = []     # type: List[Tuple[str, str]]  # (record_uid, shared_folder_uid)
        if 'shared_folders' in rs:
            for sf in rs['shared_folders']:
                shared_folder_uid = sf['shared_folder_uid']
                if 'records' in sf:
                    for rec in sf['records']:
                        record_uid = rec['record_uid']
                        record = params.record_cache.get(record_uid)
                        if not record:
                            continue
                        if record.get('version', 0) != 3:
                            continue
                        if 'record_key' not in rec:
                            continue
                        record_key = utils.base64_url_decode(rec['record_key'])
                        if len(record_key) == 60:
                            continue
                        if shared_folders is None or shared_folder_uid in shared_folders:
                            sf_keys.append((record_uid, shared_folder_uid))

        if not sf_keys:
            return

        sf_keys.sort(key=lambda x: x[0])

        record_uids = list({x[0] for x in sf_keys})
        print(f'There are {len(record_uids)} record key(s) to be corrected')
        try:
            for record_uid in record_uids[:99]:
                record = vault.KeeperRecord.load(params, record_uid)
                print(f' {record_uid}  {record.title}')
            if len(record_uids) > 99:
                print(f' {(len(record_uids) - 99)} more ...')
        except:
            pass
        answer = user_choice('Do you want to proceed?', 'yn', 'n')
        if answer.lower() == 'y':
            while sf_keys:
                chunk = sf_keys[:999]
                sf_keys = sf_keys[999:]

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

            params.sync_data = True


class VerifyRecordsCommand(Command):
    def execute(self, params, **kwargs):
        records_to_fix = {}
        records_to_delete = set()
        for record_uid in params.record_cache:
            record = params.record_cache[record_uid]
            if record.get('version', 0) != 3:
                continue
            if 'data_unencrypted' not in record:
                continue

            try:
                data = json.loads(record['data_unencrypted'])
            except:
                records_to_delete.add(record_uid)
                continue
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
                records_to_fix[record_uid] = data

        if len(records_to_fix) > 0:
            print(f'There are {len(records_to_fix)} record(s) to be corrected')
            answer = user_choice('Do you want to proceed?', 'yn', 'n')
            if answer.lower() == 'y':
                rq = record_pb2.RecordsUpdateRequest()
                rq.client_time = utils.current_milli_time()
                for record_uid in records_to_fix:
                    record = params.record_cache[record_uid]
                    record_key = record['record_key_unencrypted']
                    upd_rq = record_pb2.RecordUpdate()
                    upd_rq.record_uid = utils.base64_url_decode(record_uid)
                    upd_rq.client_modified_time = utils.current_milli_time()
                    upd_rq.revision = record.get('revision') or 0
                    data = records_to_fix[record_uid]
                    upd_rq.data = crypto.encrypt_aes_v2(api.get_record_data_json_bytes(data), record_key)
                    rq.records.append(upd_rq)
                    if len(rq.records) >= 999:
                        break
                rs = api.communicate_rest(params, rq, 'vault/records_update', rs_type=record_pb2.RecordsModifyResponse)
                success = 0
                failed = []
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

