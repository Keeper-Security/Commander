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

import json
import logging

import itertools

from .base import user_choice, Command
from .. import api, crypto, utils
from ..record import get_totp_code
from ..proto import record_pb2


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

