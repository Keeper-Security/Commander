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
import fnmatch
import json
import logging
import re
from collections import OrderedDict
from typing import Optional, Tuple

from keepercommander.utils import is_url, is_email
from .base import raise_parse_exception, suppress_exit, Command
from .folder import get_folder_path
from .. import api, crypto, loginv3, utils
from ..params import KeeperParams
from ..proto import record_pb2
from ..subfolder import try_resolve_path, find_folders


def register_commands(commands):
    commands['convert'] = ConvertCommand()


def register_command_info(aliases, command_info):
    command_info[convert_parser.prog] = convert_parser.description


convert_parser = argparse.ArgumentParser(prog='convert', description='Convert record(s) to use record types')
# convert_parser.add_argument('-t', '--type', dest='DEFAULT_CONVERT_TO_V3_RECORD_TYPE', action='store',
#                            help='Convert to record type')
convert_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                            help="Don't display info about records matched and converted")
convert_parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='Convert all records including records with attachments. '
                                 'Please note that file attachments may not be decrypted by Keeper clients.')
convert_parser.add_argument('-u', '--url', dest='url', action='store',
                            help='Convert records with URL pattern (* for record with any URL)')
convert_parser.add_argument('-n', '--dry-run', dest='dry_run', action='store_true',
                            help='Preview the record conversions without updating')
convert_parser.add_argument('-r', '--recursive', dest='recursive', action='store_true',
                            help='Convert recursively through subfolders')
convert_parser.add_argument('record-uid-name-patterns', nargs='*', type=str, action='store',
                            help='One or more record title/UID search patterns')
convert_parser.error = raise_parse_exception
convert_parser.exit = suppress_exit


def get_matching_records_from_folder(params, folder_uid, regex, url_regex, attachments=False):
    records = []
    if folder_uid in params.subfolder_record_cache:
        for uid in params.subfolder_record_cache[folder_uid]:
            if uid not in params.meta_data_cache:
                continue
            md = params.meta_data_cache[uid]
            if not md.get('owner', False):
                continue
            if uid not in params.record_cache:
                continue
            rv = params.record_cache[uid].get('version', 0)
            if rv != 2:
                continue
            r = api.get_record(params, uid)
            if not attachments and r.attachments:
                continue
            r_attrs = (r.title, r.record_uid)
            if any(attr for attr in r_attrs if isinstance(attr, str) and len(attr) > 0 and regex(attr) is not None):
                if url_regex:
                    url_match = r.login_url and url_regex(r.login_url) is not None
                else:
                    url_match = True
                if url_match:
                    records.append(r)
    return records


def recurse_folder(params, folder_uid, folder_path, records_by_folder, regex, url_regex, recurse, attachments=False):
    folder_records = get_matching_records_from_folder(params, folder_uid, regex, url_regex, attachments)
    if len(folder_records) > 0:
        if folder_uid not in folder_path:
            folder_path[folder_uid] = get_folder_path(params, folder_uid)
            records_by_folder[folder_uid] = set()
        records_by_folder[folder_uid].update(folder_records)

    if recurse:
        folder = params.folder_cache[folder_uid] if folder_uid else params.root_folder
        for subfolder_uid in folder.subfolders:
            recurse_folder(params, subfolder_uid, folder_path, records_by_folder, regex, url_regex, recurse, attachments)


class ConvertCommand(Command):
    def get_parser(self):
        return convert_parser

    def execute(self, params, **kwargs):
        if params.settings and isinstance(params.settings.get('record_types_enabled'), bool):
            v3_enabled = params.settings.get('record_types_enabled')
        else:
            v3_enabled = False
        if not v3_enabled:
            logging.warning(f'Cannot convert record(s) if record types is not enabled')
            return

        recurse = kwargs.get('recursive', False)
        url_pattern = kwargs.get('url')
        url_regex = re.compile(fnmatch.translate(url_pattern)).match if url_pattern else None

        attachments = kwargs.get('force', False)
        if not isinstance(attachments, bool):
            attachments = False

        pattern_list = kwargs.get('record-uid-name-patterns', [])
        if len(pattern_list) == 0:
            logging.warning(f'Please specify a record to convert')
            return

        folder = params.folder_cache.get(params.current_folder, params.root_folder)
        records_by_folder = {}
        folder_path = {}
        for pattern in pattern_list:
            rs = try_resolve_path(params, pattern)
            if rs is not None:
                folder, pattern = rs
            regex = re.compile(fnmatch.translate(pattern)).match if pattern else None

            folder_uid = folder.uid or ''
            recurse_folder(params, folder_uid, folder_path, records_by_folder, regex, url_regex, recurse,
                           attachments=attachments)

        if len(records_by_folder) == 0:
            patterns = ', '.join(pattern_list)
            msg = f'No records that can be converted to record types can be found for pattern "{patterns}"'
            if url_pattern:
                msg += f' with url matching "{url_pattern}"'
            logging.warning(msg)
            return

        # Sort records and if dry run print
        record_uids = set()
        record_names = OrderedDict()
        for folder_uid in sorted(folder_path, key=lambda x: folder_path[x]):
            path = folder_path[folder_uid]
            for record in sorted(records_by_folder[folder_uid], key=lambda x: getattr(x, 'title')):
                if record.record_uid not in record_uids:
                    record_uids.add(record.record_uid)
                    record_names[record.record_uid] = path + record.title

        dry_run = kwargs.get('dry_run', False)
        if dry_run:
            print(
                f'The following {len(record_uids)} records that you own were matched'
                f' and would be converted to records with type "login":'
            )

            print('\n'.join(f'{v} ({k})' for k, v in record_names.items()))
        else:
            rq = record_pb2.RecordsConvertToV3Request()
            for record_uid in record_uids:
                convert_result = ConvertCommand.convert_to_record_type_data(record_uid, params)
                if not convert_result:
                    logging.warning(f'Conversion failed for {record_names[record_uid]} ({record_uid})\n')
                    continue
                v3_data, file_info = convert_result
                record_key = params.record_cache[record_uid]['record_key_unencrypted']

                rc = record_pb2.RecordConvertToV3()
                rc.record_uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_uid)
                rc.client_modified_time = api.current_milli_time()
                record = api.get_record(params, record_uid)
                rc.revision = record.revision

                if file_info:
                    file_ref = next((x for x in v3_data['fields'] if x.get('type') == 'fileRef'), None)
                    if file_ref is None:
                        file_ref = {'type': 'fileRef'}
                        v3_data['fields'].append(file_ref)
                    if not isinstance(file_ref.get('value'), list):
                        file_ref['value'] = []

                    for f_info in file_info:
                        file_uid = utils.generate_uid()
                        file_ref['value'].append(file_uid)
                        file_key = utils.base64_url_decode(f_info['key'])

                        data = {}
                        for k in ('name', 'size', 'title', 'lastModified', 'type'):
                            data[k] = f_info[k]

                        rf = record_pb2.RecordFileForConversion()
                        rf.record_uid = utils.base64_url_decode(file_uid)
                        rf.file_file_id = f_info['id']
                        if 'thumbs' in f_info:
                            thumbs = f_info['thumbs']
                            if len(thumbs) > 0:
                                thumb = next((x for x in thumbs if isinstance(x, dict)), None)
                                if thumb:
                                    rf.thumb_file_id = thumbs[0]['id']
                        rf.data = crypto.encrypt_aes_v2(json.dumps(data).encode('utf-8'), file_key)
                        rf.record_key = crypto.encrypt_aes_v2(file_key, params.data_key)
                        rf.link_key = crypto.encrypt_aes_v2(file_key, record_key)
                        rc.record_file.append(rf)
                rc.data = crypto.encrypt_aes_v2(api.get_record_data_json_bytes(v3_data), record_key)

                for folder_uid in find_folders(params, record_uid):
                    if folder_uid in params.shared_folder_cache:
                        sf = params.shared_folder_cache[folder_uid]
                        folder_key = record_pb2.RecordFolderForConversion()
                        folder_key.folder_uid = utils.base64_url_decode(folder_uid)
                        folder_key.record_folder_key = crypto.encrypt_aes_v2(record_key, sf['shared_folder_key_unencrypted'])
                        rc.folder_key.append(folder_key)

                if params.enterprise_ec_key:
                    audit_data = {
                        'title': record.title or '',
                        'record_type': v3_data['type'],
                    }
                    if record.login_url:
                        audit_data['url'] = utils.url_strip(record.login_url)
                    rc.audit.data = crypto.encrypt_ec(json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

                rq.records.append(rc)

            quiet = kwargs.get('quiet', False)
            if not quiet:
                logging.info(f'Matched {len(record_uids)} record(s)')

            if len(rq.records) > 0:
                params.sync_data = True
                rq.client_time = api.current_milli_time()
                records_modify_rs = api.communicate_rest(params, rq, 'vault/records_convert3',
                                                         rs_type=record_pb2.RecordsModifyResponse)
                if not quiet:
                    converted_record_names = [
                        record_names[loginv3.CommonHelperMethods.bytes_to_url_safe_str(r.record_uid)]
                        for r in records_modify_rs.records if r.status == record_pb2.RS_SUCCESS
                    ]
                    if len(converted_record_names) > 0:
                        logging.info(f'Successfully converted the following {len(converted_record_names)} record(s):')
                        logging.info('\n'.join(converted_record_names))

                    convert_errors = [(record_names[loginv3.CommonHelperMethods.bytes_to_url_safe_str(x.record_uid)], x.message)
                                      for x in records_modify_rs.records if x.status != record_pb2.RS_SUCCESS]
                    if len(convert_errors) > 0:
                        logging.warning(f'Failed to convert the following {len(convert_errors)} record(s):')
                        logging.warning('\n'.join((f'{x[0]} : {x[1]}' for x in convert_errors)))
            elif not quiet:
                logging.info('No records successfully converted')

    @staticmethod
    def get_v3_field_type(field_value):
        return_type = 'text'
        if field_value:
            if is_url(field_value):
                return_type = 'url'
            elif is_email(field_value):
                return_type = 'email'
            if len(field_value) > 128:
                return_type = 'note'
        return return_type

    @staticmethod
    def convert_to_record_type_data(record_uid, params):
        # type: (str, KeeperParams) -> Optional[Tuple[dict, list]]

        if not (record_uid and params and params.record_cache and record_uid in params.record_cache):
            logging.warning('Record %s not found.', record_uid)
            return

        record = params.record_cache[record_uid]
        version = record.get('version') or 0
        if version != 2:
            logging.warning('Record %s is not version 2.', record_uid)
            return

        data = record.get('data_unencrypted')
        extra = record.get('extra_unencrypted')

        data = data if isinstance(data, dict) else json.loads(data or '{}')
        extra = extra if isinstance(extra, dict) else json.loads(extra or '{}')

        # check for other non-convertible data - ex. fields[] has "field_type" != "totp" if present
        fields = extra.get('fields') or []
        otps = [x['data'] for x in fields if 'totp' == (x.get('field_type') or '') and 'data' in x]
        totp = otps[0] if len(otps) > 0 else ''
        otps = otps[1:]
        # label = otp.get('field_title') or ''

        title = data.get('title') or ''
        login = data.get('secret1') or ''
        password = data.get('secret2') or ''
        url = data.get('link') or ''

        notes = data.get('notes') or ''
        custom2 = data.get('custom') or []
        # custom.type	- Always "text" for legacy reasons.
        custom = []
        custom.extend(({
            'type': ConvertCommand.get_v3_field_type(x.get('value')),
            'label': x.get('name') or '',
            'value': [x.get('value')] if x.get('value') else []
        } for x in custom2 if x.get('name') or x.get('value')))

        # Add any remaining TOTP codes to custom[]
        if len(otps) > 0:
            custom.extend(({
                'type': 'oneTimeCode',
                'value': [x]
            } for x in otps if x))

        file_info = extra.get('files') or []

        v3_data = {
            'title': title,
            'type': 'login',
            'fields': [
                {'type': 'login', 'value': [login] if login else []},
                {'type': 'password', 'value': [password] if password else []},
                {'type': 'url', 'value': [url] if url else []},
                {'type': 'oneTimeCode', 'value': [totp] if totp else []},
                {'type': 'fileRef', 'value': []}
            ],
            'custom': custom,
            'notes': notes
        }

        return v3_data, file_info
