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
import shutil
import sys
import time
from collections import OrderedDict
from typing import Optional, Tuple, List, Dict

from ..utils import is_url, is_email
from .base import raise_parse_exception, suppress_exit, user_choice, Command
from .folder import get_folder_path
from .. import api, crypto, loginv3, utils
from ..params import KeeperParams
from ..proto import record_pb2
from ..subfolder import try_resolve_path, find_parent_top_folder

CONVERT_BATCH_LIMIT = 999


def register_commands(commands):
    commands['convert'] = ConvertCommand()
    commands['convert-all'] = ConvertAllCommand()


def register_command_info(aliases, command_info):
    aliases['ca'] = 'convert-all'
    command_info[convert_parser.prog] = convert_parser.description
    command_info[convert_all_parser.prog] = convert_all_parser.description


# Argument Parsers

convert_parser = argparse.ArgumentParser(prog='convert', description='Convert record(s) to use record types')
convert_parser.add_argument(
    '-t', '--record-type', '--record_type', dest='record_type', action='store', help='Convert to record type'
)
convert_parser.add_argument(
    '-q', '--quiet', dest='quiet', action='store_true', help="Don't display info about records matched and converted"
)
convert_parser.add_argument(
    '--ignore-ownership', dest='ignore_owner', action='store_true', help="Convert all records including not owned"
)
convert_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Convert all records including records with attachments. '
         'Please note that file attachments may not be decrypted by Keeper clients.'
)
convert_parser.add_argument(
    '-u', '--url', dest='url', action='store', help='Convert records with URL pattern (* for record with any URL)'
)
convert_parser.add_argument(
    '-n', '--dry-run', dest='dry_run', action='store_true', help='Preview the record conversions without updating'
)
convert_parser.add_argument(
    '-r', '--recursive', dest='recursive', action='store_true', help='Convert recursively through subfolders'
)
convert_parser.add_argument(
    'record-uid-name-patterns', nargs='*', type=str, action='store', help='One or more record title/UID search patterns'
)
convert_parser.error = raise_parse_exception
convert_parser.exit = suppress_exit

convert_all_parser = argparse.ArgumentParser(
    prog='convert-all',
    description='Convert all legacy General records in the vault to a typed record format'
)
convert_all_parser.add_argument(
    '-t', '--record-type', '--record_type', dest='record_type', action='store',
    help='Target record type (default: login)'
)
convert_all_parser.add_argument(
    '-ia', '--include-attachments', dest='include_attachments', action='store_true',
    help='Include records with file attachments. '
         'Note: file attachments may not be decrypted by Keeper clients after conversion.'
)
convert_all_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Skip confirmation prompt'
)
convert_all_parser.add_argument(
    '-n', '--dry-run', dest='dry_run', action='store_true',
    help='Preview records that would be converted without making changes'
)
convert_all_parser.add_argument(
    '-io', '--ignore-ownership', dest='ignore_owner', action='store_true',
    help='Include records not owned by the current user'
)
convert_all_parser.error = raise_parse_exception
convert_all_parser.exit = suppress_exit


class ConvertHelper:
    """Shared utilities for v2-to-v3 record conversion used by both convert and convert-all."""

    @staticmethod
    def validate_v3_enabled(params):
        # type: (KeeperParams) -> bool
        if params.settings and isinstance(params.settings.get('record_types_enabled'), bool):
            return params.settings['record_types_enabled']
        return False

    @staticmethod
    def resolve_record_type(params, record_type_name):
        # type: (KeeperParams, str) -> Optional[dict]
        available_types = [json.loads(x) for x in params.record_type_cache.values()]
        type_info = next((x for x in available_types if x.get('$id') == record_type_name), None)
        if type_info is None:
            valid = ', '.join(sorted(x.get('$id') for x in available_types))
            logging.warning('Specified record type "%s" is not valid. Valid types are:\n%s',
                            record_type_name, valid)
        return type_info

    @staticmethod
    def is_v2_record(params, uid):
        # type: (KeeperParams, str) -> bool
        if uid not in params.record_cache:
            return False
        return params.record_cache[uid].get('version', 0) == 2

    @staticmethod
    def is_record_owner(params, uid):
        # type: (KeeperParams, str) -> bool
        if uid not in params.record_owner_cache:
            return False
        return bool(params.record_owner_cache[uid].owner)

    @staticmethod
    def has_attachments(params, uid):
        # type: (KeeperParams, str) -> bool
        record = api.get_record(params, uid)
        return bool(record and record.attachments)

    @staticmethod
    def infer_field_type(field_value):
        # type: (Optional[str]) -> str
        if not field_value:
            return 'text'
        if len(field_value) > 128:
            return 'note'
        if is_url(field_value):
            return 'url'
        if is_email(field_value):
            return 'email'
        return 'text'

    @staticmethod
    def build_v2_to_v3_data(record_uid, params, type_info):
        # type: (str, KeeperParams, dict) -> Optional[Tuple[dict, list]]
        if not (record_uid and params and params.record_cache and record_uid in params.record_cache):
            logging.warning('Record %s not found.', record_uid)
            return None

        record = params.record_cache[record_uid]
        if (record.get('version') or 0) != 2:
            logging.warning('Record %s is not version 2.', record_uid)
            return None

        try:
            raw_data = record.get('data_unencrypted')
            raw_extra = record.get('extra_unencrypted')
            data = raw_data if isinstance(raw_data, dict) else json.loads(raw_data or '{}')
            extra = raw_extra if isinstance(raw_extra, dict) else json.loads(raw_extra or '{}')
        except (json.JSONDecodeError, TypeError) as e:
            logging.warning('Record %s has malformed data: %s', record_uid, e)
            return None

        v2_fields = ConvertHelper._extract_v2_fields(data, extra)
        totp_extras = v2_fields.pop('_totp_extras', [])
        fields, custom = ConvertHelper._map_fields_to_v3(v2_fields, type_info, data.get('custom') or [])

        if totp_extras:
            custom.extend({'type': 'oneTimeCode', 'value': [x]} for x in totp_extras if x)

        v3_data = {
            'title': data.get('title') or '',
            'type': type_info['$id'],
            'fields': fields,
            'custom': custom,
            'notes': data.get('notes') or ''
        }
        file_info = extra.get('files') or []
        return v3_data, file_info

    @staticmethod
    def _extract_v2_fields(data, extra):
        # type: (dict, dict) -> dict
        extra_fields = extra.get('fields') or []
        otps = [x['data'] for x in extra_fields if x.get('field_type') == 'totp' and 'data' in x]

        v2_fields = {}
        for key, v2_key in [('login', 'secret1'), ('password', 'secret2'), ('url', 'link')]:
            value = data.get(v2_key) or ''
            if value:
                v2_fields[key] = value

        if otps:
            v2_fields['oneTimeCode'] = otps[0]
            v2_fields['_totp_extras'] = otps[1:]
        else:
            v2_fields['_totp_extras'] = []

        return v2_fields

    @staticmethod
    def _map_fields_to_v3(v2_fields, type_info, custom_v2):
        # type: (dict, dict, list) -> Tuple[list, list]
        fields = []
        for field_def in type_info.get('fields', []):
            ref = field_def.get('$ref', 'text')
            label = field_def.get('label')
            typed_field = {'type': ref, 'value': []}
            if label:
                typed_field['label'] = label
            if not label and ref in v2_fields:
                typed_field['value'].append(v2_fields.pop(ref))
            fields.append(typed_field)

        custom = []
        custom.extend({'type': k, 'value': [v]} for k, v in v2_fields.items() if k != '_totp_extras')
        custom.extend(
            {
                'type': ConvertHelper.infer_field_type(entry.get('value')),
                'label': entry.get('name') or '',
                'value': [entry['value']] if entry.get('value') else []
            }
            for entry in custom_v2 if entry.get('name') or entry.get('value')
        )
        return fields, custom

    @staticmethod
    def build_convert_request(record_uid, params, type_info):
        # type: (str, KeeperParams, dict) -> Optional[record_pb2.RecordConvertToV3]
        convert_result = ConvertHelper.build_v2_to_v3_data(record_uid, params, type_info)
        if not convert_result:
            return None

        v3_data, file_info = convert_result

        try:
            record_key = params.record_cache[record_uid]['record_key_unencrypted']
        except KeyError:
            logging.warning('Record %s is missing its encryption key.', record_uid)
            return None

        record = api.get_record(params, record_uid)
        if not record:
            logging.warning('Record %s could not be loaded.', record_uid)
            return None

        rc = record_pb2.RecordConvertToV3()
        rc.record_uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_uid)
        rc.client_modified_time = api.current_milli_time()
        rc.revision = record.revision

        if file_info:
            ConvertHelper._attach_file_refs(rc, v3_data, file_info, record_key, params.data_key)

        rc.data = crypto.encrypt_aes_v2(api.get_record_data_json_bytes(v3_data), record_key)

        ConvertHelper._attach_shared_folder_keys(rc, params, record_uid, record_key)
        ConvertHelper._attach_audit_data(rc, record, v3_data, params)

        return rc

    @staticmethod
    def _attach_file_refs(rc, v3_data, file_info, record_key, data_key):
        file_ref = next((x for x in v3_data['fields'] if x.get('type') == 'fileRef'), None)
        if file_ref is None:
            file_ref = {'type': 'fileRef'}
            v3_data['fields'].append(file_ref)
        if not isinstance(file_ref.get('value'), list):
            file_ref['value'] = []

        for f_info in file_info:
            try:
                file_uid = utils.generate_uid()
                file_ref['value'].append(file_uid)
                file_key = utils.base64_url_decode(f_info['key'])

                metadata = {k: f_info.get(k) for k in ('name', 'size', 'title', 'lastModified', 'type')}

                rf = record_pb2.RecordFileForConversion()
                rf.record_uid = utils.base64_url_decode(file_uid)
                rf.file_file_id = f_info['id']

                thumbs = f_info.get('thumbs') or []
                if thumbs:
                    thumb = next((x for x in thumbs if isinstance(x, dict)), None)
                    if thumb:
                        rf.thumb_file_id = thumb.get('id', '')

                rf.data = crypto.encrypt_aes_v2(json.dumps(metadata).encode('utf-8'), file_key)
                rf.record_key = crypto.encrypt_aes_v2(file_key, data_key)
                rf.link_key = crypto.encrypt_aes_v2(file_key, record_key)
                rc.record_file.append(rf)
            except (KeyError, TypeError) as e:
                logging.warning('Skipping file attachment due to incomplete metadata: %s', e)

    @staticmethod
    def _attach_shared_folder_keys(rc, params, record_uid, record_key):
        shared_folders = find_parent_top_folder(params, record_uid)
        for shared_folder in shared_folders:
            try:
                sf = params.shared_folder_cache[shared_folder.uid]
                fk = record_pb2.RecordFolderForConversion()
                fk.folder_uid = utils.base64_url_decode(shared_folder.uid)
                fk.record_folder_key = crypto.encrypt_aes_v2(
                    record_key, sf['shared_folder_key_unencrypted']
                )
                rc.folder_key.append(fk)
            except KeyError:
                logging.warning('Shared folder %s missing key, skipping folder key conversion.', shared_folder.uid)

    @staticmethod
    def _attach_audit_data(rc, record, v3_data, params):
        if not params.enterprise_ec_key:
            return
        audit_data = {
            'title': record.title or '',
            'record_type': v3_data['type'],
        }
        if record.login_url:
            audit_data['url'] = utils.url_strip(record.login_url)
        rc.audit.data = crypto.encrypt_ec(
            json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key
        )

    @staticmethod
    def send_batch(params, records, record_names=None, quiet=False):
        # type: (KeeperParams, list, Optional[dict], bool) -> Tuple[int, int, list]
        """Send a batch of RecordConvertToV3 to the API. Returns (success_count, fail_count, failures)."""
        successes = 0
        failures = 0
        failed_list = []  # type: List[Tuple[str, str, str]]

        params.sync_data = True
        rq = record_pb2.RecordsConvertToV3Request()
        rq.records.extend(records)
        rq.client_time = api.current_milli_time()

        rs = api.communicate_rest(params, rq, 'vault/records_convert3',
                                  rs_type=record_pb2.RecordsModifyResponse)

        for r in rs.records:
            uid = loginv3.CommonHelperMethods.bytes_to_url_safe_str(r.record_uid)
            name = (record_names or {}).get(uid, uid)
            if r.status == record_pb2.RS_SUCCESS:
                successes += 1
            else:
                failures += 1
                failed_list.append((uid, name, r.message))

        if not quiet and record_names:
            converted = [
                '  %s  %s' % (loginv3.CommonHelperMethods.bytes_to_url_safe_str(r.record_uid),
                              record_names.get(loginv3.CommonHelperMethods.bytes_to_url_safe_str(r.record_uid), ''))
                for r in rs.records if r.status == record_pb2.RS_SUCCESS
            ]
            if converted:
                logging.info('Successfully converted the following %d record(s):', len(converted))
                logging.info('\n'.join(converted))

            if failed_list:
                logging.warning('Failed to convert the following %d record(s):', len(failed_list))
                logging.warning('\n'.join('%s  %s : %s' % f for f in failed_list))

        return successes, failures, failed_list

    @staticmethod
    def render_progress(current, total, start_time, bar_width=30):
        elapsed = time.time() - start_time
        avg = elapsed / current if current > 0 else 0
        filled = int(bar_width * current / total) if total > 0 else bar_width
        bar = '#' * filled + '-' * (bar_width - filled)
        try:
            term_width = shutil.get_terminal_size().columns
        except Exception:
            term_width = 80
        line = '\r  [%s] %d/%d  (%.1fs avg)' % (bar, current, total, avg)
        sys.stderr.write(line[:term_width])
        sys.stderr.flush()

    @staticmethod
    def print_failures(failed_records):
        # type: (List[Tuple[str, str, str]]) -> None
        logging.warning('')
        logging.warning('Failed records:')
        for uid, title, message in failed_records:
            logging.warning('  %s  %s  —  %s', uid, title, message)


class ConvertCommand(Command):
    def get_parser(self):
        return convert_parser

    def execute(self, params, **kwargs):
        if not ConvertHelper.validate_v3_enabled(params):
            logging.warning('Cannot convert record(s) if record types is not enabled')
            return

        record_type = kwargs.get('record_type') or 'login'
        type_info = ConvertHelper.resolve_record_type(params, record_type)
        if type_info is None:
            return

        include_attachments = bool(kwargs.get('force', False))
        ignore_owner = bool(kwargs.get('ignore_owner', False))
        quiet = bool(kwargs.get('quiet', False))

        pattern_list = kwargs.get('record-uid-name-patterns', [])
        if not pattern_list:
            logging.warning('Please specify a record to convert')
            return

        url_pattern = kwargs.get('url')
        try:
            url_regex = re.compile(fnmatch.translate(url_pattern)).match if url_pattern else None
        except re.error as e:
            logging.warning('Invalid URL pattern "%s": %s', url_pattern, e)
            return

        recurse = kwargs.get('recursive', False)

        record_uids, record_names = self._find_matching_records(
            params, pattern_list, url_regex, url_pattern, recurse, include_attachments, ignore_owner
        )
        if not record_uids:
            return

        if kwargs.get('dry_run', False):
            print(
                'The following %d record(s) that you own were matched'
                ' and would be converted to records with type "%s":' % (len(record_uids), record_type)
            )
            print('\n'.join('  %s  %s' % (k, v) for k, v in record_names.items()))
            return

        self._convert_and_send(params, record_uids, record_names, type_info, quiet)

    @staticmethod
    def _find_matching_records(params, pattern_list, url_regex, url_pattern, recurse, include_attachments, ignore_owner):
        # type: (...) -> Tuple[set, OrderedDict]
        folder = params.folder_cache.get(params.current_folder, params.root_folder)
        records_by_folder = {}  # type: Dict
        folder_path = {}

        for pattern in pattern_list:
            if pattern in params.record_cache:
                record = api.get_record(params, pattern)
                if record:
                    if '' not in folder_path:
                        folder_path[''] = ''
                    if '' not in records_by_folder:
                        records_by_folder[''] = set()
                    records_by_folder[''].add(record)
                continue

            rs = try_resolve_path(params, pattern)
            if rs is not None:
                folder, pattern = rs

            try:
                regex = re.compile(fnmatch.translate(pattern)).match if pattern else None
            except re.error as e:
                logging.warning('Invalid pattern "%s": %s', pattern, e)
                continue

            folder_uid = folder.uid or ''
            ConvertCommand._recurse_folder(
                params, folder_uid, folder_path, records_by_folder, regex,
                url_regex, recurse, include_attachments, ignore_owner
            )

        if not records_by_folder:
            patterns = ', '.join(pattern_list)
            msg = 'No records that can be converted to record types can be found for pattern "%s"' % patterns
            if url_pattern:
                msg += ' with url matching "%s"' % url_pattern
            logging.warning(msg)
            return set(), OrderedDict()

        record_uids = set()
        record_names = OrderedDict()
        for fuid in sorted(folder_path, key=lambda x: folder_path[x]):
            path = folder_path[fuid]
            for record in sorted(records_by_folder[fuid], key=lambda x: getattr(x, 'title', '')):
                if record.record_uid not in record_uids:
                    record_uids.add(record.record_uid)
                    record_names[record.record_uid] = path + record.title

        return record_uids, record_names

    @staticmethod
    def _get_matching_records_from_folder(params, folder_uid, regex, url_regex, include_attachments, ignore_owner):
        records = []
        if folder_uid not in params.subfolder_record_cache:
            return records
        for uid in params.subfolder_record_cache[folder_uid]:
            if not ignore_owner and not ConvertHelper.is_record_owner(params, uid):
                continue
            if not ConvertHelper.is_v2_record(params, uid):
                continue
            r = api.get_record(params, uid)
            if not r:
                continue
            if not include_attachments and r.attachments:
                continue
            r_attrs = (r.title, r.record_uid)
            if not any(isinstance(a, str) and a and regex(a) is not None for a in r_attrs):
                continue
            if url_regex and not (r.login_url and url_regex(r.login_url) is not None):
                continue
            records.append(r)
        return records

    @staticmethod
    def _recurse_folder(params, folder_uid, folder_path, records_by_folder, regex,
                        url_regex, recurse, include_attachments, ignore_owner):
        folder_records = ConvertCommand._get_matching_records_from_folder(
            params, folder_uid, regex, url_regex, include_attachments, ignore_owner
        )
        if folder_records:
            if folder_uid not in folder_path:
                folder_path[folder_uid] = get_folder_path(params, folder_uid)
                records_by_folder[folder_uid] = set()
            records_by_folder[folder_uid].update(folder_records)

        if recurse:
            folder = params.folder_cache[folder_uid] if folder_uid else params.root_folder
            for subfolder_uid in folder.subfolders:
                ConvertCommand._recurse_folder(
                    params, subfolder_uid, folder_path, records_by_folder, regex,
                    url_regex, recurse, include_attachments, ignore_owner
                )

    @staticmethod
    def _convert_and_send(params, record_uids, record_names, type_info, quiet):
        records = []
        for record_uid in record_uids:
            rc = ConvertHelper.build_convert_request(record_uid, params, type_info)
            if not rc:
                logging.warning('Conversion failed for %s (%s)', record_names.get(record_uid, ''), record_uid)
                continue
            records.append(rc)

        if not quiet:
            logging.info('Matched %d record(s)', len(record_uids))

        if not records:
            if not quiet:
                logging.info('No records successfully converted')
            return

        while records:
            batch = records[:CONVERT_BATCH_LIMIT]
            records = records[CONVERT_BATCH_LIMIT:]
            ConvertHelper.send_batch(params, batch, record_names, quiet)


class ConvertAllCommand(Command):
    def get_parser(self):
        return convert_all_parser

    def execute(self, params, **kwargs):
        if not ConvertHelper.validate_v3_enabled(params):
            logging.warning('Cannot convert records: record types is not enabled for this account.')
            return

        record_type = kwargs.get('record_type') or 'login'
        type_info = ConvertHelper.resolve_record_type(params, record_type)
        if type_info is None:
            return

        include_attachments = kwargs.get('include_attachments', False)
        ignore_owner = kwargs.get('ignore_owner', False)
        dry_run = kwargs.get('dry_run', False)
        force = kwargs.get('force', False)

        api.sync_down(params)

        partition = self._partition_v2_records(params, ignore_owner)

        if not partition['all']:
            logging.info('No General-type records found in the vault. Nothing to convert.')
            return

        record_uids = partition['all'] if include_attachments else partition['without_attachments']
        skipped_attachment_count = len(partition['with_attachments']) if not include_attachments else 0
        skipped_not_owned_count = partition['skipped_not_owned']

        if not record_uids:
            logging.info('All %d General-type record(s) have attachments. Use -ia to include them.',
                         len(partition['all']))
            return

        logging.info('Found %d General-type record(s) to convert to "%s".', len(record_uids), record_type)
        if include_attachments and partition['with_attachments']:
            logging.warning(
                '  %d record(s) have file attachments. '
                'Note: file attachments may not be decrypted by Keeper clients after conversion.',
                len(partition['with_attachments'])
            )
        if skipped_attachment_count > 0:
            logging.info('  %d record(s) with attachments were skipped. Use -ia to include them.',
                         skipped_attachment_count)
        if skipped_not_owned_count > 0:
            logging.info('  %d record(s) not owned by you were skipped. Use -io to include them.',
                         skipped_not_owned_count)

        if dry_run:
            self._print_dry_run(params, record_uids)
            return

        if not force:
            if params.batch_mode:
                logging.warning('Confirmation required. Use --force (-f) to skip in batch mode.')
                return
            answer = user_choice(
                'Convert %d General record(s) to "%s"?' % (len(record_uids), record_type),
                'yn', default='n'
            )
            if answer.lower() != 'y':
                logging.info('Operation cancelled.')
                return

        self._execute_conversion(params, record_uids, type_info)

    @staticmethod
    def _partition_v2_records(params, ignore_owner):
        # type: (KeeperParams, bool) -> dict
        """Returns dict with keys: all, with_attachments, without_attachments, skipped_not_owned."""
        all_v2 = []
        with_attachments = []
        without_attachments = []
        skipped_not_owned = 0

        for uid in params.record_cache:
            if not ConvertHelper.is_v2_record(params, uid):
                continue
            if not ConvertHelper.is_record_owner(params, uid):
                if not ignore_owner:
                    skipped_not_owned += 1
                    continue
            all_v2.append(uid)
            if ConvertHelper.has_attachments(params, uid):
                with_attachments.append(uid)
            else:
                without_attachments.append(uid)

        return {
            'all': all_v2,
            'with_attachments': with_attachments,
            'without_attachments': without_attachments,
            'skipped_not_owned': skipped_not_owned,
        }

    @staticmethod
    def _print_dry_run(params, record_uids):
        logging.info('The following %d record(s) would be converted:\n', len(record_uids))
        for uid in record_uids:
            record = api.get_record(params, uid)
            title = record.title if record else ''
            logging.info('  %s  %s', uid, title)

    @staticmethod
    def _execute_conversion(params, record_uids, type_info):
        start_time = time.time()
        converted_count = 0
        failed_count = 0
        failed_records = []

        records_to_send = []
        record_names = {}

        logging.info('Preparing %d record(s) for conversion...', len(record_uids))

        for record_uid in record_uids:
            record = api.get_record(params, record_uid)
            title = record.title if record else record_uid
            record_names[record_uid] = title

            rc = ConvertHelper.build_convert_request(record_uid, params, type_info)
            if not rc:
                failed_count += 1
                failed_records.append((record_uid, title, 'Field conversion failed'))
                continue
            records_to_send.append(rc)

        if not records_to_send:
            logging.warning('No records were successfully prepared for conversion.')
            if failed_records:
                ConvertHelper.print_failures(failed_records)
            return

        total_to_send = len(records_to_send)
        sent_count = 0

        logging.info('Converting %d record(s)...', total_to_send)

        while records_to_send:
            batch = records_to_send[:CONVERT_BATCH_LIMIT]
            records_to_send = records_to_send[CONVERT_BATCH_LIMIT:]

            try:
                successes, failures, batch_failures = ConvertHelper.send_batch(
                    params, batch, record_names, quiet=True
                )
                converted_count += successes
                failed_count += failures
                failed_records.extend(batch_failures)
                sent_count += successes + failures
            except Exception as e:
                for rc_item in batch:
                    uid = loginv3.CommonHelperMethods.bytes_to_url_safe_str(rc_item.record_uid)
                    failed_count += 1
                    failed_records.append((uid, record_names.get(uid, uid), str(e)))
                    sent_count += 1

            ConvertHelper.render_progress(sent_count, total_to_send, start_time)

        sys.stderr.write('\n')
        sys.stderr.flush()

        elapsed = time.time() - start_time
        total_processed = converted_count + failed_count

        logging.info('')
        logging.info('Conversion complete.')
        logging.info('  Converted: %d', converted_count)
        if failed_count > 0:
            logging.warning('  Failed:    %d', failed_count)
        logging.info('  Total:     %d', total_processed)
        logging.info('  Time:      %.1fs', elapsed)
        if total_processed > 0:
            logging.info('  Average:   %.2fs per record', elapsed / total_processed)

        if failed_records:
            ConvertHelper.print_failures(failed_records)
