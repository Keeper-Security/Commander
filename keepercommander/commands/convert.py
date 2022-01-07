#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import argparse
import fnmatch
import json
import logging
import re
from collections import OrderedDict

from .. import api, loginv3, recordv3
from ..subfolder import try_resolve_path
from ..proto import record_pb2
from .folder import get_folder_path
from .base import raise_parse_exception, suppress_exit, Command


DEFAULT_CONVERT_TO_V3_RECORD_TYPE = 'login'


def register_commands(commands):
    commands['convert'] = ConvertCommand()


def register_command_info(aliases, command_info):
    command_info[convert_parser.prog] = convert_parser.description


convert_parser = argparse.ArgumentParser(prog='convert', description='Convert record(s) to use record types')
convert_parser.add_argument('-t', '--type', dest='type', action='store', help='Convert to record type')
convert_parser.add_argument(
    '-q', '--quiet', dest='quiet', action='store_true', help="Don't display info about records matched and converted"
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


def get_matching_records_from_folder(params, folder_uid, regex, url_regex):
    records = []
    if folder_uid in params.subfolder_record_cache:
        for uid in params.subfolder_record_cache[folder_uid]:
            rv = params.record_cache[uid].get('version') if uid in params.record_cache else None
            if rv > 2:
                continue
            r = api.get_record(params, uid)
            r_attrs = (r.title, r.record_uid)
            if any(attr for attr in r_attrs if isinstance(attr, str) and len(attr) > 0 and regex(attr) is not None):
                if url_regex:
                    url_match = r.login_url and url_regex(r.login_url) is not None
                else:
                    url_match = True
                if url_match:
                    records.append(r)
    return records


def recurse_folder(params, folder_uid, folder_path, records_by_folder, regex, url_regex, recurse):
    folder_records = get_matching_records_from_folder(params, folder_uid, regex, url_regex)
    if len(folder_records) > 0:
        if folder_uid not in folder_path:
            folder_path[folder_uid] = get_folder_path(params, folder_uid)
            records_by_folder[folder_uid] = set()
        records_by_folder[folder_uid].update(folder_records)

    if recurse:
        folder = params.folder_cache[folder_uid] if folder_uid else params.root_folder
        for subfolder_uid in folder.subfolders:
            recurse_folder(params, subfolder_uid, folder_path, records_by_folder, regex, url_regex, recurse)


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

        record_type = kwargs.get('type') or DEFAULT_CONVERT_TO_V3_RECORD_TYPE
        available_types = [json.loads(params.record_type_cache.get(rti)).get('$id') for rti in params.record_type_cache]
        if record_type not in available_types:
            logging.warning(
                f'Specified record type "{record_type}" is not valid. '
                f'Valid types are:\n{", ".join(sorted(available_types))}'
            )
            return

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
            recurse_folder(params, folder_uid, folder_path, records_by_folder, regex, url_regex, recurse)

        if len(records_by_folder) == 0:
            msg = f'No records that can be converted to record types can be found for pattern "{pattern}"'
            if url_pattern:
                msg += f' with url matching "{url_pattern}"'
            logging.warning(msg)
            return

        # Sort records and if dry run print
        records = []
        record_names = OrderedDict()
        for folder_uid in sorted(folder_path, key=lambda x: folder_path[x]):
            path = folder_path[folder_uid]
            for record in sorted(records_by_folder[folder_uid], key=lambda x: getattr(x, 'title')):
                records.append(record)
                record_names[record.record_uid] = path + record.title

        dry_run = kwargs.get('dry_run', False)
        if dry_run:
            print(
                f'The following {len(records)} records were matched'
                f' and would be converted to records with type "{record_type}":'
            )
            print('\n'.join(f'{v} ({k})' for k, v in record_names.items()))
        else:
            rq = record_pb2.RecordsConvertToV3Request()
            for record in records:
                convert_result = recordv3.RecordV3.convert_to_record_type(
                    record.record_uid, params, record_type=record_type
                )
                if convert_result:
                    v3_record = api.get_record(params, record.record_uid)
                else:
                    logging.warning(f'Conversion failed for {record_names[record.record_uid]} ({record.record_uid})\n')
                    continue

                prepare_result = api.prepare_record_v3(params, v3_record)
                if prepare_result:
                    record_rq, audit_data = prepare_result
                else:
                    logging.warning(f'Conversion failed for {record_names[record.record_uid]} ({record.record_uid})\n')
                    continue

                rc = record_pb2.RecordConvertToV3()
                rc.record_uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_rq['record_uid'])
                rc.client_modified_time = record_rq['client_modified_time']
                rc.revision = record_rq['revision']
                rc.data = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_rq['data'])
                rc.audit.data = audit_data
                rq.records.append(rc)

            quiet = kwargs.get('quiet', False)
            if not quiet:
                logging.info(f'Matched {len(records)} record(s)')

            if len(rq.records) > 0:
                rq.client_time = api.current_milli_time()
                rs = api.communicate_rest(params, rq, 'vault/records_convert3')
                if not quiet:
                    records_modify_rs = record_pb2.RecordsModifyResponse()
                    records_modify_rs.ParseFromString(rs)
                    success = record_pb2.RecordModifyResult.DESCRIPTOR.values_by_name['RS_SUCCESS'].number
                    converted_record_names = [
                        record_names[loginv3.CommonHelperMethods.bytes_to_url_safe_str(r.record_uid)]
                        for r in records_modify_rs.records if r.status == success
                    ]
                    logging.info(f'Successfully converted the following {len(converted_record_names)} record(s):')
                    logging.info('\n'.join(converted_record_names))
            elif not quiet:
                logging.info('No records successfully converted')
