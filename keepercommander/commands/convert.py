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
import logging
import re

from keepercommander import api, loginv3, record_pb2, recordv3
from keepercommander.subfolder import try_resolve_path
from .base import raise_parse_exception, suppress_exit, Command


def register_commands(commands):
    commands['convert'] = ConvertCommand()


def register_command_info(aliases, command_info):
    command_info[convert_parser.prog] = convert_parser.description


convert_parser = argparse.ArgumentParser(prog='convert', description='Convert record(s) to use record types')
convert_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
convert_parser.error = raise_parse_exception
convert_parser.exit = suppress_exit


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

        folder = params.folder_cache.get(params.current_folder, params.root_folder)
        pattern = kwargs.get('pattern')
        if not pattern:
            logging.warning(f'Please specify a record to convert')
            return

        rs = try_resolve_path(params, kwargs['pattern'])
        if rs is not None:
            folder, pattern = rs

        regex = None
        if pattern:
            regex = re.compile(fnmatch.translate(pattern)).match

        records = []
        folder_uid = folder.uid or ''
        if folder_uid in params.subfolder_record_cache:
            for uid in params.subfolder_record_cache[folder_uid]:
                rv = params.record_cache[uid].get('version') if uid in params.record_cache else None
                if rv > 2:
                    continue
                r = api.get_record(params, uid)
                r_attrs = (r.title, r.record_uid)
                if any(attr for attr in r_attrs if isinstance(attr, str) and len(attr) > 0 and regex(attr) is not None):
                    records.append(r)

        if len(records) == 0:
            logging.warning(
                f'No records that can be converted to record types can be found found for pattern "{kwargs["pattern"]}"'
            )
            return

        rq = record_pb2.RecordsConvertToV3Request()
        record_rq_by_uid = {}
        for record in records:
            if recordv3.RecordV3.convert_to_record_type(record.record_uid, params):
                v3_record = api.get_record(params, record.record_uid)
            else:
                logging.warning(f'Conversion failed for {record.title} ({record.record_uid})')
                continue

            record_rq, audit_data = api.prepare_record_v3(params, v3_record)
            record_rq_by_uid[record.record_uid] = record_rq

            rc = record_pb2.RecordConvertToV3()
            rc.record_uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_rq['record_uid'])
            rc.client_modified_time = record_rq['client_modified_time']
            rc.revision = record_rq['revision']
            rc.data = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_rq['data'])
            rc.audit.data = audit_data
            rq.records.append(rc)

        if len(record_rq_by_uid) > 0:
            rq.client_time = api.current_milli_time()
            result = api.get_record_v3_response(
                params, rq, 'vault/records_convert3', record_rq_by_uid, silent=kwargs.get('silent')
            )
