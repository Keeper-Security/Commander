#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import logging
import requests

from .base import report_output_parser, dump_report_data, field_to_title, Command
from .. import vault, attachment, record_facades

file_report_parser = argparse.ArgumentParser(prog='file-report', parents=[report_output_parser],
                                             description='List records with file attachments.')
file_report_parser.add_argument('-d', '--try-download', dest='try_download', action='store_true',
                                help='Try downloading every attachment you have access to.')


class RecordFileReportCommand(Command):
    def get_parser(self):
        return file_report_parser

    def execute(self, params, **kwargs):
        try_download = kwargs.get('try_download') is True

        headers = ['title', 'record_uid', 'record_type', 'file_id', 'file_name', 'file_size']
        if try_download:
            headers.append('downloadable')
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]

        facade = record_facades.FileRefRecordFacade()
        table = []
        for record_uid in params.record_cache:
            rec = vault.KeeperRecord.load(params, record_uid)
            if isinstance(rec, vault.PasswordRecord):
                if not rec.attachments:
                    continue
            elif isinstance(rec, vault.TypedRecord):
                facade.record = rec
                if not facade.file_ref:
                    continue
            else:
                continue

            statuses = {}
            if try_download:
                logging.info('Downloading attachment(s) for record: %s', rec.title)
                downloads = list(attachment.prepare_attachment_download(params, record_uid))
                for download in downloads:
                    try:
                        if download.url:
                            opt_rs = requests.get(download.url, proxies=params.rest_context.proxies,
                                                  headers={"Range": "bytes=0-1"})
                            statuses[download.file_id] = 'OK' if opt_rs.status_code in {200, 206} else str(opt_rs.status_code)
                    except Exception as e:
                        logging.debug(e)

            if isinstance(rec, vault.PasswordRecord):
                for atta in rec.attachments:
                    row = [rec.title, rec.record_uid, '', atta.id, atta.title or atta.name, atta.size]
                    if try_download:
                        row.append(statuses.get(atta.id))
                    table.append(row)
            elif isinstance(rec, vault.TypedRecord):
                facade.record = rec
                for file_uid in facade.file_ref:
                    file_rec = vault.KeeperRecord.load(params, file_uid)
                    if isinstance(file_rec, vault.FileRecord):
                        row = [rec.title, rec.record_uid, rec.record_type, file_rec.record_uid, file_rec.title or file_rec.name, file_rec.size]
                        if try_download:
                            row.append(statuses.get(file_rec.record_uid))
                        table.append(row)
        return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))
