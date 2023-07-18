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
import fnmatch
import itertools
import json
import logging
import re
from typing import Union, Iterable, Optional, List

from .base import GroupCommand, Command, FolderMixin, try_resolve_path, report_output_parser, dump_report_data
from .. import vault, utils, crypto, api
from ..params import KeeperParams
from ..error import CommandError
from ..proto import record_pb2


kf_parse = argparse.ArgumentParser(add_help=False)
kf_parse.add_argument('-r', '--recursive', dest='recursive', action='store_true',
                           help='Traverse recursively through subfolders')
kf_parse.add_argument('paths', nargs='+', type=str, help='folder or record path or UID')


kf_list_parser = argparse.ArgumentParser(prog='keeper-fill list', parents=[kf_parse, report_output_parser])
kf_list_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Do not truncate long names')


kf_set_parser = argparse.ArgumentParser(prog='keeper-fill set', parents=[kf_parse])
kf_set_parser.add_argument('--auto-fill', dest='auto_fill', action='store', choices=['on', 'off', 'none'],
                           help='Auto Fill')
kf_set_parser.add_argument('--auto-submit', dest='auto_submit', action='store', choices=['on', 'off', 'none'],
                           help='Auto Submit')


class KeeperFillCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('list', KeeperFillListCommand(), 'Displays a list of KeeperFill values.')
        self.register_command('set', KeeperFillSetCommand(), 'Sets Keeper Fill settings.')
        self.default_verb = 'list'


class KeeperFillMixin:
    @staticmethod
    def resolve_records(params, **kwargs):   # type: (KeeperParams, ...) -> Iterable[str]
        recursive = kwargs.get('recursive') is True
        folders = []
        records = set()

        paths = kwargs.get('paths')
        if not paths:
            raise CommandError('', '"paths" parameter is required.')

        for path in paths:
            if path in params.folder_cache:
                folders.append(path)
            elif path in params.record_cache:
                records.add(path)
            else:
                rs = try_resolve_path(params, path)
                if rs is None:
                    raise CommandError('', f'Folder or record path {path} not found')

                folder, pattern = rs
                folder_uid = folder.uid or ''
                if len(pattern) == 0:
                    folders.append(folder_uid)
                else:
                    regex = re.compile(fnmatch.translate(pattern), re.IGNORECASE).match
                    if folder_uid in params.subfolder_record_cache:
                        for record_uid in params.subfolder_record_cache[folder_uid]:
                            if record_uid in params.record_cache:
                                rec = params.record_cache[record_uid]
                                if rec.get('version', 0) in (2, 3):
                                    r = vault.KeeperRecord.load(params, rec)
                                    if r and regex(r.title):
                                        records.add(r.record_uid)

        for folder_uid in folders:
            if recursive:
                records.update(FolderMixin.get_records_in_folder_tree(params, folder_uid))
            else:
                recs = params.subfolder_record_cache.get(folder_uid)
                if recs:
                    records.update(recs)

        return records

    @staticmethod
    def get_keeper_fill_data(params, record_uid):    # type: (KeeperParams, str) -> Optional[dict]
        if record_uid not in params.non_shared_data_cache:
            return
        if record_uid not in params.record_cache:
            return
        rd = params.record_cache[record_uid]
        if 'version' not in rd:
            return
        if rd['version'] not in (2, 3):
            return
        nsd = params.non_shared_data_cache[record_uid]
        if 'data_unencrypted' not in nsd:
            return
        try:
            return json.loads(nsd['data_unencrypted'])
        except Exception as e:
            logging.debug('Record UID: %s: Load NSD error: %s', record_uid, e)

    @staticmethod
    def get_record_url(record):      # type: (vault.KeeperRecord) -> Union[str, List[str], None]
        if isinstance(record, vault.PasswordRecord):
            if record.link:
                return record.link
        elif isinstance(record, vault.TypedRecord):
            url_fields = [x for x in itertools.chain(record.fields, record.custom) if x.type == 'url' and x.value]
            url = []
            for field in url_fields:
                url_str = field.get_default_value(str)
                if url_str:
                    url.append(url_str)
            if url:
                return url


class KeeperFillListCommand(Command, KeeperFillMixin):
    def get_parser(self):
        return kf_list_parser

    def execute(self, params, **kwargs):
        record_uids = self.resolve_records(params, **kwargs)

        verbose = kwargs.get('verbose') is True
        fmt = kwargs.get('format')
        if fmt != 'table':
            verbose = True

        table = []
        for record_uid in record_uids:
            data = self.get_keeper_fill_data(params, record_uid)
            if data is None:
                continue

            record = vault.KeeperRecord.load(params, record_uid)
            if not record:
                continue

            auto_fill_mode = data.get('auto_fill_mode')
            ext_auto_submit = data.get('ext_auto_submit')

            if isinstance(auto_fill_mode, str):
                if auto_fill_mode == 'always':
                    auto_fill_mode = True
                elif auto_fill_mode == 'never':
                    auto_fill_mode = False
                else:
                    auto_fill_mode = None

            url = self.get_record_url(record)

            if not url and auto_fill_mode is None and ext_auto_submit is None:
                continue

            title = record.title
            if not verbose:
                if len(record.title) > 32:
                    title = record.title[:30] + '...'
                if isinstance(url, str):
                    if len(url) > 32:
                        url = url[:30] + '...'

            table.append([record_uid, title, url, auto_fill_mode, ext_auto_submit])
        fmt = kwargs.get('format')
        headers = ['UID', 'Title', 'URL', 'Auto Fill', 'Auto Submit']
        return dump_report_data(table, headers, row_number=True, sort_by=1, fmt=fmt, filename=kwargs.get('output'))


class KeeperFillSetCommand(Command, KeeperFillMixin):
    def get_parser(self):
        return kf_set_parser

    def execute(self, params, **kwargs):
        auto_fill = kwargs.get('auto_fill')
        auto_submit = kwargs.get('auto_submit')
        if auto_fill is None and auto_submit is None:
            raise CommandError('', 'Nothing to set.')

        record_v3_updates = []   # type: List[record_pb2.RecordUpdate]
        record_v2_updates = []   # type: List[dict]
        record_uids = self.resolve_records(params, **kwargs)
        for record_uid in record_uids:
            data = self.get_keeper_fill_data(params, record_uid)
            if data is None:
                continue

            record = vault.KeeperRecord.load(params, record_uid)
            if not record:
                return

            url = self.get_record_url(record)
            if not url:
                continue

            auto_fill_mode = data.get('auto_fill_mode')
            ext_auto_submit = data.get('ext_auto_submit')

            if isinstance(auto_fill_mode, str):
                if auto_fill_mode == 'always':
                    auto_fill_mode = 'on'
                elif auto_fill_mode == 'never':
                    auto_fill_mode = 'off'
                else:
                    auto_fill_mode = 'none'
            else:
                auto_fill_mode = 'none'
            if ext_auto_submit is True:
                ext_auto_submit = 'on'
            elif ext_auto_submit is False:
                ext_auto_submit = 'off'
            else:
                ext_auto_submit = 'none'

            should_save = False
            if auto_fill is not None:
                if auto_fill_mode != auto_fill:
                    if auto_fill == 'on':
                        data['auto_fill_mode'] = 'always'
                    elif auto_fill == 'off':
                        data['auto_fill_mode'] = 'never'
                    elif auto_fill == 'none':
                        if 'auto_fill_mode' in data:
                            del data['auto_fill_mode']
                    should_save = True

            if auto_submit is not None:
                if ext_auto_submit != auto_submit:
                    if auto_submit == 'on':
                        data['ext_auto_submit'] = True
                    elif auto_submit == 'off':
                        data['ext_auto_submit'] = False
                    elif auto_submit == 'none':
                        if 'ext_auto_submit' in data:
                            del data['ext_auto_submit']
                    should_save = True

            if should_save:
                nsd = json.dumps(data).encode()
                if isinstance(record, vault.PasswordRecord):
                    nsd = crypto.encrypt_aes_v1(nsd, params.data_key)
                    ur = {
                        'record_uid': record_uid,
                        'revision': record.revision,
                        'non_shared_data': utils.base64_url_encode(nsd),
                        'version': 2,
                        'client_modified_time': utils.current_milli_time()
                    }
                    record_v2_updates.append(ur)
                elif isinstance(record, vault.TypedRecord):
                    ru = record_pb2.RecordUpdate()
                    ru.record_uid = utils.base64_url_decode(record_uid)
                    ru.client_modified_time = utils.current_milli_time()
                    ru.revision = record.revision
                    ru.non_shared_data = crypto.encrypt_aes_v2(nsd, params.data_key)
                    record_v3_updates.append(ru)

        if len(record_v3_updates) > 0 or len(record_v2_updates) > 0:
            params.sync_data = True

        while len(record_v3_updates) > 0:
            chunk = record_v3_updates[:900]
            record_v3_updates = record_v3_updates[900:]
            rq = record_pb2.RecordsUpdateRequest()
            rq.records.extend(chunk)
            rq.client_time = utils.current_milli_time()

            rs = api.communicate_rest(params, rq, 'vault/records_update')

        while len(record_v2_updates):
            chunk = record_v2_updates[:90]
            record_v2_updates = record_v2_updates[90:]
            rq = {
                'command': 'record_update',
                'update_records': chunk
            }
            rs = api.communicate(params, rq)
