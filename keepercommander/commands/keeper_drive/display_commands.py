#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
KeeperDrive — display / inspection commands.

Single Responsibility: every class here is read-only — it queries data and
presents it; no mutations.
"""

import json
import logging

from ..base import Command
from ...error import CommandError
from ... import keeper_drive as _kd
from .helpers import (
    RECORD_PERM_LABELS, FOLDER_PERM_LABELS,
    normalize_parent_uid, get_access_role_label, format_timestamp,
    load_record_metadata, command_error_handler,
)
from .parsers import (
    keeper_drive_get_record_details_parser,
    keeper_drive_get_record_access_parser,
    kd_get_parser,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════
# kd-record-details
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveGetRecordDetailsCommand(Command):
    """Get record metadata details."""

    def get_parser(self):
        return keeper_drive_get_record_details_parser

    def execute(self, params, **kwargs):
        identifiers = kwargs.get('record_uids', [])
        output_format = kwargs.get('format', 'table')

        if not identifiers:
            raise CommandError('kd-record-details', 'At least one record UID or title is required')

        record_uids = []
        for ident in identifiers:
            uid = _kd.resolve_kd_record_uid(params, ident)
            if not uid:
                raise CommandError('kd-record-details',
                                   f"Record '{ident}' not found")
            record_uids.append(uid)

        with command_error_handler('kd-record-details'):
            result = _kd.get_record_details_v3(params, record_uids)
            if output_format == 'json':
                print(json.dumps(result, indent=2))
            else:
                for record in result.get('data', []):
                    logging.info("Record UID: %s", record['record_uid'])
                    logging.info("  Title: %s", record['title'])
                    logging.info("  Type: %s", record.get('type', 'Unknown'))
                    logging.info("  Version: %s", record.get('version', 0))
                    logging.info("  Revision: %s", record.get('revision', 0))
                    logging.info("")
                if result.get('forbidden_records'):
                    logging.warning("Forbidden records: %d", len(result['forbidden_records']))
                    for uid in result['forbidden_records']:
                        logging.warning("  %s", uid)
                logging.info("Total records retrieved: %d", len(result.get('data', [])))


# ══════════════════════════════════════════════════════════════════════════
# kd-record-access
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveGetRecordAccessCommand(Command):
    """Get record access information."""

    def get_parser(self):
        return keeper_drive_get_record_access_parser

    def execute(self, params, **kwargs):
        from keepercommander.display import dump_report_data

        identifiers = kwargs.get('record_uids', [])
        output_format = kwargs.get('format', 'table')
        verbose = kwargs.get('verbose', False)

        if not identifiers:
            raise CommandError('kd-record-access', 'At least one record UID or title is required')

        record_uids = []
        for ident in identifiers:
            uid = _kd.resolve_kd_record_uid(params, ident)
            if not uid:
                raise CommandError('kd-record-access',
                                   f"Record '{ident}' not found")
            record_uids.append(uid)

        with command_error_handler('kd-record-access'):
            result = _kd.get_record_accesses_v3(params, record_uids)

            if output_format == 'json':
                print(json.dumps(result, indent=2))
                return

            accesses = result['record_accesses']
            if not accesses:
                logging.info("No access entries found.")
            elif not verbose:
                rows = [[a['record_uid'],
                         a.get('accessor_name', a.get('access_type_uid', '')),
                         a.get('access_type', ''),
                         get_access_role_label(a),
                         '\u2713' if a.get('owner') else '']
                        for a in accesses]
                dump_report_data(rows,
                                 ['Record UID', 'Accessor', 'Type', 'Role', 'Owner'],
                                 title='Record Access (KeeperDrive)',
                                 row_number=True, group_by=0)
            else:
                self._print_verbose(accesses)

            if result.get('forbidden_records'):
                logging.warning("Forbidden records (%d):", len(result['forbidden_records']))
                for uid in result['forbidden_records']:
                    logging.warning("  %s", uid)
            logging.info("\nTotal entries: %d", len(accesses))

    @staticmethod
    def _print_verbose(accesses):
        for a in accesses:
            print(f"\n  Record : {a['record_uid']}")
            print(f"  Accessor: {a.get('accessor_name', a.get('access_type_uid', ''))}"
                  f"  [{a.get('access_type', '')}]")
            print(f"  Role    : {get_access_role_label(a)}"
                  + ('  (owner)' if a.get('owner') else ''))
            print(f"  {'Permission':<20}  Value")
            print(f"  {'-'*20}  -----")
            for flag, lbl in RECORD_PERM_LABELS:
                print(f"  {lbl:<20}  {'Y' if a.get(flag) else 'N'}")


# ══════════════════════════════════════════════════════════════════════════
# kd-get  (composite — inspects both records and folders)
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveGetCommand(Command):
    """Show details of a KeeperDrive record or folder."""

    _MASKED_TYPES = frozenset({'password', 'secret', 'pinCode', 'pin_code'})

    def get_parser(self):
        return kd_get_parser

    def execute(self, params, **kwargs):
        uid     = (kwargs.get('uid') or '').strip()
        fmt     = kwargs.get('format') or 'detail'
        verbose = kwargs.get('verbose', False)
        unmask  = kwargs.get('unmask', False)

        if not uid:
            raise CommandError('kd-get', 'UID parameter is required')

        resolved = self._resolve_as_folder(params, uid)
        if resolved:
            (self._folder_json if fmt == 'json' else self._folder_detail)(params, resolved, verbose)
            return

        resolved = self._resolve_as_record(params, uid)
        if resolved:
            (self._record_json if fmt == 'json' else self._record_detail)(
                params, resolved, verbose, unmask)
            return

        raise CommandError('kd-get', f'Cannot find any KeeperDrive object with UID or title: {uid}')

    # ── Resolution ────────────────────────────────────────────────────

    @staticmethod
    def _resolve_as_folder(params, uid):
        kd_folders = getattr(params, 'keeper_drive_folders', {})
        if uid in kd_folders:
            return uid
        lower = uid.lower()
        matches = [f for f, o in kd_folders.items() if o.get('name', '').lower() == lower]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            from keepercommander.display import dump_report_data
            rows = [[f, kd_folders[f].get('name', '')] for f in matches]
            dump_report_data(rows, ['Folder UID', 'Name'],
                             title='Multiple folders match the name', row_number=True)
        return None

    @staticmethod
    def _resolve_as_record(params, uid):
        kd_records = getattr(params, 'keeper_drive_records', {})
        if uid in kd_records:
            return uid
        lower = uid.lower()
        kd_data = getattr(params, 'keeper_drive_record_data', {})
        matches = []
        for ruid in kd_records:
            if ruid in kd_data and 'data_json' in kd_data[ruid]:
                title = kd_data[ruid]['data_json'].get('title', '')
                if title and lower in title.lower():
                    matches.append((ruid, title))
        if len(matches) == 1:
            return matches[0][0]
        if len(matches) > 1:
            from keepercommander.display import dump_report_data
            dump_report_data(
                sorted(matches, key=lambda x: x[1]),
                ['Record UID', 'Title'],
                title='Multiple records match the title', row_number=True)
        return None

    # ── Record display ────────────────────────────────────────────────

    def _record_detail(self, params, record_uid, verbose, unmask):
        meta = load_record_metadata(params, record_uid)

        print('')
        print('{0:>20s}: {1}'.format('UID',      record_uid))
        print('{0:>20s}: {1}'.format('Type',     meta['type']))
        print('{0:>20s}: {1}'.format('Title',    meta['title']))
        if meta['version']:
            print('{0:>20s}: {1}'.format('Version',  str(meta['version'])))
        if meta['revision']:
            print('{0:>20s}: {1}'.format('Revision', str(meta['revision'])))
        if meta['folder_location']:
            print('{0:>20s}: {1}'.format('Folder',   meta['folder_location']))

        for f in meta['fields']:
            ftype = f.get('type', '')
            label = f.get('label') or ftype.replace('_', ' ').title()
            values = f.get('value', [])
            if not isinstance(values, list):
                values = [values]
            for val in values:
                if not val and val != 0:
                    continue
                if ftype in self._MASKED_TYPES:
                    dval = str(val) if unmask else '********'
                elif isinstance(val, dict):
                    dval = ', '.join(f'{k}: {v}' for k, v in val.items() if v)
                else:
                    dval = str(val)
                print('{0:>20s}: {1}'.format(label, dval))

        if meta['notes']:
            for i, line in enumerate(meta['notes'].split('\n')):
                print('{0:>21s} {1}'.format('Notes:' if i == 0 else '', line.strip()))

        self._print_record_access(params, record_uid, verbose)

    def _record_json(self, params, record_uid, verbose, _unmask=False):
        meta = load_record_metadata(params, record_uid)
        ro = {
            'record_uid': record_uid, 'title': meta['title'],
            'type': meta['type'], 'version': meta['version'],
            'revision': meta['revision'],
        }
        if meta['folder_location']:
            ro['folder'] = meta['folder_location']
        if meta['fields']:
            ro['fields'] = meta['fields']
        if meta['notes']:
            ro['notes'] = meta['notes']

        try:
            accesses = _kd.get_record_accesses_v3(
                params, [record_uid]).get('record_accesses', [])
            if accesses:
                access_list = []
                for a in accesses:
                    entry = {
                        'accessor':    a.get('accessor_name') or a.get('access_type_uid', ''),
                        'access_type': a.get('access_type', ''),
                        'role':        get_access_role_label(a),
                        'owner':       a.get('owner', False),
                    }
                    if verbose:
                        for flag, _ in RECORD_PERM_LABELS:
                            entry[flag] = a.get(flag, False)
                    access_list.append(entry)
                ro['record_access'] = access_list
        except Exception as e:
            logger.debug('Could not retrieve record access: %s', e)

        print(json.dumps(ro, indent=2))

    @staticmethod
    def _print_record_access(params, record_uid, verbose):
        try:
            accesses = _kd.get_record_accesses_v3(
                params, [record_uid]).get('record_accesses', [])
            if not accesses:
                return
            print('')
            print('Record Access:')
            if not verbose:
                for a in accesses:
                    accessor = a.get('accessor_name') or a.get('access_type_uid', '')
                    owner = '  (owner)' if a.get('owner') else ''
                    print(f'  {accessor}  [{a.get("access_type", "")}]  '
                          f'Role: {get_access_role_label(a)}{owner}')
            else:
                for a in accesses:
                    accessor = a.get('accessor_name') or a.get('access_type_uid', '')
                    print('')
                    print(f'  Accessor : {accessor}  [{a.get("access_type", "")}]')
                    print(f'  Role     : {get_access_role_label(a)}'
                          + ('  (owner)' if a.get('owner') else ''))
                    print(f'  {"Permission":<20}  Value')
                    print(f'  {"-"*20}  -----')
                    for flag, lbl in RECORD_PERM_LABELS:
                        print(f'  {lbl:<20}  {"Y" if a.get(flag) else "N"}')
        except Exception as e:
            logger.debug('Could not retrieve record access: %s', e)

    # ── Folder display ────────────────────────────────────────────────

    @staticmethod
    def _folder_detail(params, folder_uid, verbose):
        fobj = getattr(params, 'keeper_drive_folders', {}).get(folder_uid, {})
        name = fobj.get('name', folder_uid)
        parent_uid = normalize_parent_uid(fobj.get('parent_uid', ''))

        parent_name = parent_uid
        if parent_uid and parent_uid != 'root':
            parent_name = getattr(params, 'keeper_drive_folders', {}).get(
                parent_uid, {}).get('name', parent_uid)

        print('')
        print('{0:>20s}: {1}'.format('Folder UID', folder_uid))
        print('{0:>20s}: {1}'.format('Name',       name))
        if parent_uid:
            print('{0:>20s}: {1}'.format('Parent', parent_name))

        KeeperDriveGetCommand._print_folder_access(params, folder_uid, verbose)

    @staticmethod
    def _folder_json(params, folder_uid, verbose):
        fobj = getattr(params, 'keeper_drive_folders', {}).get(folder_uid, {})
        name = fobj.get('name', folder_uid)
        parent_uid = normalize_parent_uid(fobj.get('parent_uid', ''))

        fo = {'folder_uid': folder_uid, 'name': name}
        if parent_uid:
            fo['parent_uid'] = parent_uid

        try:
            result = _kd.get_folder_access_v3(params, folder_uids=[folder_uid])
            for fr in result.get('results', []):
                if not fr.get('success'):
                    continue
                accessors = fr.get('accessors', [])
                if not accessors:
                    continue
                access_list = []
                for a in accessors:
                    entry = {
                        'accessor':    a.get('username') or a.get('accessor_uid', ''),
                        'access_type': a.get('access_type', ''),
                        'role':        a.get('role', ''),
                        'inherited':   a.get('inherited', False),
                    }
                    if a.get('date_created'):
                        entry['date_created'] = format_timestamp(a['date_created'])
                    if a.get('last_modified'):
                        entry['last_modified'] = format_timestamp(a['last_modified'])
                    if verbose and a.get('permissions'):
                        entry['permissions'] = a['permissions']
                    access_list.append(entry)
                fo['folder_access'] = access_list
        except Exception as e:
            logger.debug('Could not retrieve folder access: %s', e)

        print(json.dumps(fo, indent=2))

    @staticmethod
    def _print_folder_access(params, folder_uid, verbose):
        try:
            result = _kd.get_folder_access_v3(params, folder_uids=[folder_uid])
            for fr in result.get('results', []):
                if not fr.get('success'):
                    err = fr.get('error', {})
                    logging.warning("  Access error: %s — %s",
                                    err.get('status'), err.get('message'))
                    continue
                accessors = fr.get('accessors', [])
                if not accessors:
                    continue
                print('')
                print('Folder Access:')
                if not verbose:
                    for a in accessors:
                        label = a.get('username') or a.get('accessor_uid', '')
                        inh = '  (inherited)' if a.get('inherited') else ''
                        print(f'  {label}  [{a.get("access_type", "")}]  '
                              f'Role: {a.get("role", "")}{inh}')
                else:
                    for a in accessors:
                        label = a.get('username') or a.get('accessor_uid', '')
                        print('')
                        print(f'  Accessor : {label}  [{a.get("access_type", "")}]')
                        print(f'  Role     : {a.get("role", "")}'
                              + ('  (inherited)' if a.get('inherited') else ''))
                        if a.get('date_created'):
                            print(f'  Created  : {format_timestamp(a["date_created"])}')
                        if a.get('last_modified'):
                            print(f'  Modified : {format_timestamp(a["last_modified"])}')
                        perms = a.get('permissions', {})
                        if perms:
                            print(f'  {"Permission":<26}  Value')
                            print(f'  {"-"*26}  -----')
                            for flag, lbl in FOLDER_PERM_LABELS:
                                print(f'  {lbl:<26}  {"Y" if perms.get(flag) else "N"}')
        except Exception as e:
            logger.debug('Could not retrieve folder access: %s', e)
