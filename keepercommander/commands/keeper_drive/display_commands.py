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
        print('{0:>20s}: {1:<20s}'.format('UID', record_uid))
        print('{0:>20s}: {1:<20s}'.format('Type', meta['type'] or ''))
        if meta['title']:
            print('{0:>20s}: {1:<20s}'.format('Title', meta['title']))

        login_val = self._extract_field_value(meta['fields'], 'login')
        if login_val:
            print('{0:>20s}: {1:<20s}'.format('Login', login_val))

        password_val = self._extract_field_value(meta['fields'], 'password')
        if password_val:
            display_pw = password_val if unmask else '********'
            print('{0:>20s}: {1:<20s}'.format('Password', display_pw))

        url_val = self._extract_field_value(meta['fields'], 'url')
        if url_val:
            print('{0:>20s}: {1:<20s}'.format('URL', url_val))

        shown_types = {'login', 'password', 'url'}
        for f in meta['fields']:
            ftype = f.get('type', '')
            if ftype in shown_types:
                continue
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
                print('{0:>20s}: {1:<s}'.format(label, dval))

        if meta['notes']:
            for i, line in enumerate(meta['notes'].split('\n')):
                print('{0:>21s} {1}'.format('Notes:' if i == 0 else '', line.strip()))

        self._print_record_permissions(params, record_uid, verbose)

    @staticmethod
    def _extract_field_value(fields, field_type):
        """Extract the first non-empty value for a given field type."""
        for f in fields:
            if f.get('type', '') == field_type:
                values = f.get('value', [])
                if not isinstance(values, list):
                    values = [values]
                for val in values:
                    if val:
                        return str(val) if not isinstance(val, dict) else \
                            ', '.join(f'{k}: {v}' for k, v in val.items() if v)
        return ''

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
                user_perms = []
                share_admins = []
                for a in accesses:
                    accessor = a.get('accessor_name') or a.get('access_type_uid', '')
                    role = get_access_role_label(a)
                    entry = {
                        'username':  accessor,
                        'owner':     a.get('owner', False),
                        'shareable': a.get('can_approve_access', False) or a.get('can_update_access', False),
                        'editable':  a.get('can_edit', False),
                        'role':      role,
                    }
                    if verbose:
                        for flag, _ in RECORD_PERM_LABELS:
                            entry[flag] = a.get(flag, False)
                    user_perms.append(entry)
                    if role == 'MANAGER' and a.get('can_change_ownership', False):
                        share_admins.append(accessor)
                if user_perms:
                    ro['user_permissions'] = user_perms
                if share_admins:
                    ro['share_admins'] = share_admins
        except Exception as e:
            logger.debug('Could not retrieve record access: %s', e)

        print(json.dumps(ro, indent=2))

    @staticmethod
    def _print_record_permissions(params, record_uid, verbose):
        """Display record permissions in a format similar to the legacy get command."""
        try:
            accesses = _kd.get_record_accesses_v3(
                params, [record_uid]).get('record_accesses', [])
            if not accesses:
                return

            print('')
            print('User Permissions:')
            share_admins = []
            for a in accesses:
                accessor = a.get('accessor_name') or a.get('access_type_uid', '')
                is_owner = a.get('owner', False)
                can_edit = a.get('can_edit', False)
                can_share = a.get('can_approve_access', False) or a.get('can_update_access', False)
                role = get_access_role_label(a)

                print('')
                print('  User: ' + accessor)
                if is_owner:
                    print('  Owner: Yes')
                print('  Shareable: ' + ('Yes' if can_share else 'No'))
                print('  Read-Only: ' + ('Yes' if not can_edit else 'No'))

                if verbose:
                    print(f'  Role: {role}')
                    print(f'  {"Permission":<20}  Value')
                    print(f'  {"-"*20}  -----')
                    for flag, lbl in RECORD_PERM_LABELS:
                        print(f'  {lbl:<20}  {"Y" if a.get(flag) else "N"}')

                if role == 'MANAGER' and a.get('can_change_ownership', False):
                    share_admins.append(accessor)

            if share_admins:
                print('')
                total = len(share_admins)
                max_shown = 10
                if total <= max_shown:
                    print(f'Share Admins ({total}):')
                    for admin in share_admins:
                        print(f'  {admin}')
                else:
                    print(f'Share Admins ({total}, showing first {max_shown}):')
                    for admin in share_admins[:max_shown]:
                        print(f'  {admin}')
                    print(f'  ... and {total - max_shown} more')
        except Exception as e:
            logger.debug('Could not retrieve record access: %s', e)

    # ── Folder display ────────────────────────────────────────────────

    @staticmethod
    def _folder_permission_summary(perms):
        """Derive a human-readable permission string from folder permission flags."""
        if not perms:
            return 'No Folder Permissions'
        can_manage_records = (perms.get('can_edit_records', False)
                              and perms.get('can_add', False)
                              and perms.get('can_remove', False))
        can_manage_users = perms.get('can_update_access', False)
        if can_manage_users and can_manage_records:
            return 'Can Manage Users & Records'
        if can_manage_users:
            return 'Can Manage Users'
        if can_manage_records:
            return 'Can Manage Records'
        if perms.get('can_view_records', False):
            return 'Can View'
        return 'No Folder Permissions'

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
        print('{0:>25s}: {1:<20s}'.format('Folder UID', folder_uid))
        print('{0:>25s}: {1}'.format('Name', name))
        if parent_uid:
            print('{0:>25s}: {1}'.format('Parent', parent_name))

        KeeperDriveGetCommand._print_folder_permissions(params, folder_uid, verbose)

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
                user_perms = []
                team_perms = []
                share_admins = []
                for a in accessors:
                    accessor = a.get('username') or a.get('accessor_uid', '')
                    at = a.get('access_type', '')
                    perms = a.get('permissions', {})
                    perm_str = KeeperDriveGetCommand._folder_permission_summary(perms)
                    entry = {
                        'accessor':    accessor,
                        'access_type': at,
                        'role':        a.get('role', ''),
                        'permissions': perm_str,
                        'inherited':   a.get('inherited', False),
                    }
                    if verbose and perms:
                        entry['permission_flags'] = perms
                    if at == 'AT_TEAM':
                        team_perms.append(entry)
                    else:
                        user_perms.append(entry)
                    if a.get('role', '') == 'MANAGER':
                        share_admins.append(accessor)
                if user_perms:
                    fo['user_permissions'] = user_perms
                if team_perms:
                    fo['team_permissions'] = team_perms
                if share_admins:
                    fo['share_admins'] = share_admins
        except Exception as e:
            logger.debug('Could not retrieve folder access: %s', e)

        print(json.dumps(fo, indent=2))

    @staticmethod
    def _print_folder_permissions(params, folder_uid, verbose):
        """Display folder permissions in a format similar to the legacy get command."""
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

                users = []
                teams = []
                share_admins = []
                for a in accessors:
                    at = a.get('access_type', '')
                    if at == 'AT_TEAM':
                        teams.append(a)
                    else:
                        users.append(a)
                    if a.get('role', '') == 'MANAGER':
                        name = a.get('username') or a.get('accessor_uid', '')
                        share_admins.append(name)

                if users:
                    print('')
                    print('{0:>25s}:'.format('User Permissions'))
                    for a in users:
                        label = a.get('username') or a.get('accessor_uid', '')
                        perms = a.get('permissions', {})
                        perm_str = KeeperDriveGetCommand._folder_permission_summary(perms)
                        print('{0:>25s}: {1}'.format(label, perm_str))
                        if verbose:
                            if a.get('date_created'):
                                print('{0:>25s}  Created: {1}'.format('', format_timestamp(a['date_created'])))
                            if a.get('last_modified'):
                                print('{0:>25s}  Modified: {1}'.format('', format_timestamp(a['last_modified'])))
                            if perms:
                                print('{0:>25s}  {1:<26}  {2}'.format('', 'Permission', 'Value'))
                                print('{0:>25s}  {1:<26}  {2}'.format('', '-' * 26, '-----'))
                                for flag, lbl in FOLDER_PERM_LABELS:
                                    print('{0:>25s}  {1:<26}  {2}'.format(
                                        '', lbl, 'Y' if perms.get(flag) else 'N'))

                if teams:
                    print('')
                    print('{0:>25s}:'.format('Team Permissions'))
                    for a in teams:
                        label = a.get('username') or a.get('accessor_uid', '')
                        perms = a.get('permissions', {})
                        perm_str = KeeperDriveGetCommand._folder_permission_summary(perms)
                        print('{0:>25s}: {1}'.format(label, perm_str))
                        if verbose and perms:
                            print('{0:>25s}  {1:<26}  {2}'.format('', 'Permission', 'Value'))
                            print('{0:>25s}  {1:<26}  {2}'.format('', '-' * 26, '-----'))
                            for flag, lbl in FOLDER_PERM_LABELS:
                                print('{0:>25s}  {1:<26}  {2}'.format(
                                    '', lbl, 'Y' if perms.get(flag) else 'N'))

                if share_admins:
                    print('')
                    print('{0:>25s}:'.format('Share Administrators'))
                    for admin in share_admins:
                        print('{0:>25s}: {1}'.format(admin, 'Can Manage Users & Records'))

                print('')
        except Exception as e:
            logger.debug('Could not retrieve folder access: %s', e)
