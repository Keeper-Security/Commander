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
KeeperDrive — record sharing, permission, and transfer commands.

Single Responsibility: every class here deals with *who* can access a
record and at what permission level.

Design patterns:
  - Strategy: ``KeeperDriveShareRecordCommand`` dispatches by action name.
  - Template Method: ``KeeperDriveRecordPermissionCommand`` decomposes its
    workflow into resolve → collect → compute → display → execute steps.
"""

import logging

from ..base import Command
from ...error import CommandError
from ... import keeper_drive as _kd
from .helpers import (
    parse_expiration, infer_role,
    command_error_handler, check_result,
    check_record_share_permission,
)
from .parsers import (
    keeper_drive_share_record_parser,
    keeper_drive_record_permission_parser,
    keeper_drive_transfer_record_parser,
)


# ══════════════════════════════════════════════════════════════════════════
# kd-share-record   (Strategy pattern — grant / revoke / owner)
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveShareRecordCommand(Command):
    """Manage record sharing using grant/update/revoke actions."""

    def get_parser(self):
        return keeper_drive_share_record_parser

    def execute(self, params, **kwargs):
        from keepercommander.commands.base import user_choice

        record_arg = kwargs.get('record')
        emails = kwargs.get('email') or []
        action = kwargs.get('action') or 'grant'
        role = kwargs.get('role')
        dry_run = kwargs.get('dry_run', False)
        recursive = kwargs.get('recursive', False)
        force = kwargs.get('force', False)

        if not record_arg:
            raise CommandError('kd-share-record', 'Record path or UID is required')
        if not emails:
            raise CommandError('kd-share-record', 'Recipient email is required (use -e or --email)')
        if action == 'owner' and len(emails) > 1:
            raise CommandError('kd-share-record', 'Ownership can only be transferred to a single account')
        if action == 'grant' and not role:
            raise CommandError('kd-share-record', 'Role is required for grant action')

        if kwargs.get('contacts_only'):
            emails = [self._resolve_contact(params, e, force) for e in emails]

        expiration = parse_expiration(
            kwargs.get('expire_at'), kwargs.get('expire_in'), 'kd-share-record')
        access_role_type = _kd.resolve_role_name(role) if role else None
        record_uids = self._resolve_record_uids(params, record_arg, recursive)

        for uid in record_uids:
            check_record_share_permission(params, uid, 'kd-share-record')

        if dry_run:
            self._print_dry_run(action, record_uids, emails, role, expiration)
            return

        with command_error_handler('kd-share-record'):
            for email in emails:
                for record_uid in record_uids:
                    result, effective_action = self._dispatch(
                        params, action, record_uid, email, access_role_type, expiration)
                    self._log_results(result, effective_action, email)

    # Strategy dispatch — returns (result, effective_action)
    @staticmethod
    def _dispatch(params, action, record_uid, email, access_role_type, expiration):
        if action == 'owner':
            return (_kd.transfer_record_ownership_v3(
                params=params, record_uid=record_uid, new_owner_email=email), 'owner')

        if action == 'grant':
            already_shared = KeeperDriveShareRecordCommand._is_already_shared(
                params, record_uid, email)
            if already_shared:
                logging.debug(
                    "Record '%s' is already shared with '%s'; switching to update.",
                    record_uid, email)
                return (_kd.update_record_share_v3(
                    params=params, record_uid=record_uid, recipient_email=email,
                    access_role_type=access_role_type, expiration_timestamp=expiration), 'update')
            return (_kd.share_record_v3(
                params=params, record_uid=record_uid, recipient_email=email,
                access_role_type=access_role_type, expiration_timestamp=expiration), 'grant')

        return (_kd.unshare_record_v3(
            params=params, record_uid=record_uid, recipient_email=email), 'revoke')

    @staticmethod
    def _is_already_shared(params, record_uid, email):
        """Return True if *email* already has a non-owner share on *record_uid*."""
        try:
            access_result = _kd.get_record_accesses_v3(params, [record_uid])
            return any(
                a.get('accessor_name', '').casefold() == email.casefold()
                and not a.get('owner', False)
                for a in access_result.get('record_accesses', [])
                if a.get('record_uid') == record_uid
            )
        except Exception as exc:
            logging.debug("Could not fetch record accesses for '%s': %s", record_uid, exc)
            return False

    @staticmethod
    def _log_results(result, action, email):
        verbs = {'grant': 'granted to', 'update': 'changed for', 'revoke': 'revoked from'}
        for res in result['results']:
            uid = res['record_uid']
            if action == 'owner':
                if res['success']:
                    logging.info("Record '%s' ownership transferred to '%s'", uid, email)
                    logging.warning("You will no longer have access to this record!")
                else:
                    logging.error("Failed to transfer ownership of '%s' to '%s': %s",
                                  uid, email, res.get('message', 'unknown error'))
            elif res.get('pending'):
                logging.warning("Share invitation has been sent to '%s'", email)
                logging.warning('Please repeat this command when invitation is accepted.')
            elif res['success']:
                logging.info('Record "%s" access permissions has been %s user \'%s\'',
                             uid, verbs.get(action, action), email)
            else:
                logging.info('Failed to %s record "%s" access for user \'%s\': %s',
                             action, uid, email, res['message'])

    @staticmethod
    def _resolve_contact(params, email, force):
        from keepercommander import api
        from keepercommander.commands.base import user_choice, dump_report_data

        known_users = api.get_share_objects(params).get('users', {})
        if email.casefold() in [u.casefold() for u in known_users]:
            return email

        get_user = lambda addr: next(iter(addr.split('@')), '').casefold()
        matches = [c for c in known_users if get_user(email) == get_user(c)]
        if len(matches) > 1:
            raise CommandError('kd-share-record', 'More than 1 matching usernames found. Aborting')
        match = next(iter(matches), None)
        if match:
            dump_report_data([[email, match]], ['Requested', 'Known Contact'])
            if force or user_choice('\tReplace with known matching contact?', 'yn', default='n') == 'y':
                return match
        raise CommandError('kd-share-record',
                           f'Recipient {email!r} is not a known contact')

    @staticmethod
    def _resolve_record_uids(params, record_arg, recursive):
        kd_folders = getattr(params, 'keeper_drive_folders', {})
        kd_records = getattr(params, 'keeper_drive_records', {})

        # Fast path: if the identifier is a known record UID, don't attempt
        # to resolve it as a folder path (folder resolution can traverse the
        # folder tree and raise on malformed/missing nodes).
        if record_arg in kd_records:
            return [record_arg]

        try:
            folder_uid = _kd.resolve_folder_identifier(params, record_arg)
        except Exception:
            folder_uid = None
        if folder_uid and folder_uid in kd_folders:
            record_uids = []
            def collect(fuid, visited=None):
                if visited is None:
                    visited = set()
                if fuid in visited:
                    return
                visited.add(fuid)
                folder = kd_folders.get(fuid, {})
                record_uids.extend(folder.get('record_uids', []))
                if recursive:
                    for child in folder.get('children', []):
                        collect(child, visited)
            collect(folder_uid)
            if not record_uids:
                raise CommandError('kd-share-record', 'No records found in the specified folder')
            return record_uids

        resolved_uid = _kd.resolve_kd_record_uid(params, record_arg)
        if not resolved_uid:
            raise CommandError('kd-share-record',
                               f"Record '{record_arg}' not found")
        return [resolved_uid]

    @staticmethod
    def _print_dry_run(action, record_uids, emails, role, expiration):
        print(f"[dry-run] Action    : {action.upper()}")
        print(f"[dry-run] Records   : {', '.join(record_uids)}")
        if action == 'owner':
            print(f"[dry-run] New Owner : {emails[0]}")
            print("[dry-run] Warning   : You will no longer have access to transferred records!")
        else:
            print(f"[dry-run] Recipients: {', '.join(emails)}")
            if role:
                print(f"[dry-run] Role      : {role}")
            if expiration:
                print(f"[dry-run] Expires   : {expiration} ms")


# ══════════════════════════════════════════════════════════════════════════
# kd-record-permission  (Template Method — resolve → collect → compute → display → execute)
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveRecordPermissionCommand(Command):
    """Bulk-update sharing permissions on records within a KeeperDrive folder."""

    _ROLE_NAMES = [
        'viewer', 'shared-manager',
        'content-manager', 'content-share-manager', 'full-manager',
    ]

    def get_parser(self):
        return keeper_drive_record_permission_parser

    def execute(self, params, **kwargs):
        from keepercommander.commands.base import dump_report_data, user_choice
        from keepercommander.display import bcolors

        folder_name = kwargs.get('folder') or ''
        action = kwargs.get('action')
        role = kwargs.get('role')
        recursive = kwargs.get('recursive', False)
        dry_run = kwargs.get('dry_run', False)
        force = kwargs.get('force', False)

        if action == 'grant' and not role:
            raise CommandError('kd-record-permission', 'Role is required for grant action')

        kd_folders = getattr(params, 'keeper_drive_folders', {})
        kd_folder_records = getattr(params, 'keeper_drive_folder_records', {})
        kd_record_data = getattr(params, 'keeper_drive_record_data', {})

        role_map_pb = {name: _kd.resolve_role_name(name) for name in self._ROLE_NAMES}

        # Step 1: Resolve
        folder_uid, display_name = self._resolve_folder(kd_folders, folder_name, params)

        if not force:
            role_label = '"' + role + '"' if role else 'all'
            logging.info('\nRequest to %s %s permission(s) in "%s" folder %s',
                         'GRANT' if action == 'grant' else 'REVOKE',
                         role_label, display_name,
                         'recursively' if recursive else 'only')

        # Step 2: Collect
        record_uids = self._collect_record_uids(kd_folders, kd_folder_records, folder_uid, recursive)
        if not record_uids:
            raise CommandError('kd-record-permission', 'No records found in the specified folder')

        try:
            accesses_result = _kd.get_record_accesses_v3(params, list(record_uids))
        except Exception as e:
            raise CommandError('kd-record-permission', f'Failed to fetch record accesses: {e}')

        # Step 3: Compute
        updates, revokes, skipped = self._compute_changes(
            accesses_result, record_uids, params.user, action, role, role_map_pb)
        if not updates and not revokes:
            if skipped:
                logging.warning('No permission changes can be made. '
                                'See skipped entries below (insufficient permissions).')
                from keepercommander.commands.base import dump_report_data
                from keepercommander.display import bcolors
                self._print_plan([], [], skipped, kd_record_data, dump_report_data, bcolors)
            else:
                logging.info('No permission changes are needed.')
            return

        # Step 4: Display
        if dry_run or not force:
            self._print_plan(updates, revokes, skipped, kd_record_data, dump_report_data, bcolors)
        if dry_run:
            return

        if not force:
            print('\n\n' + bcolors.WARNING + bcolors.BOLD + 'ALERT!!!' + bcolors.ENDC)
            if user_choice('Do you want to proceed with these permission changes?', 'yn', 'n').lower() != 'y':
                return

        # Step 5: Execute
        self._execute_changes(params, updates, revokes)
        params.sync_data = True

    @staticmethod
    def _resolve_folder(kd_folders, folder_name, params=None):
        if not folder_name:
            return None, 'root'
        if params is not None:
            resolved = _kd.resolve_folder_identifier(params, folder_name)
            if resolved and resolved in kd_folders:
                return resolved, kd_folders[resolved].get('name', resolved)
        if folder_name in kd_folders:
            return folder_name, kd_folders[folder_name].get('name', folder_name)
        lower = folder_name.lower()
        for fuid, fobj in kd_folders.items():
            if fobj.get('name', '').lower() == lower:
                return fuid, fobj.get('name', fuid)
        raise CommandError('kd-record-permission', f'Folder "{folder_name}" not found')

    @staticmethod
    def _collect_record_uids(kd_folders, kd_folder_records, folder_uid, recursive):
        record_uids = set()

        def walk(fuid, visited=None):
            if visited is None:
                visited = set()
            if fuid in visited:
                return
            visited.add(fuid)
            record_uids.update(kd_folder_records.get(fuid, set()))
            if recursive:
                for child_uid, child_obj in kd_folders.items():
                    if child_obj.get('parent_uid') == fuid and child_uid not in visited:
                        walk(child_uid, visited)

        if folder_uid:
            walk(folder_uid)
        else:
            for fuid, recs in kd_folder_records.items():
                if fuid not in kd_folders:
                    record_uids.update(recs)
            if recursive:
                for fuid in list(kd_folders):
                    walk(fuid)
        return record_uids

    @staticmethod
    def _compute_changes(accesses_result, record_uids, current_user, action, role, role_map_pb):
        """Classify every non-owner share into updates, revokes, or skipped.

        A share is added to *skipped* when:
          - The record UID appears in ``forbidden_records`` (current user cannot
            read or modify its sharing at all), OR
          - The current user's own access entry lacks ``can_update_access``
            (the user can see the share list but cannot modify it — equivalent
            to the classic ``has_record_share_permissions`` check).
        """
        updates, revokes, skipped = [], [], []

        # Pre-flight: record UIDs the server refused to return access info for.
        forbidden = set(accesses_result.get('forbidden_records', []))

        # Index current-user's own access flags per record_uid for fast lookup.
        owner_flags = {}  # record_uid -> can_update_access bool
        for access in accesses_result.get('record_accesses', []):
            if access.get('accessor_name', '') == current_user:
                owner_flags[access.get('record_uid')] = access.get('can_update_access', False)

        for rec_uid in record_uids:
            if rec_uid in forbidden:
                skipped.append({
                    'record_uid': rec_uid, 'email': '', 'cur_role': '',
                    'reason': 'No access — record is forbidden',
                })

        for access in accesses_result.get('record_accesses', []):
            rec_uid = access.get('record_uid')
            if not rec_uid or rec_uid not in record_uids or access.get('owner'):
                continue
            email = access.get('accessor_name', '')
            if not email or email == current_user:
                continue

            cur_role = infer_role(access)

            # Pre-flight: does the current user have permission to modify this share?
            can_update = owner_flags.get(rec_uid, False)
            if not can_update:
                skipped.append({
                    'record_uid': rec_uid, 'email': email, 'cur_role': cur_role,
                    'reason': 'Insufficient permission (can_update_access is false)',
                })
                continue

            if action == 'grant':
                if cur_role != role:
                    updates.append({
                        'record_uid': rec_uid, 'email': email,
                        'cur_role': cur_role, 'new_role': role,
                        'access_role_type': role_map_pb.get(role),
                    })
            else:
                if not role or cur_role == role:
                    revokes.append({'record_uid': rec_uid, 'email': email, 'cur_role': cur_role})

        return updates, revokes, skipped

    @staticmethod
    def _print_plan(updates, revokes, skipped, kd_record_data, dump_report_data, bcolors):
        def title_for(rec_uid):
            obj = kd_record_data.get(rec_uid, {})
            dj = obj.get('data_json', {}) if isinstance(obj, dict) else {}
            return (dj.get('title', '')[:32]) if isinstance(dj, dict) else ''

        if skipped:
            table = [[s['record_uid'], title_for(s['record_uid']),
                       s['email'] or '—', s['cur_role'] if s['cur_role'] else '—',
                       s['reason']] for s in skipped]
            title = (bcolors.FAIL + ' SKIP ' + bcolors.ENDC
                     + 'Record permission(s). Not permitted')
            dump_report_data(table,
                             ['Record UID', 'Title', 'Email', 'Current Role', 'Reason'],
                             title=title, row_number=True, group_by=0)
            logging.info('')
            logging.info('')

        if updates:
            table = []
            for u in updates:
                row = [u['record_uid'], title_for(u['record_uid']), u['email'],
                       u['cur_role'],
                       bcolors.BOLD + '   ' + u['new_role'] + bcolors.ENDC]
                table.append(row)
            title = (bcolors.OKGREEN + ' GRANT' + bcolors.ENDC
                     + ' Record permission(s)')
            dump_report_data(table,
                             ['Record UID', 'Title', 'Email', 'Current Role', 'New Role'],
                             title=title, row_number=True, group_by=0)
            logging.info('')
            logging.info('')

        if revokes:
            table = []
            for r in revokes:
                row = [r['record_uid'], title_for(r['record_uid']), r['email'],
                       bcolors.BOLD + '   ' + r['cur_role'] + bcolors.ENDC]
                table.append(row)
            title = (bcolors.FAIL + ' REVOKE' + bcolors.ENDC
                     + ' Record share(s)')
            dump_report_data(table,
                             ['Record UID', 'Title', 'Email', 'Current Role'],
                             title=title, row_number=True, group_by=0)
            logging.info('')
            logging.info('')

    @staticmethod
    def _execute_changes(params, updates, revokes):
        """Apply permission changes in batched REST calls (up to 200 per request)."""
        from keepercommander.commands.base import dump_report_data
        from keepercommander.display import bcolors

        if updates:
            table = []
            outcomes = _kd.batch_update_record_shares_v3(params, updates)
            for item, result in outcomes:
                record_uid = item['record_uid']
                email = item['email']
                if result.get('skipped'):
                    table.append([record_uid, email, 'skipped',
                                  result.get('message', 'could not build permission')])
                elif result.get('success'):
                    logging.info("Updated '%s' for %s: %s -> %s",
                                 record_uid, email,
                                 item['cur_role'], item['new_role'])
                else:
                    table.append([record_uid, email, 'error',
                                  result.get('message', 'Unknown error')])

            if table:
                headers = ['Record UID', 'Email', 'Error Code', 'Message']
                title = (bcolors.WARNING + 'Failed to GRANT' + bcolors.ENDC
                         + ' Record permission(s)')
                dump_report_data(table, headers, title=title, row_number=True)
                logging.info('')
                logging.info('')

        if revokes:
            table = []
            outcomes = _kd.batch_unshare_records_v3(params, revokes)
            for item, result in outcomes:
                record_uid = item['record_uid']
                email = item['email']
                if result.get('skipped'):
                    table.append([record_uid, email, 'skipped',
                                  result.get('message', 'could not build permission')])
                elif result.get('success'):
                    logging.info("Revoked '%s' from %s (%s)",
                                 record_uid, email,
                                 item['cur_role'])
                else:
                    table.append([record_uid, email, 'error',
                                  result.get('message', 'Unknown error')])

            if table:
                headers = ['Record UID', 'Email', 'Error Code', 'Message']
                title = (bcolors.WARNING + 'Failed to REVOKE' + bcolors.ENDC
                         + ' Record share(s)')
                dump_report_data(table, headers, title=title, row_number=True)
                logging.info('')
                logging.info('')


# ══════════════════════════════════════════════════════════════════════════
# kd-transfer-record
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveTransferRecordCommand(Command):
    """Transfer record ownership to another user."""

    def get_parser(self):
        return keeper_drive_transfer_record_parser

    def execute(self, params, **kwargs):
        identifiers = kwargs.get('record_uids') or []
        new_owner_email = kwargs.get('new_owner_email')

        if not identifiers or not new_owner_email:
            raise CommandError('kd-transfer-record', 'Record UID(s) and new owner email are required')

        with command_error_handler('kd-transfer-record'):
            for identifier in identifiers:
                record_uid = _kd.resolve_kd_record_uid(params, identifier)
                if not record_uid:
                    raise CommandError('kd-transfer-record',
                                       f"Record '{identifier}' not found")
                result = _kd.transfer_record_ownership_v3(
                    params=params, record_uid=record_uid, new_owner_email=new_owner_email)
                check_result(result, 'kd-transfer-record')
                for res in result['results']:
                    if res['success']:
                        logging.info("Record '%s' ownership transferred to %s",
                                     res['record_uid'], new_owner_email)
                        logging.warning("You will no longer have access to this record!")
                    else:
                        logging.error("Failed to transfer: %s", res['message'])
