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
Nested Share Folder — record sharing, permission, and transfer commands.

Single Responsibility: every class here deals with *who* can access a
record and at what permission level.

Design patterns:
  - Strategy: ``NestedShareRecordShareCommand`` dispatches by action name.
  - Template Method: ``NestedShareRecordPermissionCommand`` decomposes its
    workflow into resolve → collect → compute → display → execute steps.
"""

import logging

from ..base import Command
from ...error import CommandError
from ... import nested_share_folder as _nsf
from ... import vault_extensions
from .helpers import (
    parse_expiration, get_access_role_label,
    validate_rotate_on_expiration,
    command_error_handler, check_result,
    check_record_share_permission,
    collect_records_in_folder,
    ensure_nested_share_folder, ensure_nested_share_record,
    raise_if_record_share_target_is_owner,
)
from .parsers import (
    nested_share_record_share_parser,
    nested_share_record_permission_parser,
    nested_share_record_transfer_parser,
)


# ══════════════════════════════════════════════════════════════════════════
# nsf-share-record   (Strategy pattern — grant / revoke / owner)
# ══════════════════════════════════════════════════════════════════════════

class NestedShareRecordShareCommand(Command):
    """Manage record sharing using grant/update/revoke actions."""

    def get_parser(self):
        return nested_share_record_share_parser

    def execute(self, params, **kwargs):
        record_arg = kwargs.get('record')
        emails = kwargs.get('email') or []
        action = kwargs.get('action') or 'grant'
        role = kwargs.get('role')
        dry_run = kwargs.get('dry_run', False)
        recursive = kwargs.get('recursive', False)
        force = kwargs.get('force', False)
        rotate_on_expiration = bool(kwargs.get('rotate_on_expiration'))

        if not record_arg:
            raise CommandError('nsf-share-record', 'Record path or UID is required')
        if not emails:
            raise CommandError('nsf-share-record', 'Recipient email is required (use -e or --email)')
        if action == 'owner' and len(emails) > 1:
            raise CommandError('nsf-share-record', 'Ownership can only be transferred to a single account')
        if action == 'grant' and not role:
            raise CommandError('nsf-share-record', 'Role is required for grant action')

        if kwargs.get('contacts_only'):
            emails = [self._resolve_contact(params, e, force) for e in emails]

        expiration = parse_expiration(
            kwargs.get('expire_at'), kwargs.get('expire_in'), 'nsf-share-record')
        access_role_type = _nsf.resolve_role_name(role) if role else None
        record_uids = self._resolve_record_uids(params, record_arg, recursive)

        if rotate_on_expiration:
            validate_rotate_on_expiration('nsf-share-record', action, expiration)
            ineligible = [
                uid for uid in record_uids
                if not vault_extensions.nested_share_record_is_pam_user_with_rotation(params, uid)
            ]
            if ineligible:
                raise CommandError(
                    'nsf-share-record',
                    '--rotate-on-expiration requires a pamUser record with rotation configured. '
                    'Ineligible record(s): ' + ', '.join(sorted(ineligible)))

        for uid in record_uids:
            check_record_share_permission(params, uid, 'nsf-share-record')

        if dry_run:
            self._print_dry_run(action, record_uids, emails, role, expiration,
                                rotate_on_expiration)
            return

        with command_error_handler('nsf-share-record'):
            for email in emails:
                for record_uid in record_uids:
                    raise_if_record_share_target_is_owner(
                        params, record_uid, email, 'nsf-share-record',
                        is_ownership_transfer=(action == 'owner'))
                    result, effective_action = self._dispatch(
                        params, action, record_uid, email, access_role_type, expiration,
                        rotate_on_expiration)
                    self._log_results(result, effective_action, email)

    # Strategy dispatch — returns (result, effective_action)
    @staticmethod
    def _dispatch(params, action, record_uid, email, access_role_type, expiration,
                  rotate_on_expiration=False):
        if action == 'owner':
            return (_nsf.transfer_record_ownership_v3(
                params=params, record_uid=record_uid, new_owner_email=email), 'owner')

        if action == 'grant':
            existing = NestedShareRecordShareCommand._get_direct_user_share(
                params, record_uid, email)
            if existing:
                if _nsf.is_record_share_update_noop(
                        existing, access_role_type, expiration,
                        rotate_on_expiration=rotate_on_expiration):
                    logging.info(
                        "Record '%s' already shared with '%s' at the requested "
                        "role and expiration; no change needed.",
                        record_uid, email)
                    return ({
                        'results': [{
                            'record_uid': record_uid,
                            'success': True,
                            'message': 'Already has requested access',
                        }],
                        'success': True,
                    }, 'update')
                logging.debug(
                    "Record '%s' is already shared with user '%s'; switching to update.",
                    record_uid, email)
                return (_nsf.update_record_share_v3(
                    params=params, record_uid=record_uid, recipient_email=email,
                    access_role_type=access_role_type,
                    expiration_timestamp=expiration,
                    rotate_on_expiration=rotate_on_expiration), 'update')
            return (_nsf.share_record_v3(
                params=params, record_uid=record_uid, recipient_email=email,
                access_role_type=access_role_type,
                expiration_timestamp=expiration,
                rotate_on_expiration=rotate_on_expiration), 'grant')

        return (_nsf.unshare_record_v3(
            params=params, record_uid=record_uid, recipient_email=email), 'revoke')

    @staticmethod
    def _get_direct_user_share(params, record_uid, email):
        """Return direct AT_USER share metadata for *email*, or None."""
        try:
            access_result = _nsf.get_record_accesses_v3(params, [record_uid])
            return _nsf.find_direct_user_share_access(
                access_result, record_uid, email)
        except Exception as exc:
            logging.debug("Could not fetch record accesses for '%s': %s", record_uid, exc)
            return None

    @staticmethod
    def _is_already_shared(params, record_uid, email):
        """Return True if *email* already has a *direct* non-owner share on *record_uid*.

        Inherited permissions (delivered via a parent shared folder) are
        intentionally ignored: the v3 share endpoint cannot ``update`` an
        inherited row — attempting to do so is rejected with ``trying to
        update or revoke non existing permissions``. Returning False here
        causes the caller to dispatch ``share_record_v3`` (a fresh direct
        grant) which correctly overrides the inherited folder permission.
        """
        return NestedShareRecordShareCommand._get_direct_user_share(
            params, record_uid, email) is not None

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
                logging.info('Record "%s" access permissions has been %s \'%s\'',
                             uid, verbs.get(action, action), email)
            else:
                logging.info('Failed to %s record "%s" access for \'%s\': %s',
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
            raise CommandError('nsf-share-record', 'More than 1 matching usernames found. Aborting')
        match = next(iter(matches), None)
        if match:
            dump_report_data([[email, match]], ['Requested', 'Known Contact'])
            if force or user_choice('\tReplace with known matching contact?', 'yn', default='n') == 'y':
                return match
        raise CommandError('nsf-share-record',
                           f'Recipient {email!r} is not a known contact')

    @staticmethod
    def _resolve_record_uids(params, record_arg, recursive):
        nsf_folders = getattr(params, 'nested_share_folders', {})
        nsf_records = getattr(params, 'nested_share_records', {})

        # Fast path: if the identifier is a known record UID, don't attempt
        # to resolve it as a folder path (folder resolution can traverse the
        # folder tree and raise on malformed/missing nodes).
        if record_arg in nsf_records:
            return [record_arg]

        try:
            folder_uid = _nsf.resolve_folder_identifier(params, record_arg)
        except Exception:
            folder_uid = None
        if folder_uid:
            # Reject legacy folders up-front with a friendly message rather
            # than letting them slip through as a "no records found" error.
            if folder_uid not in nsf_folders:
                ensure_nested_share_folder(params, folder_uid, 'nsf-share-record',
                                           identifier=record_arg)
            record_uids = collect_records_in_folder(params, folder_uid, recursive)
            if not record_uids:
                raise CommandError('nsf-share-record', 'No records found in the specified folder')
            return record_uids

        resolved_uid = _nsf.resolve_nested_share_record_uid(params, record_arg)
        if not resolved_uid:
            raise CommandError('nsf-share-record',
                               f"Record '{record_arg}' not found")
        ensure_nested_share_record(params, resolved_uid, 'nsf-share-record',
                                   identifier=record_arg)
        return [resolved_uid]

    @staticmethod
    def _print_dry_run(action, record_uids, emails, role, expiration,
                       rotate_on_expiration=False):
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
            if rotate_on_expiration:
                print("[dry-run] Rotate    : rotate password on share expiration")


# ══════════════════════════════════════════════════════════════════════════
# nsf-record-permission  (Template Method — resolve → collect → compute → display → execute)
# ══════════════════════════════════════════════════════════════════════════

class NestedShareRecordPermissionCommand(Command):
    """Bulk-update sharing permissions on records within a Nested Share Folder."""

    _ROLE_NAMES = [
        'viewer', 'share-manager',
        'content-manager', 'content-share-manager', 'full-manager',
    ]

    def get_parser(self):
        return nested_share_record_permission_parser

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
            raise CommandError('nsf-record-permission', 'Role is required for grant action')

        nsf_folders = getattr(params, 'nested_share_folders', {})
        nsf_folder_records = getattr(params, 'nested_share_folder_records', {})
        nsf_record_data = getattr(params, 'nested_share_record_data', {})

        role_map_pb = {name: _nsf.resolve_role_name(name) for name in self._ROLE_NAMES}

        # Step 1: Resolve
        folder_uid, display_name = self._resolve_folder(nsf_folders, folder_name, params)

        if not force:
            role_label = '"' + role + '"' if role else 'all'
            logging.info('\nRequest to %s %s permission(s) in "%s" folder %s',
                         'GRANT' if action == 'grant' else 'REVOKE',
                         role_label, display_name,
                         'recursively' if recursive else 'only')

        # Step 2: Collect
        record_uids = self._collect_record_uids(nsf_folders, nsf_folder_records, folder_uid, recursive)
        if not record_uids:
            raise CommandError('nsf-record-permission', 'No records found in the specified folder')

        try:
            accesses_result = _nsf.get_record_accesses_v3(params, list(record_uids))
        except Exception as e:
            raise CommandError('nsf-record-permission', f'Failed to fetch record accesses: {e}')

        # Step 3: Compute
        updates, creates, revokes, skipped = self._compute_changes(
            accesses_result, record_uids, params.user, action, role, role_map_pb)
        if not updates and not creates and not revokes:
            if skipped:
                logging.warning('No permission changes can be made. '
                                'See skipped entries below (insufficient permissions).')
                from keepercommander.commands.base import dump_report_data
                from keepercommander.display import bcolors
                self._print_plan([], [], [], skipped, nsf_record_data, dump_report_data, bcolors)
            else:
                logging.info('No permission changes are needed.')
            return

        # Step 4: Display
        if dry_run or not force:
            self._print_plan(updates, creates, revokes, skipped, nsf_record_data, dump_report_data, bcolors)
        if dry_run:
            return

        if not force:
            print('\n\n' + bcolors.WARNING + bcolors.BOLD + 'ALERT!!!' + bcolors.ENDC)
            if user_choice('Do you want to proceed with these permission changes?', 'yn', 'n').lower() != 'y':
                return

        # Step 5: Execute
        self._execute_changes(params, updates, creates, revokes)
        params.sync_data = True

    @staticmethod
    def _resolve_folder(nsf_folders, folder_name, params=None):
        if not folder_name:
            return None, 'root'
        if params is not None:
            resolved = _nsf.resolve_folder_identifier(params, folder_name)
            if resolved and resolved in nsf_folders:
                return resolved, nsf_folders[resolved].get('name', resolved)
            if resolved:
                # Resolution succeeded against legacy caches; reject with a
                # friendly cross-type message instead of "not found".
                ensure_nested_share_folder(params, resolved, 'nsf-record-permission',
                                           identifier=folder_name)
        if folder_name in nsf_folders:
            return folder_name, nsf_folders[folder_name].get('name', folder_name)
        lower = folder_name.lower()
        for fuid, fobj in nsf_folders.items():
            if fobj.get('name', '').lower() == lower:
                return fuid, fobj.get('name', fuid)
        raise CommandError('nsf-record-permission', f'Folder "{folder_name}" not found')

    @staticmethod
    def _collect_record_uids(nsf_folders, nsf_folder_records, folder_uid, recursive):
        record_uids = set()

        def walk(fuid, visited=None):
            if visited is None:
                visited = set()
            if fuid in visited:
                return
            visited.add(fuid)
            record_uids.update(nsf_folder_records.get(fuid, set()))
            if recursive:
                for child_uid, child_obj in nsf_folders.items():
                    if child_obj.get('parent_uid') == fuid and child_uid not in visited:
                        walk(child_uid, visited)

        if folder_uid:
            walk(folder_uid)
        else:
            for fuid, recs in nsf_folder_records.items():
                if fuid not in nsf_folders:
                    record_uids.update(recs)
            if recursive:
                for fuid in list(nsf_folders):
                    walk(fuid)
        return record_uids

    @staticmethod
    def _compute_changes(accesses_result, record_uids, current_user, action, role, role_map_pb):
        """Classify every non-owner share into updates, creates, revokes, or skipped.

        Buckets:
          - ``updates``  — direct shares whose role differs from *role*; sent
            via ``updateSharingPermissions``.
          - ``creates`` — recipients who currently only have an *inherited*
            (folder-level) permission. ``vault/records/v3/share`` cannot
            ``update`` an inherited row (server returns ``trying to update or
            revoke non existing permissions``); a fresh
            ``createSharingPermissions`` adds a direct override.
          - ``revokes`` — direct shares to remove. Inherited shares cannot be
            revoked at the record level and are routed to *skipped*.
          - ``skipped`` — added when:
              * The record UID appears in ``forbidden_records`` (current user
                cannot read or modify its sharing at all), OR
              * The current user's own access entry lacks
                ``can_update_access`` (the user can see the share list but
                cannot modify it — equivalent to the classic
                ``has_record_share_permissions`` check), OR
              * The action is ``revoke`` and the existing share is inherited
                (must be removed from the parent shared folder instead).
        """
        updates, creates, revokes, skipped = [], [], [], []

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

            cur_role = get_access_role_label(access)
            is_inherited = bool(access.get('inherited'))

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
                    entry = {
                        'record_uid': rec_uid, 'email': email,
                        'cur_role': cur_role, 'new_role': role,
                        'access_role_type': role_map_pb.get(role),
                    }
                    if is_inherited:
                        creates.append(entry)
                    else:
                        updates.append(entry)
            else:
                if not role or cur_role == role:
                    if is_inherited:
                        skipped.append({
                            'record_uid': rec_uid, 'email': email, 'cur_role': cur_role,
                            'reason': 'Inherited from a shared folder — '
                                      'revoke at the parent shared folder',
                        })
                    else:
                        revokes.append({'record_uid': rec_uid, 'email': email, 'cur_role': cur_role})

        return updates, creates, revokes, skipped

    @staticmethod
    def _print_plan(updates, creates, revokes, skipped, nsf_record_data, dump_report_data, bcolors):
        def title_for(rec_uid):
            obj = nsf_record_data.get(rec_uid, {})
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

        # Display GRANTs as a single table for the user — direct updates and
        # inherited-overrides are both presented as "current → new" rows even
        # though the underlying API call differs (update vs. create).
        grant_rows = []
        for u in updates:
            grant_rows.append([u['record_uid'], title_for(u['record_uid']), u['email'],
                               u['cur_role'],
                               bcolors.BOLD + '   ' + u['new_role'] + bcolors.ENDC])
        for c in creates:
            grant_rows.append([c['record_uid'], title_for(c['record_uid']), c['email'],
                               c['cur_role'] + ' (inherited)',
                               bcolors.BOLD + '   ' + c['new_role'] + bcolors.ENDC])
        if grant_rows:
            title = (bcolors.OKGREEN + ' GRANT' + bcolors.ENDC
                     + ' Record permission(s)')
            dump_report_data(grant_rows,
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
    def _execute_changes(params, updates, creates, revokes):
        """Apply permission changes in batched REST calls (up to 200 per request).

        ``updates`` use ``updateSharingPermissions`` (modify a direct share);
        ``creates`` use ``createSharingPermissions`` (add a new direct share
        that overrides a folder-inherited permission). Both are reported to
        the user under a single "Failed to GRANT" error table.
        """
        from keepercommander.commands.base import dump_report_data
        from keepercommander.display import bcolors

        grant_failures = []

        if updates:
            outcomes = _nsf.batch_update_record_shares_v3(params, updates)
            for item, result in outcomes:
                record_uid = item['record_uid']
                email = item['email']
                if result.get('skipped'):
                    grant_failures.append([record_uid, email, 'skipped',
                                           result.get('message', 'could not build permission')])
                elif result.get('success'):
                    logging.info("Updated '%s' for %s: %s -> %s",
                                 record_uid, email,
                                 item['cur_role'], item['new_role'])
                else:
                    grant_failures.append([record_uid, email, 'error',
                                           result.get('message', 'Unknown error')])

        if creates:
            outcomes = _nsf.batch_create_record_shares_v3(params, creates)
            for item, result in outcomes:
                record_uid = item['record_uid']
                email = item['email']
                if result.get('skipped'):
                    grant_failures.append([record_uid, email, 'skipped',
                                           result.get('message', 'could not build permission')])
                elif result.get('success'):
                    logging.info("Granted '%s' to %s: %s (inherited) -> %s",
                                 record_uid, email,
                                 item['cur_role'], item['new_role'])
                else:
                    grant_failures.append([record_uid, email, 'error',
                                           result.get('message', 'Unknown error')])

        if grant_failures:
            headers = ['Record UID', 'Email', 'Error Code', 'Message']
            title = (bcolors.WARNING + 'Failed to GRANT' + bcolors.ENDC
                     + ' Record permission(s)')
            dump_report_data(grant_failures, headers, title=title, row_number=True)
            logging.info('')
            logging.info('')

        if revokes:
            table = []
            outcomes = _nsf.batch_unshare_records_v3(params, revokes)
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
# nsf-transfer-record
# ══════════════════════════════════════════════════════════════════════════

class NestedShareRecordTransferCommand(Command):
    """Transfer record ownership to another user."""

    def get_parser(self):
        return nested_share_record_transfer_parser

    def execute(self, params, **kwargs):
        identifiers = kwargs.get('record_uids') or []
        new_owner_email = kwargs.get('new_owner_email')

        if not identifiers or not new_owner_email:
            raise CommandError('nsf-transfer-record', 'Record UID(s) and new owner email are required')

        with command_error_handler('nsf-transfer-record'):
            for identifier in identifiers:
                record_uid = _nsf.resolve_nested_share_record_uid(params, identifier)
                if not record_uid:
                    raise CommandError('nsf-transfer-record',
                                       f"Record '{identifier}' not found")
                ensure_nested_share_record(params, record_uid, 'nsf-transfer-record',
                                           identifier=identifier)
                result = _nsf.transfer_record_ownership_v3(
                    params=params, record_uid=record_uid, new_owner_email=new_owner_email)
                check_result(result, 'nsf-transfer-record')
                for res in result['results']:
                    if res['success']:
                        logging.info("Record '%s' ownership transferred to %s",
                                     res['record_uid'], new_owner_email)
                        logging.warning("You will no longer have access to this record!")
                    else:
                        logging.error("Failed to transfer: %s", res['message'])
