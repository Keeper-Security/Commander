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
KeeperDrive — folder management commands.

Single Responsibility: every class in this module deals with *folder*
operations only (create, rename, remove, list, share, access).
"""

import logging

from ..base import Command
from ...error import CommandError
from ... import keeper_drive as _kd
from .helpers import (
    ROOT_FOLDER_UID, FOLDER_PERM_LABELS,
    normalize_parent_uid, resolve_folder_uid, parse_expiration,
    format_timestamp, command_error_handler, check_result,
)
from .parsers import (
    keeper_drive_mkdir_parser,
    keeper_drive_update_folder_parser,
    keeper_drive_list_parser,
    keeper_drive_share_folder_parser,
    keeper_drive_get_folder_access_parser,
    kd_rmdir_parser,
)


# ══════════════════════════════════════════════════════════════════════════
# kd-mkdir
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveMkdirCommand(Command):
    """Create a KeeperDrive folder using the v3 API."""

    def get_parser(self):
        return keeper_drive_mkdir_parser

    def execute(self, params, **kwargs):
        folder_path = (kwargs.get('folder') or '').strip()
        if not folder_path:
            raise CommandError('keeper-drive-mkdir', 'Folder name or path is required')

        create_parents = kwargs.get('create_parents', False)
        color = kwargs.get('color')
        inherit_permissions = not kwargs.get('no_inherit_permissions', False)

        base_folder_uid = None
        current = getattr(params, 'current_folder', None)
        if current and current in getattr(params, 'keeper_drive_folders', {}):
            base_folder_uid = current

        folder_parts = self._parse_path(folder_path, create_parents)
        if len(folder_parts) > 1 and not create_parents:
            raise CommandError('keeper-drive-mkdir',
                               'Character "/" is reserved. Use "//" inside folder name')

        created_folders = []
        current_parent_uid = base_folder_uid

        for i, folder_name in enumerate(folder_parts):
            is_last = (i == len(folder_parts) - 1)
            existing_uid = self._find_existing_child(params, folder_name, current_parent_uid)

            if existing_uid:
                if is_last and not create_parents:
                    logging.warning('kd-mkdir: Folder "%s" already exists', folder_name)
                    return existing_uid
                current_parent_uid = existing_uid
                continue

            with command_error_handler('keeper-drive-mkdir'):
                result = _kd.create_folder_v3(
                    params=params, folder_name=folder_name,
                    parent_uid=current_parent_uid,
                    color=color if is_last else None,
                    inherit_permissions=inherit_permissions,
                )
                check_result(result, 'keeper-drive-mkdir')

            created_uid = result['folder_uid']
            created_folders.append(created_uid)
            params.sync_data = True

            if i < len(folder_parts) - 1:
                from keepercommander import api as comm_api
                comm_api.sync_down(params)
            current_parent_uid = created_uid

        return created_folders[-1] if created_folders else None

    @staticmethod
    def _parse_path(folder_path, create_parents):
        if '/' not in folder_path:
            return [folder_path]
        is_slash = False
        for x in range(len(folder_path) - 1):
            if folder_path[x] == '/':
                is_slash = not is_slash
            else:
                if is_slash and not create_parents:
                    raise CommandError('keeper-drive-mkdir',
                                       'Character "/" is reserved. Use "//" inside folder name')
        parts = folder_path.replace('//', '\x00').split('/')
        result = [p.replace('\x00', '/') for p in parts if p]
        if not result:
            raise CommandError('keeper-drive-mkdir', 'Invalid folder path')
        return result

    @staticmethod
    def _find_existing_child(params, folder_name, parent_uid):
        kd_folders = getattr(params, 'keeper_drive_folders', {})
        name_lower = folder_name.lower()
        expected_parent = parent_uid or ''
        for fuid, fobj in kd_folders.items():
            if fobj.get('name', '').lower() != name_lower:
                continue
            existing_parent = normalize_parent_uid(fobj.get('parent_uid', ''))
            if existing_parent == 'root':
                existing_parent = ''
            if existing_parent == expected_parent:
                return fuid
        return None


# ══════════════════════════════════════════════════════════════════════════
# kd-rndir
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveUpdateFolderCommand(Command):
    """Rename or recolor a KeeperDrive folder."""

    def get_parser(self):
        return keeper_drive_update_folder_parser

    def execute(self, params, **kwargs):
        folder_arg = kwargs.get('folder')
        if not folder_arg:
            raise CommandError('kd-rndir', 'Enter the path or UID of existing folder.')

        new_name = kwargs.get('folder_name')
        color = kwargs.get('color')

        if new_name is not None:
            new_name = new_name.strip()
            if not new_name:
                raise CommandError('kd-rndir', 'Folder name cannot be empty')

        inherit_permissions = None
        if kwargs.get('inherit_permissions'):
            inherit_permissions = True
        elif kwargs.get('no_inherit_permissions'):
            inherit_permissions = False

        if new_name is None and color is None and inherit_permissions is None:
            raise CommandError('kd-rndir', 'New folder name and/or color parameters are required.')

        with command_error_handler('kd-rndir'):
            result = _kd.update_folder_v3(
                params=params, folder_uid=folder_arg, folder_name=new_name,
                color=color, inherit_permissions=inherit_permissions,
            )
            check_result(result, 'kd-rndir')
            params.sync_data = True
            if not kwargs.get('quiet'):
                kd_folders = getattr(params, 'keeper_drive_folders', {})
                resolved_uid = result.get('folder_uid', folder_arg)
                folder_display_name = kd_folders.get(resolved_uid, {}).get('name', folder_arg)
                if new_name:
                    logging.info('Folder "%s" has been renamed to "%s"', folder_display_name, new_name)
                elif color:
                    logging.info('Folder "%s" color has been updated', folder_display_name)
                else:
                    logging.info('Folder "%s" has been updated', folder_display_name)


# ══════════════════════════════════════════════════════════════════════════
# kd-list
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveListCommand(Command):
    """List Keeper Drive folders and records."""

    def get_parser(self):
        return keeper_drive_list_parser

    def execute(self, params, **kwargs):
        from keepercommander.commands import base

        show_folders = kwargs.get('folders', False)
        show_records = kwargs.get('records', False)
        verbose = kwargs.get('verbose', False)
        fmt = kwargs.get('format', 'table')

        if not show_folders and not show_records:
            show_folders = show_records = True

        combined = []
        if show_folders:
            combined.extend(self._collect_folders(params))
        if show_records:
            combined.extend(self._collect_records(params))

        if not combined:
            self._print_empty_summary(params, show_folders, show_records)
            return

        combined.sort(key=lambda x: (x[0], (x[2] or '').lower()))
        if verbose or fmt in ('json', 'csv'):
            headers = ['Item Type', 'UID', 'Title', 'Type', 'Description', 'Shared', 'Parent/Folder']
        else:
            combined = [row[:6] for row in combined]
            headers = ['Item Type', 'UID', 'Title', 'Type', 'Description', 'Shared']
        if fmt != 'json':
            headers = [base.field_to_title(x) for x in headers]
        return base.dump_report_data(
            combined, headers, fmt=fmt, filename=kwargs.get('output'),
            row_number=True, column_width=None if verbose else 40,
        )

    @staticmethod
    def _collect_folders(params):
        kd_folders = getattr(params, 'keeper_drive_folders', {})
        rows = []
        for folder_uid, fobj in kd_folders.items():
            title = fobj.get('name', 'Unnamed')
            parent_uid = normalize_parent_uid(fobj.get('parent_uid', ''))
            shared = 'No'
            accesses = getattr(params, 'keeper_drive_folder_accesses', {}).get(folder_uid)
            if accesses:
                from keepercommander.proto import folder_pb2
                at_owner = int(folder_pb2.AT_OWNER)
                non_owner = [a for a in accesses if int(a.get('access_type', 0)) != at_owner]
                if non_owner:
                    shared = f"Yes ({len(non_owner)})"
            rows.append(['Folder', folder_uid, title, '', '', shared, parent_uid])
        return rows

    @staticmethod
    def _collect_records(params):
        kd_records = getattr(params, 'keeper_drive_records', {})
        kd_record_data = getattr(params, 'keeper_drive_record_data', {})
        kd_folder_records = getattr(params, 'keeper_drive_folder_records', {})
        kd_folders = getattr(params, 'keeper_drive_folders', {})
        sharing_states = getattr(params, 'keeper_drive_record_sharing_states', {})
        record_accesses_map = getattr(params, 'keeper_drive_record_accesses', {})

        rows = []
        for record_uid in kd_records:
            title, rec_type, description = 'Unknown', 'Unknown', ''
            if record_uid in kd_record_data and 'data_json' in kd_record_data[record_uid]:
                dj = kd_record_data[record_uid]['data_json']
                title = dj.get('title', 'Unknown')
                rec_type = dj.get('type', 'Unknown')
                for field in dj.get('fields', []):
                    if field.get('type') in ('note', 'multiline'):
                        fv = field.get('value', [])
                        if isinstance(fv, list) and fv:
                            description = str(fv[0])
                            break

            shared = 'No'
            ss = sharing_states.get(record_uid)
            if ss and ss.get('is_directly_shared'):
                non_owner = [a for a in record_accesses_map.get(record_uid, [])
                             if not a.get('owner')]
                shared = f"Yes ({len(non_owner)})" if non_owner else "Yes"

            folder_location = ''
            for fuid, rec_set in kd_folder_records.items():
                if record_uid in rec_set:
                    folder_location = ('root' if fuid == ROOT_FOLDER_UID
                                       else kd_folders.get(fuid, {}).get('name', fuid))
                    break
            rows.append(['Record', record_uid, title, rec_type, description,
                         shared, folder_location or 'root'])
        return rows

    @staticmethod
    def _print_empty_summary(params, show_folders, show_records):
        if show_folders and show_records:
            logging.info("No Keeper Drive folders or records found in cache.")
        elif show_folders:
            logging.info("No Keeper Drive folders found in cache.")
        else:
            logging.info("No Keeper Drive records found in cache.")
        logging.info("\nSummary:")
        logging.info("  Keeper Drive folders: %d", len(getattr(params, 'keeper_drive_folders', {})))
        logging.info("  Keeper Drive records: %d", len(getattr(params, 'keeper_drive_records', {})))


# ══════════════════════════════════════════════════════════════════════════
# kd-share-folder   (Strategy pattern — grant / remove)
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveShareFolderCommand(Command):
    """Change the sharing permissions of a KeeperDrive folder."""

    def get_parser(self):
        return keeper_drive_share_folder_parser

    # Strategy dispatch table: action → (api_function, success_verb)
    _ACTIONS = {
        'grant':  ('grant_folder_access_v3',  'added'),
        'remove': ('revoke_folder_access_v3', 'removed'),
    }

    def execute(self, params, **kwargs):
        action = kwargs.get('action') or 'grant'
        users = kwargs.get('user') or []
        folder_args = kwargs.get('folder') or []
        role = kwargs.get('role') or 'viewer'

        if not folder_args:
            raise CommandError('kd-share-folder', 'Folder path or UID is required')
        if not users:
            raise CommandError('kd-share-folder', 'Recipient email is required (use -e / --email)')

        expiration = parse_expiration(
            kwargs.get('expire_at'), kwargs.get('expire_in'), 'kd-share-folder')

        for folder_arg in folder_args:
            folder_uid = resolve_folder_uid(params, folder_arg)
            if not folder_uid:
                raise CommandError('kd-share-folder', f'No such folder: {folder_arg!r}')
            for email in users:
                targets = self._expand_users(params, email, folder_uid, folder_arg)
                if targets is None:
                    continue
                for target in targets:
                    self._apply(params, action, folder_uid, target, role, expiration)

    @staticmethod
    def _expand_users(params, email, folder_uid, folder_arg):
        if email not in ('@existing', '@current'):
            return [email]
        kd_folder = getattr(params, 'keeper_drive_folders', {}).get(folder_uid, {})
        result = [a.get('username') for a in kd_folder.get('accesses', [])
                  if a.get('username') and a.get('username') != params.user]
        if not result:
            logging.info("No existing users found in folder '%s'", folder_arg)
            return None
        return result

    @classmethod
    def _apply(cls, params, action, folder_uid, email, role, expiration):
        api_name, verb = cls._ACTIONS[action]
        api_func = getattr(_kd, api_name)
        kw = dict(params=params, folder_uid=folder_uid, user_uid=email)
        if action != 'remove':
            kw['role'] = role
        if action == 'grant' and expiration is not None:
            kw['expiration_timestamp'] = expiration
        try:
            result = api_func(**kw)
            if result['success']:
                taken = result.get('action_taken', verb)
                if taken == 'already_had_access':
                    logging.info("User '%s' already has access", email)
                else:
                    logging.info("User share '%s' %s", email, verb)
            else:
                logging.warning("User share '%s' failed", email)
        except ValueError:
            logging.warning('User %s not found', email)
        except Exception as e:
            raise CommandError('kd-share-folder', str(e))


# ══════════════════════════════════════════════════════════════════════════
# kd-folder-access
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveGetFolderAccessCommand(Command):
    """Retrieve accessors (users and teams) of Keeper Drive folders."""

    def get_parser(self):
        return keeper_drive_get_folder_access_parser

    def execute(self, params, **kwargs):
        from keepercommander.display import dump_report_data

        folders = kwargs.get('folder_uids', [])
        verbose = kwargs.get('verbose', False)

        if not folders:
            raise CommandError('kd-folder-access', 'At least one folder must be specified')
        if len(folders) > 100:
            raise CommandError('kd-folder-access', 'Maximum 100 folders can be queried at once')

        with command_error_handler('kd-folder-access'):
            result = _kd.get_folder_access_v3(params, folder_uids=folders)
            for fr in result['results']:
                folder_uid = fr['folder_uid']
                label = getattr(params, 'keeper_drive_folders', {}).get(
                    folder_uid, {}).get('name', folder_uid)

                if not fr['success']:
                    err = fr['error']
                    logging.error("\nFolder '%s': %s — %s", label, err['status'], err['message'])
                    continue

                accessors = fr['accessors']
                print(f"\n{'='*72}")
                print(f"  Folder: {label}  [{folder_uid}]")
                print(f"{'='*72}")

                if not accessors:
                    print("  No accessors found")
                    continue

                if not verbose:
                    rows = [[a.get('username') or a['accessor_uid'],
                             a.get('access_type', ''), a.get('role', ''),
                             '\u2713' if a.get('inherited') else '']
                            for a in accessors]
                    dump_report_data(rows, ['Accessor', 'Type', 'Role', 'Inherited'],
                                     title=None, row_number=True)
                else:
                    self._print_verbose(accessors)

            print(f"\n{'='*72}\n")

    @staticmethod
    def _print_verbose(accessors):
        for a in accessors:
            label = a.get('username') or a['accessor_uid']
            role = a.get('role', 'UNKNOWN')
            print(f"\n  Accessor : {label}  [{a.get('access_type', '')}]")
            print(f"  Role     : {role}" + ('  (inherited)' if a.get('inherited') else ''))
            if a.get('date_created'):
                print(f"  Created  : {format_timestamp(a['date_created'])}")
            if a.get('last_modified'):
                print(f"  Modified : {format_timestamp(a['last_modified'])}")
            perms = a.get('permissions', {})
            if perms:
                print(f"  {'Permission':<26}  Value")
                print(f"  {'-'*26}  -----")
                for flag, lbl in FOLDER_PERM_LABELS:
                    print(f"  {lbl:<26}  {'Y' if perms.get(flag) else 'N'}")


# ══════════════════════════════════════════════════════════════════════════
# kd-rmdir
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveRemoveFolderCommand(Command):
    """Remove one or more KeeperDrive folders."""

    def get_parser(self):
        return kd_rmdir_parser

    def execute(self, params, **kwargs):
        folder_args = kwargs.get('folders') or []
        operation   = kwargs.get('operation', 'folder-trash')
        force       = kwargs.get('force', False)
        dry_run     = kwargs.get('dry_run', False)
        quiet       = kwargs.get('quiet', False)

        if not folder_args:
            raise CommandError('kd-rmdir', 'Enter the name or UID of at least one folder.')

        removals = []
        for identifier in folder_args:
            folder_uid = _kd.resolve_kd_folder_uid(params, identifier)
            if not folder_uid:
                raise CommandError('kd-rmdir', f"Folder '{identifier}' not found")
            removals.append({'folder_uid': folder_uid, 'operation_type': operation})

        if len(removals) > 100:
            raise CommandError('kd-rmdir', 'Maximum 100 folders per invocation')

        if operation == 'delete-permanent' and not force and not dry_run:
            print(
                '\n  *** WARNING ***\n'
                '  --operation delete-permanent is IRREVERSIBLE.\n'
                '  All sub-folders and records inside will be permanently destroyed.\n')

        with command_error_handler('kd-rmdir'):
            self._preview_and_confirm(params, removals, operation, force, dry_run, quiet)

    def _preview_and_confirm(self, params, removals, operation, force, dry_run, quiet):
        result = _kd.remove_folder_v3(params, removals, dry_run=True)
        any_error = False
        error_lines = []
        summary_lines = []

        for pr in result['preview_results']:
            name = self._folder_name(params, pr['folder_uid'])
            if pr.get('error'):
                any_error = True
                err = pr['error']
                error_lines.append(
                    f"  • {name} [{pr['folder_uid']}]: {err.get('code', '')} — {err.get('message', '')}"
                )
            else:
                summary_lines.extend(
                    self._impact_summary(pr['folder_uid'], name, operation, pr.get('impact'), quiet)
                )

        if summary_lines:
            for line in summary_lines:
                print(line)

        if any_error:
            print(f"\n{'[Dry-run] ' if dry_run else ''}The following folder(s) cannot be removed:")
            for line in error_lines:
                print(line)
            if not dry_run:
                print('\nAborting — fix the errors above before retrying.')
            return

        if dry_run:
            print('\n[Dry-run] No folders were deleted.')
            return

        if not force:
            from ..base import user_choice
            prompt = ('Do you want to permanently delete the folder(s) and all their contents?'
                      if operation == 'delete-permanent'
                      else 'Do you want to proceed with the folder deletion?')
            if user_choice(prompt, 'yn', default='n').lower() != 'y':
                return

        confirm_result = _kd.remove_folder_v3(params, removals, dry_run=False)
        if confirm_result['confirmed']:
            params.sync_data = True
        else:
            logging.warning('Folder removal was not confirmed by the server.')

    @staticmethod
    def _folder_name(params, folder_uid):
        kd = getattr(params, 'keeper_drive_folders', {})
        f = kd.get(folder_uid) or getattr(params, 'subfolder_cache', {}).get(folder_uid, {})
        return f.get('name') or folder_uid

    @staticmethod
    def _impact_summary(folder_uid, name, operation, impact, quiet):
        action = 'permanently deleted' if operation == 'delete-permanent' else 'moved to trash'
        lines = [f"\nThe following folder will be {action}:"]
        lines.append(f"  {name} [{folder_uid}]")
        if impact and not quiet:
            parts = []
            folders = impact.get('folders_count', 0)
            records = impact.get('records_count', 0)
            users = impact.get('affected_users_count', 0)
            teams = impact.get('affected_teams_count', 0)
            if folders:
                parts.append(f"{folders} sub-folder(s)")
            if records:
                parts.append(f"{records} record(s)")
            if users:
                parts.append(f"{users} user(s)")
            if teams:
                parts.append(f"{teams} team(s)")
            if parts:
                lines.append(f"  This will affect: {', '.join(parts)}")
            for w in impact.get('warnings', []):
                lines.append(f"  Warning: {w}")
        return lines
