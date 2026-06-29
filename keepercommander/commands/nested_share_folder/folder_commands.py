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
Nested Share Folder — folder management commands.

Single Responsibility: every class in this module deals with *folder*
operations only (create, rename, remove, list, share, access).
"""

import logging

from ..base import Command
from ...error import CommandError
from ...recordv3 import RecordV3
from ... import nested_share_folder as _nsf
from .helpers import (
    ROOT_FOLDER_UID,
    normalize_parent_uid, resolve_folder_uid, parse_expiration,
    command_error_handler, check_result,
    check_folder_edit_permission, check_folder_share_permission, check_folder_delete_permission,
    classify_share_recipient,
    ensure_nested_share_folder,
)
from .parsers import (
    nested_share_folder_mkdir_parser,
    nested_share_folder_update_parser,
    nested_share_folder_list_parser,
    nested_share_folder_share_parser,
    nested_share_folder_rmdir_parser,
)


# ══════════════════════════════════════════════════════════════════════════
# nsf-mkdir
# ══════════════════════════════════════════════════════════════════════════

class NestedShareFolderMkdirCommand(Command):
    """Create a Nested Share Folder using the v3 API."""

    def get_parser(self):
        return nested_share_folder_mkdir_parser

    def execute(self, params, **kwargs):
        folder_path = (kwargs.get('folder') or '').strip()
        if not folder_path:
            raise CommandError('nsf-mkdir', 'Folder name is required')

        color = kwargs.get('color')
        inherit_permissions = not kwargs.get('no_inherit_permissions', False)

        base_folder_uid = None
        current = getattr(params, 'current_folder', None)
        if current and current in getattr(params, 'nested_share_folders', {}):
            base_folder_uid = current

        segments = self._parse_path(folder_path)
        self._validate_name_only_path(segments)

        parent_uid = base_folder_uid
        last_idx = len(segments) - 1
        created_uid = None

        for idx, segment in enumerate(segments):
            is_leaf = (idx == last_idx)
            existing_uid = self._find_existing_child(params, segment, parent_uid)
            if existing_uid:
                if is_leaf:
                    logging.warning('nsf-mkdir: Folder "%s" already exists', segment)
                    return existing_uid
                parent_uid = existing_uid
                continue

            seg_color = color if is_leaf else None
            seg_inherit = inherit_permissions if is_leaf else True

            with command_error_handler('nsf-mkdir'):
                result = _nsf.create_folder_v3(
                    params=params, folder_name=segment,
                    parent_uid=parent_uid,
                    color=seg_color,
                    inherit_permissions=seg_inherit,
                )
                check_result(result, 'nsf-mkdir')

            created_uid = result['folder_uid']
            self._cache_new_folder(
                params, created_uid, segment, parent_uid,
                folder_key=result.get('folder_key_unencrypted'))

            if not is_leaf:
                logging.debug('nsf-mkdir: Created intermediate folder "%s"', segment)
            parent_uid = created_uid

        params.sync_data = True
        return created_uid

    @staticmethod
    def _parse_path(folder_path):
        """Split *folder_path* into a list of segment names.
        """
        sentinel = '\x00'
        collapsed = folder_path.replace('//', sentinel)
        raw_segments = collapsed.split('/')
        segments = []
        for raw in raw_segments:
            name = raw.replace(sentinel, '/').strip()
            if name:
                segments.append(name)
        if not segments:
            raise CommandError('nsf-mkdir', 'Invalid folder name')
        return segments

    @staticmethod
    def _validate_name_only_path(segments):
        """Reject UID segments in parent path positions.

        ``nsf-mkdir`` accepts name-based paths only (e.g. ``Engineering/Project``),
        matching legacy ``mkdir`` documentation. UIDs are not valid path segments.
        """
        for segment in segments[:-1]:
            if RecordV3.is_valid_ref_uid(segment):
                raise CommandError(
                    'nsf-mkdir',
                    f'Folder path must use folder names only, not UIDs: "{segment}"')

    @staticmethod
    def _cache_new_folder(params, folder_uid, name, parent_uid, folder_key=None):
        """Insert a just-created folder into the local NSF cache so that
        subsequent segments in the same path can discover it as a parent
        without requiring a full sync round-trip.
        """
        nsf = getattr(params, 'nested_share_folders', None)
        if nsf is None:
            return
        entry = {
            'name': name,
            'parent_uid': parent_uid or '',
        }
        if folder_key:
            entry['folder_key_unencrypted'] = folder_key
        nsf[folder_uid] = entry

    @staticmethod
    def _find_existing_child(params, folder_name, parent_uid):
        """Find an existing NSF folder named *folder_name* whose parent matches
        *parent_uid*. ``parent_uid=None`` means "root level".
        """
        nsf_folders = getattr(params, 'nested_share_folders', {})
        name_lower = folder_name.lower()
        looking_for_root = not parent_uid
        for fuid, fobj in nsf_folders.items():
            if fobj.get('name', '').lower() != name_lower:
                continue
            raw_parent = fobj.get('parent_uid') or ''
            normalized = normalize_parent_uid(raw_parent)
            is_root_child = (
                normalized in ('', 'root')
                or (raw_parent and raw_parent not in nsf_folders)
            )
            if looking_for_root:
                if is_root_child:
                    return fuid
            else:
                if raw_parent == parent_uid:
                    return fuid
        return None


# ══════════════════════════════════════════════════════════════════════════
# nsf-rndir
# ══════════════════════════════════════════════════════════════════════════

class NestedShareFolderUpdateCommand(Command):
    """Rename or recolor a Nested Share Folder."""

    def get_parser(self):
        return nested_share_folder_update_parser

    def execute(self, params, **kwargs):
        folder_arg = kwargs.get('folder')
        if not folder_arg:
            raise CommandError('nsf-rndir', 'Enter the path or UID of existing folder.')

        new_name = kwargs.get('folder_name')
        color = kwargs.get('color')

        if new_name is not None:
            new_name = new_name.strip()
            if not new_name:
                raise CommandError('nsf-rndir', 'Folder name cannot be empty')

        if new_name is None and color is None:
            raise CommandError('nsf-rndir', 'New folder name and/or color parameters are required.')

        folder_uid = resolve_folder_uid(params, folder_arg)
        if folder_uid:
            ensure_nested_share_folder(params, folder_uid, 'nsf-rndir',
                                       identifier=folder_arg)
            check_folder_edit_permission(params, folder_uid, 'nsf-rndir')

        with command_error_handler('nsf-rndir'):
            result = _nsf.update_folder_v3(
                params=params, folder_uid=folder_arg, folder_name=new_name,
                color=color,
            )
            check_result(result, 'nsf-rndir')
            params.sync_data = True
            if not kwargs.get('quiet'):
                nsf_folders = getattr(params, 'nested_share_folders', {})
                resolved_uid = result.get('folder_uid', folder_arg)
                folder_display_name = nsf_folders.get(resolved_uid, {}).get('name', folder_arg)
                if new_name:
                    logging.info('Folder "%s" has been renamed to "%s"', folder_display_name, new_name)
                elif color:
                    logging.info('Folder "%s" color has been updated', folder_display_name)
                else:
                    logging.info('Folder "%s" has been updated', folder_display_name)


# ══════════════════════════════════════════════════════════════════════════
# nsf-list
# ══════════════════════════════════════════════════════════════════════════

class NestedShareFolderListCommand(Command):
    """List Nested Share Folder folders and records."""

    def get_parser(self):
        return nested_share_folder_list_parser

    def execute(self, params, **kwargs):
        from keepercommander.commands import base

        show_folders = kwargs.get('folders', False)
        show_records = kwargs.get('records', False)
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
        if fmt in ('json', 'csv'):
            headers = ['Item Type', 'UID', 'Title', 'Type', 'Description', 'Parent/Folder']
        else:
            combined = [row[:5] for row in combined]
            headers = ['Item Type', 'UID', 'Title', 'Type', 'Description']
        if fmt != 'json':
            headers = [base.field_to_title(x) for x in headers]
        return base.dump_report_data(
            combined, headers, fmt=fmt, filename=kwargs.get('output'),
            row_number=True, column_width=40,
        )

    @staticmethod
    def _collect_folders(params):
        nsf_folders = getattr(params, 'nested_share_folders', {})
        rows = []
        for folder_uid, fobj in nsf_folders.items():
            title = fobj.get('name', 'Unnamed')
            parent_uid = normalize_parent_uid(fobj.get('parent_uid', ''))
            rows.append(['Folder', folder_uid, title, '', '', parent_uid])
        return rows

    @staticmethod
    def _collect_records(params):
        nsf_records = getattr(params, 'nested_share_records', {})
        nsf_record_data = getattr(params, 'nested_share_record_data', {})
        nsf_folder_records = getattr(params, 'nested_share_folder_records', {})
        nsf_folders = getattr(params, 'nested_share_folders', {})

        rows = []
        for record_uid in nsf_records:
            title, rec_type, description = 'Unknown', 'Unknown', ''
            if record_uid in nsf_record_data and 'data_json' in nsf_record_data[record_uid]:
                dj = nsf_record_data[record_uid]['data_json']
                title = dj.get('title', 'Unknown')
                rec_type = dj.get('type', 'Unknown')
                for field in dj.get('fields', []):
                    if field.get('type') in ('note', 'multiline'):
                        fv = field.get('value', [])
                        if isinstance(fv, list) and fv:
                            description = str(fv[0])
                            break

            folder_location = ''
            for fuid, rec_set in nsf_folder_records.items():
                if record_uid in rec_set:
                    folder_location = ('root' if fuid == ROOT_FOLDER_UID
                                       else nsf_folders.get(fuid, {}).get('name', fuid))
                    break
            rows.append(['Record', record_uid, title, rec_type, description,
                         folder_location or 'root'])
        return rows

    @staticmethod
    def _print_empty_summary(params, show_folders, show_records):
        if show_folders and show_records:
            logging.info("No Nested Share Folder folders or records found in cache.")
        elif show_folders:
            logging.info("No Nested Share Folder folders found in cache.")
        else:
            logging.info("No Nested Share Folder records found in cache.")
        logging.info("\nSummary:")
        logging.info("  Nested Share Folder folders: %d", len(getattr(params, 'nested_share_folders', {})))
        logging.info("  Nested Share Folder records: %d", len(getattr(params, 'nested_share_records', {})))


# ══════════════════════════════════════════════════════════════════════════
# nsf-share-folder   (Strategy pattern — grant / remove)
# ══════════════════════════════════════════════════════════════════════════

class NestedShareFolderShareCommand(Command):
    """Change the sharing permissions of a Nested Share Folder."""

    def get_parser(self):
        return nested_share_folder_share_parser

    # Strategy dispatch table: action → (api_function, success_verb)
    _ACTIONS = {
        'grant':  ('grant_folder_access_v3',  'added'),
        'remove': ('revoke_folder_access_v3', 'removed'),
    }

    def execute(self, params, **kwargs):
        action = kwargs.get('action') or 'grant'
        recipients = kwargs.get('user') or []
        folder_args = kwargs.get('folder') or []
        role = kwargs.get('role') or 'viewer'

        if not folder_args:
            raise CommandError('nsf-share-folder', 'Folder path or UID is required')
        if not recipients:
            raise CommandError(
                'nsf-share-folder',
                'Recipient is required (use -e/--email; accepts an email, '
                'team name, team UID, or @existing)')

        expiration = parse_expiration(
            kwargs.get('expire_at'), kwargs.get('expire_in'), 'nsf-share-folder')

        for folder_arg in folder_args:
            folder_uid = resolve_folder_uid(params, folder_arg)
            if not folder_uid:
                raise CommandError('nsf-share-folder', f'No such folder: {folder_arg!r}')
            ensure_nested_share_folder(params, folder_uid, 'nsf-share-folder',
                                       identifier=folder_arg)
            check_folder_share_permission(params, folder_uid, 'nsf-share-folder')

            targets = self._collect_targets(params, recipients, folder_uid, folder_arg)
            for recipient, is_team in targets:
                self._apply(params, action, folder_uid, recipient, role,
                            expiration, as_team=is_team)

    @classmethod
    def _collect_targets(cls, params, recipients, folder_uid, folder_arg):
        """Resolve every ``-e`` value into a list of ``(identifier, is_team)`` tuples.

        Mirrors legacy ``share-folder``: each entry is auto-classified as a
        user (matching ``EMAIL_PATTERN``) or a team (matched against the
        share-objects / available-teams cache). ``@existing`` / ``@current``
        expands to all current users *and* teams in the folder (excluding
        the caller).
        """
        targets = []
        seen = set()

        def add(kind, ident):
            key = (kind, ident.casefold() if kind == 'user' else ident)
            if key in seen:
                return
            seen.add(key)
            targets.append((ident, kind == 'team'))

        for raw in recipients:
            if raw in ('@existing', '@current'):
                expanded = cls._expand_existing(params, folder_uid, folder_arg)
                if not expanded:
                    continue
                for kind, ident in expanded:
                    add(kind, ident)
                continue

            classified = classify_share_recipient(params, raw)
            if classified is None:
                continue
            kind, ident = classified
            add(kind, ident)

        return targets

    @staticmethod
    def _expand_existing(params, folder_uid, folder_arg):
        """Expand ``@existing`` / ``@current`` into all users and teams currently
        on the folder, excluding the caller. Mirrors legacy behaviour
        (``shared_folder_cache[...]['users']`` + ``['teams']`` union).
        """
        from keepercommander.proto import folder_pb2
        accesses = (getattr(params, 'nested_share_folder_accesses', {})
                    .get(folder_uid, []))
        at_user = int(folder_pb2.AT_USER)
        at_team = int(folder_pb2.AT_TEAM)

        result = []
        for a in accesses:
            access_type = int(a.get('access_type', 0) or 0)
            if access_type == at_user:
                username = a.get('username')
                if username and username != params.user:
                    result.append(('user', username))
            elif access_type == at_team:
                team_uid = a.get('access_type_uid')
                if team_uid:
                    result.append(('team', team_uid))

        if not result:
            logging.info("No existing users or teams found in folder '%s'", folder_arg)
            return None
        return result

    @classmethod
    def _apply(cls, params, action, folder_uid, recipient, role, expiration,
                as_team=False):
        api_name, verb = cls._ACTIONS[action]
        api_func = getattr(_nsf, api_name)
        kw = dict(params=params, folder_uid=folder_uid, user_uid=recipient,
                  as_team=as_team)
        if action != 'remove':
            kw['role'] = role
        if action == 'grant' and expiration is not None:
            kw['expiration_timestamp'] = expiration
        kind = 'Team' if as_team else 'User'
        try:
            result = api_func(**kw)
            if result['success']:
                taken = result.get('action_taken', verb)
                if taken == 'already_had_access':
                    logging.info("%s '%s' already has access", kind, recipient)
                else:
                    logging.info("%s share '%s' %s", kind, recipient, verb)
            else:
                logging.warning("%s share '%s' failed", kind, recipient)
        except ValueError as e:
            logging.warning("nsf-share-folder: %s", e)
        except Exception as e:
            raise CommandError('nsf-share-folder', str(e))


# ══════════════════════════════════════════════════════════════════════════
# nsf-rmdir
# ══════════════════════════════════════════════════════════════════════════

class NestedShareFolderRemoveCommand(Command):
    """Remove one or more Nested Share Folders."""

    def get_parser(self):
        return nested_share_folder_rmdir_parser

    def execute(self, params, **kwargs):
        folder_args = kwargs.get('folders') or []
        operation   = kwargs.get('operation', 'folder-trash')
        force       = kwargs.get('force', False)
        dry_run     = kwargs.get('dry_run', False)
        quiet       = kwargs.get('quiet', False)

        if not folder_args:
            raise CommandError('nsf-rmdir', 'Enter the name or UID of at least one folder.')

        removals = []
        for identifier in folder_args:
            folder_uid = _nsf.resolve_nested_share_folder_uid(params, identifier)
            if not folder_uid:
                raise CommandError('nsf-rmdir', f"Folder '{identifier}' not found")
            ensure_nested_share_folder(params, folder_uid, 'nsf-rmdir',
                                       identifier=identifier)
            check_folder_delete_permission(params, folder_uid, 'nsf-rmdir')
            removals.append({'folder_uid': folder_uid, 'operation_type': operation})

        if len(removals) > 100:
            raise CommandError('nsf-rmdir', 'Maximum 100 folders per invocation')

        if operation == 'delete-permanent' and not force and not dry_run:
            print(
                '\n  *** WARNING ***\n'
                '  --operation delete-permanent is IRREVERSIBLE.\n'
                '  All sub-folders and records inside will be permanently destroyed.\n')

        with command_error_handler('nsf-rmdir'):
            self._preview_and_confirm(params, removals, operation, force, dry_run, quiet)

    def _preview_and_confirm(self, params, removals, operation, force, dry_run, quiet):
        result = _nsf.remove_folder_v3(params, removals, dry_run=True)
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

        if summary_lines and (dry_run or not force):
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

        confirm_result = _nsf.remove_folder_v3(params, removals, dry_run=False)
        if confirm_result['confirmed']:
            params.sync_data = True
        else:
            logging.warning('Folder removal was not confirmed by the server.')

    @staticmethod
    def _folder_name(params, folder_uid):
        nsf = getattr(params, 'nested_share_folders', {})
        f = nsf.get(folder_uid) or getattr(params, 'subfolder_cache', {}).get(folder_uid, {})
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
