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
KeeperDrive — record CRUD, linking, and removal commands.

Single Responsibility: every class here deals with record lifecycle
(create, update, link/unlink, shortcut management, delete).
"""

import logging
from typing import List

from ..base import Command, GroupCommand
from ..record_edit import RecordEditMixin, record_fields_description, ParsedFieldValue
from ...error import CommandError
from ... import keeper_drive as _kd, vault
from .helpers import (
    resolve_folder_uid, command_error_handler, check_result,
    check_record_edit_permission, check_record_delete_permission,
)
from .parsers import (
    keeper_drive_add_record_parser,
    keeper_drive_update_record_parser,
    keeper_drive_ln_parser,
    kd_shortcut_list_parser,
    kd_shortcut_keep_parser,
    kd_rm_parser,
)


# ══════════════════════════════════════════════════════════════════════════
# kd-record-add
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveAddRecordCommand(Command, RecordEditMixin):
    """Create a KeeperDrive record, matching ``record-add`` behaviour."""

    def __init__(self):
        super().__init__()

    def get_parser(self):
        return keeper_drive_add_record_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            print(record_fields_description)
            return

        title = kwargs.get('title')
        if not title:
            raise CommandError('kd-record-add', 'Title parameter is required.')
        record_type = kwargs.get('record_type')
        if not record_type:
            raise CommandError('kd-record-add', 'Record type parameter is required.')

        notes = kwargs.get('notes')
        record_fields, add_attachments = self._parse_fields(kwargs.get('fields', []))
        folder_uid = self._resolve_folder(params, kwargs.get('folder_uid'))
        self.warnings.clear()

        data = self._build_record_data(params, record_type, title, notes, record_fields)

        if self.warnings:
            for w in self.warnings:
                logging.warning(w)
            if not kwargs.get('force'):
                return

        if add_attachments:
            logging.warning('File attachments are not yet supported in kd-record-add. '
                            'Use record-add for attachment support.')
            if not kwargs.get('force'):
                return

        with command_error_handler('kd-record-add'):
            result = _kd.create_record_v3(params=params, folder_uid=folder_uid, record_data=data)
            check_result(result, 'kd-record-add')
            params.sync_data = True
            return result['record_uid']

    def _parse_fields(self, raw_fields):
        fields = [f.strip() for f in raw_fields if f.strip()]
        record_fields = []
        attachments = []
        for field in fields:
            parsed = RecordEditMixin.parse_field(field)
            (attachments if parsed.type == 'file' else record_fields).append(parsed)
        return record_fields, attachments

    @staticmethod
    def _resolve_folder(params, folder_input):
        if not folder_input:
            return None
        uid = resolve_folder_uid(params, folder_input)
        if uid is None:
            raise CommandError('kd-record-add', f'No such folder: {folder_input}')
        return uid

    def _build_record_data(self, params, record_type, title, notes, record_fields):
        if record_type in ('legacy', 'general'):
            record = vault.PasswordRecord()
            self.assign_legacy_fields(record, record_fields)
            record.title = title
            record.notes = self.validate_notes(notes or '')
            return self._legacy_to_data(record, title, notes)

        rt_fields = self.get_record_type_fields(params, record_type)
        if not rt_fields:
            raise CommandError('kd-record-add', f'Record type "{record_type}" cannot be found.')
        record = vault.TypedRecord()
        record.type_name = record_type
        for rf in rt_fields:
            ref = rf.get('$ref')
            if not ref:
                continue
            default_value = rf.get('appFillerData') if ref == 'appFiller' else None
            field = vault.TypedField.new_field(ref, default_value, rf.get('label', ''))
            if rf.get('required'):
                field.required = True
            record.fields.append(field)
        self.assign_typed_fields(record, record_fields)
        record.title = title
        record.notes = self.validate_notes(notes or '')
        return self._typed_to_data(record, title, notes)

    @staticmethod
    def _typed_to_data(record, title, notes=None):
        data = {
            'type': record.type_name, 'title': title,
            'fields': [{'type': f.type, 'label': f.label or '', 'value': list(f.value)}
                        for f in record.fields],
            'custom': [{'type': f.type, 'label': f.label or '', 'value': list(f.value)}
                        for f in record.custom],
        }
        if notes:
            data['notes'] = notes
        return data

    @staticmethod
    def _legacy_to_data(record, title, notes=None):
        data = {'type': record.get_record_type(), 'title': title, 'fields': []}
        for ftype, val in [('login', record.login), ('password', record.password),
                           ('url', record.link), ('oneTimeCode', record.totp)]:
            if val:
                data['fields'].append({'type': ftype, 'value': [val]})
        for cf in (record.custom or []):
            data['fields'].append({
                'type': 'text',
                'label': cf.name if hasattr(cf, 'name') else '',
                'value': [cf.value if hasattr(cf, 'value') else str(cf)],
            })
        if notes:
            data['notes'] = notes
        return data


# ══════════════════════════════════════════════════════════════════════════
# kd-record-update
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveUpdateRecordCommand(Command, RecordEditMixin):
    """Update a KeeperDrive record."""

    def __init__(self):
        super().__init__()

    def get_parser(self):
        return keeper_drive_update_record_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            print(record_fields_description)
            return

        record_uids = kwargs.get('record_uids') or []
        if not record_uids:
            raise CommandError('kd-record-update', 'Record UID is required (use -r or --record)')

        record_type = kwargs.get('record_type')
        if record_type and record_type not in ('legacy', 'general'):
            rt_fields = self.get_record_type_fields(params, record_type)
            if not rt_fields:
                raise CommandError('kd-record-update', f'Record type "{record_type}" cannot be found.')

        fields = {}
        for spec in [f.strip() for f in kwargs.get('fields', []) if f.strip()]:
            try:
                parsed = RecordEditMixin.parse_field(spec)
                if parsed.type in fields:
                    existing = fields[parsed.type]
                    fields[parsed.type] = ([existing] if not isinstance(existing, list)
                                           else existing) + [parsed.value]
                else:
                    fields[parsed.type] = parsed.value
            except ValueError as e:
                raise CommandError('kd-record-update', f'Invalid field specification: {e}')

        with command_error_handler('kd-record-update'):
            for identifier in record_uids:
                record_uid = _kd.resolve_kd_record_uid(params, identifier)
                if not record_uid:
                    raise CommandError('kd-record-update',
                                       f"Record '{identifier}' not found")
                check_record_edit_permission(params, record_uid, 'kd-record-update')
                result = _kd.update_record_v3(
                    params=params, record_uid=record_uid,
                    title=kwargs.get('title'), record_type=record_type,
                    fields=fields or None, notes=kwargs.get('notes'),
                )
                check_result(result, 'kd-record-update')
            params.sync_data = True


# ══════════════════════════════════════════════════════════════════════════
# kd-ln
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveLnCommand(Command):
    """Create a link between a record and a KeeperDrive folder (positional: RECORD FOLDER)."""

    def get_parser(self):
        return keeper_drive_ln_parser

    def execute(self, params, **kwargs):
        src, dst = kwargs.get('src'), kwargs.get('dst')
        if not src or not dst:
            self.get_parser().print_help()
            return
        record_uid = _kd.resolve_kd_record_uid(params, src)
        if not record_uid:
            raise CommandError('kd-ln', f"Record '{src}' not found")
        folder_uid = resolve_folder_uid(params, dst)
        if not folder_uid:
            raise CommandError('kd-ln', f"Folder '{dst}' not found")
        with command_error_handler('kd-ln'):
            result = _kd.add_record_to_folder_v3(params, folder_uid=folder_uid, record_uid=record_uid)
            check_result(result, 'kd-ln')
            params.sync_data = True


# ══════════════════════════════════════════════════════════════════════════
# kd-shortcut
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveShortcutCommand(GroupCommand):
    """Manage KeeperDrive record shortcuts (records linked to multiple folders)."""

    def __init__(self):
        super().__init__()
        self.register_command('list', KeeperDriveShortcutListCommand(), 'List multi-folder records')
        self.register_command('keep', KeeperDriveShortcutKeepCommand(),
                              'Keep record in one folder, remove from others')
        self.default_verb = 'list'

    @staticmethod
    def get_record_shortcuts(params):
        """Return ``{record_uid: set(folder_uids)}`` for records in 2+ folders."""
        records = {}
        for folder_uid, rec_set in getattr(params, 'keeper_drive_folder_records', {}).items():
            for record_uid in rec_set:
                records.setdefault(record_uid, set()).add(folder_uid)
        return {k: v for k, v in records.items() if len(v) > 1}


class KeeperDriveShortcutListCommand(Command):
    """List KeeperDrive records that appear in more than one folder."""

    def get_parser(self):
        return kd_shortcut_list_parser

    def execute(self, params, **kwargs):
        records = KeeperDriveShortcutCommand.get_record_shortcuts(params)
        target = kwargs.get('target')

        kd_records = getattr(params, 'keeper_drive_records', {})
        kd_folders = getattr(params, 'keeper_drive_folders', {})

        to_show = self._resolve_target(params, target, records, kd_records, kd_folders) \
            if target else set(records.keys())

        if not to_show:
            logging.info('No KeeperDrive shortcut records found')
            return

        fmt = kwargs.get('format') or 'table'
        table = []
        for record_uid in sorted(to_show):
            title = kd_records.get(record_uid, {}).get('title', record_uid)
            folder_names = []
            for fuid in sorted(records[record_uid]):
                fname = kd_folders.get(fuid, {}).get('name', fuid)
                folder_names.append({'folder_uid': fuid, 'name': fname} if fmt == 'json'
                                    else f'{fname} ({fuid})')
            table.append([record_uid, title, folder_names])

        headers = (['record_uid', 'record_title', 'folders'] if fmt == 'json'
                    else ['Record UID', 'Record Title', 'Folders'])
        from ..base import dump_report_data
        return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))

    @staticmethod
    def _resolve_target(params, target, records, kd_records, kd_folders):
        to_show = set()
        if target in kd_records:
            if target not in records:
                raise CommandError('kd-shortcut list', f'Record UID {target} does not have shortcuts')
            return {target}

        lower = target.casefold()
        for uid, rec in kd_records.items():
            if rec.get('title', '').casefold() == lower:
                if uid not in records:
                    raise CommandError('kd-shortcut list', f'Record "{target}" does not have shortcuts')
                return {uid}

        resolved_folder = _kd.resolve_folder_identifier(params, target)
        if resolved_folder:
            return {r for r in records if resolved_folder in records[r]}

        raise CommandError('kd-shortcut list',
                           f'Target "{target}" is not a known record UID, title, or folder path')


class KeeperDriveShortcutKeepCommand(Command):
    """Keep a KeeperDrive record in exactly one folder, removing it from all others."""

    def get_parser(self):
        return kd_shortcut_keep_parser

    def execute(self, params, **kwargs):
        target = kwargs.get('target')
        if not target:
            self.get_parser().print_help()
            return

        force = kwargs.get('force', False)
        kd_records = getattr(params, 'keeper_drive_records', {})
        kd_folders = getattr(params, 'keeper_drive_folders', {})

        record_uid = self._resolve_record(target, kd_records)
        keep_folder_uid = self._resolve_keep_folder(params, kwargs.get('folder'), kd_folders)

        records = KeeperDriveShortcutCommand.get_record_shortcuts(params)
        if record_uid not in records:
            raise CommandError('kd-shortcut keep',
                               f'Record "{target}" does not appear in multiple folders')
        if keep_folder_uid not in records[record_uid]:
            fname = kd_folders.get(keep_folder_uid, {}).get('name', keep_folder_uid)
            raise CommandError('kd-shortcut keep', f'Record "{target}" is not in folder "{fname}"')

        folders_to_remove = [f for f in records[record_uid] if f != keep_folder_uid]
        if not folders_to_remove:
            logging.info('Nothing to do — record is already in only one folder.')
            return

        if not force:
            lines = [f'  Will remove record "{target}" ({record_uid}) from:']
            for fuid in folders_to_remove:
                lines.append(f'    - {kd_folders.get(fuid, {}).get("name", fuid)} ({fuid})')
            keep_name = kd_folders.get(keep_folder_uid, {}).get('name', keep_folder_uid)
            lines.append(f'  Keeping in: {keep_name} ({keep_folder_uid})')
            print('\n'.join(lines))
            from ..base import user_choice
            if user_choice('Do you want to proceed with deletion?', 'yn', default='n').lower() != 'y':
                return

        errors = []
        for fuid in folders_to_remove:
            try:
                result = _kd.remove_record_from_folder_v3(params, fuid, record_uid)
                if not result.get('success'):
                    errors.append(f'{fuid}: {result.get("message", "unknown error")}')
            except Exception as exc:
                errors.append(f'{fuid}: {exc}')

        if errors:
            raise CommandError('kd-shortcut keep', 'Some removals failed:\n' + '\n'.join(errors))

        params.sync_data = True
        keep_name = kd_folders.get(keep_folder_uid, {}).get('name', keep_folder_uid)
        logging.info('Record "%s" kept in "%s" and removed from %d other folder(s).',
                     target, keep_name, len(folders_to_remove))

    @staticmethod
    def _resolve_record(target, kd_records):
        if target in kd_records:
            return target
        lower = target.casefold()
        for uid, rec in kd_records.items():
            if rec.get('title', '').casefold() == lower:
                return uid
        raise CommandError('kd-shortcut keep', f'Record "{target}" not found in KeeperDrive')

    @staticmethod
    def _resolve_keep_folder(params, folder_arg, kd_folders):
        if folder_arg:
            uid = _kd.resolve_folder_identifier(params, folder_arg)
            if not uid:
                raise CommandError('kd-shortcut keep', f'Folder "{folder_arg}" not found')
            return uid
        current = getattr(params, 'current_folder', None)
        if current and current in kd_folders:
            return current
        raise CommandError('kd-shortcut keep',
                           'No folder specified and current folder is not a KeeperDrive folder.')


# ══════════════════════════════════════════════════════════════════════════
# kd-rm
# ══════════════════════════════════════════════════════════════════════════

class KeeperDriveRemoveRecordCommand(Command):
    """Remove (delete/unlink) one or more KeeperDrive records."""

    def get_parser(self):
        return kd_rm_parser

    def execute(self, params, **kwargs):
        record_args = kwargs.get('records') or []
        folder_arg = kwargs.get('folder_uid')
        operation = kwargs.get('operation', 'owner-trash')
        force = kwargs.get('force', False)
        dry_run = kwargs.get('dry_run', False)

        if not record_args:
            raise CommandError('kd-rm', 'At least one record UID or title is required')
        if operation == 'unlink' and not folder_arg:
            raise CommandError('kd-rm', '--folder is required when --operation is "unlink"')

        folder_uid = None
        if folder_arg:
            folder_uid = _kd.resolve_folder_identifier(params, folder_arg)
            if not folder_uid:
                raise CommandError('kd-rm', f"Folder '{folder_arg}' not found")

        removals = self._build_removals(params, record_args, folder_uid, operation)
        if len(removals) > 500:
            raise CommandError('kd-rm', 'Maximum 500 records per invocation')

        with command_error_handler('kd-rm'):
            self._preview_and_confirm(params, removals, operation, force, dry_run)

    def _build_removals(self, params, record_args, folder_uid, operation):
        removals = []
        for identifier in record_args:
            record_uid = _kd.resolve_kd_record_uid(params, identifier)
            if not record_uid:
                raise CommandError('kd-rm', f"Record '{identifier}' not found")
            check_record_delete_permission(params, record_uid, 'kd-rm')
            ctx_folder = folder_uid
            if not ctx_folder:
                folders = _kd.find_kd_folders_for_record(params, record_uid)
                if not folders and operation != 'owner-trash':
                    raise CommandError('kd-rm',
                                       f"No folder context for record '{identifier}'. "
                                       f"Use --folder or --operation owner-trash.")
                ctx_folder = folders[0] if folders else None
            removals.append({
                'record_uid': record_uid,
                'folder_uid': ctx_folder,
                'operation_type': operation,
            })
        return removals

    def _preview_and_confirm(self, params, removals, operation, force, dry_run):
        result = _kd.remove_record_v3(params, removals, dry_run=True)
        any_error = False
        summary_lines = []

        for pr in result['preview_results']:
            title = self._record_title(params, pr['record_uid'])
            if pr.get('error'):
                any_error = True
                err = pr['error']
                summary_lines.append(
                    f"  {title} [{pr['record_uid']}]: "
                    f"{err.get('code', '')} — {err.get('message', '')}"
                )
            else:
                summary_lines.extend(
                    self._impact_summary(pr['record_uid'], title, operation, pr.get('impact'))
                )

        for line in summary_lines:
            print(line)

        if any_error:
            print('\nOne or more records could not be previewed. Aborting.')
            return
        if dry_run:
            print('\n[Dry-run] No records were deleted.')
            return
        if not force:
            from ..base import user_choice
            if user_choice('Do you want to proceed with deletion?', 'yn', default='n').lower() != 'y':
                return

        confirm_result = _kd.remove_record_v3(params, removals, dry_run=False)
        if confirm_result['confirmed']:
            params.sync_data = True
        else:
            logging.warning('Record removal was not confirmed by the server.')

    @staticmethod
    def _record_title(params, record_uid):
        return getattr(params, 'keeper_drive_records', {}).get(
            record_uid, {}).get('title') or record_uid

    @staticmethod
    def _impact_summary(record_uid, title, operation, impact):
        lines = [f"\nThe following record will be {operation}:"]
        lines.append(f"  {title} [{record_uid}]")
        if impact:
            folders = impact.get('folders_count', 0)
            records = impact.get('records_count', 0)
            users = impact.get('affected_users_count', 0)
            teams = impact.get('affected_teams_count', 0)
            parts = []
            if folders:
                parts.append(f"{folders} folder(s)")
            if records:
                parts.append(f"{records} record(s)")
            if users:
                parts.append(f"{users} user(s)")
            if teams:
                parts.append(f"{teams} team(s)")
            if parts:
                lines.append(f"  This will affect: {', '.join(parts)}")
            for ri in impact.get('record_info', []):
                if ri.get('locations_count', 0) > 1:
                    lines.append(
                        f"  Note: record exists in {ri['locations_count']} folder locations"
                    )
            for w in impact.get('warnings', []):
                lines.append(f"  Warning: {w}")
        return lines
