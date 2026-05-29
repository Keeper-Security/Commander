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
Nested Share Folder — record CRUD, linking, and removal commands.

Single Responsibility: every class here deals with record lifecycle
(create, update, link/unlink, shortcut management, delete).
"""

import logging
from typing import List

from ..base import Command, GroupCommand
from ..record_edit import RecordEditMixin, record_fields_description, ParsedFieldValue
from ...error import CommandError
from ... import nested_share_folder as _nsf, vault
from .helpers import (
    resolve_folder_uid, command_error_handler, check_result,
    check_record_edit_permission, check_record_delete_permission,
    ensure_nested_share_record, ensure_nested_share_folder,
    ROOT_FOLDER_UID,
)
from .parsers import (
    nested_share_record_add_parser,
    nested_share_record_update_parser,
    nested_share_record_ln_parser,
    nested_share_record_shortcut_list_parser,
    nested_share_record_shortcut_keep_parser,
    nested_share_record_rm_parser,
)


# ══════════════════════════════════════════════════════════════════════════
# nsf-record-add
# ══════════════════════════════════════════════════════════════════════════

class NestedShareRecordAddCommand(Command, RecordEditMixin):
    """Create a Nested Share Record, matching ``record-add`` behaviour."""

    def __init__(self):
        super().__init__()

    def get_parser(self):
        return nested_share_record_add_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            print(record_fields_description)
            return

        title = kwargs.get('title')
        if not title:
            raise CommandError('nsf-record-add', 'Title parameter is required.')
        record_type = kwargs.get('record_type')
        if not record_type:
            raise CommandError('nsf-record-add', 'Record type parameter is required.')

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
            logging.warning('File attachments are not yet supported in nsf-record-add. '
                            'Use record-add for attachment support.')
            if not kwargs.get('force'):
                return

        with command_error_handler('nsf-record-add'):
            result = _nsf.create_record_v3(params=params, folder_uid=folder_uid, record_data=data)
            check_result(result, 'nsf-record-add')
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
            raise CommandError('nsf-record-add', f'No such folder: {folder_input}')
        ensure_nested_share_folder(params, uid, 'nsf-record-add', identifier=folder_input)
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
            raise CommandError('nsf-record-add', f'Record type "{record_type}" cannot be found.')
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
# nsf-record-update
# ══════════════════════════════════════════════════════════════════════════

class NestedShareRecordUpdateCommand(Command, RecordEditMixin):
    """Update a Nested Share Record."""

    def __init__(self):
        super().__init__()

    def get_parser(self):
        return nested_share_record_update_parser

    def _resolve_field_value(self, parsed):
        raw = parsed.value
        if not raw:
            return raw

        action_params = []
        if self.is_json_value(raw, action_params):
            return action_params[0] if action_params else None
        action_params.clear()
        if self.is_generate_value(raw, action_params):
            if parsed.type == 'password':
                return self.generate_password(action_params)
            if parsed.type in ('oneTimeCode', 'otp'):
                return self.generate_totp_url()
            return raw
        action_params.clear()
        if self.is_base64_value(raw, action_params):
            return action_params[0] if action_params else None
        return raw

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            print(record_fields_description)
            return

        record_uids = kwargs.get('record_uids') or []
        if not record_uids:
            raise CommandError('nsf-record-update', 'Record UID is required (use -r or --record)')

        record_type = kwargs.get('record_type')
        if record_type and record_type not in ('legacy', 'general'):
            rt_fields = self.get_record_type_fields(params, record_type)
            if not rt_fields:
                raise CommandError('nsf-record-update', f'Record type "{record_type}" cannot be found.')

        fields = {}
        for spec in [f.strip() for f in kwargs.get('fields', []) if f.strip()]:
            try:
                parsed = RecordEditMixin.parse_field(spec)
                value = self._resolve_field_value(parsed)
                if value is None:
                    continue
                if parsed.type in fields:
                    existing = fields[parsed.type]
                    fields[parsed.type] = ([existing] if not isinstance(existing, list)
                                           else existing) + [value]
                else:
                    fields[parsed.type] = value
            except ValueError as e:
                raise CommandError('nsf-record-update', f'Invalid field specification: {e}')

        if self.warnings:
            for w in self.warnings:
                logging.warning(w)
            if not kwargs.get('force'):
                return

        with command_error_handler('nsf-record-update'):
            for identifier in record_uids:
                record_uid = _nsf.resolve_nested_share_record_uid(params, identifier)
                if not record_uid:
                    raise CommandError('nsf-record-update',
                                       f"Record '{identifier}' not found")
                ensure_nested_share_record(params, record_uid, 'nsf-record-update',
                                           identifier=identifier)
                check_record_edit_permission(params, record_uid, 'nsf-record-update')
                result = _nsf.update_record_v3(
                    params=params, record_uid=record_uid,
                    title=kwargs.get('title'), record_type=record_type,
                    fields=fields or None, notes=kwargs.get('notes'),
                )
                check_result(result, 'nsf-record-update')
            params.sync_data = True


# ══════════════════════════════════════════════════════════════════════════
# nsf-ln
# ══════════════════════════════════════════════════════════════════════════

class NestedShareRecordLnCommand(Command):
    """Create a link between a record and a Nested Share Folder (positional: RECORD FOLDER)."""

    def get_parser(self):
        return nested_share_record_ln_parser

    def execute(self, params, **kwargs):
        src, dst = kwargs.get('src'), kwargs.get('dst')
        if not src or not dst:
            self.get_parser().print_help()
            return
        record_uid = _nsf.resolve_nested_share_record_uid(params, src)
        if not record_uid:
            raise CommandError('nsf-ln', f"Record '{src}' not found")
        folder_uid = resolve_folder_uid(params, dst)
        if not folder_uid:
            raise CommandError('nsf-ln', f"Folder '{dst}' not found")
        ensure_nested_share_record(params, record_uid, 'nsf-ln', identifier=src)
        ensure_nested_share_folder(params, folder_uid, 'nsf-ln', identifier=dst)
        with command_error_handler('nsf-ln'):
            result = _nsf.add_record_to_folder_v3(params, folder_uid=folder_uid, record_uid=record_uid)
            check_result(result, 'nsf-ln')
            params.sync_data = True


# ══════════════════════════════════════════════════════════════════════════
# nsf-shortcut
# ══════════════════════════════════════════════════════════════════════════

class NestedShareRecordShortcutCommand(GroupCommand):
    """Manage Nested Share Record shortcuts (records linked to multiple folders)."""

    def __init__(self):
        super().__init__()
        self.register_command('list', NestedShareRecordShortcutListCommand(), 'List multi-folder records')
        self.register_command('keep', NestedShareRecordShortcutKeepCommand(),
                              'Keep record in one folder, remove from others')
        self.default_verb = 'list'

    @staticmethod
    def get_record_shortcuts(params):
        """Return ``{record_uid: set(folder_uids)}`` for records in 2+ folders.

        ``nested_share_folder_records`` can carry server-side virtual folder
        UIDs (e.g. shared-with-me containers) that have no real folder entry
        in ``nested_share_folders``. These cannot be resolved or modified, so
        they are filtered out — counting them would inflate shortcut totals
        and break ``nsf-shortcut keep`` removals downstream.
        """
        nsf_folders = getattr(params, 'nested_share_folders', {})
        records = {}
        for folder_uid, rec_set in getattr(params, 'nested_share_folder_records', {}).items():
            if folder_uid != ROOT_FOLDER_UID and folder_uid not in nsf_folders:
                continue
            for record_uid in rec_set:
                records.setdefault(record_uid, set()).add(folder_uid)
        return {k: v for k, v in records.items() if len(v) > 1}


class NestedShareRecordShortcutListCommand(Command):
    """List Nested Share Records that appear in more than one folder."""

    def get_parser(self):
        return nested_share_record_shortcut_list_parser

    def execute(self, params, **kwargs):
        records = NestedShareRecordShortcutCommand.get_record_shortcuts(params)
        target = kwargs.get('target')

        nsf_records = getattr(params, 'nested_share_records', {})
        nsf_record_data = getattr(params, 'nested_share_record_data', {})
        nsf_folders = getattr(params, 'nested_share_folders', {})

        to_show = self._resolve_target(params, target, records, nsf_records,
                                       nsf_record_data, nsf_folders) \
            if target else set(records.keys())

        if not to_show:
            logging.info('No Nested Share Folder shortcut records found')
            return

        fmt = kwargs.get('format') or 'table'
        table = []
        for record_uid in sorted(to_show):
            title = self._record_title(record_uid, nsf_record_data)
            folder_names = []
            for fuid in sorted(records[record_uid]):
                fname = self._folder_name(fuid, nsf_folders)
                folder_names.append({'folder_uid': fuid, 'name': fname} if fmt == 'json'
                                    else f'{fname} ({fuid})')
            table.append([record_uid, title, folder_names])

        headers = (['record_uid', 'record_title', 'folders'] if fmt == 'json'
                    else ['Record UID', 'Record Title', 'Folders'])
        from ..base import dump_report_data
        return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))

    # Record titles live in ``nested_share_record_data[uid]['data_json']``
    # (the decrypted record payload). ``nested_share_records`` only stores
    # metadata (revision/version/shared/etc.) and has no ``title`` key, so
    # the previous lookup always fell back to the raw UID.
    @staticmethod
    def _record_title(record_uid, nsf_record_data):
        rd = nsf_record_data.get(record_uid) or {}
        dj = rd.get('data_json') or {}
        title = dj.get('title')
        return title if title else record_uid

    @staticmethod
    def _folder_name(folder_uid, nsf_folders):
        if folder_uid == ROOT_FOLDER_UID:
            return 'root'
        return nsf_folders.get(folder_uid, {}).get('name', folder_uid)

    @classmethod
    def _resolve_target(cls, params, target, records, nsf_records,
                        nsf_record_data, nsf_folders):
        if target in nsf_records:
            if target not in records:
                raise CommandError('nsf-shortcut list', f'Record UID {target} does not have shortcuts')
            return {target}

        lower = target.casefold()
        for uid in nsf_records:
            if cls._record_title(uid, nsf_record_data).casefold() == lower:
                if uid not in records:
                    raise CommandError('nsf-shortcut list', f'Record "{target}" does not have shortcuts')
                return {uid}

        resolved_folder = _nsf.resolve_folder_identifier(params, target)
        if resolved_folder:
            return {r for r in records if resolved_folder in records[r]}

        raise CommandError('nsf-shortcut list',
                           f'Target "{target}" is not a known record UID, title, or folder path')


class NestedShareRecordShortcutKeepCommand(Command):
    """Keep a Nested Share Record in exactly one folder, removing it from all others."""

    def get_parser(self):
        return nested_share_record_shortcut_keep_parser

    def execute(self, params, **kwargs):
        target = kwargs.get('target')
        if not target:
            self.get_parser().print_help()
            return

        force = kwargs.get('force', False)
        nsf_records = getattr(params, 'nested_share_records', {})
        nsf_folders = getattr(params, 'nested_share_folders', {})

        nsf_record_data = getattr(params, 'nested_share_record_data', {})
        record_uid = self._resolve_record(target, nsf_records, nsf_record_data)
        keep_folder_uid = self._resolve_keep_folder(params, kwargs.get('folder'), nsf_folders)

        records = NestedShareRecordShortcutCommand.get_record_shortcuts(params)
        if record_uid not in records:
            raise CommandError('nsf-shortcut keep',
                               f'Record "{target}" does not appear in multiple folders')
        if keep_folder_uid not in records[record_uid]:
            fname = nsf_folders.get(keep_folder_uid, {}).get('name', keep_folder_uid)
            raise CommandError('nsf-shortcut keep', f'Record "{target}" is not in folder "{fname}"')

        folders_to_remove = [f for f in records[record_uid] if f != keep_folder_uid]
        if not folders_to_remove:
            logging.info('Nothing to do — record is already in only one folder.')
            return

        if not force:
            lines = [f'  Will remove record "{target}" ({record_uid}) from:']
            for fuid in folders_to_remove:
                lines.append(f'    - {nsf_folders.get(fuid, {}).get("name", fuid)} ({fuid})')
            keep_name = nsf_folders.get(keep_folder_uid, {}).get('name', keep_folder_uid)
            lines.append(f'  Keeping in: {keep_name} ({keep_folder_uid})')
            print('\n'.join(lines))
            from ..base import user_choice
            if user_choice('Do you want to proceed with deletion?', 'yn', default='n').lower() != 'y':
                return

        errors = []
        for fuid in folders_to_remove:
            try:
                result = _nsf.remove_record_from_folder_v3(params, fuid, record_uid)
                if not result.get('success'):
                    errors.append(f'{fuid}: {result.get("message", "unknown error")}')
            except Exception as exc:
                errors.append(f'{fuid}: {exc}')

        if errors:
            raise CommandError('nsf-shortcut keep', 'Some removals failed:\n' + '\n'.join(errors))

        params.sync_data = True
        keep_name = nsf_folders.get(keep_folder_uid, {}).get('name', keep_folder_uid)
        logging.info('Record "%s" kept in "%s" and removed from %d other folder(s).',
                     target, keep_name, len(folders_to_remove))

    @staticmethod
    def _resolve_record(target, nsf_records, nsf_record_data=None):
        if target in nsf_records:
            return target
        lower = target.casefold()
        if nsf_record_data:
            for uid in nsf_records:
                rd = nsf_record_data.get(uid) or {}
                dj = rd.get('data_json') or {}
                if (dj.get('title') or '').casefold() == lower:
                    return uid

        for uid, rec in nsf_records.items():
            if rec.get('title', '').casefold() == lower:
                return uid
        raise CommandError('nsf-shortcut keep', f'Record "{target}" not found in Nested Share Folder')

    @staticmethod
    def _resolve_keep_folder(params, folder_arg, nsf_folders):
        if folder_arg:
            uid = _nsf.resolve_folder_identifier(params, folder_arg)
            if not uid:
                raise CommandError('nsf-shortcut keep', f'Folder "{folder_arg}" not found')
            ensure_nested_share_folder(params, uid, 'nsf-shortcut keep',
                                       identifier=folder_arg)
            return uid
        current = getattr(params, 'current_folder', None)
        if current and current in nsf_folders:
            return current
        raise CommandError('nsf-shortcut keep',
                           'No folder specified and current folder is not a Nested Share Folder.')


# ══════════════════════════════════════════════════════════════════════════
# nsf-rm
# ══════════════════════════════════════════════════════════════════════════

class NestedShareRecordRemoveCommand(Command):
    """Remove (delete/unlink) one or more Nested Share Records."""

    def get_parser(self):
        return nested_share_record_rm_parser

    def execute(self, params, **kwargs):
        record_args = kwargs.get('records') or []
        folder_arg = kwargs.get('folder_uid')
        operation = kwargs.get('operation', 'owner-trash')
        force = kwargs.get('force', False)
        dry_run = kwargs.get('dry_run', False)

        if not record_args:
            raise CommandError('nsf-rm', 'At least one record UID or title is required')
        if operation == 'unlink' and not folder_arg:
            raise CommandError('nsf-rm', '--folder is required when --operation is "unlink"')

        folder_uid = None
        if folder_arg:
            folder_uid = _nsf.resolve_folder_identifier(params, folder_arg)
            if not folder_uid:
                raise CommandError('nsf-rm', f"Folder '{folder_arg}' not found")
            ensure_nested_share_folder(params, folder_uid, 'nsf-rm',
                                       identifier=folder_arg)

        removals = self._build_removals(params, record_args, folder_uid, operation)
        if len(removals) > 500:
            raise CommandError('nsf-rm', 'Maximum 500 records per invocation')

        with command_error_handler('nsf-rm'):
            self._preview_and_confirm(params, removals, operation, force, dry_run)

    def _build_removals(self, params, record_args, folder_uid, operation):
        removals = []
        for identifier in record_args:
            record_uid = _nsf.resolve_nested_share_record_uid(params, identifier)
            if not record_uid:
                raise CommandError('nsf-rm', f"Record '{identifier}' not found")
            ensure_nested_share_record(params, record_uid, 'nsf-rm',
                                       identifier=identifier)
            check_record_delete_permission(params, record_uid, 'nsf-rm')
            ctx_folder = folder_uid
            if not ctx_folder:
                folders = _nsf.find_nested_share_folders_for_record(params, record_uid)
                if not folders and operation != 'owner-trash':
                    raise CommandError('nsf-rm',
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
        result = _nsf.remove_record_v3(params, removals, dry_run=True)
        any_error = False
        error_lines = []
        info_lines = []

        for pr in result['preview_results']:
            title = self._record_title(params, pr['record_uid'])
            if pr.get('error'):
                any_error = True
                err = pr['error']
                error_lines.append(
                    f"  {title} [{pr['record_uid']}]: "
                    f"{err.get('code', '')} — {err.get('message', '')}"
                )
            else:
                info_lines.extend(
                    self._impact_summary(pr['record_uid'], title, operation, pr.get('impact'))
                )

        # Errors must always surface, even in --force mode, so the caller (or
        # Service Mode HTTP layer) can see why the operation aborted.
        if any_error:
            for line in error_lines:
                print(line)
            print('\nOne or more records could not be previewed. Aborting.')
            return

        if dry_run or not force:
            for line in info_lines:
                print(line)

        if dry_run:
            print('\n[Dry-run] No records were deleted.')
            return
        if not force:
            from ..base import user_choice
            if user_choice('Do you want to proceed with deletion?', 'yn', default='n').lower() != 'y':
                return

        confirm_result = _nsf.remove_record_v3(params, removals, dry_run=False)
        if confirm_result['confirmed']:
            params.sync_data = True
        else:
            logging.warning('Record removal was not confirmed by the server.')

    @staticmethod
    def _record_title(params, record_uid):
        return getattr(params, 'nested_share_records', {}).get(
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
