"""Shared helpers for Classic-to-Nested Share conversion commands."""

import json
import logging

from .... import nested_share_folder as _nsf, sync_down
from .... import vault
from ....display import bcolors
from ....error import CommandError
from ....nested_share_folder.common import PAM_RECORD_TYPE_PREFIX, ROOT_FOLDER_UID
from ....nested_share_folder.folder_api import FolderIdentifierAmbiguousError


class ConversionUtilities:
    """Resolve conversion identifiers and format conversion output."""

    @staticmethod
    def _record_title(params, record_uid):
        """Return a cached record title when the data can be decoded."""
        record = (getattr(params, 'record_cache', {}) or {}).get(record_uid) or {}
        raw_data = record.get('data_unencrypted')
        if not raw_data:
            return None
        try:
            if isinstance(raw_data, bytes):
                raw_data = raw_data.decode('utf-8')
            data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
        except (TypeError, ValueError):
            return None
        title = data.get('title') if isinstance(data, dict) else None
        if not isinstance(title, str) or not title:
            return None
        return title

    @staticmethod
    def _escape_non_printable(value):
        """Escape terminal control characters before display."""
        return ''.join(
            char if char.isprintable() else f'\\u{ord(char):04x}'
            for char in str(value)
        )

    @staticmethod
    def _record_type(params, record_uid):
        """Return the Keeper record type from the local vault cache."""
        record = vault.KeeperRecord.load(params, record_uid)
        return getattr(record, 'record_type', '') if record else ''

    @staticmethod
    def _pam_record_details(params, record_uid, record_type=None):
        """Describe a PAM record that must be skipped during conversion."""
        record_type = str(
            record_type if record_type is not None else _record_type(params, record_uid) or '')
        if not record_type.casefold().startswith(PAM_RECORD_TYPE_PREFIX):
            return None
        return {
            'record_uid': record_uid,
            'record_type': record_type,
            'title': _record_title(params, record_uid),
        }

    @staticmethod
    def _print_skipped_pam_records(records):
        """Warn about PAM records excluded from conversion."""
        if not records:
            return
        print(
            f'\n{bcolors.WARNING}Warning: PAM records cannot be converted and will be '
            f'skipped; supported records will continue.{bcolors.ENDC}')
        for record in records:
            title = record.get('title')
            label = f'{json.dumps(title, ensure_ascii=False)} ' if title else ''
            print(
                f"  {label}({record['record_uid']}) "
                f"[{record['record_type']}]")

    @staticmethod
    def _folder_path(params, folder_uid):
        """Return the display path for an NSF folder UID."""
        folders = getattr(params, 'nested_share_folders', {}) or {}
        parts = []
        seen = set()
        while folder_uid and folder_uid in folders and folder_uid not in seen:
            seen.add(folder_uid)
            folder = folders[folder_uid]
            parts.append(folder.get('name') or folder_uid)
            parent_uid = folder.get('parent_uid') or ''
            folder_uid = parent_uid if parent_uid in folders else None
        return '/'.join(reversed(parts))

    @staticmethod
    def _select_numbered_option(prompt, option_count, command, allow_zero=False):
        """Read a numbered interactive choice, returning None when zero is chosen."""
        first_option = 0 if allow_zero else 1
        while True:
            try:
                answer = input(prompt).strip()
            except (EOFError, OSError) as exc:
                raise CommandError(
                    command,
                    'Interactive selection is required; use a folder UID instead.'
                ) from exc
            if answer.casefold() in ('q', 'quit', 'cancel'):
                raise CommandError(command, 'Selection cancelled.')
            try:
                selection = int(answer)
            except ValueError:
                selection = -1
            if first_option <= selection <= option_count:
                return None if selection == 0 else selection - 1
            print(f'Enter a number from {first_option} to {option_count}, or q to cancel.')

    @staticmethod
    def _resolve_destination_folder(params, folder_input, command, force=False):
        """Resolve an NSF destination, prompting when a flat name is ambiguous."""
        if not folder_input or folder_input.casefold() in ('root', ROOT_FOLDER_UID.casefold()):
            return None

        display_input = _escape_non_printable(folder_input)
        nested_folders = getattr(params, 'nested_share_folders', {}) or {}
        if folder_input in nested_folders:
            return folder_input
        if '/' not in folder_input and '\\' not in folder_input:
            matching_uids = sorted(
                uid for uid, folder in nested_folders.items()
                if (folder.get('name') or '').casefold() == folder_input.casefold())
            if len(matching_uids) == 1:
                return matching_uids[0]
            if len(matching_uids) > 1:
                if force:
                    raise CommandError(
                        command,
                        f"Destination '{display_input}' matches multiple NSF folders. "
                        'Use a folder UID or an unambiguous full path when --force is specified.')
                print(f"Destination '{display_input}' matches multiple NSF folders:")
                for index, folder_uid in enumerate(matching_uids, 1):
                    path = _folder_path(params, folder_uid)
                    print(f'  {index}. {_escape_non_printable(path)} ({folder_uid})')
                selected = _select_numbered_option(
                    f'Select destination [1-{len(matching_uids)}] (or q to cancel): ',
                    len(matching_uids), command)
                return matching_uids[selected]

        try:
            folder_uid = _nsf.resolve_folder_identifier(
                params, folder_input, raise_on_ambiguous=True)
        except FolderIdentifierAmbiguousError as e:
            raise CommandError(command, _escape_non_printable(e)) from e
        if not folder_uid:
            raise CommandError(command, f"Folder '{display_input}' was not found")
        if folder_uid not in nested_folders:
            raise CommandError(
                command,
                f"'{display_input}' is not a Nested Share Folder")
        return folder_uid

    @staticmethod
    def _resolve_target_folder(params, folder_input, force=False):
        """Resolve a Nested Share Folder; omitted/root means the caller's root."""
        return _resolve_destination_folder(
            params, folder_input, 'nsf-convert-record', force=force)

    @staticmethod
    def _classic_folder_label(node):
        """Format a Classic folder name and UID for output."""
        return f'{_escape_non_printable(node.name)} ({node.uid})'

    @staticmethod
    def _nested_share_folder_label(params, folder_uid):
        """Format an NSF folder name and UID for output."""
        if not folder_uid:
            return 'Vault (root)'
        folder = (getattr(params, 'nested_share_folders', {}) or {}).get(folder_uid) or {}
        name = folder.get('name') or folder_uid
        name = _escape_non_printable(name)
        return f'{name} ({folder_uid})' if name != folder_uid else folder_uid

    @staticmethod
    def _print_conversion_step(step, total_steps, message):
        """Print a numbered conversion stage."""
        print(f'\n{bcolors.OKBLUE}[{step}/{total_steps}]{bcolors.ENDC} {message}')


# Module-level aliases keep call sites concise while helpers stay grouped.
_record_title = ConversionUtilities._record_title
_escape_non_printable = ConversionUtilities._escape_non_printable
_record_type = ConversionUtilities._record_type
_pam_record_details = ConversionUtilities._pam_record_details
_print_skipped_pam_records = ConversionUtilities._print_skipped_pam_records
_folder_path = ConversionUtilities._folder_path
_select_numbered_option = ConversionUtilities._select_numbered_option
_resolve_destination_folder = ConversionUtilities._resolve_destination_folder
_resolve_target_folder = ConversionUtilities._resolve_target_folder
_classic_folder_label = ConversionUtilities._classic_folder_label
_nested_share_folder_label = ConversionUtilities._nested_share_folder_label
_print_conversion_step = ConversionUtilities._print_conversion_step


class FolderConversionVerification:
    """Confirm target folders, records, and retried placements after sync-down."""

    @staticmethod
    def verify(params, source_record_uids, converted_uids, target_uids, placements,
               retry, link_failures, record_permission_failures, app_share_failures):
        """Return whether conversion is complete and any verification diagnostics."""
        sync_error = None
        try:
            sync_down.sync_down(params)
        except Exception as exc:
            sync_error = exc
            logging.warning('Could not refresh the vault to verify conversion: %s', exc)

        complete = (
            len(converted_uids) == len(source_record_uids) and
            not link_failures and not record_permission_failures and
            not app_share_failures and sync_error is None)
        issues = []
        if sync_error is not None:
            issues.append(
                f'Final sync-down failed, so the last cached record locations may be stale: '
                f'{sync_error}')

        missing_folders = [
            uid for uid in target_uids.values()
            if uid not in (getattr(params, 'nested_share_folders', {}) or {})
        ] if sync_error is None else []
        if missing_folders:
            complete = False
            issues.append(
                f'{len(missing_folders)} NSF folder(s) were not confirmed by sync-down')
            logging.warning(
                'Sync-down did not confirm %d created NSF folder(s).',
                len(missing_folders))

        nested_records = getattr(params, 'nested_share_records', {}) or {}
        if source_record_uids and sync_error is None:
            missing_records = [
                uid for uid in source_record_uids if uid not in nested_records
            ]
            if missing_records:
                complete = False
                issues.append(
                    f'{len(missing_records)} converted record(s) were not confirmed by sync-down')
                logging.warning(
                    'Sync-down did not confirm %d converted record(s).',
                    len(missing_records))

        if retry and sync_error is None:
            folder_records = getattr(params, 'nested_share_folder_records', {}) or {}
            missing_placements = [
                (record_uid, target_uids[source_uid])
                for record_uid in source_record_uids
                for source_uid in placements.get(record_uid) or []
                if record_uid in nested_records
                and record_uid not in (folder_records.get(target_uids[source_uid]) or set())
            ]
            if missing_placements:
                complete = False
                issues.append(
                    f'{len(missing_placements)} record placement(s) were not confirmed')
                logging.warning(
                    'Sync-down did not confirm %d record placement(s) in retry targets.',
                    len(missing_placements))

        issues.extend(
            f'Additional placement failure: {failure}' for failure in link_failures[:5])
        issues.extend(
            f'Record permission failure: {failure}'
            for failure in record_permission_failures[:5])
        issues.extend(
            f'Application-share failure: {failure}' for failure in app_share_failures[:5])
        params.sync_data = True
        return complete, issues
