"""Commands for converting Classic records and folders to Nested Share data."""

import json
import logging

from ...base import Command, RecordMixin, user_choice
from .... import nested_share_folder as _nsf
from ....display import bcolors
from ....error import CommandError
from .conversion_utils import (
    _escape_non_printable, _pam_record_details, _print_conversion_step,
    _print_skipped_pam_records, _record_title, _resolve_target_folder,
)
from ..helpers import command_error_handler, resolve_record_uid
from ..parsers import nested_share_convert_parser


_STATUS_MESSAGES = {
    'ENTERPRISE_NOT_KEEPER_DRIVE_ENABLED':
        'Nested Share Folders are not enabled for this account',
    'NOT_RECORD_OWNER': 'The caller does not own this record',
    'RECORD_NOT_FOUND': 'No active owner record was found',
    'RECORD_ALREADY_CONVERTED': 'The record is already a Nested Share Record',
    'FOLDER_ACCESS_DENIED': 'The caller cannot add records to the destination folder',
    'INVALID_FOLDER_KEY': 'The destination-folder encrypted key is invalid',
    'INVALID_OWNER_KEY': 'The owner encrypted key is invalid',
    'RECORD_NOT_LEGACY': 'The record is not a Classic record',
    'TARGET_NOT_DRIVE_FOLDER': 'The destination is not a Nested Share Folder',
    'RECORD_LINK_CHILD_NOT_OWNED': 'A linked child record is not owned by the caller',
    'RECORD_LINK_PARENT_NOT_OWNED': 'A linked parent record is not owned by the caller',
    'RECORD_LINK_RECORD_IN_TRASH': "A linked record is in the caller's trash",
    'INTERNAL_ERROR': 'The server could not complete the conversion',
    'RECORD_LINK_CHILD_NOT_INCLUDED': 'A linked Classic record must also be included',
    'RECORD_LINK_FILE_PROMOTION_FAILED': 'A linked file attachment could not be promoted',
    'RECORD_LINK_COMPONENT_FAILED': 'A related record failed; this record was rolled back',
    'RECORD_VERSION_NOT_CONVERTIBLE': 'The record version cannot be converted',
}

def _resolve_record_uid(params, identifier):
    """Resolve a UID or use Commander's normal current-folder/path resolution."""
    if not identifier:
        return None

    record_cache = getattr(params, 'record_cache', {}) or {}
    nested_share_records = getattr(params, 'nested_share_records', {}) or {}
    if identifier in nested_share_records:
        return identifier
    if identifier in record_cache:
        return identifier

    record = RecordMixin.resolve_single_record(params, identifier)
    if record:
        return record.record_uid

    # Preserve current-folder/path selection above, but still distinguish an
    # ambiguous title from a genuinely missing record.
    resolve_record_uid(params, identifier, 'nsf-convert-record')
    return None

class NestedShareConvertCommand(Command):
    """Convert one or more Classic records into Nested Share Records."""

    def get_parser(self):
        """Return the parser for the record conversion command."""
        return nested_share_convert_parser

    def execute(self, params, **kwargs):
        """Validate selected Classic records and convert supported records."""
        if (kwargs.get('command') or '').casefold() == 'nsf-convert':
            print(
                f'{bcolors.WARNING}Warning: nsf-convert is deprecated; '
                f'use nsf-convert-record instead.{bcolors.ENDC}')
        identifiers = kwargs.get('records') or []
        if isinstance(identifiers, str):
            identifiers = [identifiers]
        if not identifiers:
            raise CommandError('nsf-convert-record', 'At least one record is required')

        record_uids = []
        already_nested_share_uids = []
        skipped_pam_records = []
        nested_share_records = getattr(params, 'nested_share_records', {}) or {}
        seen_record_uids = set()
        for identifier in identifiers:
            with command_error_handler('nsf-convert-record'):
                record_uid = _resolve_record_uid(params, identifier)
            if not record_uid:
                raise CommandError('nsf-convert-record', f"Record '{identifier}' was not found")
            if record_uid in seen_record_uids:
                raise CommandError(
                    'nsf-convert-record',
                    'The same record was selected more than once; remove duplicate records')
            seen_record_uids.add(record_uid)
            if record_uid in nested_share_records:
                already_nested_share_uids.append(record_uid)
                continue
            pam_record = _pam_record_details(params, record_uid)
            if pam_record:
                skipped_pam_records.append(pam_record)
                continue
            record_uids.append(record_uid)

        _print_skipped_pam_records(skipped_pam_records)

        if len(record_uids) > _nsf.MAX_CONVERT_RECORDS:
            raise CommandError(
                'nsf-convert-record',
                f"Maximum {_nsf.MAX_CONVERT_RECORDS} Classic records per request")

        for record_uid in already_nested_share_uids:
            logging.info(
                'Record "%s" is already a Nested Share Record; skipped.', record_uid)
        if not record_uids:
            logging.info('No Classic records remain to convert.')
            return

        with command_error_handler('nsf-convert-record'):
            folder_uid = _resolve_target_folder(
                params, kwargs.get('folder_uid'), force=kwargs.get('force', False))
        folder_description = folder_uid or 'Vault (root)'
        if folder_uid:
            folder_data = (getattr(params, 'nested_share_folders', {}) or {}).get(folder_uid) or {}
            folder_name = folder_data.get('name') or folder_uid
            if folder_name != folder_uid:
                folder_description = (
                    f'{_escape_non_printable(folder_name)} ({folder_uid})')
        print(
            f'\n{bcolors.WARNING}Warning: Conversion is permanent. '
            'Classic shared-folder membership and additional Classic folder '
            'placements are not retained.'
            f'{bcolors.ENDC}')
        print(f'Records to convert ({len(record_uids)}):')
        for record_uid in record_uids:
            title = _record_title(params, record_uid)
            if title:
                quoted_title = _escape_non_printable(
                    json.dumps(title, ensure_ascii=False))
                label = f'{quoted_title} ({record_uid})'
            else:
                label = record_uid
            print(f'  {label}')
        print(f'Destination: {folder_description}')

        if not kwargs.get('force'):
            if user_choice(
                    'Do you want to proceed with conversion?', 'yn', default='n').lower() != 'y':
                logging.info('Conversion cancelled.')
                return

        with command_error_handler('nsf-convert-record'):
            _print_conversion_step(
                1, 2, f'Converting {len(record_uids)} Classic record(s)...')
            # A failed transport can leave the conversion outcome unknown.
            # Refresh the local cache after any request that may have reached
            # the server, including requests that return no successful results.
            params.sync_data = True
            results = _nsf.convert_records_v3(
                params, record_uids=record_uids, folder_uid=folder_uid)
        if not results:
            logging.warning(
                'No conversion results were returned; the vault will be refreshed.')
            params.sync_data = True
            return

        requested_uids = set(record_uids)
        result_by_uid = {}
        duplicate_uids = set()
        unexpected_result_count = 0
        for result in results:
            result_uid = result['record_uid']
            if result_uid not in requested_uids:
                unexpected_result_count += 1
                continue
            if result_uid in duplicate_uids:
                continue
            if result_uid in result_by_uid:
                duplicate_uids.add(result_uid)
                result_by_uid.pop(result_uid)
                continue
            result_by_uid[result_uid] = result

        _print_conversion_step(2, 2, 'Processing conversion results...')
        if duplicate_uids:
            logging.warning(
                'The conversion endpoint returned duplicate results for %d record(s).',
                len(duplicate_uids))
        if unexpected_result_count:
            logging.warning(
                'The conversion endpoint returned %d result(s) for unrequested records.',
                unexpected_result_count)

        converted = 0
        for record_uid in record_uids:
            if record_uid in duplicate_uids:
                logging.warning(
                    'The conversion result for Classic record "%s" is ambiguous.', record_uid)
                continue
            result = result_by_uid.get(record_uid)
            if result is None:
                logging.warning(
                    'No conversion result was returned for Classic record "%s".', record_uid)
                continue
            status = result['status']
            if result['success']:
                converted += 1
                logging.info(
                    '  ✓ Classic record "%s" converted to a Nested Share Record.',
                    record_uid)
            else:
                message = _STATUS_MESSAGES.get(status, status.replace('_', ' ').title())
                logging.warning(
                    '  ⚠ Classic record "%s" was not converted: %s.',
                    record_uid, message)
                logging.debug('Conversion status for record %s: %s', record_uid, status)

        logging.info(
            'Conversion complete: %d of %d Classic record(s) converted; '
            '%d already Nested Share Record(s) skipped.',
            converted, len(record_uids), len(already_nested_share_uids))

# Keep established command and helper import paths available.
from .conversion_acl import FolderPermissionMigration as _PermissionMigration  # noqa: E402
from .conversion_app_shares import (  # noqa: E402
    FolderApplicationShareMigration as _AppShareMigration,
)
from .conversion_planning import FolderConversionPlanner as _FolderPlanner  # noqa: E402
from .conversion_utils import ConversionUtilities as _ConversionUtilities  # noqa: E402
from .folder_conversion import (  # noqa: E402
    NestedShareFolderConvertCommand as _FolderConvertCommand,
)

NestedShareFolderConvertCommand = _FolderConvertCommand
_collect_classic_subtree = _FolderPlanner._collect_classic_subtree
_folder_plan = _FolderPlanner._folder_plan
_record_access_plan = _PermissionMigration._record_access_plan
_scope_accessors = _PermissionMigration._scope_accessors
_read_applications = _AppShareMigration._read_applications
_record_type = _ConversionUtilities._record_type
_resolve_destination_folder = _ConversionUtilities._resolve_destination_folder

__all__ = [
    'NestedShareConvertCommand',
    'NestedShareFolderConvertCommand',
    '_collect_classic_subtree',
    '_folder_plan',
    '_pam_record_details',
    '_read_applications',
    '_record_access_plan',
    '_record_type',
    '_resolve_destination_folder',
    '_scope_accessors',
]
