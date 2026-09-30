"""Command for converting Classic records to Nested Share Records."""

import json
import logging

from ..base import Command, RecordMixin, user_choice
from ... import nested_share_folder as _nsf
from ...display import bcolors
from ...error import CommandError
from .helpers import ROOT_FOLDER_UID, command_error_handler
from .parsers import nested_share_convert_parser

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
    'RECORD_LINK_RECORD_IN_TRASH': 'A linked record is in the caller’s trash',
    'INTERNAL_ERROR': 'The server could not complete the conversion',
    'RECORD_LINK_CHILD_NOT_INCLUDED': 'A linked Classic record must also be included',
    'RECORD_LINK_FILE_PROMOTION_FAILED': 'A linked file attachment could not be promoted',
    'RECORD_LINK_COMPONENT_FAILED': 'A related record failed; this record was rolled back',
    'RECORD_VERSION_NOT_CONVERTIBLE': 'The record version cannot be converted',
}


def _resolve_record_uid(params, identifier):
    """Resolve a record UID/title/path, rejecting ambiguous title matches."""
    if not identifier:
        return None

    record_cache = getattr(params, 'record_cache', {}) or {}
    if identifier in record_cache:
        return identifier

    lower_identifier = identifier.casefold()
    matches = []
    for record_uid, record in record_cache.items():
        raw_data = record.get('data_unencrypted')
        if not raw_data:
            continue
        try:
            if isinstance(raw_data, bytes):
                raw_data = raw_data.decode('utf-8')
            data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            title = data.get('title') if isinstance(data, dict) else None
            if isinstance(title, str) and title.casefold() == lower_identifier:
                matches.append(record_uid)
        except (TypeError, ValueError):
            continue

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise CommandError(
            'nsf-convert',
            f"More than one record is titled '{identifier}'. Use a record UID.")

    resolved = _nsf.resolve_nested_share_record_uid(params, identifier)
    if resolved:
        return resolved

    record = RecordMixin.resolve_single_record(params, identifier)
    return record.record_uid if record else None


def _resolve_target_folder(params, folder_input):
    """Resolve a Nested Share Folder; omitted/root means the caller's root."""
    if not folder_input or folder_input.casefold() in ('root', ROOT_FOLDER_UID.casefold()):
        return None

    folder_uid = _nsf.resolve_folder_identifier(params, folder_input)
    if not folder_uid:
        raise CommandError('nsf-convert', f"Folder '{folder_input}' was not found")
    if folder_uid not in (getattr(params, 'nested_share_folders', {}) or {}):
        raise CommandError(
            'nsf-convert',
            f"'{folder_input}' is not a Nested Share Folder")
    return folder_uid


class NestedShareConvertCommand(Command):
    """Convert one or more Classic records into Nested Share Records."""

    def get_parser(self):
        return nested_share_convert_parser

    def execute(self, params, **kwargs):
        identifiers = kwargs.get('records') or []
        if isinstance(identifiers, str):
            identifiers = [identifiers]
        if not identifiers:
            raise CommandError('nsf-convert', 'At least one record is required')
        if len(identifiers) > _nsf.MAX_CONVERT_RECORDS:
            raise CommandError(
                'nsf-convert',
                f"Maximum {_nsf.MAX_CONVERT_RECORDS} records per request")

        record_uids = []
        for identifier in identifiers:
            with command_error_handler('nsf-convert'):
                record_uid = _resolve_record_uid(params, identifier)
            if not record_uid:
                raise CommandError('nsf-convert', f"Record '{identifier}' was not found")
            record_uids.append(record_uid)

        if len(set(record_uids)) != len(record_uids):
            raise CommandError(
                'nsf-convert',
                'The same record was selected more than once; remove duplicate records')

        with command_error_handler('nsf-convert'):
            folder_uid = _resolve_target_folder(params, kwargs.get('folder_uid'))
        folder_description = folder_uid or 'Vault (root)'
        if folder_uid:
            folder_data = (getattr(params, 'nested_share_folders', {}) or {}).get(folder_uid) or {}
            folder_name = folder_data.get('name') or folder_uid
            if folder_name != folder_uid:
                folder_description = f'{folder_name} ({folder_uid})'
        print(
            f'\n{bcolors.WARNING}Warning: Conversion is permanent. '
            'Classic shared-folder membership and additional Classic folder '
            'placements are not retained.'
            f'{bcolors.ENDC}')
        print(f'Records to convert ({len(record_uids)}):')
        for record_uid in record_uids:
            print(f'  {record_uid}')
        print(f'Destination: {folder_description}')

        if not kwargs.get('force'):
            if user_choice(
                    'Do you want to proceed with conversion?', 'yn', default='n').lower() != 'y':
                logging.info('Conversion cancelled.')
                return

        with command_error_handler('nsf-convert'):
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

        if duplicate_uids:
            logging.warning(
                'The conversion endpoint returned duplicate results for %d record(s).',
                len(duplicate_uids))
        if unexpected_result_count:
            logging.warning(
                'The conversion endpoint returned %d result(s) for unrequested records.',
                unexpected_result_count)

        converted = 0
        missing_results = False
        for record_uid in record_uids:
            if record_uid in duplicate_uids:
                logging.warning(
                    'The conversion result for Classic record "%s" is ambiguous.', record_uid)
                missing_results = True
                continue
            result = result_by_uid.get(record_uid)
            if result is None:
                logging.warning(
                    'No conversion result was returned for Classic record "%s".', record_uid)
                missing_results = True
                continue
            status = result['status']
            if result['success']:
                converted += 1
                logging.info(
                    'Classic record "%s" converted to a Nested Share Record.', record_uid)
            else:
                message = _STATUS_MESSAGES.get(status, status.replace('_', ' ').title())
                logging.warning(
                    'Classic record "%s" was not converted: %s.', record_uid, message)
                logging.debug('Conversion status for record %s: %s', record_uid, status)

        if converted or missing_results or unexpected_result_count:
            params.sync_data = True
        logging.info('Conversion complete: %d of %d Classic record(s) converted.',
                     converted, len(record_uids))
