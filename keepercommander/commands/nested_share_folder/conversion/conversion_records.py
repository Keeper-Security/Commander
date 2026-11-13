"""Record conversion and placement migration for Classic folder trees."""

import logging

from .... import nested_share_folder as _nsf
from ....nested_share_folder.common import (
    NSF_FOLDER_RECORD_BATCH_SIZE,
)


class FolderRecordMigration:
    """Convert Classic records and recreate their NSF folder placements."""

    @staticmethod
    def _convert_records(params, record_uids, placements, target_uids):
        """Convert supported Classic records into their primary NSF folders."""
        by_target = {}
        for record_uid in record_uids:
            source_locations = placements.get(record_uid) or []
            if not source_locations:
                continue
            primary_target_uid = target_uids[source_locations[0]]
            by_target.setdefault(primary_target_uid, []).append(record_uid)

        converted = set()
        for target_uid, target_records in by_target.items():
            for start in range(0, len(target_records), _nsf.MAX_CONVERT_RECORDS):
                batch = target_records[start:start + _nsf.MAX_CONVERT_RECORDS]
                try:
                    results = _nsf.convert_records_v3(
                        params, record_uids=batch, folder_uid=target_uid)
                except Exception as exc:
                    logging.warning(
                        'Could not convert record batch for folder %s: %s',
                        target_uid, exc)
                    continue

                result_by_uid = {}
                duplicate_uids = set()
                requested = set(batch)
                for result in results or []:
                    record_uid = result.get('record_uid')
                    if record_uid not in requested:
                        logging.warning(
                            'Record conversion returned unrequested UID %s.', record_uid)
                        continue
                    if record_uid in result_by_uid:
                        duplicate_uids.add(record_uid)
                        result_by_uid.pop(record_uid, None)
                    else:
                        result_by_uid[record_uid] = result

                for record_uid in batch:
                    result = result_by_uid.get(record_uid)
                    if record_uid in duplicate_uids or result is None:
                        logging.warning(
                            'No unambiguous conversion result for Classic record %s.',
                            record_uid)
                    elif result.get('success'):
                        converted.add(record_uid)
                        logging.info(
                            '  ✓ Classic record %s converted to a Nested Share Record.',
                            record_uid)
                    else:
                        status = result.get('status') or 'unknown error'
                        logging.warning(
                            '  ⚠ Classic record %s was not converted: %s.',
                            record_uid, status.replace('_', ' ').title())
        return converted

    @staticmethod
    def _create_additional_placements(params, converted_uids, placements, target_uids,
                                      include_primary_for=None):
        """Restore additional NSF placements for converted records."""
        additional_by_target = {}
        existing_placements = getattr(params, 'nested_share_folder_records', {}) or {}
        include_primary_for = include_primary_for or set()
        for record_uid in converted_uids:
            locations = placements.get(record_uid) or []
            target_locations = list(dict.fromkeys(target_uids[uid] for uid in locations))
            for index, target_uid in enumerate(target_locations):
                if index == 0 and record_uid not in include_primary_for:
                    continue
                if record_uid in (existing_placements.get(target_uid) or set()):
                    continue
                additional_by_target.setdefault(target_uid, []).append(record_uid)

        failures = []
        for target_uid, record_uids in additional_by_target.items():
            for start in range(0, len(record_uids), NSF_FOLDER_RECORD_BATCH_SIZE):
                chunk = record_uids[start:start + NSF_FOLDER_RECORD_BATCH_SIZE]
                try:
                    results = _nsf.manage_folder_records_batch_v3(
                        params, target_uid, records_to_add=chunk)
                except Exception as exc:
                    failures.append(f'{target_uid}: {exc}')
                    continue
                result_by_uid = {}
                duplicate_uids = set()
                requested_uids = set(chunk)
                for result in results or []:
                    record_uid = result.get('record_uid')
                    if record_uid not in requested_uids:
                        failures.append(
                            f'{record_uid} -> {target_uid}: unexpected link result')
                        continue
                    if record_uid in result_by_uid:
                        duplicate_uids.add(record_uid)
                        result_by_uid.pop(record_uid)
                    elif record_uid not in duplicate_uids:
                        result_by_uid[record_uid] = result

                for record_uid in chunk:
                    result = result_by_uid.get(record_uid)
                    if record_uid in duplicate_uids:
                        failures.append(
                            f'{record_uid} -> {target_uid}: ambiguous link result')
                    elif result is None:
                        failures.append(
                            f'{record_uid} -> {target_uid}: no link result returned')
                    elif not result.get('success'):
                        failures.append(
                            f"{record_uid} -> {target_uid}: "
                            f"{result.get('message') or result.get('status') or 'link failed'}")
        return failures
