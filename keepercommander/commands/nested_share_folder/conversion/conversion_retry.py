"""Retry mapping and partial-conversion reconciliation."""

from collections import defaultdict

from .... import nested_share_folder as _nsf
from ...base import user_choice
from ....display import bcolors
from ....error import CommandError
from .conversion_planning import FolderConversionPlanner
from .conversion_utils import (
    _escape_non_printable, _folder_path, _select_numbered_option,
)


class FolderConversionRetry:
    """Reconcile partially created folder structures on retry."""

    @staticmethod
    def _print_incomplete_conversion(params, source_uid, destination_uid,
                                     source_record_uids, converted_uids, target_uids,
                                     existing_target_uids, diagnostics=None):
        """Report confirmed, remaining, and uncertain state after partial conversion."""
        classic_placements = getattr(params, 'subfolder_record_cache', {}) or {}
        scan_failed = False
        try:
            source_folder_uids = set(
                FolderConversionPlanner._collect_classic_subtree(params, source_uid)[0])
        except CommandError:
            source_folder_uids = {source_uid}
            scan_failed = True
        remaining_records = sorted({
            record_uid
            for folder_uid in source_folder_uids
            for record_uid in (classic_placements.get(folder_uid) or set())
            if record_uid in source_record_uids
        })
        nested_records = getattr(params, 'nested_share_records', {}) or {}
        confirmed_records = sorted(
            record_uid for record_uid in source_record_uids
            if record_uid in nested_records)
        confirmed_set = set(confirmed_records)
        remaining_set = set(remaining_records)
        uncertain_records = sorted(
            (set(converted_uids) - confirmed_set) |
            (set(source_record_uids) - confirmed_set - remaining_set))
        print(
            f'\n{bcolors.WARNING}Conversion incomplete. '
            f'The Classic source tree was retained.{bcolors.ENDC}')
        print(f'  Records confirmed in NSF: {len(confirmed_records)}')
        for record_uid in confirmed_records:
            print(f'    - {record_uid}')
        print(f'  Records still placed in Classic: {len(remaining_records)}')
        for record_uid in remaining_records:
            print(f'    - {record_uid}')
        if scan_failed:
            print(
                '  The full Classic subtree could not be enumerated; remaining-record '
                'status may be incomplete.')
        if uncertain_records:
            print(
                f'  Records with an unconfirmed conversion result: '
                f'{len(uncertain_records)}')
            for record_uid in uncertain_records:
                print(f'    - {record_uid}')
        print(
            f'  NSF folders created: {len(target_uids) - len(existing_target_uids)}; '
            f'reused: {len(existing_target_uids)}.')
        print(
            '  Existing NSF folders and any permissions already applied were left in '
            'place; no automatic rollback was attempted.')
        for diagnostic in diagnostics or []:
            print(f'  - {_escape_non_printable(diagnostic)}')
        destination = (
            f' --folder "{destination_uid}"' if destination_uid else '')
        print(
            f'  To reconcile, review the existing folder mapping and rerun: '
            f'nsf-convert-folder "{source_uid}" --retry{destination}')
        print(
            '  Retry can process records still placed in the Classic source; '
            'manually verify records no longer listed there.')

    @staticmethod
    def _select_retry_folders(params, nodes, target_levels, target_parent_sources,
                              destination_uid, records_by_folder):
        """Offer structurally matching existing NSF folders for manual retry."""
        nsf_folders = getattr(params, 'nested_share_folders', {}) or {}
        target_uids = {}
        used_uids = set()
        candidate_uids_seen = set()
        inaccessible_uids = set()
        found_candidates = False

        def normalized_parent(folder_uid):
            """Normalize the folder's parent to an existing NSF folder UID."""
            parent_uid = (nsf_folders.get(folder_uid) or {}).get('parent_uid') or ''
            return parent_uid if parent_uid in nsf_folders else None

        for target_level in sorted(set(target_levels.values())):
            groups = defaultdict(list)
            for source_uid, level in target_levels.items():
                if level != target_level:
                    continue
                parent_source_uid = target_parent_sources[source_uid]
                if parent_source_uid and parent_source_uid not in target_uids:
                    continue
                parent_uid = (
                    target_uids.get(parent_source_uid) if parent_source_uid else destination_uid)
                groups[(parent_uid, nodes[source_uid].name)].append(source_uid)

            for (parent_uid, name), source_uids in groups.items():
                candidates = []
                for uid, folder in nsf_folders.items():
                    if (normalized_parent(uid) != parent_uid or
                            folder.get('name') != name or uid in used_uids):
                        continue
                    if not _nsf.get_folder_key(params, uid, raise_on_missing=False):
                        inaccessible_uids.add(uid)
                        continue
                    candidates.append(uid)
                candidates.sort()
                if not candidates:
                    continue
                found_candidates = True
                candidate_uids_seen.update(candidates)
                if len(source_uids) == 1 and len(candidates) == 1:
                    selected_uid = candidates[0]
                    target_uids[source_uids[0]] = selected_uid
                    used_uids.add(selected_uid)
                    continue

                for source_uid in source_uids:
                    available = [uid for uid in candidates if uid not in used_uids]
                    if not available:
                        break
                    print(
                        f'\nClassic folder {_escape_non_printable(nodes[source_uid].name)} '
                        f'({source_uid}) has matching NSF folder(s):')
                    for index, candidate_uid in enumerate(available, 1):
                        path = _folder_path(params, candidate_uid)
                        record_matches = (
                            set(records_by_folder.get(source_uid) or []) &
                            set((getattr(params, 'nested_share_folder_records', {}) or {})
                                .get(candidate_uid, set()) or set()))
                        print(
                            f'  {index}. {_escape_non_printable(path)} ({candidate_uid}) — '
                            f'{len(record_matches)} matching record(s)')
                    print('  0. Create a new NSF folder for this Classic folder')
                    choice = _select_numbered_option(
                        f'Select a matching folder [0-{len(available)}]: ',
                        len(available), 'nsf-convert-folder', allow_zero=True)
                    if choice is not None:
                        selected_uid = available[choice]
                        target_uids[source_uid] = selected_uid
                        used_uids.add(selected_uid)

        if not target_uids:
            if found_candidates:
                message = (
                    'No existing NSF folders were selected for reuse; '
                    'a new NSF folder structure will be created.')
            elif inaccessible_uids:
                message = (
                    'Matching NSF folders were found but their keys are unavailable; '
                    'a new NSF folder structure will be created.')
            else:
                message = (
                    'No matching existing NSF folders were found for this retry; '
                    'a new NSF folder structure will be created.')
            print(f'\n{message}')
            unselected_uids = candidate_uids_seen | inaccessible_uids
            if unselected_uids:
                print('Matching NSF folders left untouched:')
                for candidate_uid in sorted(unselected_uids):
                    path = _escape_non_printable(_folder_path(params, candidate_uid))
                    suffix = (
                        ' — folder key unavailable'
                        if candidate_uid in inaccessible_uids else '')
                    print(f'  {path} ({candidate_uid}){suffix}')
            return {}

        print('\nProposed retry folder mapping:')
        folder_records = getattr(params, 'nested_share_folder_records', {}) or {}
        for source_uid, target_uid in target_uids.items():
            source_label = _escape_non_printable(nodes[source_uid].name)
            target_path = _escape_non_printable(_folder_path(params, target_uid))
            record_matches = (
                set(records_by_folder.get(source_uid) or []) &
                set(folder_records.get(target_uid) or set()))
            print(
                f'  {source_label} ({source_uid}) -> {target_path} ({target_uid}) — '
                f'{len(record_matches)} matching record(s)')
        print(f'  NSF folders to create: {len(nodes) - len(target_uids)}')
        try:
            reuse = user_choice(
                'Reuse these existing NSF folders and create any missing folders?',
                'yn', default='n').lower() == 'y'
        except (EOFError, OSError) as exc:
            raise CommandError(
                'nsf-convert-folder',
                'Interactive confirmation is required for --retry.') from exc
        if not reuse:
            print(
                'Existing NSF folders will be left untouched; creating a new '
                'structure may leave duplicate partial folders.')
            for candidate_uid in sorted(candidate_uids_seen):
                path = _escape_non_printable(_folder_path(params, candidate_uid))
                print(f'  {path} ({candidate_uid})')
            return {}
        for target_uid in target_uids.values():
            try:
                _nsf.get_folder_key(params, target_uid, raise_on_missing=True)
            except Exception as exc:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Cannot reuse NSF folder {target_uid} because its key is unavailable: '
                    f'{exc}') from exc
        unused_candidates = candidate_uids_seen - used_uids
        unused_candidates.update(inaccessible_uids)
        if unused_candidates:
            print('Other matching NSF folders will be left untouched:')
            for candidate_uid in sorted(unused_candidates):
                path = _escape_non_printable(_folder_path(params, candidate_uid))
                suffix = ' — folder key unavailable' if candidate_uid in inaccessible_uids else ''
                print(f'  {path} ({candidate_uid}){suffix}')
        return target_uids
