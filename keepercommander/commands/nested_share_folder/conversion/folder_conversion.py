"""Orchestration for Classic folder subtree conversion."""

import logging

from ...base import Command, user_choice
from .... import sync_down
from ....display import bcolors
from ....error import CommandError
from ....nested_share_folder.common import ROOT_FOLDER_UID
from .conversion_acl import FolderPermissionMigration
from .conversion_app_shares import FolderApplicationShareMigration
from .conversion_planning import (
    FolderConversionPlanner, _CLASSIC_FOLDER_TYPES,
)
from .conversion_records import FolderRecordMigration
from .conversion_retry import FolderConversionRetry
from .conversion_tree import FolderConversionTree
from .conversion_utils import (
    FolderConversionVerification,
    _classic_folder_label, _escape_non_printable,
    _nested_share_folder_label, _print_conversion_step, _print_skipped_pam_records,
    _resolve_destination_folder,
)
from ..parsers import nested_share_folder_convert_parser


class NestedShareFolderConvertCommand(Command):
    """Convert a Classic folder subtree to Nested Share Folders and Records."""

    def get_parser(self):
        """Return the parser for Classic folder subtree conversion."""
        return nested_share_folder_convert_parser

    def execute(self, params, **kwargs):
        """Plan, migrate, verify, and optionally delete a Classic folder tree."""
        source_arg = kwargs.get('source')
        if not source_arg:
            raise CommandError(
                'nsf-convert-folder',
                'A Classic folder UID, title, or path is required.')
        source_label = _escape_non_printable(source_arg)
        retry = bool(kwargs.get('retry'))
        if retry and kwargs.get('force'):
            raise CommandError(
                'nsf-convert-folder',
                '--retry cannot be combined with --force because retry requires confirmation.')
        try:
            sync_down.sync_down(params)
        except Exception as exc:
            raise CommandError(
                'nsf-convert-folder',
                f'Could not refresh the vault before conversion; no changes were made. '
                f'{_escape_non_printable(exc)}') from exc

        source_uid = FolderConversionPlanner._resolve_classic_folder(params, source_arg)
        if not source_uid:
            raise CommandError(
                'nsf-convert-folder', f"Classic folder '{source_label}' was not found.")

        source_node = (getattr(params, 'folder_cache', {}) or {}).get(source_uid)
        if source_node is None or source_node.type not in _CLASSIC_FOLDER_TYPES:
            raise CommandError(
                'nsf-convert-folder',
                f"'{source_label}' is not a Classic folder.")

        destination_uid = self._resolve_destination(
            params, kwargs.get('folder_uid'), force=kwargs.get('force', False))
        nodes, parents, depths, records_by_folder = (
            FolderConversionPlanner._collect_classic_subtree(params, source_uid))
        destination_depth = FolderConversionTree._destination_depth(
            params, destination_uid)
        available_depth, target_levels, target_parent_sources = (
            FolderConversionPlanner._folder_plan(parents, depths, destination_depth))

        source_record_uids, placements, skipped_pam_records = (
            FolderConversionPlanner._collect_records(
                params, nodes, records_by_folder, allow_converted=retry))
        preconverted_uids = (
            set(source_record_uids) &
            set(getattr(params, 'nested_share_records', {}) or {})
            if retry else set())
        records_to_convert = [
            uid for uid in source_record_uids if uid not in preconverted_uids
        ]
        records_to_convert_by_folder = {uid: [] for uid in nodes}
        for record_uid, folder_uids in placements.items():
            if record_uid in preconverted_uids:
                continue
            for folder_uid in folder_uids:
                records_to_convert_by_folder[folder_uid].append(record_uid)
        external_placements = FolderConversionPlanner._external_placements(
            params, source_record_uids, set(nodes))
        if external_placements:
            details = '; '.join(
                f'{record_uid}: {", ".join(folder_uids)}'
                for record_uid, folder_uids in list(external_placements.items())[:5])
            raise CommandError(
                'nsf-convert-folder',
                'Some records also appear outside the selected Classic subtree, and '
                'nsf-convert-folder cannot preserve those placements. Convert the enclosing '
                f'tree or resolve those placements first. {details}')

        scope_by_folder = {
            uid: FolderConversionPlanner._classic_scope_uid(node)
            for uid, node in nodes.items()
        }
        scope_grants = FolderPermissionMigration._scope_grant_targets(
            nodes, target_parent_sources, scope_by_folder)
        scope_accessors = {
            scope_uid: FolderPermissionMigration._scope_accessors(params, scope_uid)
            for scope_uid, _ in scope_grants
        }

        FolderConversionTree._validate_folder_keys(params, destination_uid)
        destination_accessors = FolderPermissionMigration._destination_accessors(
            params, destination_uid)
        record_access_plan = FolderPermissionMigration._record_access_plan(
            params, placements, scope_by_folder, destination_accessors)
        existing_target_uids = {}
        if retry:
            existing_target_uids = FolderConversionRetry._select_retry_folders(
                params, nodes, target_levels, target_parent_sources,
                destination_uid, records_by_folder)
        self._print_preview(
            params, nodes, records_to_convert_by_folder, source_node, destination_uid,
            available_depth, records_to_convert, depths, target_levels,
            skipped_pam_records,
            destination_accessors=destination_accessors)

        if kwargs.get('dry_run'):
            return
        if not kwargs.get('force'):
            if user_choice(
                    'Do you want to proceed with folder conversion?', 'yn',
                    default='n').lower() != 'y':
                logging.info('Folder conversion cancelled.')
                return

        applications = FolderApplicationShareMigration._read_applications(params)
        folder_app_shares, record_app_shares = (
            FolderApplicationShareMigration._collect_app_shares(
                applications, set(scope_by_folder.values()), source_record_uids))
        linked_app_uids = {
            share['app_uid']
            for shares in (folder_app_shares, record_app_shares)
            for app_shares in shares.values()
            for share in app_shares
        }
        missing_app_keys = sorted(
            app_uid for app_uid in linked_app_uids
            if not (applications.get(app_uid) or {}).get('key'))
        if missing_app_keys:
            raise CommandError(
                'nsf-convert-folder',
                'Application keys are unavailable for linked KSM application(s): '
                + ', '.join(missing_app_keys[:5]))

        _print_conversion_step(1, 6, 'Creating NSF folder structure...')
        target_uids = FolderConversionTree._create_target_tree(
            params, nodes, target_levels, target_parent_sources,
            destination_uid, show_progress=True,
            existing_target_uids=existing_target_uids)
        params.sync_data = True
        FolderConversionTree._print_uid_mapping(nodes, target_uids)

        # Apply folder-level ACLs before record conversion so converted
        # records inherit the intended access from their destination folders.
        _print_conversion_step(
            2, 6, 'Migrating folder permissions and application shares...')
        try:
            FolderPermissionMigration._grant_scope_access(
                params, scope_grants, scope_accessors, target_uids)
            FolderApplicationShareMigration._grant_folder_app_shares(
                params, folder_app_shares, scope_by_folder, target_uids, applications)
        except Exception as exc:
            params.sync_data = True
            raise CommandError(
                'nsf-convert-folder',
                f'NSF folders were created, but permission migration failed; some folder '
                f'permissions may already have been applied. The Classic tree was left '
                f'intact, and no NSF rollback was attempted. Review the target folders '
                f'and rerun with --retry to reconcile. {exc}')

        _print_conversion_step(
            3, 6,
            f'Converting {len(records_to_convert)} supported Classic record(s)...')
        converted_uids = preconverted_uids | FolderRecordMigration._convert_records(
            params, records_to_convert, placements, target_uids)
        if converted_uids:
            try:
                sync_down.sync_down(params)
            except Exception as exc:
                logging.warning(
                    'Could not refresh the vault after record conversion: %s', exc)

        _print_conversion_step(
            4, 6, 'Applying record permissions and preserving placements/app shares...')
        link_failures = FolderRecordMigration._create_additional_placements(
            params, converted_uids, placements, target_uids,
            include_primary_for=converted_uids if retry else set())
        if link_failures:
            for failure in link_failures:
                logging.warning('Could not preserve record placement: %s', failure)

        record_permission_failures = FolderPermissionMigration._grant_record_accesses(
            params, record_access_plan, converted_uids)
        for failure in record_permission_failures:
            logging.warning('Could not preserve Classic record permissions: %s', failure)

        app_share_failures = FolderApplicationShareMigration._grant_record_app_shares(
            params, record_app_shares, converted_uids, applications)
        for failure in app_share_failures:
            logging.warning('Could not preserve application record share: %s', failure)

        _print_conversion_step(5, 6, 'Verifying conversion results...')
        conversion_complete, verification_issues = FolderConversionVerification.verify(
            params, source_record_uids, converted_uids, target_uids, placements,
            retry, link_failures, record_permission_failures, app_share_failures)
        if not conversion_complete:
            FolderConversionRetry._print_incomplete_conversion(
                params, source_uid, destination_uid, source_record_uids,
                converted_uids, target_uids, existing_target_uids,
                diagnostics=verification_issues)
            return
        print(f'\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Conversion complete{bcolors.ENDC}')
        print(f'  NSF folders created: {len(target_uids) - len(existing_target_uids)}')
        if existing_target_uids:
            print(f'  Existing NSF folders reused: {len(existing_target_uids)}')
        print(f'  Classic records converted: {len(converted_uids)}')
        if preconverted_uids:
            print(f'  Records already converted before retry: {len(preconverted_uids)}')
        print(f'  PAM records skipped: {len(skipped_pam_records)}')
        if skipped_pam_records:
            _print_conversion_step(
                6, 6, 'Keeping the Classic source tree because PAM records were skipped.')
            print(
                f'  {bcolors.WARNING}Classic source tree retained because skipped '
                f'PAM records remain in it.{bcolors.ENDC}')
            return

        if not kwargs.get('force'):
            if user_choice(
                    'Conversion succeeded. Do you want to delete the Classic source tree?',
                    'yn', default='n').lower() != 'y':
                _print_conversion_step(6, 6, 'Keeping the Classic source tree.')
                return

        _print_conversion_step(6, 6, 'Deleting the Classic source tree...')
        delete_result = FolderConversionTree._delete_classic_source(params, source_uid)
        if delete_result is False:
            print(
                f'  {bcolors.WARNING}Classic source tree retained because it could '
                f'not be verified empty.{bcolors.ENDC}')
        elif delete_result is None:
            print(
                f'  {bcolors.WARNING}Classic source tree deletion status is unknown; '
                f'run sync-down and inspect the source tree.{bcolors.ENDC}')

    @staticmethod
    def _resolve_destination(params, folder_arg, force=False):
        """Resolve an optional NSF destination folder."""
        if not folder_arg or folder_arg.casefold() in ('root', ROOT_FOLDER_UID.casefold()):
            return None
        return _resolve_destination_folder(
            params, folder_arg, 'nsf-convert-folder', force=force)

    @staticmethod
    def _print_preview(params, nodes, records_by_folder, source_node, destination_uid,
                       available_depth, record_uids, source_depths, target_levels,
                       skipped_pam_records, destination_accessors=None):
        """Show the complete conversion plan before any changes are made."""
        destination = _nested_share_folder_label(params, destination_uid)
        print(
            f'\n{"=" * 72}\n'
            f'{bcolors.BOLD}Classic-to-NSF folder conversion preview{bcolors.ENDC}\n'
            f'{"=" * 72}\n'
            f'{bcolors.WARNING}Warning: Folder conversion is permanent. '
            'The Classic folder tree will only be deleted after a fully successful '
            'conversion and confirmation (unless --force is used).'
            f'{bcolors.ENDC}')
        print(f'Source: {_classic_folder_label(source_node)}')
        print(f'Destination: {destination}')
        if destination_uid:
            print('\nAccess inherited by new folders from the destination:')
            if not destination_accessors:
                print('  No inherited access grants found.')
            else:
                for accessor in destination_accessors:
                    access_type = accessor.get('access_type')
                    kind = {
                        'AT_APPLICATION': 'Application',
                        'AT_OWNER': 'Owner',
                        'AT_TEAM': 'Team',
                        'AT_USER': 'User',
                    }.get(
                        access_type,
                        access_type[3:].replace('_', ' ').title()
                        if isinstance(access_type, str) and access_type.startswith('AT_')
                        else 'Unknown accessor')
                    accessor_uid = accessor.get('accessor_uid') or 'Unknown'
                    identifier = (
                        accessor.get('username') or accessor_uid)
                    if accessor.get('hidden'):
                        identifier = f'Hidden {kind.lower()} ({accessor_uid})'
                    role = (accessor.get('role') or 'unknown').replace('_', ' ').lower()
                    location = (
                        'already inherited by destination'
                        if accessor.get('inherited') else 'granted directly on destination')
                    print(
                        f'  - {kind}: {_escape_non_printable(identifier)} '
                        f'— {role}; {location}')
        _print_skipped_pam_records(skipped_pam_records)
        if skipped_pam_records:
            print(
                'The Classic source tree will be retained so skipped PAM records '
                'remain in their Classic folders.')
        overflow = sum(
            1 for depth in source_depths.values() if depth > available_depth)
        if overflow:
            print(
                f'{overflow} folder(s) deeper than the available limit will be '
                f'promoted to level {available_depth} as separate folders.')
        print('Source folders:')
        for folder_uid, node in nodes.items():
            record_count = len(records_by_folder.get(folder_uid) or [])
            print(
                f'  - {_escape_non_printable(node.name)} ({folder_uid}) — '
                f'{record_count} record(s)')
        print()
        print(f'{bcolors.BOLD}Summary{bcolors.ENDC}')
        print(f'  Folders: {len(nodes)}')
        print(f'  Records to convert: {len(record_uids)}')
        print(f'  PAM records skipped: {len(skipped_pam_records)}')
        print(f'{"=" * 72}\n')
