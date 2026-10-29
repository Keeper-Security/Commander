"""Commands for converting Classic records and folders to Nested Share data."""

from collections import deque
import json
import logging

from ..base import Command, RecordMixin, user_choice
from ... import nested_share_folder as _nsf
from ... import sync_down, utils
from ...display import bcolors
from ...error import CommandError
from ...subfolder import (
    BaseFolderNode, SharedFolderFolderNode, SharedFolderNode, try_resolve_path,
)
from ...utils import current_milli_time
from ...nested_share_folder.permissions import classic_perms_to_nsf_role
from .helpers import (
    MAX_NESTED_SHARE_FOLDER_DEPTH,
    NSF_APP_INFO_BATCH_SIZE,
    NSF_FOLDER_BATCH_SIZE,
    NSF_FOLDER_RECORD_BATCH_SIZE,
    ROOT_FOLDER_UID,
    _folder_depth,
    command_error_handler,
)
from .parsers import nested_share_convert_parser, nested_share_folder_convert_parser

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

_CLASSIC_FOLDER_TYPES = {
    BaseFolderNode.UserFolderType,
    BaseFolderNode.SharedFolderType,
    BaseFolderNode.SharedFolderFolderType,
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
    return record.record_uid if record else None


def _record_title(params, record_uid):
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


def _resolve_target_folder(params, folder_input):
    """Resolve a Nested Share Folder; omitted/root means the caller's root."""
    if not folder_input or folder_input.casefold() in ('root', ROOT_FOLDER_UID.casefold()):
        return None

    folder_uid = _nsf.resolve_folder_identifier(params, folder_input)
    if not folder_uid:
        raise CommandError('nsf-convert-record', f"Folder '{folder_input}' was not found")
    if folder_uid not in (getattr(params, 'nested_share_folders', {}) or {}):
        raise CommandError(
            'nsf-convert-record',
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
            raise CommandError('nsf-convert-record', 'At least one record is required')

        record_uids = []
        already_nested_share_uids = []
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
            else:
                record_uids.append(record_uid)

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
            title = _record_title(params, record_uid)
            if title:
                quoted_title = json.dumps(title, ensure_ascii=False)
                quoted_title = ''.join(
                    char if char.isprintable() else f'\\u{ord(char):04x}'
                    for char in quoted_title)
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
            if getattr(params, 'service_mode', False):
                from ..pam_import.nsf_helpers import sync_down_preserving_nsf_keys
                sync_down_preserving_nsf_keys(params)
            else:
                params.sync_data = True
        logging.info(
            'Conversion complete: %d of %d Classic record(s) converted; '
            '%d already Nested Share Record(s) skipped.',
            converted, len(record_uids), len(already_nested_share_uids))


def _resolve_classic_folder(params, identifier):
    """Resolve one Classic folder by UID, path, or an unambiguous title."""
    folders = getattr(params, 'folder_cache', {}) or {}
    if identifier in folders:
        return identifier

    resolved = []
    try:
        result = try_resolve_path(params, identifier, find_all_matches=True)
        if result is not None:
            nodes, tail = result
            if not tail:
                resolved.extend(node.uid for node in nodes if node and node.uid)
    except Exception:
        # Fall back to an exact title search below. Path parsing errors are
        # reported as "not found" only after both resolution approaches fail.
        pass

    resolved = list(dict.fromkeys(resolved))
    if len(resolved) == 1:
        return resolved[0]
    if len(resolved) > 1:
        raise CommandError(
            'nsf-convert-folder',
            f"Folder '{identifier}' is ambiguous. Use a folder UID or full path.")

    matches = [
        uid for uid, node in folders.items()
        if getattr(node, 'name', None) and
        node.name.casefold() == identifier.casefold()
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise CommandError(
            'nsf-convert-folder',
            f"Folder '{identifier}' is ambiguous. Use a folder UID or full path.")
    return None


def _classic_scope_uid(node):
    """Return the Classic Shared Folder ACL scope for a node, if any."""
    if isinstance(node, SharedFolderNode):
        return node.uid
    if isinstance(node, SharedFolderFolderNode):
        return node.shared_folder_uid
    return None


def _collect_classic_subtree(params, root_uid):
    """Snapshot the selected Classic subtree and its direct record placements."""
    folder_cache = getattr(params, 'folder_cache', {}) or {}
    record_cache = getattr(params, 'subfolder_record_cache', {}) or {}
    nodes = {}
    parents = {}
    depths = {}
    record_placements = {}

    queue = deque([(root_uid, None, 1)])
    while queue:
        folder_uid, parent_uid, depth = queue.popleft()
        if folder_uid in nodes:
            raise CommandError(
                'nsf-convert-folder',
                f'The source folder tree contains a cycle or duplicate reference at {folder_uid}.')
        node = folder_cache.get(folder_uid)
        if node is None:
            raise CommandError(
                'nsf-convert-folder',
                f'Folder {folder_uid} is missing from the local cache; run sync-down and retry.')
        if node.type not in _CLASSIC_FOLDER_TYPES:
            raise CommandError(
                'nsf-convert-folder',
                f"'{getattr(node, 'name', folder_uid)}' is not a Classic folder.")
        if not node.name:
            raise CommandError(
                'nsf-convert-folder',
                f'Folder {folder_uid} has no name in the local cache.')

        nodes[folder_uid] = node
        parents[folder_uid] = parent_uid
        depths[folder_uid] = depth
        record_placements[folder_uid] = sorted(record_cache.get(folder_uid) or [])

        for child_uid in getattr(node, 'subfolders', []) or []:
            if child_uid not in folder_cache:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Child folder {child_uid} is missing from the local cache; '
                    'run sync-down and retry.')
            queue.append((child_uid, folder_uid, depth + 1))

    return nodes, parents, depths, record_placements


def _folder_plan(parents, depths, destination_depth):
    """Map source UIDs to destination levels/parents, flattening overflow.

    Every source folder remains a distinct destination folder. Source folders
    deeper than the available depth become siblings under the deepest allowed
    source ancestor; their names are deliberately not used as identity.
    """
    available_depth = MAX_NESTED_SHARE_FOLDER_DEPTH - destination_depth
    if available_depth < 1:
        raise CommandError(
            'nsf-convert-folder',
            f'The destination is already at the maximum folder depth '
            f'({MAX_NESTED_SHARE_FOLDER_DEPTH}).')

    target_levels = {
        uid: min(depth, available_depth)
        for uid, depth in depths.items()
    }
    target_parent_sources = {}
    for uid, source_depth in depths.items():
        if source_depth <= available_depth:
            target_parent_sources[uid] = parents[uid]
            continue

        # All overflow folders are promoted to the last representable level.
        # Find the source ancestor at the preceding level (or the external
        # destination when only one level is available).
        promoted_parent = None
        cursor = parents[uid]
        while cursor and depths[cursor] >= available_depth:
            cursor = parents[cursor]
        if cursor and depths[cursor] == available_depth - 1:
            promoted_parent = cursor
        target_parent_sources[uid] = promoted_parent

    return available_depth, target_levels, target_parent_sources


def _current_user_account_uid(params):
    account_uid = getattr(params, 'account_uid_bytes', None)
    if not account_uid:
        return None
    return utils.base64_url_encode(account_uid)


def _scope_accessors(params, scope_uid):
    """Build user/team grants from the Classic Shared Folder cache."""
    shared_folder = (getattr(params, 'shared_folder_cache', {}) or {}).get(scope_uid)
    if shared_folder is None:
        raise CommandError(
            'nsf-convert-folder',
            f'Access details for Classic Shared Folder {scope_uid} are not cached; '
            'run sync-down and retry.')

    accessors = []
    seen = set()
    for user in shared_folder.get('users') or []:
        identifier = user.get('username') or user.get('account_uid')
        if not identifier:
            continue
        key = ('user', (user.get('account_uid') or identifier).casefold())
        if key in seen:
            continue
        seen.add(key)
        accessors.append({
            'identifier': identifier,
            '_account_uid': user.get('account_uid'),
            'as_team': False,
            'role': classic_perms_to_nsf_role(
                user.get('manage_users'), user.get('manage_records')),
            'expiration': user.get('expiration'),
        })

    for team in shared_folder.get('teams') or []:
        identifier = team.get('team_uid')
        if not identifier:
            continue
        key = ('team', identifier)
        if key in seen:
            continue
        seen.add(key)
        accessors.append({
            'identifier': identifier,
            'as_team': True,
            'role': classic_perms_to_nsf_role(
                team.get('manage_users'), team.get('manage_records')),
            'expiration': team.get('expiration'),
        })

    # The Classic owner is not always represented in the member list. NSF
    # folders are owned by the converting account, so preserve a different
    # Classic owner as a full manager on the migrated ACL boundary.
    owner_uid = shared_folder.get('owner_account_uid')
    current_uid = _current_user_account_uid(params)
    if owner_uid and owner_uid != current_uid:
        existing = next((a for a in accessors if not a['as_team'] and
                         (a.get('_account_uid') == owner_uid or
                          a['identifier'] == owner_uid)), None)
        if existing:
            existing['role'] = 'full-manager'
            existing['expiration'] = None
        else:
            accessors.append({
                'identifier': owner_uid,
                'as_team': False,
                'role': 'full-manager',
                'expiration': None,
            })
    return accessors


def _read_applications(params):
    """Read visible KSM app shares in batches for Classic folder/record migration."""
    from ..ksm import KSMCommand

    candidates = {}
    for uid, record in (getattr(params, 'record_cache', {}) or {}).items():
        app = KSMCommand._app_record_from_cache_entry(record)
        if app:
            app = dict(app)
            app.setdefault('record_uid', uid)
            candidates[uid] = app
    for uid in (getattr(params, 'nested_share_records', {}) or {}):
        app = KSMCommand._normalize_nsf_app_record(
            params, uid, require_key=False)
        if app:
            candidates[uid] = app

    applications = {}
    for app_uid, app_record in candidates.items():
        applications[app_uid] = {
            'key': app_record.get('record_key_unencrypted'),
            'shares': [],
        }

    app_uids = list(applications)
    for start in range(0, len(app_uids), NSF_APP_INFO_BATCH_SIZE):
        batch = app_uids[start:start + NSF_APP_INFO_BATCH_SIZE]
        try:
            app_info_list = KSMCommand.get_app_info_batch(params, batch)
        except Exception as exc:
            batch_label = ', '.join(batch[:5])
            if len(batch) > 5:
                batch_label += f', ... ({len(batch)} applications)'
            raise CommandError(
                'nsf-convert-folder',
                f'Could not inspect KSM application batch [{batch_label}]: {exc}')

        returned_app_uids = set()
        for app_info in app_info_list or []:
            app_uid = utils.base64_url_encode(app_info.appRecordUid)
            returned_app_uids.add(app_uid)
            app = applications.get(app_uid)
            if app is None:
                continue
            for share in app_info.shares or []:
                app['shares'].append({
                    'uid': utils.base64_url_encode(share.secretUid),
                    'type': int(share.shareType),
                    'editable': bool(share.editable),
                })
        missing_app_uids = set(batch) - returned_app_uids
        if missing_app_uids:
            missing_apps = ', '.join(sorted(missing_app_uids)[:5])
            raise CommandError(
                'nsf-convert-folder',
                f'No application details were returned for KSM application(s): '
                f'{missing_apps}')
    return applications


def _classic_folder_label(node):
    return f'{node.name} ({node.uid})'


class NestedShareFolderConvertCommand(Command):
    """Convert a Classic folder subtree to Nested Share Folders and Records."""

    def get_parser(self):
        return nested_share_folder_convert_parser

    def execute(self, params, **kwargs):
        source_arg = kwargs.get('source')
        if not source_arg:
            raise CommandError(
                'nsf-convert-folder',
                'A Classic folder UID, title, or path is required.')
        source_uid = _resolve_classic_folder(params, source_arg)
        if not source_uid:
            raise CommandError(
                'nsf-convert-folder', f"Classic folder '{source_arg}' was not found.")

        source_node = (getattr(params, 'folder_cache', {}) or {}).get(source_uid)
        if source_node is None or source_node.type not in _CLASSIC_FOLDER_TYPES:
            raise CommandError(
                'nsf-convert-folder',
                f"'{source_arg}' is not a Classic folder.")

        destination_uid = self._resolve_destination(params, kwargs.get('folder_uid'))
        nodes, parents, depths, records_by_folder = _collect_classic_subtree(params, source_uid)
        destination_depth = self._destination_depth(params, destination_uid)
        available_depth, target_levels, target_parent_sources = _folder_plan(
            parents, depths, destination_depth)

        source_record_uids, placements = self._collect_records(
            params, nodes, records_by_folder)
        external_placements = self._external_placements(
            params, source_record_uids, set(nodes))
        if external_placements:
            details = '; '.join(
                f'{record_uid}: {", ".join(folder_uids)}'
                for record_uid, folder_uids in list(external_placements.items())[:5])
            raise CommandError(
                'nsf-convert-folder',
                'Some records also appear outside the selected Classic subtree, and '
                'nsf-convert-record cannot preserve those placements. Convert the enclosing '
                f'tree or resolve those placements first. {details}')

        scope_by_folder = {
            uid: _classic_scope_uid(node) for uid, node in nodes.items()
        }
        scope_grants = self._scope_grant_targets(
            nodes, target_parent_sources, scope_by_folder)
        scope_accessors = {
            scope_uid: _scope_accessors(params, scope_uid)
            for scope_uid in {scope for scope, _ in scope_grants}
        }

        self._validate_folder_keys(params, destination_uid)
        self._print_preview(
            nodes, records_by_folder, source_node, destination_uid,
            available_depth, source_record_uids, depths, target_levels)

        if kwargs.get('dry_run'):
            return
        if not kwargs.get('force'):
            if user_choice(
                    'Do you want to proceed with folder conversion?', 'yn',
                    default='n').lower() != 'y':
                logging.info('Folder conversion cancelled.')
                return

        applications = _read_applications(params)
        folder_app_shares, record_app_shares = self._collect_app_shares(
            applications, set(scope_by_folder.values()), source_record_uids)
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

        target_uids = self._create_target_tree(
            params, nodes, target_levels, target_parent_sources,
            scope_by_folder, destination_uid, show_progress=True)
        params.sync_data = True
        self._log_uid_mapping(nodes, target_uids)

        # Apply folder-level ACLs before record conversion so converted
        # records inherit the intended access from their destination folders.
        try:
            self._grant_scope_access(params, scope_grants, scope_accessors, target_uids)
            self._grant_folder_app_shares(
                params, folder_app_shares, scope_by_folder, target_uids, applications)
        except Exception as exc:
            params.sync_data = True
            raise CommandError(
                'nsf-convert-folder',
                f'NSF folders were created, but permission migration failed; '
                f'the Classic tree was left intact. {exc}')

        converted_uids = self._convert_records(
            params, source_record_uids, placements, target_uids)
        if converted_uids:
            sync_down.sync_down(params)

        link_failures = self._create_additional_placements(
            params, converted_uids, placements, target_uids)
        if link_failures:
            for failure in link_failures:
                logging.warning('Could not preserve record placement: %s', failure)

        app_share_failures = self._grant_record_app_shares(
            params, record_app_shares, converted_uids, applications)
        for failure in app_share_failures:
            logging.warning('Could not preserve application record share: %s', failure)
        sync_down.sync_down(params)

        conversion_complete = (
            len(converted_uids) == len(source_record_uids) and
            not link_failures and not app_share_failures)
        missing_folders = [
            uid for uid in target_uids.values()
            if uid not in (getattr(params, 'nested_share_folders', {}) or {})
        ]
        if missing_folders:
            conversion_complete = False
            logging.warning(
                'Sync-down did not confirm %d created NSF folder(s).',
                len(missing_folders))
        if source_record_uids and conversion_complete:
            missing_records = [
                uid for uid in source_record_uids
                if uid not in (getattr(params, 'nested_share_records', {}) or {})
            ]
            if missing_records:
                conversion_complete = False
                logging.warning(
                    'Sync-down did not confirm %d converted record(s).',
                    len(missing_records))

        params.sync_data = True
        if not conversion_complete:
            logging.warning(
                'Folder conversion was partial. The Classic source tree was not deleted.')
            return

        if not kwargs.get('force'):
            if user_choice(
                    'Conversion succeeded. Do you want to delete the Classic source tree?',
                    'yn', default='n').lower() != 'y':
                logging.info('Classic source tree retained.')
                return

        self._delete_classic_source(params, source_uid)

    @staticmethod
    def _resolve_destination(params, folder_arg):
        if not folder_arg or folder_arg.casefold() in ('root', ROOT_FOLDER_UID.casefold()):
            return None
        folder_uid = _nsf.resolve_folder_identifier(params, folder_arg)
        if not folder_uid:
            raise CommandError(
                'nsf-convert-folder', f"Destination folder '{folder_arg}' was not found.")
        if folder_uid not in (getattr(params, 'nested_share_folders', {}) or {}):
            raise CommandError(
                'nsf-convert-folder',
                f"Destination '{folder_arg}' is not a Nested Share Folder.")
        return folder_uid

    @staticmethod
    def _destination_depth(params, destination_uid):
        if not destination_uid:
            return 0
        depth = _folder_depth(params, destination_uid)
        if depth <= 0:
            raise CommandError(
                'nsf-convert-folder',
                f'Could not determine the depth of destination folder {destination_uid}.')
        return depth

    @staticmethod
    def _validate_folder_keys(params, destination_uid):
        if not getattr(params, 'data_key', None):
            raise CommandError(
                'nsf-convert-folder', 'User data key is unavailable; run sync-down and retry.')
        if destination_uid:
            try:
                _nsf.get_folder_key(params, destination_uid, raise_on_missing=True)
            except Exception as exc:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Destination folder key is unavailable; run sync-down and retry. {exc}')

    @staticmethod
    def _collect_records(params, nodes, records_by_folder):
        nested_records = getattr(params, 'nested_share_records', {}) or {}
        record_cache = getattr(params, 'record_cache', {}) or {}
        records = set()
        placements = {}
        for folder_uid in nodes:
            for record_uid in records_by_folder.get(folder_uid) or []:
                if record_uid in nested_records:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Record {record_uid} is already a Nested Share Record.')
                if record_uid not in record_cache:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Record {record_uid} is missing from the Classic record cache; '
                        'run sync-down and retry.')
                owner_info = (getattr(params, 'record_owner_cache', {}) or {}).get(record_uid)
                if owner_info is not None and getattr(owner_info, 'owner', None) is False:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Record {record_uid} is not owned by the caller and cannot be converted.')
                records.add(record_uid)
                placements.setdefault(record_uid, []).append(folder_uid)
        # Placements retain tree order so the primary target is deterministic.
        ordered_records = sorted(records)
        for record_uid in placements:
            placements[record_uid] = list(dict.fromkeys(placements[record_uid]))
        return ordered_records, placements

    @staticmethod
    def _external_placements(params, records, selected_folder_uids):
        all_placements = getattr(params, 'subfolder_record_cache', {}) or {}
        result = {}
        for record_uid in records:
            outside = sorted(
                folder_uid for folder_uid, record_uids in all_placements.items()
                if record_uid in (record_uids or set()) and
                folder_uid not in selected_folder_uids)
            if outside:
                result[record_uid] = outside
        return result

    @staticmethod
    def _scope_grant_targets(nodes, target_parent_sources, scope_by_folder):
        grants = []
        for folder_uid in nodes:
            scope_uid = scope_by_folder.get(folder_uid)
            if not scope_uid:
                continue
            target_parent_source = target_parent_sources.get(folder_uid)
            parent_scope = (
                scope_by_folder.get(target_parent_source) if target_parent_source else None)
            # A target root attached to the caller's destination, or any
            # Classic Shared Folder boundary, must carry its own ACL.
            if target_parent_source is None or parent_scope != scope_uid:
                grants.append((scope_uid, folder_uid))
        return grants

    @staticmethod
    def _collect_app_shares(applications, scopes, record_uids):
        from ...proto import APIRequest_pb2

        folder_type = APIRequest_pb2.ApplicationShareType.Value('SHARE_TYPE_FOLDER')
        record_type = APIRequest_pb2.ApplicationShareType.Value('SHARE_TYPE_RECORD')
        folder_shares = {}
        record_shares = {}
        scopes = {uid for uid in scopes if uid}
        record_uids = set(record_uids)
        for app_uid, app in applications.items():
            for share in app['shares']:
                if share['type'] == folder_type and share['uid'] in scopes:
                    folder_shares.setdefault(share['uid'], []).append({
                        'app_uid': app_uid, 'editable': share['editable'],
                    })
                elif share['type'] == record_type and share['uid'] in record_uids:
                    record_shares.setdefault(share['uid'], []).append({
                        'app_uid': app_uid, 'editable': share['editable'],
                    })
        return folder_shares, record_shares

    @staticmethod
    def _print_preview(nodes, records_by_folder, source_node, destination_uid,
                       available_depth, record_uids, source_depths, target_levels):
        destination = destination_uid or 'Vault (root)'
        print(
            f'\n{bcolors.WARNING}Warning: Folder conversion is permanent. '
            'The Classic folder tree will only be deleted after a fully successful '
            'conversion and confirmation (unless --force is used).'
            f'{bcolors.ENDC}')
        print(f'Source: {_classic_folder_label(source_node)}')
        print(f'Destination: {destination}')
        print(f'Folders: {len(nodes)}; unique records: {len(record_uids)}')
        overflow = sum(
            1 for depth in source_depths.values() if depth > available_depth)
        if overflow:
            print(
                f'{overflow} folder(s) deeper than the available limit will be '
                f'promoted to level {available_depth} as separate folders.')
        print('Source folders:')
        for folder_uid, node in nodes.items():
            record_count = len(records_by_folder.get(folder_uid) or [])
            print(f'  {node.name} ({folder_uid}) — {record_count} record(s)')

    @staticmethod
    def _create_target_tree(params, nodes, target_levels, target_parent_sources,
                            scope_by_folder, destination_uid, show_progress):
        if getattr(params, 'nested_share_folders', None) is None:
            params.nested_share_folders = {}
        target_uids = {}
        for target_level in sorted(set(target_levels.values())):
            source_uids = [
                uid for uid, level in target_levels.items() if level == target_level
            ]
            for start in range(0, len(source_uids), NSF_FOLDER_BATCH_SIZE):
                chunk = source_uids[start:start + NSF_FOLDER_BATCH_SIZE]
                specs = []
                for source_uid in chunk:
                    source_node = nodes[source_uid]
                    parent_source_uid = target_parent_sources[source_uid]
                    parent_uid = (
                        target_uids[parent_source_uid] if parent_source_uid
                        else destination_uid
                    )
                    parent_scope = (
                        scope_by_folder.get(parent_source_uid) if parent_source_uid else None)
                    inherit_permissions = bool(parent_source_uid and
                                               parent_scope == scope_by_folder.get(source_uid))
                    specs.append({
                        'name': source_node.name,
                        'parent_uid': parent_uid,
                        'color': getattr(source_node, 'color', None),
                        'inherit_permissions': inherit_permissions,
                    })

                # Ensure an uncertain transport failure triggers a refresh;
                # the batch API allocates UIDs internally before sending.
                params.sync_data = True
                try:
                    results = _nsf.create_folders_batch_v3(params, specs)
                except Exception as exc:
                    raise CommandError(
                        'nsf-convert-folder',
                        'The outcome of an NSF folder creation request is unknown. '
                        'Run sync-down and inspect the destination before retrying; '
                        f'the Classic source tree was left intact. {exc}')
                if len(results) != len(chunk):
                    params.sync_data = True
                    raise CommandError(
                        'nsf-convert-folder',
                        'Folder creation returned an incomplete result set; '
                        'the Classic source tree was left intact.')
                failures = []
                for source_uid, result in zip(chunk, results):
                    if not result.get('success'):
                        failures.append(
                            f"{nodes[source_uid].name} ({source_uid}): "
                            f"{result.get('message') or result.get('status')}")
                        continue
                    target_uid = result['folder_uid']
                    target_uids[source_uid] = target_uid
                    entry = {
                        'name': result.get('name') or nodes[source_uid].name,
                        'parent_uid': result.get('parent_uid') or
                                      (target_uids.get(target_parent_sources[source_uid])
                                       if target_parent_sources[source_uid]
                                       else destination_uid or ''),
                        'folder_key_unencrypted': result['folder_key_unencrypted'],
                    }
                    color = getattr(nodes[source_uid], 'color', None)
                    if color and color != 'none':
                        entry['color'] = color
                    params.nested_share_folders[target_uid] = entry

                if failures:
                    params.sync_data = True
                    raise CommandError(
                        'nsf-convert-folder',
                        'Could not create the full NSF folder tree; the Classic source '
                        'tree was left intact. ' + '; '.join(failures[:5]))

                if show_progress:
                    logging.info(
                        'Created %d NSF folder(s) at target depth %d.',
                        len(chunk), target_level)
        return target_uids

    @staticmethod
    def _log_uid_mapping(nodes, target_uids):
        logging.info('Classic-to-NSF folder UID mapping:')
        for source_uid, target_uid in target_uids.items():
            logging.info(
                '  %s (%s) -> %s', nodes[source_uid].name, source_uid, target_uid)

    @staticmethod
    def _grant_scope_access(params, scope_grants, scope_accessors, target_uids):
        current_user = (getattr(params, 'user', '') or '').casefold()
        current_account_uid = _current_user_account_uid(params)
        now_ms = current_milli_time()
        for scope_uid, source_uid in scope_grants:
            target_uid = target_uids[source_uid]
            for accessor in scope_accessors.get(scope_uid) or []:
                identifier = accessor['identifier']
                if (not accessor['as_team'] and
                        (identifier.casefold() == current_user or
                         identifier == current_account_uid)):
                    continue
                expiration = accessor.get('expiration')
                if expiration is not None and expiration <= 0:
                    expiration = None
                if expiration and expiration <= now_ms:
                    logging.info(
                        'Skipping expired Classic folder access for %s on %s.',
                        identifier, scope_uid)
                    continue
                with command_error_handler('nsf-convert-folder'):
                    result = _nsf.grant_folder_access_v3(
                        params=params,
                        folder_uid=target_uid,
                        user_uid=identifier,
                        role=accessor['role'],
                        expiration_timestamp=expiration,
                        as_team=accessor['as_team'],
                    )
                    if not result.get('success'):
                        raise CommandError(
                            'nsf-convert-folder',
                            f"Could not share target folder {target_uid} with "
                            f"'{identifier}': {result.get('message')}")

    @staticmethod
    def _grant_folder_app_shares(params, folder_app_shares, scope_by_folder,
                                 target_uids, applications):
        for source_uid, scope_uid in scope_by_folder.items():
            if not scope_uid:
                continue
            for share in folder_app_shares.get(scope_uid) or []:
                app = applications[share['app_uid']]
                with command_error_handler('nsf-convert-folder'):
                    result = _nsf.grant_folder_access_to_application_v3(
                        params, target_uids[source_uid], share['app_uid'],
                        app['key'], is_editable=share['editable'])
                    if not result.get('success'):
                        raise CommandError(
                            'nsf-convert-folder',
                            f"Could not preserve KSM application access on "
                            f"{target_uids[source_uid]}: {result.get('message')}")

    @staticmethod
    def _convert_records(params, record_uids, placements, target_uids):
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
                            'Classic record %s converted to a Nested Share Record.',
                            record_uid)
                    else:
                        status = result.get('status') or 'unknown error'
                        logging.warning(
                            'Classic record %s was not converted: %s.',
                            record_uid, status.replace('_', ' ').title())
        return converted

    @staticmethod
    def _create_additional_placements(params, converted_uids, placements, target_uids):
        additional_by_target = {}
        for record_uid in converted_uids:
            locations = placements.get(record_uid) or []
            target_locations = list(dict.fromkeys(target_uids[uid] for uid in locations))
            for target_uid in target_locations[1:]:
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

    @staticmethod
    def _grant_record_app_shares(params, record_app_shares, converted_uids, applications):
        if not record_app_shares:
            return []

        from ..ksm import KSMCommand
        from ...proto import APIRequest_pb2

        targets = [
            (record_uid, share)
            for record_uid in converted_uids
            for share in record_app_shares.get(record_uid) or []
        ]
        app_uids = list(dict.fromkeys(share['app_uid'] for _, share in targets))
        record_share_type = APIRequest_pb2.SHARE_TYPE_RECORD
        share_state = {app_uid: set() for app_uid in app_uids}
        lookup_errors = {}
        for start in range(0, len(app_uids), NSF_APP_INFO_BATCH_SIZE):
            batch = app_uids[start:start + NSF_APP_INFO_BATCH_SIZE]
            try:
                app_info_list = KSMCommand.get_app_info_batch(params, batch)
            except Exception as exc:
                lookup_errors.update({app_uid: exc for app_uid in batch})
                continue
            returned_app_uids = set()
            for app_info in app_info_list or []:
                app_uid = utils.base64_url_encode(app_info.appRecordUid)
                if app_uid not in share_state:
                    continue
                returned_app_uids.add(app_uid)
                share_state[app_uid].update(
                    (utils.base64_url_encode(item.secretUid), bool(item.editable))
                    for item in (app_info.shares or [])
                    if item.shareType == record_share_type)
            for app_uid in set(batch) - returned_app_uids:
                lookup_errors[app_uid] = 'no application details were returned'

        failures = []
        for record_uid, share in targets:
            app_uid = share['app_uid']
            if app_uid in lookup_errors:
                failures.append(
                    f'{record_uid} / application {app_uid}: {lookup_errors[app_uid]}')
                continue
            app = applications.get(app_uid) or {}
            app_key = app.get('key')
            if not app_key:
                failures.append(
                    f'{record_uid} / application {app_uid}: application key is unavailable')
                continue

            existing = share_state[app_uid]
            desired_share = (record_uid, share['editable'])
            if desired_share in existing:
                continue

            try:
                if any(uid == record_uid for uid, _ in existing):
                    result = _nsf.update_record_share_to_application_v3(
                        params, record_uid, app_uid, app_key,
                        is_editable=share['editable'])
                else:
                    result = _nsf.share_record_to_application_v3(
                        params, record_uid, app_uid, app_key,
                        is_editable=share['editable'])
            except Exception as exc:
                failures.append(f'{record_uid} / application {app_uid}: {exc}')
                continue
            if result.get('success'):
                existing.difference_update({
                    current_share for current_share in existing
                    if current_share[0] == record_uid
                })
                existing.add(desired_share)
            else:
                failures.append(
                    f'{record_uid} / application {app_uid}: '
                    f'{result.get("message") or result.get("status") or "share failed"}')
        return failures

    @staticmethod
    def _delete_classic_source(params, source_uid):
        from ..folder import FolderRemoveCommand

        try:
            FolderRemoveCommand().execute(
                params, pattern=[source_uid], force=True, quiet=True)
            sync_down.sync_down(params)
            if source_uid in (getattr(params, 'folder_cache', {}) or {}):
                logging.warning(
                    'The conversion succeeded, but Classic source folder %s '
                    'still appears after deletion.', source_uid)
            else:
                logging.info('Classic source folder tree deleted.')
        except Exception as exc:
            logging.warning(
                'Conversion succeeded, but the Classic source tree could not be '
                'deleted: %s', exc)
