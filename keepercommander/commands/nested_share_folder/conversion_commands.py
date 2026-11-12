"""Commands for converting Classic records and folders to Nested Share data."""

from collections import defaultdict, deque
import json
import logging

from ..base import Command, RecordMixin, user_choice
from ... import nested_share_folder as _nsf
from ... import sync_down, utils, vault
from ...display import bcolors
from ...error import CommandError
from ...nested_share_folder.folder_api import FolderIdentifierAmbiguousError
from ...subfolder import (
    BaseFolderNode, SharedFolderFolderNode, SharedFolderNode, try_resolve_path,
)
from ...utils import current_milli_time
from ...nested_share_folder.permissions import (
    classic_record_permissions_to_nsf_role,
    classic_shared_folder_permissions_to_nsf_role,
    merge_record_access_roles,
)
from ...nested_share_folder.common import (
    MAX_NESTED_SHARE_FOLDER_DEPTH,
    NSF_APP_INFO_BATCH_SIZE,
    NSF_FOLDER_ACCESS_PAGE_SIZE,
    NSF_FOLDER_BATCH_SIZE,
    NSF_FOLDER_RECORD_BATCH_SIZE,
    NSF_RECORD_BATCH_SIZE,
    PAM_RECORD_TYPE_PREFIX,
    ROOT_FOLDER_UID,
    resolve_user_uid_bytes,
)
from .helpers import (
    _folder_depth,
    command_error_handler,
    resolve_record_uid,
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
    if record:
        return record.record_uid

    # Preserve current-folder/path selection above, but still distinguish an
    # ambiguous title from a genuinely missing record.
    resolve_record_uid(params, identifier, 'nsf-convert-record')
    return None


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


def _escape_non_printable(value):
    return ''.join(
        char if char.isprintable() else f'\\u{ord(char):04x}'
        for char in str(value)
    )


def _record_type(params, record_uid):
    record = vault.KeeperRecord.load(params, record_uid)
    return getattr(record, 'record_type', '') if record else ''


def _pam_record_details(params, record_uid, record_type=None):
    record_type = str(
        record_type if record_type is not None else _record_type(params, record_uid) or '')
    if not record_type.casefold().startswith(PAM_RECORD_TYPE_PREFIX):
        return None
    return {
        'record_uid': record_uid,
        'record_type': record_type,
        'title': _record_title(params, record_uid),
    }


def _print_skipped_pam_records(records):
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


def _select_numbered_option(prompt, option_count, command, allow_zero=False):
    """Read a numbered interactive choice, returning None when zero is chosen."""
    first_option = 0 if allow_zero else 1
    while True:
        try:
            answer = input(prompt).strip()
        except (EOFError, OSError) as exc:
            raise CommandError(
                command, 'Interactive selection is required; use a folder UID instead.') from exc
        if answer.casefold() in ('q', 'quit', 'cancel'):
            raise CommandError(command, 'Selection cancelled.')
        try:
            selection = int(answer)
        except ValueError:
            selection = -1
        if first_option <= selection <= option_count:
            return None if selection == 0 else selection - 1
        print(f'Enter a number from {first_option} to {option_count}, or q to cancel.')


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


def _resolve_target_folder(params, folder_input, force=False):
    """Resolve a Nested Share Folder; omitted/root means the caller's root."""
    return _resolve_destination_folder(
        params, folder_input, 'nsf-convert-record', force=force)


class NestedShareConvertCommand(Command):
    """Convert one or more Classic records into Nested Share Records."""

    def get_parser(self):
        return nested_share_convert_parser

    def execute(self, params, **kwargs):
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


def _resolve_classic_folder(params, identifier):
    """Resolve one Classic folder by UID, path, or an unambiguous title."""
    folders = getattr(params, 'folder_cache', {}) or {}
    if identifier in folders:
        return identifier

    result = try_resolve_path(params, identifier, find_all_matches=True)
    resolved = []
    if result is not None:
        nodes, tail = result
        if not tail:
            resolved.extend(node.uid for node in nodes if node and node.uid)

    resolved = list(dict.fromkeys(resolved))
    if len(resolved) == 1:
        return resolved[0]
    if len(resolved) > 1:
        raise CommandError(
            'nsf-convert-folder',
            f"Folder '{_escape_non_printable(identifier)}' is ambiguous. "
            'Use a folder UID or full path.')

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
            f"Folder '{_escape_non_printable(identifier)}' is ambiguous. "
            'Use a folder UID or full path.')
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


def _scope_members(params, scope_uid):
    """Return the deduplicated user/team members of a Classic share scope."""
    shared_folder = (getattr(params, 'shared_folder_cache', {}) or {}).get(scope_uid)
    if shared_folder is None:
        raise CommandError(
            'nsf-convert-folder',
            f'Access details for Classic Shared Folder {scope_uid} are not cached; '
            'run sync-down and retry.')

    members = []
    seen = set()
    for user in shared_folder.get('users') or []:
        identifier = user.get('username') or user.get('account_uid')
        if not identifier:
            continue
        account_uid = user.get('account_uid')
        if not account_uid:
            uid_bytes = resolve_user_uid_bytes(params, identifier)
            if uid_bytes:
                account_uid = utils.base64_url_encode(uid_bytes)
        key = ('AT_USER', account_uid or identifier.casefold())
        if key in seen:
            continue
        seen.add(key)
        members.append({
            'identifier': identifier,
            'accessor_uid': account_uid,
            'access_type': 'AT_USER',
            'as_team': False,
            'manage_users': bool(user.get('manage_users')),
            'manage_records': bool(user.get('manage_records')),
            'expiration': user.get('expiration'),
        })

    for team in shared_folder.get('teams') or []:
        identifier = team.get('team_uid')
        if not identifier:
            continue
        key = ('AT_TEAM', identifier)
        if key in seen:
            continue
        seen.add(key)
        members.append({
            'identifier': identifier,
            'accessor_uid': identifier,
            'access_type': 'AT_TEAM',
            'as_team': True,
            'manage_users': bool(team.get('manage_users')),
            'manage_records': bool(team.get('manage_records')),
            'expiration': team.get('expiration'),
        })
    return members


def _scope_accessors(params, scope_uid):
    """Build folder-level NSF grants from Classic member permissions."""
    shared_folder = (getattr(params, 'shared_folder_cache', {}) or {}).get(scope_uid)
    if shared_folder is None:
        raise CommandError(
            'nsf-convert-folder',
            f'Access details for Classic Shared Folder {scope_uid} are not cached; '
            'run sync-down and retry.')

    accessors = []
    for member in _scope_members(params, scope_uid):
        accessors.append({
            'identifier': member['identifier'],
            '_account_uid': member['accessor_uid'],
            'as_team': member['as_team'],
            'role': classic_shared_folder_permissions_to_nsf_role(
                manage_users=member['manage_users'],
                manage_records=member['manage_records']),
            'expiration': member['expiration'],
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


def _classic_record_permissions_by_uid(shared_folder):
    default_permissions = (
        bool(shared_folder.get('default_can_edit')),
        bool(shared_folder.get('default_can_share')),
    )
    permissions_by_uid = {}
    for record in shared_folder.get('records') or []:
        record_uid = record.get('record_uid')
        if record_uid and record_uid not in permissions_by_uid:
            permissions_by_uid[record_uid] = (
                bool(record.get('can_edit', default_permissions[0])),
                bool(record.get('can_share', default_permissions[1])),
            )
    return default_permissions, permissions_by_uid


def _record_accessor_key(access_type, accessor_uid):
    if access_type == 'AT_USER':
        return access_type, accessor_uid if '@' not in accessor_uid else accessor_uid.casefold()
    return access_type, accessor_uid


def _record_access_role_changes_before_expiry(record_roles, expirations):
    active = list(zip(record_roles, expirations))
    current_role = merge_record_access_roles(
        *(role for role, _ in active))
    for expiration in sorted({
            expiration for _, expiration in active if expiration is not None}):
        remaining_roles = [
            role for role, role_expiration in active
            if role_expiration is None or role_expiration > expiration
        ]
        if not remaining_roles:
            break
        next_role = merge_record_access_roles(*remaining_roles)
        if next_role != current_role:
            return True
        current_role = next_role
    return False


def _record_access_plan(params, placements, scope_by_folder, destination_accessors):
    """Plan per-record overrides for each Classic Shared Folder member."""
    shared_folders = getattr(params, 'shared_folder_cache', {}) or {}
    scope_members = {}
    scope_record_permissions = {}
    role_by_record_accessor = defaultdict(list)
    folder_role_by_record_accessor = defaultdict(list)
    expiration_by_record_accessor = defaultdict(list)
    email_by_record_accessor = {}

    now_ms = current_milli_time()
    current_uid = _current_user_account_uid(params)
    for record_uid, source_folders in placements.items():
        seen_scopes = set()
        for source_folder_uid in source_folders:
            scope_uid = scope_by_folder.get(source_folder_uid)
            if not scope_uid or scope_uid in seen_scopes:
                continue
            seen_scopes.add(scope_uid)
            shared_folder = shared_folders.get(scope_uid)
            if shared_folder is None:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Access details for Classic Shared Folder {scope_uid} are not cached; '
                    'run sync-down and retry.')
            if scope_uid not in scope_record_permissions:
                scope_record_permissions[scope_uid] = (
                    _classic_record_permissions_by_uid(shared_folder))
            defaults, permissions_by_uid = scope_record_permissions[scope_uid]
            can_edit, can_share = permissions_by_uid.get(record_uid, defaults)
            record_role = classic_record_permissions_to_nsf_role(
                can_edit=can_edit, can_share=can_share)
            if scope_uid not in scope_members:
                scope_members[scope_uid] = _scope_members(params, scope_uid)
            for member in scope_members[scope_uid]:
                accessor_uid = member.get('accessor_uid') or member['identifier']
                if member['access_type'] == 'AT_USER' and (
                        accessor_uid == current_uid or
                        accessor_uid == shared_folder.get('owner_account_uid')):
                    continue
                expiration = member.get('expiration')
                if expiration is not None and expiration <= 0:
                    expiration = None
                if expiration is not None and expiration <= now_ms:
                    continue
                if member['access_type'] == 'AT_USER' and '@' in accessor_uid:
                    raise CommandError(
                        'nsf-convert-folder',
                        f"Could not resolve Classic user '{accessor_uid}' to an account UID.")
                key = (
                    record_uid,
                    *_record_accessor_key(member['access_type'], accessor_uid),
                )
                role_by_record_accessor[key].append(record_role)
                folder_role_by_record_accessor[key].append(
                    classic_shared_folder_permissions_to_nsf_role(
                        manage_users=member['manage_users'],
                        manage_records=member['manage_records']))
                expiration_by_record_accessor[key].append(expiration)
                email_by_record_accessor[key] = (
                    member['identifier'] if member['access_type'] == 'AT_USER' else None)

    destination_roles = {}
    expiring_destination_access = set()
    for accessor in destination_accessors or []:
        access_type = accessor.get('access_type')
        accessor_uid = accessor.get('accessor_uid')
        role = accessor.get('role')
        if access_type not in ('AT_USER', 'AT_TEAM') or not accessor_uid or not role:
            continue
        accessor_key = _record_accessor_key(access_type, accessor_uid)
        destination_roles.setdefault(accessor_key, []).append(role)
        expiration = accessor.get('tla_expiration')
        if expiration and expiration > now_ms:
            expiring_destination_access.add(accessor_key)

    plan = []
    for key, record_roles in role_by_record_accessor.items():
        record_uid, access_type, accessor_uid = key
        accessor_key = _record_accessor_key(access_type, accessor_uid)
        destination_role_list = destination_roles.get(accessor_key, [])
        classic_record_role = merge_record_access_roles(*record_roles)
        desired_role = merge_record_access_roles(classic_record_role, *destination_role_list)
        inherited_role = merge_record_access_roles(
            *folder_role_by_record_accessor[key], *destination_role_list)
        if desired_role == inherited_role:
            continue
        if _record_access_role_changes_before_expiry(
                record_roles, expiration_by_record_accessor[key]):
            raise CommandError(
                'nsf-convert-folder',
                f'Classic permissions for {accessor_uid} on record {record_uid} '
                'change role before all access expires, which cannot be represented '
                'by one NSF record permission. Align the Classic share expirations '
                'and retry.')
        if (accessor_key in expiring_destination_access and
                desired_role != classic_record_role):
            raise CommandError(
                'nsf-convert-folder',
                f'Cannot safely preserve expiring destination access for '
                f'{accessor_uid} on record {record_uid} while applying a different '
                'Classic record role. Remove the destination expiration or convert '
                'the Classic tree at the vault root.')

        expirations = expiration_by_record_accessor[key]
        expiration = (
            None if any(value is None for value in expirations)
            else max(expirations) if expirations else None)
        plan.append({
            'record_uid': record_uid,
            'accessor_uid': accessor_uid,
            'access_type': access_type,
            'access_role_type': desired_role,
            'expiration_timestamp': expiration,
            'email': email_by_record_accessor.get(key),
        })
    return plan


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
    return f'{_escape_non_printable(node.name)} ({node.uid})'


def _nested_share_folder_label(params, folder_uid):
    if not folder_uid:
        return 'Vault (root)'
    folder = (getattr(params, 'nested_share_folders', {}) or {}).get(folder_uid) or {}
    name = folder.get('name') or folder_uid
    name = _escape_non_printable(name)
    return f'{name} ({folder_uid})' if name != folder_uid else folder_uid


def _print_conversion_step(step, total_steps, message):
    print(f'\n{bcolors.OKBLUE}[{step}/{total_steps}]{bcolors.ENDC} {message}')


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

        source_uid = _resolve_classic_folder(params, source_arg)
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
        nodes, parents, depths, records_by_folder = _collect_classic_subtree(params, source_uid)
        destination_depth = self._destination_depth(params, destination_uid)
        available_depth, target_levels, target_parent_sources = _folder_plan(
            parents, depths, destination_depth)

        source_record_uids, placements, skipped_pam_records = self._collect_records(
            params, nodes, records_by_folder, allow_converted=retry)
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
        external_placements = self._external_placements(
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
            uid: _classic_scope_uid(node) for uid, node in nodes.items()
        }
        scope_grants = self._scope_grant_targets(
            nodes, target_parent_sources, scope_by_folder)
        scope_accessors = {
            scope_uid: _scope_accessors(params, scope_uid)
            for scope_uid, _ in scope_grants
        }

        self._validate_folder_keys(params, destination_uid)
        destination_accessors = self._destination_accessors(params, destination_uid)
        record_access_plan = _record_access_plan(
            params, placements, scope_by_folder, destination_accessors)
        existing_target_uids = {}
        if retry:
            existing_target_uids = self._select_retry_folders(
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

        _print_conversion_step(1, 6, 'Creating NSF folder structure...')
        target_uids = self._create_target_tree(
            params, nodes, target_levels, target_parent_sources,
            destination_uid, show_progress=True,
            existing_target_uids=existing_target_uids)
        params.sync_data = True
        self._print_uid_mapping(nodes, target_uids)

        # Apply folder-level ACLs before record conversion so converted
        # records inherit the intended access from their destination folders.
        _print_conversion_step(
            2, 6, 'Migrating folder permissions and application shares...')
        try:
            self._grant_scope_access(params, scope_grants, scope_accessors, target_uids)
            self._grant_folder_app_shares(
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
        converted_uids = preconverted_uids | self._convert_records(
            params, records_to_convert, placements, target_uids)
        if converted_uids:
            try:
                sync_down.sync_down(params)
            except Exception as exc:
                logging.warning(
                    'Could not refresh the vault after record conversion: %s', exc)

        _print_conversion_step(
            4, 6, 'Applying record permissions and preserving placements/app shares...')
        link_failures = self._create_additional_placements(
            params, converted_uids, placements, target_uids,
            include_primary_for=converted_uids if retry else set())
        if link_failures:
            for failure in link_failures:
                logging.warning('Could not preserve record placement: %s', failure)

        record_permission_failures = self._grant_record_accesses(
            params, record_access_plan, converted_uids)
        for failure in record_permission_failures:
            logging.warning('Could not preserve Classic record permissions: %s', failure)

        app_share_failures = self._grant_record_app_shares(
            params, record_app_shares, converted_uids, applications)
        for failure in app_share_failures:
            logging.warning('Could not preserve application record share: %s', failure)

        _print_conversion_step(5, 6, 'Verifying conversion results...')
        verification_sync_error = None
        try:
            sync_down.sync_down(params)
        except Exception as exc:
            verification_sync_error = exc
            logging.warning('Could not refresh the vault to verify conversion: %s', exc)

        conversion_complete = (
            len(converted_uids) == len(source_record_uids) and
            not link_failures and not record_permission_failures and
            not app_share_failures and
            verification_sync_error is None)
        verification_issues = []
        if verification_sync_error is not None:
            verification_issues.append(
                f'Final sync-down failed, so the last cached record locations may be stale: '
                f'{verification_sync_error}')
        missing_folders = [
            uid for uid in target_uids.values()
            if uid not in (getattr(params, 'nested_share_folders', {}) or {})
        ] if verification_sync_error is None else []
        if missing_folders:
            conversion_complete = False
            verification_issues.append(
                f'{len(missing_folders)} NSF folder(s) were not confirmed by sync-down')
            logging.warning(
                'Sync-down did not confirm %d created NSF folder(s).',
                len(missing_folders))
        missing_records = []
        if source_record_uids and verification_sync_error is None:
            missing_records = [
                uid for uid in source_record_uids
                if uid not in (getattr(params, 'nested_share_records', {}) or {})
            ]
            if missing_records:
                conversion_complete = False
                verification_issues.append(
                    f'{len(missing_records)} converted record(s) were not confirmed by sync-down')
                logging.warning(
                    'Sync-down did not confirm %d converted record(s).',
                    len(missing_records))
        missing_placements = []
        if retry and verification_sync_error is None:
            folder_records = getattr(params, 'nested_share_folder_records', {}) or {}
            missing_placements = [
                (record_uid, target_uids[source_uid])
                for record_uid in source_record_uids
                for source_uid in placements.get(record_uid) or []
                if record_uid in (getattr(params, 'nested_share_records', {}) or {})
                and record_uid not in (folder_records.get(target_uids[source_uid]) or set())
            ]
            if missing_placements:
                conversion_complete = False
                verification_issues.append(
                    f'{len(missing_placements)} record placement(s) were not confirmed')
                logging.warning(
                    'Sync-down did not confirm %d record placement(s) in retry targets.',
                    len(missing_placements))

        verification_issues.extend(
            f'Additional placement failure: {failure}' for failure in link_failures[:5])
        verification_issues.extend(
            f'Record permission failure: {failure}'
            for failure in record_permission_failures[:5])
        verification_issues.extend(
            f'Application-share failure: {failure}' for failure in app_share_failures[:5])
        params.sync_data = True
        if not conversion_complete:
            self._print_incomplete_conversion(
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
        delete_result = self._delete_classic_source(params, source_uid)
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
        if not folder_arg or folder_arg.casefold() in ('root', ROOT_FOLDER_UID.casefold()):
            return None
        return _resolve_destination_folder(
            params, folder_arg, 'nsf-convert-folder', force=force)

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
    def _destination_accessors(params, destination_uid):
        """Read all effective accessors that new destination children inherit."""
        if not destination_uid:
            return []

        from ...nested_share_folder.folder_api import get_folder_access_v3

        accessors_by_key = {}
        continuation_token = None
        seen_tokens = set()
        now_ms = current_milli_time()
        while True:
            try:
                result = get_folder_access_v3(
                    params, [destination_uid],
                    continuation_token=continuation_token,
                    page_size=NSF_FOLDER_ACCESS_PAGE_SIZE,
                    resolve_usernames=True)
            except Exception as exc:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Could not determine who will inherit access from destination '
                    f'{destination_uid}; conversion was not started. '
                    f'{_escape_non_printable(exc)}') from exc

            folder_result = next(
                (item for item in result.get('results', [])
                 if item.get('folder_uid') == destination_uid),
                None)
            if not folder_result or not folder_result.get('success'):
                error = (folder_result or {}).get('error') or {}
                message = error.get('message') or error.get('status')
                message = _escape_non_printable(
                    message or 'No access details returned.')
                raise CommandError(
                    'nsf-convert-folder',
                    f'Could not determine who will inherit access from destination '
                    f'{destination_uid}; conversion was not started. '
                    f'{message}')

            for accessor in folder_result.get('accessors') or []:
                if accessor.get('denied_access'):
                    continue
                access_type = accessor.get('access_type')
                accessor_uid = accessor.get('accessor_uid') or ''
                key = (access_type, accessor_uid)
                if not accessor_uid:
                    continue
                existing = accessors_by_key.get(key)
                if existing:
                    existing['role'] = merge_record_access_roles(
                        existing.get('role'), accessor.get('role'))
                    expirations = [
                        value for value in (
                            existing.get('tla_expiration'),
                            accessor.get('tla_expiration'))
                        if value and value > now_ms
                    ]
                    if expirations:
                        existing['tla_expiration'] = max(expirations)
                else:
                    accessors_by_key[key] = dict(accessor)

            if not result.get('has_more'):
                break
            continuation_token = result.get('continuation_token')
            if continuation_token is None or continuation_token in seen_tokens:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Could not read the full access list for destination '
                    f'{destination_uid}; conversion was not started.')
            seen_tokens.add(continuation_token)

        return sorted(
            accessors_by_key.values(),
            key=lambda accessor: (
                accessor.get('access_type', ''),
                (accessor.get('username') or accessor.get('accessor_uid') or '').casefold(),
                accessor.get('accessor_uid', ''),
            ))

    @staticmethod
    def _print_incomplete_conversion(params, source_uid, destination_uid,
                                     source_record_uids, converted_uids, target_uids,
                                     existing_target_uids, diagnostics=None):
        classic_placements = getattr(params, 'subfolder_record_cache', {}) or {}
        scan_failed = False
        try:
            source_folder_uids = set(_collect_classic_subtree(params, source_uid)[0])
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
    def _collect_records(params, nodes, records_by_folder, allow_converted=False):
        nested_records = getattr(params, 'nested_share_records', {}) or {}
        record_cache = getattr(params, 'record_cache', {}) or {}
        records = set()
        placements = {}
        skipped_pam_records = {}
        for folder_uid in nodes:
            for record_uid in records_by_folder.get(folder_uid) or []:
                if record_uid in nested_records and not allow_converted:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Record {record_uid} is already a Nested Share Record.')
                if record_uid not in record_cache and record_uid not in nested_records:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Record {record_uid} is missing from the Classic record cache; '
                        'run sync-down and retry.')
                pam_record = _pam_record_details(params, record_uid)
                if pam_record:
                    skipped_pam_records.setdefault(record_uid, pam_record)
                    continue
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
        return ordered_records, placements, list(skipped_pam_records.values())

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
    def _print_preview(params, nodes, records_by_folder, source_node, destination_uid,
                       available_depth, record_uids, source_depths, target_levels,
                       skipped_pam_records, destination_accessors=None):
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
                    suffix = ' — folder key unavailable' if candidate_uid in inaccessible_uids else ''
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

    @staticmethod
    def _create_target_tree(params, nodes, target_levels, target_parent_sources,
                            destination_uid, show_progress, existing_target_uids=None):
        if getattr(params, 'nested_share_folders', None) is None:
            params.nested_share_folders = {}
        target_uids = dict(existing_target_uids or {})
        if len(set(target_uids.values())) != len(target_uids):
            raise CommandError(
                'nsf-convert-folder',
                'The retry mapping selects the same NSF folder more than once.')

        def normalized_parent(folder_uid):
            parent_uid = (params.nested_share_folders.get(folder_uid) or {}).get('parent_uid') or ''
            return parent_uid if parent_uid in params.nested_share_folders else None

        for source_uid, target_uid in target_uids.items():
            target_folder = params.nested_share_folders.get(target_uid)
            parent_source_uid = target_parent_sources[source_uid]
            expected_parent_uid = (
                target_uids.get(parent_source_uid) if parent_source_uid else destination_uid)
            if (not target_folder or
                    target_folder.get('name') != nodes[source_uid].name or
                    normalized_parent(target_uid) != expected_parent_uid):
                raise CommandError(
                    'nsf-convert-folder',
                    f'Retry target folder {target_uid} no longer matches Classic folder '
                    f'{source_uid}; run sync-down and inspect before retrying.')

        for target_level in sorted(set(target_levels.values())):
            source_uids = [
                uid for uid, level in target_levels.items()
                if level == target_level and uid not in target_uids
            ]
            if not source_uids:
                continue
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
                    specs.append({
                        'name': source_node.name,
                        'parent_uid': parent_uid,
                        'color': getattr(source_node, 'color', None),
                        # NSF permissions inherit along the reconstructed tree;
                        # each Classic share boundary is granted separately.
                        'inherit_permissions': bool(parent_uid),
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
                            f"{_escape_non_printable(nodes[source_uid].name)} "
                            f"({source_uid}): "
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
                        'Could not create the full NSF folder tree; any folders already '
                        'created were left in place and the Classic source tree was left '
                        'intact. Review the partial NSF structure and rerun with --retry '
                        'to reconcile. ' + '; '.join(failures[:5]))

                if show_progress:
                    print(
                        f'  {bcolors.OKGREEN}✓{bcolors.ENDC} Created '
                        f'{len(chunk)} NSF folder(s) at target depth {target_level}.')
        return target_uids

    @staticmethod
    def _print_uid_mapping(nodes, target_uids):
        print('  Folder UID mapping:')
        for source_uid, target_uid in target_uids.items():
            print(
                f'    {_escape_non_printable(nodes[source_uid].name)} '
                f'({source_uid}) -> {target_uid}')

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
    def _grant_record_accesses(params, grants, converted_uids):
        """Apply direct NSF record roles that differ from inherited folder roles."""
        grants = [grant for grant in grants if grant['record_uid'] in converted_uids]
        if not grants:
            return []

        accesses_by_record = {}
        forbidden = set()
        record_uids = sorted({grant['record_uid'] for grant in grants})
        for start in range(0, len(record_uids), NSF_RECORD_BATCH_SIZE):
            batch = record_uids[start:start + NSF_RECORD_BATCH_SIZE]
            try:
                result = _nsf.get_record_accesses_v3(params, batch)
            except Exception as exc:
                return [f'Could not read NSF record permissions: {exc}']
            forbidden.update(result.get('forbidden_records') or [])
            for access in result.get('record_accesses') or []:
                accesses_by_record.setdefault(access['record_uid'], []).append(access)

        failures = []
        updates = []
        for grant in grants:
            record_uid = grant['record_uid']
            if record_uid in forbidden:
                failures.append(
                    f'{record_uid}: record permissions could not be read')
                continue

            matching_accesses = [
                access for access in accesses_by_record.get(record_uid, [])
                if access.get('access_type') == grant['access_type'] and
                access.get('access_type_uid') == grant['accessor_uid']
            ]
            if any(access.get('denied_access') for access in matching_accesses):
                failures.append(
                    f'{record_uid}: access for {grant["accessor_uid"]} is explicitly denied')
                continue
            if any(access.get('owner') for access in matching_accesses):
                continue

            direct_accesses = [
                access for access in matching_accesses
                if not access.get('inherited') and not access.get('denied_access')
            ]
            if len(direct_accesses) > 1:
                failures.append(
                    f'{record_uid}: multiple direct permissions found for '
                    f"{grant['accessor_uid']}")
                continue

            planned = dict(grant)
            if direct_accesses:
                current_role = direct_accesses[0].get('access_role_type')
                planned_role = merge_record_access_roles(
                    current_role, grant['access_role_type'])
                if planned_role == merge_record_access_roles(current_role):
                    continue
                planned['access_role_type'] = planned_role
                planned['action'] = 'update'
                planned['expiration_timestamp'] = None
            else:
                planned['action'] = 'create'
            updates.append(planned)

        if not updates:
            return failures

        for grant, result in _nsf.batch_upsert_record_accesses_v3(params, updates):
            if not result.get('success'):
                message = result.get('message') or 'permission update failed'
                failures.append(
                    f"{grant['record_uid']} -> {grant['accessor_uid']}: {message}")
        return failures

    @staticmethod
    def _grant_folder_app_shares(params, folder_app_shares, scope_by_folder,
                                 target_uids, applications):
        from ...proto import APIRequest_pb2

        folder_share_type = APIRequest_pb2.SHARE_TYPE_FOLDER
        for source_uid, scope_uid in scope_by_folder.items():
            if not scope_uid:
                continue
            for share in folder_app_shares.get(scope_uid) or []:
                app = applications[share['app_uid']]
                target_uid = target_uids[source_uid]
                if any(
                        existing.get('uid') == target_uid and
                        existing.get('type') == folder_share_type and
                        bool(existing.get('editable')) == bool(share['editable'])
                        for existing in app['shares']):
                    continue
                with command_error_handler('nsf-convert-folder'):
                    result = _nsf.grant_folder_access_to_application_v3(
                        params, target_uid, share['app_uid'],
                        app['key'], is_editable=share['editable'])
                    if not result.get('success'):
                        raise CommandError(
                            'nsf-convert-folder',
                            f"Could not preserve KSM application access on "
                            f"{target_uid}: {result.get('message')}")
                    app['shares'].append({
                        'uid': target_uid,
                        'type': folder_share_type,
                        'editable': bool(share['editable']),
                    })

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
        """Delete only a freshly verified empty subtree; return None if outcome is unknown."""
        from ..folder import FolderRemoveCommand

        try:
            sync_down.sync_down(params)
            folder_cache = getattr(params, 'folder_cache', {}) or {}
            if source_uid not in folder_cache:
                return True
            _, _, _, records_by_folder = _collect_classic_subtree(params, source_uid)
            remaining = {
                folder_uid: record_uids
                for folder_uid, record_uids in records_by_folder.items()
                if record_uids
            }
            if remaining:
                details = '; '.join(
                    f'{folder_uid}: {", ".join(record_uids[:5])}'
                    for folder_uid, record_uids in remaining.items())
                logging.warning(
                    'Classic source tree %s still contains record placements; '
                    'skipping recursive deletion. %s', source_uid, details)
                return False

            FolderRemoveCommand().execute(
                params, pattern=[source_uid], force=True, quiet=True)
            sync_down.sync_down(params)
            if source_uid in (getattr(params, 'folder_cache', {}) or {}):
                logging.warning(
                    'The conversion succeeded, but Classic source folder %s '
                    'still appears after deletion.', source_uid)
                return False
            logging.info('Classic source folder tree deleted.')
            return True
        except Exception as exc:
            logging.warning(
                'Conversion succeeded, but the Classic source tree deletion status '
                'could not be confirmed: %s', exc)
            return None
