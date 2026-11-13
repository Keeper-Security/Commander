"""Classic-to-NSF folder and record permission migration."""

from collections import defaultdict
import logging

from .... import nested_share_folder as _nsf
from .... import utils
from ....error import CommandError
from ....nested_share_folder.common import (
    NSF_FOLDER_ACCESS_PAGE_SIZE, NSF_RECORD_BATCH_SIZE, resolve_user_uid_bytes,
)
from ....nested_share_folder.permissions import (
    classic_record_permissions_to_nsf_role,
    classic_shared_folder_permissions_to_nsf_role,
    merge_record_access_roles,
)
from ....utils import current_milli_time
from .conversion_utils import _escape_non_printable
from ..helpers import command_error_handler


class FolderPermissionMigration:
    """Translate Classic folder and record ACLs into NSF permissions."""

    @staticmethod
    def _current_user_account_uid(params):
        """Return the current account UID in the API's base64url format."""
        account_uid = getattr(params, 'account_uid_bytes', None)
        if not account_uid:
            return None
        return utils.base64_url_encode(account_uid)

    @staticmethod
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

    @staticmethod
    def _scope_accessors(params, scope_uid):
        """Build folder-level NSF grants from Classic member permissions."""
        shared_folder = (getattr(params, 'shared_folder_cache', {}) or {}).get(scope_uid)
        if shared_folder is None:
            raise CommandError(
                'nsf-convert-folder',
                f'Access details for Classic Shared Folder {scope_uid} are not cached; '
                'run sync-down and retry.')

        accessors = []
        for member in FolderPermissionMigration._scope_members(params, scope_uid):
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
        current_uid = FolderPermissionMigration._current_user_account_uid(params)
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

    @staticmethod
    def _classic_record_permissions_by_uid(shared_folder):
        """Index Classic record-level edit/share overrides by UID."""
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

    @staticmethod
    def _record_accessor_key(access_type, accessor_uid):
        """Build a stable identity key for a user or team accessor."""
        if access_type == 'AT_USER':
            return access_type, accessor_uid if '@' not in accessor_uid else accessor_uid.casefold()
        return access_type, accessor_uid

    @staticmethod
    def _record_access_role_changes_before_expiry(record_roles, expirations):
        """Check whether overlapping expirations require multiple NSF roles."""
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

    @staticmethod
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
        current_uid = FolderPermissionMigration._current_user_account_uid(params)
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
                        FolderPermissionMigration._classic_record_permissions_by_uid(
                            shared_folder))
                defaults, permissions_by_uid = scope_record_permissions[scope_uid]
                can_edit, can_share = permissions_by_uid.get(record_uid, defaults)
                record_role = classic_record_permissions_to_nsf_role(
                    can_edit=can_edit, can_share=can_share)
                if scope_uid not in scope_members:
                    scope_members[scope_uid] = FolderPermissionMigration._scope_members(
                        params, scope_uid)
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
                        *FolderPermissionMigration._record_accessor_key(
                            member['access_type'], accessor_uid),
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
            accessor_key = FolderPermissionMigration._record_accessor_key(
                access_type, accessor_uid)
            destination_roles.setdefault(accessor_key, []).append(role)
            expiration = accessor.get('tla_expiration')
            if expiration and expiration > now_ms:
                expiring_destination_access.add(accessor_key)

        plan = []
        for key, record_roles in role_by_record_accessor.items():
            record_uid, access_type, accessor_uid = key
            accessor_key = FolderPermissionMigration._record_accessor_key(
                access_type, accessor_uid)
            destination_role_list = destination_roles.get(accessor_key, [])
            classic_record_role = merge_record_access_roles(*record_roles)
            desired_role = merge_record_access_roles(classic_record_role, *destination_role_list)
            inherited_role = merge_record_access_roles(
                *folder_role_by_record_accessor[key], *destination_role_list)
            if desired_role == inherited_role:
                continue
            if FolderPermissionMigration._record_access_role_changes_before_expiry(
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

    @staticmethod
    def _destination_accessors(params, destination_uid):
        """Read all effective accessors that new destination children inherit."""
        if not destination_uid:
            return []

        from ....nested_share_folder.folder_api import get_folder_access_v3

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
    def _scope_grant_targets(nodes, target_parent_sources, scope_by_folder):
        """Find source folders that begin a distinct Classic share boundary."""
        grants = []
        for folder_uid in nodes:
            scope_uid = scope_by_folder.get(folder_uid)
            if not scope_uid:
                continue
            target_parent_source = target_parent_sources.get(folder_uid)
            parent_scope = (
                scope_by_folder.get(target_parent_source) if target_parent_source else None)
            if target_parent_source is None or parent_scope != scope_uid:
                grants.append((scope_uid, folder_uid))
        return grants

    @staticmethod
    def _grant_scope_access(params, scope_grants, scope_accessors, target_uids):
        """Apply migrated Classic share grants to NSF ACL-boundary folders."""
        current_user = (getattr(params, 'user', '') or '').casefold()
        current_account_uid = FolderPermissionMigration._current_user_account_uid(params)
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

