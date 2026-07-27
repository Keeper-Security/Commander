#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""Apply pending SailPoint entitlements once a user is Active."""

from __future__ import annotations

import shlex
from typing import Any, Dict, List, Tuple

from .....params import KeeperParams
from ....decorators.logging import logger
from .pending_store import SailPointPendingStore
from .scim_guard import SailPointScimGuard

_NOT_FOUND_HINTS = ('not found', 'no such', 'does not exist')


class SailPointEntitlementApplier:
    """Apply queued roles/teams/shares after a user becomes Active."""

    @staticmethod
    def _role_exists(params: KeeperParams, role_name: str) -> bool:
        for role in params.enterprise.get('roles') or []:
            display = (role.get('data') or {}).get('displayname') or ''
            if str(role.get('role_id')) == role_name or display.lower() == role_name.lower():
                return True
        return False

    @staticmethod
    def _team_exists(params: KeeperParams, team_name: str) -> bool:
        for team in params.enterprise.get('teams') or []:
            if team.get('team_uid') == team_name or (team.get('name') or '').lower() == team_name.lower():
                return True
        return False

    @staticmethod
    def _run(params: KeeperParams, command: str) -> None:
        from ..... import cli
        logger.info(f'SailPoint apply: {command}')
        cli.do_command(params, command)

    @staticmethod
    def _is_missing_target(error: Exception) -> bool:
        msg = str(error).lower()
        return any(h in msg for h in _NOT_FOUND_HINTS)

    @staticmethod
    def _shell_quote(value: str) -> str:
        return shlex.quote(str(value))

    @classmethod
    def user_is_active(cls, params: KeeperParams, email: str) -> bool:
        user = SailPointScimGuard.find_user(params, email)
        return bool(user and user.get('status') == 'active')

    @classmethod
    def _apply_folder(cls, params: KeeperParams, email: str, folder: Dict[str, Any]) -> None:
        uid = folder.get('uid')
        if not uid:
            raise ValueError('Folder entry missing uid')
        kind = (folder.get('kind') or 'classic').lower()
        email_q = cls._shell_quote(email)
        uid_q = cls._shell_quote(uid)
        if kind == 'nsf':
            role = folder.get('role') or 'viewer'
            cls._run(
                params,
                f'nsf-share-folder -a grant -e {email_q} -r {cls._shell_quote(role)} {uid_q}',
            )
            return

        flags = []
        manage_records = folder.get('manage_records')
        manage_users = folder.get('manage_users')
        if manage_records in ('on', 'off'):
            flags.append(f'--manage-records {manage_records}')
        if manage_users in ('on', 'off'):
            flags.append(f'--manage-users {manage_users}')
        flag_str = (' ' + ' '.join(flags)) if flags else ''
        cls._run(params, f'share-folder -a grant --email {email_q}{flag_str} {uid_q}')

    @classmethod
    def _apply_record(cls, params: KeeperParams, email: str, record: Dict[str, Any]) -> None:
        uid = record.get('uid')
        if not uid:
            raise ValueError('Record entry missing uid')
        kind = (record.get('kind') or 'classic').lower()
        email_q = cls._shell_quote(email)
        uid_q = cls._shell_quote(uid)
        if kind == 'nsf':
            role = record.get('role') or 'viewer'
            cls._run(
                params,
                f'nsf-share-record -a grant -e {email_q} -r {cls._shell_quote(role)} {uid_q}',
            )
            return

        flags = []
        if record.get('can_edit'):
            flags.append('--write')
        if record.get('can_share'):
            flags.append('--share')
        flag_str = (' ' + ' '.join(flags)) if flags else ''
        cls._run(params, f'share-record --email {email_q}{flag_str} {uid_q}')

    @classmethod
    def apply_for_user(
        cls,
        params: KeeperParams,
        email: str,
        entry: Dict[str, Any],
        *,
        entitlement_scope: str = 'both',
    ) -> Tuple[Dict[str, Any], List[str]]:
        remaining = {
            'created_at': entry.get('created_at'),
            'last_error': None,
            'roles': list(entry.get('roles') or []),
            'teams': list(entry.get('teams') or []),
            'folders': [dict(x) for x in (entry.get('folders') or [])],
            'records': [dict(x) for x in (entry.get('records') or [])],
        }
        dropped: List[str] = []
        scim_user = SailPointScimGuard.is_scim_managed_user(params, email)
        email_q = cls._shell_quote(email)

        if scim_user:
            if remaining['roles'] or remaining['teams']:
                dropped.append(
                    f'SCIM-managed user {email}: skipped pending roles/teams (identity coexistence)'
                )
                remaining['roles'] = []
                remaining['teams'] = []
        else:
            still_roles = []
            for role in remaining['roles']:
                if not cls._role_exists(params, role):
                    dropped.append(f'Role not found, dropped: {role}')
                    continue
                try:
                    cls._run(params, f'enterprise-user {email_q} --add-role {cls._shell_quote(role)}')
                except Exception as e:
                    logger.warning(f'Failed to add role {role} for {email}: {e}')
                    still_roles.append(role)
                    remaining['last_error'] = str(e)
            remaining['roles'] = still_roles

            still_teams = []
            for team in remaining['teams']:
                if not cls._team_exists(params, team):
                    dropped.append(f'Team not found, dropped: {team}')
                    continue
                try:
                    cls._run(params, f'enterprise-user {email_q} --add-team {cls._shell_quote(team)}')
                except Exception as e:
                    logger.warning(f'Failed to add team {team} for {email}: {e}')
                    still_teams.append(team)
                    remaining['last_error'] = str(e)
            remaining['teams'] = still_teams

        allow_folders = entitlement_scope in ('folders', 'both')
        allow_records = entitlement_scope in ('records', 'both')

        still_folders = []
        if allow_folders:
            for folder in remaining['folders']:
                uid = folder.get('uid')
                if not uid:
                    dropped.append('Folder entry missing uid, dropped')
                    continue
                try:
                    cls._apply_folder(params, email, folder)
                except Exception as e:
                    if cls._is_missing_target(e):
                        dropped.append(f'Folder not found, dropped: {uid}')
                    else:
                        logger.warning(f'Failed to share folder {uid} with {email}: {e}')
                        still_folders.append(folder)
                        remaining['last_error'] = str(e)
            remaining['folders'] = still_folders
        elif remaining['folders']:
            dropped.append('Folder shares skipped by entitlement_scope')
            remaining['folders'] = []

        still_records = []
        if allow_records:
            for record in remaining['records']:
                uid = record.get('uid')
                if not uid:
                    dropped.append('Record entry missing uid, dropped')
                    continue
                try:
                    cls._apply_record(params, email, record)
                except Exception as e:
                    if cls._is_missing_target(e):
                        dropped.append(f'Record not found, dropped: {uid}')
                    else:
                        logger.warning(f'Failed to share record {uid} with {email}: {e}')
                        still_records.append(record)
                        remaining['last_error'] = str(e)
            remaining['records'] = still_records
        elif remaining['records']:
            dropped.append('Record shares skipped by entitlement_scope')
            remaining['records'] = []

        if SailPointPendingStore.entry_is_empty(remaining):
            remaining = {}
        return remaining, dropped
