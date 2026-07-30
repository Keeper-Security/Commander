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
from typing import Any, Callable, Dict, List, Tuple

from .....params import KeeperParams
from ....decorators.logging import logger
from .pending_store import SailPointPendingStore
from .scim_guard import SailPointScimGuard

_NOT_FOUND_HINTS = ('not found', 'no such', 'does not exist')


class SailPointEntitlementApplier:
    """Apply queued roles/teams/shares after a user becomes Active."""

    @staticmethod
    def _role_exists(params: KeeperParams, role_name: str) -> bool:
        return any(
            str(role.get('role_id')) == role_name
            or ((role.get('data') or {}).get('displayname') or '').lower() == role_name.lower()
            for role in params.enterprise.get('roles') or []
        )

    @staticmethod
    def _team_exists(params: KeeperParams, team_name: str) -> bool:
        return any(
            team.get('team_uid') == team_name
            or (team.get('name') or '').lower() == team_name.lower()
            for team in params.enterprise.get('teams') or []
        )

    @staticmethod
    def _run(params: KeeperParams, command: str) -> None:
        from ..... import cli
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
        flag_str = f" {' '.join(flags)}" if flags else ''
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
        flag_str = f" {' '.join(flags)}" if flags else ''
        cls._run(params, f'share-record --email {email_q}{flag_str} {uid_q}')

    @classmethod
    def _apply_items(
        cls,
        params: KeeperParams,
        email: str,
        items: List[Dict[str, Any]],
        *,
        label: str,
        apply_one: Callable[[KeeperParams, str, Dict[str, Any]], None],
        remaining: Dict[str, Any],
        dropped: List[str],
    ) -> List[Dict[str, Any]]:
        still: List[Dict[str, Any]] = []
        for item in items:
            uid = item.get('uid')
            if not uid:
                dropped.append(f'{label} entry missing uid, dropped')
                continue
            try:
                apply_one(params, email, item)
                logger.info(f'SailPoint: shared {label.lower()} {uid} with {email}')
            except Exception as e:
                if cls._is_missing_target(e):
                    dropped.append(f'{label} not found, dropped: {uid}')
                else:
                    logger.warning(f'Failed to share {label.lower()} {uid} with {email}: {e}')
                    still.append(item)
                    remaining['last_error'] = str(e)
        return still

    @classmethod
    def apply_for_user(
        cls,
        params: KeeperParams,
        email: str,
        entry: Dict[str, Any],
        *,
        allow_roles: bool = True,
        allow_teams: bool = True,
        allow_folders: bool = True,
        allow_records: bool = True,
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

        if not allow_roles and remaining['roles']:
            dropped.append('Pending roles skipped by allow_roles=false')
            remaining['roles'] = []
        if not allow_teams and remaining['teams']:
            dropped.append('Pending teams skipped by allow_teams=false')
            remaining['teams'] = []

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
                    cls._run(
                        params,
                        f'enterprise-user -f {email_q} --add-role {cls._shell_quote(role)}',
                    )
                    logger.info(f"SailPoint: added role '{role}' to {email}")
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
                    cls._run(
                        params,
                        f'enterprise-user {email_q} --add-team {cls._shell_quote(team)}',
                    )
                    logger.info(f"SailPoint: added team '{team}' to {email}")
                except Exception as e:
                    logger.warning(f'Failed to add team {team} for {email}: {e}')
                    still_teams.append(team)
                    remaining['last_error'] = str(e)
            remaining['teams'] = still_teams

        if allow_folders:
            remaining['folders'] = cls._apply_items(
                params,
                email,
                remaining['folders'],
                label='Folder',
                apply_one=cls._apply_folder,
                remaining=remaining,
                dropped=dropped,
            )
        elif remaining['folders']:
            dropped.append('Pending folders skipped by allow_folders=false')
            remaining['folders'] = []

        if allow_records:
            remaining['records'] = cls._apply_items(
                params,
                email,
                remaining['records'],
                label='Record',
                apply_one=cls._apply_record,
                remaining=remaining,
                dropped=dropped,
            )
        elif remaining['records']:
            dropped.append('Pending records skipped by allow_records=false')
            remaining['records'] = []

        if SailPointPendingStore.entry_is_empty(remaining):
            remaining = {}
        return remaining, dropped
