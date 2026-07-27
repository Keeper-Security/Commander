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

"""Intercept Service Mode commands for SailPoint deferred entitlements."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .....params import KeeperParams
from ....decorators.logging import logger
from .command_parse import ParsedShare, SailPointCommandParser
from .config_fields import read_entitlement_scope
from .pending_store import SailPointPendingStore
from .scim_guard import SailPointScimGuard


class SailPointCommandHook:
    """Pre/post hooks around Service Mode command execution for SailPoint."""

    def __init__(self, record_uid: str):
        self.record_uid = record_uid

    def before_command(self, params: KeeperParams, command: str) -> Optional[Tuple[Any, int]]:
        """Return (response, status_code) to short-circuit, or None to continue."""
        invite = SailPointCommandParser.parse_invite(command)
        if invite and invite.emails:
            return self._before_invite(params, invite)

        share = SailPointCommandParser.parse_share(command)
        if share:
            return self._before_share(params, share)

        mutation = SailPointCommandParser.parse_identity_mutation(command)
        if mutation:
            for email in mutation.emails:
                err = SailPointScimGuard.identity_change_error(params, email)
                if err:
                    return {'status': 'error', 'error': err}, 403
        return None

    def after_command(self, params: KeeperParams, command: str, success: bool) -> None:
        if not success:
            return
        invite = SailPointCommandParser.parse_invite(command)
        if not invite or not invite.emails or (not invite.roles and not invite.teams):
            return

        roles = list(invite.roles) if invite.roles else None
        teams = list(invite.teams) if invite.teams else None
        queued: List[str] = []

        def updater(pending: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal queued
            queued = []
            result = pending
            for email in invite.emails:
                if (
                    SailPointScimGuard.find_user(params, email)
                    and SailPointScimGuard.identity_change_error(params, email)
                ):
                    continue
                result = SailPointPendingStore.merge_entry(
                    result, email, roles=roles, teams=teams
                )
                queued.append(email)
            return result

        SailPointPendingStore.update(params, self.record_uid, updater)
        for email in queued:
            logger.info(
                f'Queued SailPoint pending entitlements for {email} '
                f'(roles={invite.roles} teams={invite.teams})'
            )

    def _before_invite(self, params: KeeperParams, invite) -> Optional[Tuple[Any, int]]:
        roles = list(invite.roles)
        teams = list(invite.teams)
        for email in invite.emails:
            existing = SailPointScimGuard.find_user(params, email)
            if existing and (roles or teams):
                err = SailPointScimGuard.identity_change_error(params, email)
                if err:
                    return {'status': 'error', 'error': err}, 403
        return None

    def _user_status(self, params: KeeperParams, email: str) -> Optional[str]:
        user = SailPointScimGuard.find_user(params, email)
        return user.get('status') if user else None

    @staticmethod
    def _folder_payload(share: ParsedShare, target: str) -> Dict[str, Any]:
        item: Dict[str, Any] = {'uid': target}
        if share.is_nsf:
            item['kind'] = 'nsf'
            item['role'] = share.nsf_role or 'viewer'
        else:
            item['kind'] = 'classic'
            item['manage_records'] = share.manage_records
            item['manage_users'] = share.manage_users
        return item

    @staticmethod
    def _record_payload(share: ParsedShare, target: str) -> Dict[str, Any]:
        item: Dict[str, Any] = {'uid': target}
        if share.is_nsf:
            item['kind'] = 'nsf'
            item['role'] = share.nsf_role or 'viewer'
        else:
            item['kind'] = 'classic'
            item['can_edit'] = share.can_edit
            item['can_share'] = share.can_share
        return item

    def _before_share(self, params: KeeperParams, share: ParsedShare) -> Optional[Tuple[Any, int]]:
        scope = read_entitlement_scope(params, self.record_uid)
        if share.is_folder and scope == 'records':
            return {
                'status': 'error',
                'error': 'SailPoint entitlement_scope is records-only; share-folder is not allowed.',
            }, 403
        if share.is_record and scope == 'folders':
            return {
                'status': 'error',
                'error': 'SailPoint entitlement_scope is folders-only; share-record is not allowed.',
            }, 403

        deferred = [e for e in share.emails if self._user_status(params, e) != 'active']
        if not deferred:
            return None

        def updater(pending: Dict[str, Any]) -> Dict[str, Any]:
            result = pending
            for email in deferred:
                if share.is_folder:
                    folders = [self._folder_payload(share, t) for t in share.targets]
                    result = SailPointPendingStore.merge_entry(result, email, folders=folders)
                else:
                    records = [self._record_payload(share, t) for t in share.targets]
                    result = SailPointPendingStore.merge_entry(result, email, records=records)
            return result

        SailPointPendingStore.update(params, self.record_uid, updater)
        for email in deferred:
            logger.info(
                f'Queued SailPoint pending '
                f'{"folder" if share.is_folder else "record"} share for {email} '
                f'-> {", ".join(share.targets)}'
            )

        active = [e for e in share.emails if e not in deferred]
        message = f'User(s) not yet active; queued share for: {", ".join(deferred)}.'
        if active:
            message += (
                f' Active user(s) were not shared in this request (call share separately): '
                f'{", ".join(active)}.'
            )
        return {'status': 'success', 'message': message, 'queued': deferred}, 200
