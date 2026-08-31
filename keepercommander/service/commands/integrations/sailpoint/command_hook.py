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

from ..... import api
from .....params import KeeperParams
from ....decorators.logging import logger
from .command_parse import ParsedShare, SailPointCommandParser
from .command_policy import SailPointCommandPolicy
from .config_fields import SailPointCapabilities, read_capabilities
from .pending_store import SailPointPendingStore
from .scim_guard import SailPointScimGuard
from .share_targets import validate_share_targets


class SailPointCommandHook:
    """Pre/post hooks around Service Mode command execution for SailPoint."""

    def __init__(self, record_uid: str):
        self.record_uid = record_uid

    def before_command(self, params: KeeperParams, command: str) -> Tuple[str, Optional[Tuple[Any, int]]]:
        """
        Prepare a Service Mode command for SailPoint.

        Returns ``(command_to_run, short_circuit)``. When ``short_circuit`` is
        set, do not execute the command. ``command_to_run`` may be rewritten
        (e.g. transfer-user target injection).
        """
        caps = read_capabilities(params, self.record_uid)

        scope_error = self._check_capability_gates(command, caps)
        if scope_error:
            return self._reject(command, scope_error, 403)

        policy_error = (
            SailPointCommandPolicy.validate_enterprise_user(command)
            or SailPointCommandPolicy.validate_share_record(command)
        )
        if policy_error:
            return self._reject(command, policy_error, 403)

        command, transfer_error = SailPointCommandPolicy.prepare_transfer(
            command, caps.transfer_target_email
        )
        if transfer_error:
            return self._reject(command, transfer_error, 400)

        invite = SailPointCommandParser.parse_invite(command)
        if invite and invite.emails:
            return command, self._before_invite(params, invite)

        share = SailPointCommandParser.parse_share(command)
        if share:
            target_error = validate_share_targets(params, share)
            if target_error:
                return self._reject(command, target_error, 400)
            return command, self._before_share(params, share, caps)

        mutation = SailPointCommandParser.parse_identity_mutation(command)
        if mutation:
            err = self._first_scim_identity_error(params, mutation.emails)
            if err:
                return self._reject(command, err, 403)
        return command, None

    @staticmethod
    def _reject(command: str, error: str, status_code: int) -> Tuple[str, Tuple[Any, int]]:
        return command, ({'status': 'error', 'error': error}, status_code)

    @staticmethod
    def _first_scim_identity_error(params: KeeperParams, emails: List[str]) -> Optional[str]:
        for email in emails:
            err = SailPointScimGuard.identity_change_error(params, email)
            if err:
                return err
        return None

    @staticmethod
    def _check_capability_gates(command: str, caps: SailPointCapabilities) -> Optional[str]:
        tokens = SailPointCommandParser.tokenize(command)
        if not tokens:
            return None

        invite = SailPointCommandParser.parse_invite(command)
        if invite:
            if invite.roles and not caps.allow_roles:
                return (
                    'SailPoint allow_roles is disabled; --add-role is not allowed.'
                )
            if invite.teams and not caps.allow_teams:
                return (
                    'SailPoint allow_teams is disabled; --add-team is not allowed.'
                )
            return None

        mutation = SailPointCommandParser.parse_identity_mutation(command)
        if mutation:
            if mutation.has_role_change and not caps.allow_roles:
                return (
                    'SailPoint allow_roles is disabled; '
                    '--add-role / --remove-role is not allowed.'
                )
            if mutation.has_team_change and not caps.allow_teams:
                return (
                    'SailPoint allow_teams is disabled; '
                    '--add-team / --remove-team is not allowed.'
                )
        return None

    def after_command(self, params: KeeperParams, command: str, success: bool) -> None:
        if not success:
            return
        invite = SailPointCommandParser.parse_invite(command)
        if not invite or not invite.emails:
            return

        for email in invite.emails:
            logger.info(f'SailPoint: user invited {email}')

        if not invite.roles and not invite.teams:
            return

        api.query_enterprise(params)
        roles = list(invite.roles) if invite.roles else None
        teams = list(invite.teams) if invite.teams else None
        created: List[str] = []
        updated: List[str] = []

        eligible: List[str] = []
        for email in invite.emails:
            user = SailPointScimGuard.find_user(params, email)
            if not user:
                logger.warning(
                    f'SailPoint: skip pending queue; user not found after invite: {email}'
                )
                continue
            if SailPointScimGuard.identity_change_error(params, email):
                continue
            eligible.append(email)
        if not eligible:
            return

        def updater(pending: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal created, updated
            result = pending
            for email in eligible:
                key = email.strip().lower()
                existed = key in result
                result = SailPointPendingStore.merge_entry(
                    result, email, roles=roles, teams=teams
                )
                (updated if existed else created).append(email)
            return result

        next_state = SailPointPendingStore.update(params, self.record_uid, updater)
        self._log_pending_writes(next_state, created, updated)

    @staticmethod
    def _log_pending_writes(
        pending: Dict[str, Any],
        created: List[str],
        updated: List[str],
    ) -> None:
        for email in created:
            entry = pending.get(email.strip().lower()) or {}
            summary = SailPointPendingStore.summarize_entry(entry)
            detail = f' ({summary})' if summary else ''
            logger.info(f'SailPoint: pending entitlements created for {email}{detail}')
        for email in updated:
            entry = pending.get(email.strip().lower()) or {}
            summary = SailPointPendingStore.summarize_entry(entry)
            detail = f' ({summary})' if summary else ''
            logger.info(f'SailPoint: pending entitlements updated for {email}{detail}')

    def _before_invite(self, params: KeeperParams, invite) -> Optional[Tuple[Any, int]]:
        if not (invite.roles or invite.teams):
            return None
        err = self._first_scim_identity_error(params, invite.emails)
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

    def _before_share(
        self,
        params: KeeperParams,
        share: ParsedShare,
        caps: SailPointCapabilities,
    ) -> Optional[Tuple[Any, int]]:
        # Capability gates apply to every share action (grant, owner, revoke, cancel,
        # remove). Deferral below is grant-only for Invited users.
        if share.is_folder and not caps.allow_folders:
            return {
                'status': 'error',
                'error': 'SailPoint allow_folders is disabled; share-folder is not allowed.',
            }, 403
        if share.is_record and not caps.allow_records:
            return {
                'status': 'error',
                'error': 'SailPoint allow_records is disabled; share-record is not allowed.',
            }, 403

        # Non-grant actions run through Commander (native errors, no pending queue).
        if not share.is_grant:
            return None

        deferred = [e for e in share.emails if self._user_status(params, e) != 'active']
        if not deferred:
            return None

        active = [e for e in share.emails if e not in deferred]
        if active:
            return {
                'status': 'error',
                'error': (
                    'SailPoint cannot mix Active and non-Active users in one share request. '
                    f'Share Active users separately ({", ".join(active)}); '
                    f'queue non-Active users separately ({", ".join(deferred)}).'
                ),
            }, 400

        created: List[str] = []
        updated: List[str] = []

        def updater(pending: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal created, updated
            result = pending
            for email in deferred:
                key = email.strip().lower()
                existed = key in result
                if share.is_folder:
                    folders = [self._folder_payload(share, t) for t in share.targets]
                    result = SailPointPendingStore.merge_entry(result, email, folders=folders)
                else:
                    records = [self._record_payload(share, t) for t in share.targets]
                    result = SailPointPendingStore.merge_entry(result, email, records=records)
                (updated if existed else created).append(email)
            return result

        next_state = SailPointPendingStore.update(params, self.record_uid, updater)
        self._log_pending_writes(next_state, created, updated)

        return {
            'status': 'success',
            'message': f'User(s) not yet active; queued share for: {", ".join(deferred)}.',
            'queued': deferred,
        }, 200
