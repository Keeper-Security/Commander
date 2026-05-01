#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import logging
import time
from typing import List

from ..pam.router_helper import _post_request_to_router
from ..workflow.helpers import (
    ProtobufRefBuilder,
    RecordResolver,
    WorkflowFormatter,
    sanitize_router_error,
)
from ...error import CommandError, KeeperApiError
from ...params import KeeperParams
from ...proto import workflow_pb2
from ... import utils

from .base import PamWorkflowOptions


# 429 backoff matches keeper_dag.connection.commander.rest_call_to_router:
# 5 attempts, 10s base, 1.5x multiplier per retry (~131s worst case).
# Krouter rate-limits at 50 req / 5s per remote IP (see krouter HTTP.kt:96-103);
# bursts during a multi-resource import can cross that line and an unhandled
# 429 would fail the resource fatally.
_THROTTLE_BASE_WAIT = 10.0
_THROTTLE_MULTIPLIER = 1.5
_THROTTLE_MAX_RETRIES = 5


def _is_throttle_error(e: Exception) -> bool:
    if isinstance(e, KeeperApiError) and e.result_code == 429:
        return True
    msg = str(getattr(e, 'message', None) or e).lower()
    return 'throttle' in msg or 'too many' in msg


def _post_with_throttle_retry(params, path: str, **kwargs):
    """Wrap _post_request_to_router with progressive backoff on 429 / throttle errors.
    Non-throttle errors propagate immediately. Final retry's exception is re-raised.
    """
    wait = _THROTTLE_BASE_WAIT
    for attempt in range(1, _THROTTLE_MAX_RETRIES + 1):
        try:
            return _post_request_to_router(params, path, **kwargs)
        except Exception as e:
            if not _is_throttle_error(e) or attempt >= _THROTTLE_MAX_RETRIES:
                raise
            logging.warning(
                'Krouter rate-limited on %s (attempt %d/%d); waiting %.1fs',
                path, attempt, _THROTTLE_MAX_RETRIES, wait,
            )
            time.sleep(wait)
            wait *= _THROTTLE_MULTIPLIER


# Re-exported for tests and any downstream importers; the canonical map lives
# in WorkflowFormatter.DAY_PARSE_MAP and accepts both 3-letter and full names.
_DAY_PROTO_MAP = {
    k: v for k, v in WorkflowFormatter.DAY_PARSE_MAP.items() if len(k) == 3
}


def _build_temporal_filter(opts: PamWorkflowOptions):
    """Build TemporalAccessFilter from opts. Returns None when no temporal slice is set.

    Time-of-day is encoded as the HHMM integer the server expects
    (e.g. '09:00' -> 900, '17:30' -> 1730), matching WorkflowFormatter._parse_time_to_hhmm.
    """
    if not opts.allowed_days and not opts.time_ranges and not opts.timezone:
        return None
    temporal = workflow_pb2.TemporalAccessFilter()
    for day_token in opts.allowed_days:
        day_enum = WorkflowFormatter.DAY_PARSE_MAP.get(day_token)
        if day_enum is not None:
            temporal.allowedDays.append(day_enum)
    for r in opts.time_ranges:
        tr = workflow_pb2.TimeOfDayRange()
        tr.startTime = WorkflowFormatter._parse_time_to_hhmm(r['start'])
        tr.endTime = WorkflowFormatter._parse_time_to_hhmm(r['end'])
        temporal.timeRanges.append(tr)
    if opts.timezone:
        temporal.timeZone = opts.timezone
    return temporal


def _build_parameters(
    record_uid_bytes: bytes,
    record_title: str,
    opts: PamWorkflowOptions,
) -> workflow_pb2.WorkflowParameters:
    params_proto = workflow_pb2.WorkflowParameters()
    params_proto.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record_title))
    params_proto.approvalsNeeded = opts.approvals_needed
    params_proto.checkoutNeeded = opts.checkout_needed
    params_proto.startAccessOnApproval = opts.start_access_on_approval
    params_proto.requireReason = opts.require_reason
    params_proto.requireTicket = opts.require_ticket
    params_proto.requireMFA = opts.require_mfa
    params_proto.accessLength = opts.access_duration_ms

    temporal = _build_temporal_filter(opts)
    if temporal:
        params_proto.allowedTimes.CopyFrom(temporal)

    return params_proto


def _build_approver_proto(a: dict) -> workflow_pb2.WorkflowApprover:
    approver = workflow_pb2.WorkflowApprover()
    if a['principal_type'] == 'user':
        approver.user = a['email']
    else:
        approver.teamUid = utils.base64_url_decode(a['team_uid_b64'])
    approver.escalation = a['escalation']
    if a['escalation_after_ms']:
        approver.escalationAfterMs = a['escalation_after_ms']
    return approver


def _approver_key(params: KeeperParams, approver: workflow_pb2.WorkflowApprover) -> str:
    """Return a stable identity key for an existing server approver (for reconcile diff).
    Server may return either user (email) or userId (int). When userId is set, resolve
    to email through the enterprise user list so it matches the import-side key.
    """
    if approver.HasField('user'):
        return f'user:{approver.user}'
    if approver.HasField('userId'):
        email = RecordResolver.resolve_user(params, approver.userId)
        # resolve_user returns 'User ID <n>' when not found — fall back to userId so
        # we don't accidentally key two different unknown users to the same string.
        if email and not email.startswith('User ID '):
            return f'user:{email}'
        return f'userid:{approver.userId}'
    if approver.HasField('teamUid'):
        return f'team:{utils.base64_url_encode(approver.teamUid)}'
    return ''


def _new_approver_key(a: dict) -> str:
    if a['principal_type'] == 'user':
        return f'user:{a["email"]}'
    return f'team:{a["team_uid_b64"]}'


def _reconcile_approvers(
    params: KeeperParams,
    record_uid_bytes: bytes,
    record_title: str,
    existing: List[workflow_pb2.WorkflowApprover],
    new_approvers: List[dict],
) -> None:
    ref = ProtobufRefBuilder.record_ref(record_uid_bytes, record_title)

    existing_keys = {_approver_key(params, a): a for a in existing}
    new_keys = {_new_approver_key(a): a for a in new_approvers}

    to_delete = [a for k, a in existing_keys.items() if k not in new_keys]
    to_add = [a for k, a in new_keys.items() if k not in existing_keys]

    if to_delete:
        config = workflow_pb2.WorkflowConfig()
        config.parameters.resource.CopyFrom(ref)
        for a in to_delete:
            config.approvers.append(a)
        _post_with_throttle_retry(params, 'delete_workflow_approvers', rq_proto=config)

    if to_add:
        config = workflow_pb2.WorkflowConfig()
        config.parameters.resource.CopyFrom(ref)
        for a in to_add:
            config.approvers.append(_build_approver_proto(a))
        _post_with_throttle_retry(params, 'add_workflow_approvers', rq_proto=config)


def apply_workflow(
    params: KeeperParams,
    record_uid: str,
    record_title: str,
    opts: PamWorkflowOptions,
) -> None:
    """Create or update workflow config via Krouter. Raises CommandError on failure."""
    record_uid_bytes = utils.base64_url_decode(record_uid)
    ref = ProtobufRefBuilder.record_ref(record_uid_bytes, record_title)

    try:
        existing = _post_with_throttle_retry(
            params, 'read_workflow_config',
            rq_proto=ref, rs_type=workflow_pb2.WorkflowConfig,
        )
    except Exception as e:
        raise CommandError('', f'workflow read failed for "{record_title}": {sanitize_router_error(e)}')

    parameters = _build_parameters(record_uid_bytes, record_title, opts)

    try:
        if existing:
            _post_with_throttle_retry(params, 'update_workflow_config', rq_proto=parameters)
            if opts.approvals_needed > 0:
                _reconcile_approvers(
                    params, record_uid_bytes, record_title,
                    list(existing.approvers), opts.approvers,
                )
            elif existing.approvers:
                # approvals_needed dropped to 0: remove all existing approvers (V5)
                config = workflow_pb2.WorkflowConfig()
                config.parameters.resource.CopyFrom(ref)
                for a in existing.approvers:
                    config.approvers.append(a)
                _post_with_throttle_retry(params, 'delete_workflow_approvers', rq_proto=config)
        else:
            _post_with_throttle_retry(params, 'create_workflow_config', rq_proto=parameters)
            if opts.approvals_needed > 0 and opts.approvers:
                config = workflow_pb2.WorkflowConfig()
                config.parameters.resource.CopyFrom(ref)
                for a in opts.approvers:
                    config.approvers.append(_build_approver_proto(a))
                _post_with_throttle_retry(params, 'add_workflow_approvers', rq_proto=config)
    except CommandError:
        raise
    except Exception as e:
        raise CommandError('', f'workflow apply failed for "{record_title}": {sanitize_router_error(e)}')


def validate_workflow_principals(params: KeeperParams, resources) -> None:
    """Pre-flight: validate team UIDs in workflow approvers for all resources.
    Uses RecordResolver.validate_team which checks both team_cache and enterprise.teams,
    matching the lookup path used by `pam workflow add-approver`. Raises CommandError
    on the first unknown UID, with the resource title in the message for context.
    """
    for mach in resources or []:
        opts = None
        ps = getattr(mach, 'pam_settings', None)
        if ps:
            opts = getattr(ps, 'workflow', None)
        if opts is None:
            rbi = getattr(mach, 'rbi_settings', None)
            if rbi:
                opts = getattr(rbi, 'workflow', None)
        if opts is None:
            continue
        title = getattr(mach, 'title', '') or ''
        for idx, a in enumerate(opts.approvers):
            if a['principal_type'] != 'team':
                continue
            try:
                RecordResolver.validate_team(params, a['team_uid_b64'])
            except CommandError as e:
                prefix = f'Resource "{title}": ' if title else ''
                raise CommandError('', f'{prefix}workflow approvers[{idx}]: {e.message or str(e)}')
