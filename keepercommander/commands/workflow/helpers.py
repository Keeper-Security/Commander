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

import re
import shlex
from typing import List, Optional, Tuple

from ...error import CommandError
from ...params import KeeperParams
from ...proto import workflow_pb2, GraphSync_pb2
from ... import crypto, vault, utils


_PROTO_DUMP_RE = re.compile(
    r'\s*(?:type|value|name|stage|conditions|flowUid|resource)\s*:\s*(?:"[^"]*"|\S+)\s*',
)
_RESPONSE_CODE_RE = re.compile(r'\s*[Rr]esponse\s+code:\s*\S+\s*$')


class DashUidArgsMixin:
    """Mixin for commands whose positional flow-UID arg may start with '-' (base64url)."""

    def execute_args(self, params, args, **kwargs):
        args = fix_dash_uid_args(self.get_parser(), args)
        return super().execute_args(params, args, **kwargs)


def fix_dash_uid_args(parser, args):
    """Insert '--' before a base64url UID starting with '-' so argparse treats it as positional."""
    if not args:
        return args
    try:
        tokens = shlex.split(args)
    except ValueError:
        return args
    if '--' in tokens:
        return args

    known_opts = set()
    consumes_value = set()
    for action in parser._actions:
        for opt in action.option_strings:
            known_opts.add(opt)
            if action.nargs != 0:
                consumes_value.add(opt)

    result = []
    skip_next = False
    for token in tokens:
        if skip_next:
            result.append(token)
            skip_next = False
            continue
        opt_name = token.split('=', 1)[0] if token.startswith('--') and '=' in token else token
        if opt_name in known_opts:
            result.append(token)
            if opt_name in consumes_value and token == opt_name:
                skip_next = True
            continue
        if token.startswith('-'):
            result.append('--')
        result.append(token)

    if len(result) != len(tokens):
        return ' '.join(shlex.quote(t) for t in result)
    return args


def sanitize_router_error(error: Exception) -> str:
    msg = str(error)
    msg = _RESPONSE_CODE_RE.sub('', msg)
    msg = _PROTO_DUMP_RE.sub('', msg)
    msg = re.sub(r'\s+', ' ', msg).strip()
    return msg or 'Unknown error'


def print_exempt_message(fmt='table'):
    import json as _json
    from ...display import bcolors as _bc
    if fmt == 'json':
        print(_json.dumps({'status': 'exempt', 'message': 'Workflow not required'}, indent=2))
    else:
        print(f"\n{_bc.WARNING}You are exempt from workflow restrictions on this record.{_bc.ENDC}")
        print("As a record owner or approver, you can access this resource directly.\n")


def is_record_owner(params, record_uid):
    if record_uid in getattr(params, 'record_owner_cache', {}):
        owner_info = params.record_owner_cache[record_uid]
        if getattr(owner_info, 'owner', False):
            return True
    return False


def is_on_approver_list(params, config):
    """Check if current user is on the approver list (by email or team membership)."""
    if not config or not config.approvers:
        return False

    current_user = getattr(params, 'user', '')
    team_cache = getattr(params, 'team_cache', {})

    for approver in config.approvers:
        if approver.user and approver.user.lower() == current_user.lower():
            return True
        if approver.teamUid:
            team_uid_b64 = utils.base64_url_encode(approver.teamUid)
            if team_uid_b64 in team_cache:
                return True
    return False


def is_workflow_exempt(params, record_uid, config=None):
    """Exempt = record owner OR on approver list. Pass `config` to skip a round-trip.
    Transport failures fail closed (non-exempt)."""
    if is_record_owner(params, record_uid):
        return True

    if config is None:
        from ..pam.router_helper import _post_request_to_router
        try:
            ref = ProtobufRefBuilder.record_ref(
                utils.base64_url_decode(record_uid),
                '',
            )
            config = _post_request_to_router(
                params, 'read_workflow_config',
                rq_proto=ref, rs_type=workflow_pb2.WorkflowConfig,
            )
        except Exception as e:
            import logging as _logging
            _logging.debug(
                'is_workflow_exempt config read failed for %s: %s', record_uid, e,
            )
            return False

    return is_on_approver_list(params, config)


def is_pam_action_allowed_by_enforcement(params: KeeperParams, enforcement_key: str) -> bool:
    """Per-user enterprise enforcement gate. Mirrors web vault's PAM enforcement selectors.
    Non-enterprise users and unexpected payload shapes fall back to allow (gateway gates).
    Enterprise users with the key absent are denied (matches WV's `!!enforcements.<key>`).
    License is intentionally not checked here — gateway is the authoritative gate for that."""
    import logging as _logging
    try:
        enforcements = getattr(params, 'enforcements', None)
        if not enforcements or not isinstance(enforcements, dict):
            return True
        booleans = enforcements.get('booleans') or []
        if not isinstance(booleans, list) or not booleans:
            return True
        for b in booleans:
            if isinstance(b, dict) and b.get('key') == enforcement_key:
                return bool(b.get('value'))
        return False
    except Exception as e:
        _logging.debug('Enforcement check failed for %s: %s', enforcement_key, e)
        return True


def is_pam_config_action_allowed_for_record(params: KeeperParams, record_uid: str,
                                            action_key: str) -> bool:
    """Best-effort PAM config allowedSettings (DAG) gate.
    action_key: 'connections' (launch), 'tunneling' (port-forward), 'rotation'.
    Returns True on any lookup failure; False only when explicitly disabled on the config."""
    import logging as _logging
    try:
        config_uid = None
        try:
            from ..pam_launch import launch_cache
            entry = launch_cache.get(record_uid)
            if entry:
                config_uid = entry.get('config_uid')
        except Exception:
            pass

        if not config_uid:
            from ... import vault as _vault
            from ..tunnel.port_forward.tunnel_helpers import get_config_uid_from_record
            try:
                config_uid = get_config_uid_from_record(params, _vault, record_uid)
            except CommandError:
                return True

        if not config_uid:
            return True

        from ..discoveryrotation import PAMConfigurationListCommand
        allowed = PAMConfigurationListCommand._pam_config_allowed_settings_json(
            params, config_uid,
        )
        return allowed.get(action_key) is not False
    except Exception as e:
        _logging.debug(
            'PAM config allowedSettings lookup failed for %s (action=%s): %s',
            record_uid, action_key, e,
        )
        return True


def is_gateway_online_for_record(params: KeeperParams, record_uid: str) -> Optional[bool]:
    """Best-effort gateway online check. Returns None when undetermined (treat as 'proceed')."""
    import logging as _logging
    try:
        from ..pam_launch import launch_cache
        entry = launch_cache.get(record_uid)
        if not entry:
            return None
        gateway_uid_str = entry.get('gateway_uid')
        if not gateway_uid_str:
            return None
        gateway_uid_bytes = utils.base64_url_decode(gateway_uid_str)

        from ..pam.router_helper import router_get_connected_gateways
        online = router_get_connected_gateways(params)
        if not online or not online.controllers:
            return False
        return any(c.controllerUid == gateway_uid_bytes for c in online.controllers)
    except Exception as e:
        _logging.debug("Gateway online probe failed for %s: %s", record_uid, e)
        return None


def start_workflow_for_record(params: KeeperParams, record_uid: str) -> None:
    from ..pam.router_helper import _post_request_to_router
    record_uid_bytes = utils.base64_url_decode(record_uid)
    record = vault.KeeperRecord.load(params, record_uid)
    record_name = record.title if record else record_uid

    state = workflow_pb2.WorkflowState()
    state.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record_name))
    _post_request_to_router(params, 'start_workflow', rq_proto=state)


def submit_access_request(params: KeeperParams, record_uid: str,
                          reason: str = '', ticket: str = '') -> None:
    """Send a workflow access request. Reason/ticket are encrypted with the record key."""
    from ..pam.router_helper import _post_request_to_router
    record_uid_bytes = utils.base64_url_decode(record_uid)
    record = vault.KeeperRecord.load(params, record_uid)
    record_name = record.title if record else record_uid

    record_key = params.record_cache.get(record_uid, {}).get('record_key_unencrypted')
    if not record_key and (reason or ticket):
        raise CommandError(
            '', 'Record key not available — cannot encrypt reason/ticket. '
                'You do not have sufficient access to this record to send encrypted parameters.',
        )

    access_request = workflow_pb2.WorkflowAccessRequest()
    access_request.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record_name))
    if reason:
        reason_bytes = reason.encode('utf-8') if isinstance(reason, str) else reason
        access_request.reason = crypto.encrypt_aes_v2(reason_bytes, record_key)
    if ticket:
        ticket_bytes = ticket.encode('utf-8') if isinstance(ticket, str) else ticket
        access_request.ticket = crypto.encrypt_aes_v2(ticket_bytes, record_key)

    _post_request_to_router(params, 'request_workflow_access', rq_proto=access_request)


def prompt_for_reason_ticket(needs_reason: bool, needs_ticket: bool) -> Tuple[Optional[str], Optional[str]]:
    """Prompt for reason/ticket. Returns (None, None) on cancel or empty required input."""
    from prompt_toolkit import prompt as pt_prompt
    from ...display import bcolors as _bc

    reason_value = None
    ticket_value = None
    try:
        if needs_reason:
            print(f"\n{_bc.OKBLUE}Workflow requires a justification.{_bc.ENDC}")
            print('Type your reason. Press Esc then Enter to submit, or Ctrl+C to cancel.\n')
            text = pt_prompt('Reason: ', multiline=True).strip()
            if not text:
                print(f"{_bc.WARNING}Reason is required — cancelled.{_bc.ENDC}")
                return None, None
            reason_value = text
        if needs_ticket:
            print(f"\n{_bc.OKBLUE}Workflow requires a ticket / reference number.{_bc.ENDC}")
            text = pt_prompt('Ticket: ').strip()
            if not text:
                print(f"{_bc.WARNING}Ticket is required — cancelled.{_bc.ENDC}")
                return None, None
            ticket_value = text
    except (KeyboardInterrupt, EOFError):
        return None, None
    return reason_value, ticket_value


class RecordResolver:

    WORKFLOW_RECORD_TYPES = {'pamMachine', 'pamDirectory', 'pamDatabase', 'pamRemoteBrowser'}

    @staticmethod
    def resolve(params, record_input, allow_missing=False):
        if record_input in params.record_cache:
            return record_input, vault.KeeperRecord.load(params, record_input)
        for uid in params.record_cache:
            rec = vault.KeeperRecord.load(params, uid)
            if rec and rec.title == record_input:
                return uid, rec
        if allow_missing:
            return None, None
        raise CommandError('', f'Record "{record_input}" not found')

    @staticmethod
    def validate_workflow_record_type(record):
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('', 'Workflows are only supported on PAM records')
        record_type = record.record_type or 'unknown'
        if record_type not in RecordResolver.WORKFLOW_RECORD_TYPES:
            supported = ', '.join(sorted(RecordResolver.WORKFLOW_RECORD_TYPES))
            raise CommandError(
                '',
                f'Record "{record.title}" is of type "{record_type}" which does not support workflows.\n'
                f'Supported record types: {supported}'
            )

    @staticmethod
    def get_uid_bytes(params: KeeperParams, record_uid: str) -> bytes:
        uid_bytes = utils.base64_url_decode(record_uid)
        if record_uid not in params.record_cache:
            raise CommandError('', f'Record {record_uid} not found')
        return uid_bytes

    @staticmethod
    def resolve_name(params, resource_ref) -> str:
        if resource_ref.name:
            return resource_ref.name
        if resource_ref.value:
            rec_uid = utils.base64_url_encode(resource_ref.value)
            rec = vault.KeeperRecord.load(params, rec_uid)
            return rec.title if rec else ''
        return ''

    @staticmethod
    def format_label(params, resource_ref) -> str:
        rec_uid = utils.base64_url_encode(resource_ref.value) if resource_ref.value else ''
        rec_name = RecordResolver.resolve_name(params, resource_ref)
        if rec_name and rec_name != rec_uid:
            return f"{rec_name} ({rec_uid})"
        return rec_uid or 'Unknown'

    @staticmethod
    def resolve_user(params: KeeperParams, user_id: int) -> str:
        if params.enterprise and 'users' in params.enterprise:
            for u in params.enterprise['users']:
                if u.get('enterprise_user_id') == user_id or u.get('user_id') == user_id:
                    return u.get('username', f'User ID {user_id}')
        return f'User ID {user_id}'

    @staticmethod
    def resolve_team_name(params: KeeperParams, team_uid: str) -> str:
        team_data = params.team_cache.get(team_uid, {})
        name = team_data.get('name', '')
        if name:
            return name
        if params.enterprise and 'teams' in params.enterprise:
            for team in params.enterprise['teams']:
                if team.get('team_uid', '') == team_uid:
                    return team.get('name', '')
        return ''

    @staticmethod
    def validate_team(params: KeeperParams, team_input: str) -> str:
        if team_input in params.team_cache:
            return team_input
        for uid, team_data in params.team_cache.items():
            if team_data.get('name', '').casefold() == team_input.casefold():
                return uid

        if params.enterprise and 'teams' in params.enterprise:
            for team in params.enterprise['teams']:
                team_uid = team.get('team_uid', '')
                if team_uid == team_input:
                    return team_uid
                if team.get('name', '').casefold() == team_input.casefold():
                    return team_uid

        raise CommandError('', f'Team "{team_input}" not found. Use a valid team UID or team name.')


class ProtobufRefBuilder:

    @staticmethod
    def record_ref(record_uid_bytes: bytes, record_name: str = '') -> GraphSync_pb2.GraphSyncRef:
        ref = GraphSync_pb2.GraphSyncRef()
        ref.type = GraphSync_pb2.RFT_REC
        ref.value = record_uid_bytes
        if record_name:
            ref.name = record_name
        return ref

    @staticmethod
    def workflow_ref(flow_uid_bytes: bytes) -> GraphSync_pb2.GraphSyncRef:
        ref = GraphSync_pb2.GraphSyncRef()
        ref.type = GraphSync_pb2.RFT_WORKFLOW
        ref.value = flow_uid_bytes
        return ref


class WorkflowFormatter:

    STAGE_MAP = {
        workflow_pb2.WS_READY_TO_START: 'Ready to Start',
        workflow_pb2.WS_STARTED: 'Started',
        workflow_pb2.WS_NEEDS_ACTION: 'Needs Action',
        workflow_pb2.WS_WAITING: 'Waiting',
    }

    CONDITION_MAP = {
        workflow_pb2.AC_APPROVAL: 'Approval Required',
        workflow_pb2.AC_CHECKIN: 'Check-in Required',
        workflow_pb2.AC_MFA: 'MFA Required',
        workflow_pb2.AC_TIME: 'Time Restriction',
        workflow_pb2.AC_REASON: 'Reason Required',
        workflow_pb2.AC_TICKET: 'Ticket Required',
    }

    DURATION_MULTIPLIERS = {'d': 86_400_000, 'h': 3_600_000, 'm': 60_000}

    DAY_PARSE_MAP = {
        'mon': workflow_pb2.MONDAY, 'monday': workflow_pb2.MONDAY,
        'tue': workflow_pb2.TUESDAY, 'tuesday': workflow_pb2.TUESDAY,
        'wed': workflow_pb2.WEDNESDAY, 'wednesday': workflow_pb2.WEDNESDAY,
        'thu': workflow_pb2.THURSDAY, 'thursday': workflow_pb2.THURSDAY,
        'fri': workflow_pb2.FRIDAY, 'friday': workflow_pb2.FRIDAY,
        'sat': workflow_pb2.SATURDAY, 'saturday': workflow_pb2.SATURDAY,
        'sun': workflow_pb2.SUNDAY, 'sunday': workflow_pb2.SUNDAY,
    }

    DAY_NAME_MAP = {
        workflow_pb2.MONDAY: 'Monday',
        workflow_pb2.TUESDAY: 'Tuesday',
        workflow_pb2.WEDNESDAY: 'Wednesday',
        workflow_pb2.THURSDAY: 'Thursday',
        workflow_pb2.FRIDAY: 'Friday',
        workflow_pb2.SATURDAY: 'Saturday',
        workflow_pb2.SUNDAY: 'Sunday',
    }

    BLOCKING_CONDITIONS = {workflow_pb2.AC_TIME, workflow_pb2.AC_APPROVAL}

    @staticmethod
    def format_stage(stage: int, status=None) -> str:
        if stage == workflow_pb2.WS_READY_TO_START and status is not None:
            if status.conditions:
                has_blocking = any(c in WorkflowFormatter.BLOCKING_CONDITIONS for c in status.conditions)
                if has_blocking:
                    return 'Waiting'
                return 'Ready to Start'
            if status.approvedBy and not status.startedOn:
                return 'Ready to Start'
            if not status.startedOn and not status.approvedBy:
                return 'Needs Action'
        return WorkflowFormatter.STAGE_MAP.get(stage, f'Unknown ({stage})')

    @staticmethod
    def format_conditions(conditions: List[int]) -> str:
        return ', '.join(
            WorkflowFormatter.CONDITION_MAP.get(c, f'Unknown ({c})')
            for c in conditions
        )

    @staticmethod
    def parse_duration(duration_str: str) -> int:
        duration_str = duration_str.lower().strip()
        try:
            for suffix, factor in WorkflowFormatter.DURATION_MULTIPLIERS.items():
                if duration_str.endswith(suffix):
                    value = int(duration_str[:-1])
                    if value <= 0:
                        raise ValueError
                    return value * factor
            value = int(duration_str)
            if value <= 0:
                raise ValueError
            return value * 60_000
        except ValueError:
            raise CommandError(
                '', f'Invalid duration format: {duration_str}. '
                    'Use a positive value like "2h", "30m", or "1d"',
            )

    @staticmethod
    def format_duration(milliseconds: int) -> str:
        seconds = milliseconds // 1000
        minutes = seconds // 60
        hours = minutes // 60
        days = hours // 24

        if days > 0:
            return f"{days} day{'s' if days != 1 else ''}"
        if hours > 0:
            return f"{hours} hour{'s' if hours != 1 else ''}"
        if minutes > 0:
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        return f"{seconds} second{'s' if seconds != 1 else ''}"

    @staticmethod
    def build_temporal_filter(allowed_days_str, time_range_str):
        if not allowed_days_str and not time_range_str:
            return None

        temporal = workflow_pb2.TemporalAccessFilter()

        if allowed_days_str:
            for day_token in allowed_days_str.split(','):
                day_token = day_token.strip().lower()
                day_enum = WorkflowFormatter.DAY_PARSE_MAP.get(day_token)
                if day_enum is None:
                    valid = ', '.join(sorted({k for k in WorkflowFormatter.DAY_PARSE_MAP if len(k) == 3}))
                    raise CommandError('', f'Invalid day: "{day_token}". Valid: {valid}')
                temporal.allowedDays.append(day_enum)

        if time_range_str:
            if '-' not in time_range_str:
                raise CommandError('', 'Time range must be in HH:MM-HH:MM format (e.g., "09:00-17:00")')
            start_str, end_str = time_range_str.split('-', 1)
            start_hhmm = WorkflowFormatter._parse_time_to_hhmm(start_str.strip())
            end_hhmm = WorkflowFormatter._parse_time_to_hhmm(end_str.strip())
            time_range = workflow_pb2.TimeOfDayRange()
            time_range.startTime = start_hhmm
            time_range.endTime = end_hhmm
            temporal.timeRanges.append(time_range)

        temporal.timeZone = WorkflowFormatter._get_local_iana_timezone()

        return temporal

    @staticmethod
    def _get_local_iana_timezone():
        """Detect local IANA timezone via TZ env var (override) or tzlocal (cross-platform)."""
        import os

        tz = os.environ.get('TZ')
        if tz and '/' in tz:
            return tz

        try:
            from tzlocal import get_localzone_name
        except ImportError:
            raise CommandError(
                '',
                'Timezone detection requires the "tzlocal" package. '
                'Install it with: pip install tzlocal\n'
                'Or set the TZ environment variable (e.g., TZ=Asia/Kolkata).'
            )

        try:
            zone = get_localzone_name()
            if zone:
                return zone
        except Exception as e:
            import logging as _logging
            _logging.debug('tzlocal lookup failed: %s', e)

        raise CommandError(
            '',
            'Could not detect local IANA timezone. '
            'Set the TZ environment variable (e.g., TZ=Asia/Kolkata).'
        )

    @staticmethod
    def _parse_time_to_hhmm(time_str):
        """Parse 'HH:MM' to HHMM integer (hours*100 + minutes), e.g. '09:00' -> 900, '17:30' -> 1730."""
        try:
            parts = time_str.split(':')
            h = int(parts[0])
            m = int(parts[1]) if len(parts) > 1 else 0
            if not (0 <= h <= 23 and 0 <= m <= 59):
                raise ValueError
            return h * 100 + m
        except (ValueError, IndexError):
            raise CommandError('', f'Invalid time format: "{time_str}". Use HH:MM (e.g., "09:00")')

    @staticmethod
    def format_temporal_filter(at):
        if not at:
            return None
        result = {}
        if at.allowedDays:
            result['allowed_days'] = [WorkflowFormatter.DAY_NAME_MAP.get(d, str(d)) for d in at.allowedDays]
        if at.timeRanges:
            ranges = []
            for tr in at.timeRanges:
                sh, sm = divmod(tr.startTime, 100)
                eh, em = divmod(tr.endTime, 100)
                ranges.append(f"{sh:02d}:{sm:02d}-{eh:02d}:{em:02d}")
            result['time_ranges'] = ranges
        if at.timeZone:
            result['timezone'] = at.timeZone
        return result or None
