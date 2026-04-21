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
from typing import List

from ...error import CommandError
from ...params import KeeperParams
from ...proto import workflow_pb2, GraphSync_pb2
from ... import vault, utils


_PROTO_DUMP_RE = re.compile(
    r'\s*(?:type|value|name|stage|conditions|flowUid|resource)\s*:\s*(?:"[^"]*"|\S+)\s*',
)
_RESPONSE_CODE_RE = re.compile(r'\s*[Rr]esponse\s+code:\s*\S+\s*$')


def sanitize_router_error(error: Exception) -> str:
    msg = str(error)
    msg = _RESPONSE_CODE_RE.sub('', msg)
    msg = _PROTO_DUMP_RE.sub('', msg)
    msg = re.sub(r'\s+', ' ', msg).strip()
    return msg or 'Unknown error'


_ENFORCEMENT_KEY = 'allow_configure_workflow_settings'


def print_exempt_message(fmt='table'):
    """Print the standard exemption message in the appropriate format."""
    import json as _json
    from ...display import bcolors as _bc
    if fmt == 'json':
        print(_json.dumps({'status': 'exempt', 'message': 'Workflow not required'}, indent=2))
    else:
        print(f"\n{_bc.WARNING}You have edit access and workflow management permissions for this record.{_bc.ENDC}\n")
        print("Workflow is not required — you can access this resource directly.\n")


def is_workflow_exempt(params, record_uid):
    """Users with edit access AND 'Can manage workflow settings' are exempt from workflow."""
    enforcements = getattr(params, 'enforcements', None)
    if not enforcements or 'booleans' not in enforcements:
        return False
    can_manage = any(
        b.get('value') for b in enforcements['booleans']
        if b.get('key') == _ENFORCEMENT_KEY
    )
    if not can_manage:
        return False

    if record_uid in getattr(params, 'record_owner_cache', {}):
        owner_info = params.record_owner_cache[record_uid]
        if getattr(owner_info, 'owner', False):
            return True

    meta = getattr(params, 'meta_data_cache', {}).get(record_uid)
    if meta and meta.get('can_edit'):
        return True

    for sf_uid in getattr(params, 'shared_folder_cache', {}):
        sf = params.shared_folder_cache[sf_uid]
        for sfr in sf.get('records', []):
            if sfr.get('record_uid') == record_uid:
                if sfr.get('owner') or sfr.get('can_edit'):
                    return True

    return False


class RecordResolver:

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

    @staticmethod
    def format_stage(stage: int, status=None) -> str:
        if stage == workflow_pb2.WS_READY_TO_START and status is not None:
            if not status.startedOn and not status.conditions:
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
    def build_temporal_filter(allowed_days_str, time_range_str, timezone_str):
        if not allowed_days_str and not time_range_str and not timezone_str:
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
            start_minutes = WorkflowFormatter._parse_time_to_minutes(start_str.strip())
            end_minutes = WorkflowFormatter._parse_time_to_minutes(end_str.strip())
            time_range = workflow_pb2.TimeOfDayRange()
            time_range.startTime = start_minutes
            time_range.endTime = end_minutes
            temporal.timeRanges.append(time_range)

        if timezone_str:
            temporal.timeZone = timezone_str

        return temporal

    @staticmethod
    def _parse_time_to_minutes(time_str):
        try:
            parts = time_str.split(':')
            h = int(parts[0])
            m = int(parts[1]) if len(parts) > 1 else 0
            if not (0 <= h <= 23 and 0 <= m <= 59):
                raise ValueError
            return h * 60 + m
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
                sh, sm = divmod(tr.startTime, 60)
                eh, em = divmod(tr.endTime, 60)
                ranges.append(f"{sh:02d}:{sm:02d}-{eh:02d}:{em:02d}")
            result['time_ranges'] = ranges
        if at.timeZone:
            result['timezone'] = at.timeZone
        return result or None
