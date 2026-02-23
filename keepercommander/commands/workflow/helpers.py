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

from typing import List

from ..pam.router_helper import _post_request_to_router
from ...error import CommandError
from ...params import KeeperParams
from ...proto import workflow_pb2, GraphSync_pb2
from ... import vault, utils


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
                if u.get('enterprise_user_id') == user_id:
                    return u.get('username', f'User ID {user_id}')
        return f'User ID {user_id}'

    @staticmethod
    def validate_team(params: KeeperParams, team_input: str) -> str:
        if team_input in params.team_cache:
            return team_input
        for uid, team_data in params.team_cache.items():
            if team_data.get('name', '').casefold() == team_input.casefold():
                return uid
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

    @staticmethod
    def format_stage(stage: int) -> str:
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
                    return int(duration_str[:-1]) * factor
            return int(duration_str) * 60_000
        except ValueError:
            raise CommandError(
                '', f'Invalid duration format: {duration_str}. '
                    'Use format like "2h", "30m", or "1d"',
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
