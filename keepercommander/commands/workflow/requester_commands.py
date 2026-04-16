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

import argparse
import json

from ..base import Command
from ..pam.router_helper import _post_request_to_router
from ...display import bcolors
from ...error import CommandError
from ...params import KeeperParams
from ...proto import workflow_pb2, GraphSync_pb2
from ... import crypto, utils

from .helpers import RecordResolver, ProtobufRefBuilder, sanitize_router_error, is_workflow_exempt, print_exempt_message


class WorkflowRequestAccessCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow request',
        description='Request access to a PAM resource, escalate, or cancel a pending request',
    )
    parser.add_argument('record', help='Record UID or name')
    parser.add_argument('-r', '--reason', help='Reason for access request')
    parser.add_argument('-t', '--ticket', help='External ticket/reference number')
    parser.add_argument('-e', '--escalate', action='store_true',
                        help='Escalate a pending request to escalation approvers')
    parser.add_argument('-c', '--cancel', action='store_true',
                        help='Cancel a pending or active workflow request')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowRequestAccessCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        cancel = kwargs.get('cancel')
        escalate = kwargs.get('escalate')

        if cancel and escalate:
            raise CommandError('', '--cancel and --escalate cannot be used together')
        if cancel and (kwargs.get('reason') or kwargs.get('ticket')):
            raise CommandError('', '--cancel cannot be used with --reason or --ticket')

        if cancel:
            return self._cancel(params, **kwargs)
        if escalate:
            return self._escalate(params, **kwargs)
        return self._request(params, **kwargs)

    @staticmethod
    def _request(params, **kwargs):
        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        if is_workflow_exempt(params, record_uid):
            print_exempt_message(kwargs.get('format', 'table'))
            return
        record_uid_bytes = utils.base64_url_decode(record_uid)
        reason = kwargs.get('reason') or ''
        ticket = kwargs.get('ticket') or ''

        record_key = params.record_cache.get(record_uid, {}).get('record_key_unencrypted')
        if not record_key and (reason or ticket):
            raise CommandError(
                '', 'Record key not available — cannot encrypt reason/ticket. '
                    'You do not have sufficient access to this record to send encrypted parameters.',
            )

        access_request = workflow_pb2.WorkflowAccessRequest()
        access_request.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record.title))
        if reason:
            reason_bytes = reason.encode('utf-8') if isinstance(reason, str) else reason
            access_request.reason = crypto.encrypt_aes_v2(reason_bytes, record_key)
        if ticket:
            ticket_bytes = ticket.encode('utf-8') if isinstance(ticket, str) else ticket
            access_request.ticket = crypto.encrypt_aes_v2(ticket_bytes, record_key)

        try:
            _post_request_to_router(params, 'request_workflow_access', rq_proto=access_request)

            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'message': 'Access request sent to approvers',
                }
                if reason:
                    result['reason'] = reason
                if ticket:
                    result['ticket'] = ticket
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}Access request sent{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                if reason:
                    print(f"Reason: {reason}")
                if ticket:
                    print(f"Ticket: {ticket}")
                print("\nApprovers have been notified.")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to request access: {sanitize_router_error(e)}')

    @staticmethod
    def _escalate(params, **kwargs):
        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        if is_workflow_exempt(params, record_uid):
            print_exempt_message(kwargs.get('format', 'table'))
            return
        record_uid_bytes = utils.base64_url_decode(record_uid)

        state = workflow_pb2.WorkflowState()
        state.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record.title))

        try:
            _post_request_to_router(params, 'request_escalation', rq_proto=state)

            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'action': 'escalated',
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}Request escalated{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print("\nEscalation approvers have been notified.")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to escalate request: {sanitize_router_error(e)}')

    @staticmethod
    def _cancel(params, **kwargs):
        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        record_uid_bytes = utils.base64_url_decode(record_uid)

        try:
            state_query = workflow_pb2.WorkflowState()
            state_query.resource.CopyFrom(
                ProtobufRefBuilder.record_ref(record_uid_bytes, record.title if record else '')
            )
            workflow_state = _post_request_to_router(
                params, 'get_workflow_state',
                rq_proto=state_query, rs_type=workflow_pb2.WorkflowState,
            )
            if not workflow_state or not workflow_state.flowUid:
                raise CommandError(
                    '', 'No active workflow request found for this record.',
                )

            flow_ref = ProtobufRefBuilder.workflow_ref(workflow_state.flowUid)
            _post_request_to_router(params, 'end_workflow', rq_proto=flow_ref)

            flow_uid_str = utils.base64_url_encode(workflow_state.flowUid)
            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'flow_uid': flow_uid_str,
                    'action': 'cancelled',
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}Workflow request cancelled{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print(f"Flow UID: {flow_uid_str}")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to cancel request: {sanitize_router_error(e)}')


class WorkflowStartCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow start',
        description='Start a workflow (check-out). '
                    'Can use either record UID/name or flow UID.',
    )
    parser.add_argument('uid', help='Record UID, record name, or Flow UID')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowStartCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        uid = kwargs.get('uid')
        record_uid, record = RecordResolver.resolve(params, uid, allow_missing=True)

        state = workflow_pb2.WorkflowState()
        if record_uid:
            record_uid_bytes = utils.base64_url_decode(record_uid)
            state.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record.title))
        else:
            try:
                uid_bytes = utils.base64_url_decode(uid)
            except Exception:
                raise CommandError('', f'"{uid}" is not a valid record UID/name or flow UID')
            state.flowUid = uid_bytes
            state.resource.CopyFrom(ProtobufRefBuilder.workflow_ref(uid_bytes))

        try:
            _post_request_to_router(params, 'start_workflow', rq_proto=state)

            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'action': 'checked_out'}
                if record:
                    result['record_uid'] = record_uid
                    result['record_name'] = record.title
                else:
                    result['flow_uid'] = uid
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}Workflow started (checked out){bcolors.ENDC}\n")
                if record:
                    print(f"Record: {record.title} ({record_uid})")
                else:
                    print(f"Flow UID: {uid}")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to start workflow: {sanitize_router_error(e)}')


class WorkflowEndCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow end',
        description='End a workflow (check-in).',
    )
    parser.add_argument('uid', help='Record UID, record name, or Flow UID')
    parser.add_argument('-f', '--force', action='store_true',
                        help='force check-in: approvers can terminate another user\'s active session\nwhen single-user checkout is enabled.')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowEndCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        if kwargs.get('force'):
            return self._force_checkin(params, **kwargs)

        uid = kwargs.get('uid')
        record_uid, record = RecordResolver.resolve(params, uid, allow_missing=True)

        if record_uid:
            self._end_by_record(params, record_uid, record, kwargs)
        else:
            self._end_by_flow_uid(params, uid, kwargs)

    @staticmethod
    def _force_checkin(params, **kwargs):
        uid = kwargs.get('uid')
        record_uid, record = RecordResolver.resolve(params, uid, allow_missing=True)

        if record_uid:
            ref = GraphSync_pb2.GraphSyncRef()
            ref.type = GraphSync_pb2.RFT_REC
            ref.value = utils.base64_url_decode(record_uid)
            if record:
                ref.name = record.title
            label = f"Record: {record.title} ({record_uid})" if record else f"Record: {record_uid}"
        else:
            try:
                uid_bytes = utils.base64_url_decode(uid)
            except Exception:
                raise CommandError('', f'"{uid}" is not a valid record UID/name or flow UID')
            ref = GraphSync_pb2.GraphSyncRef()
            ref.type = GraphSync_pb2.RFT_WORKFLOW
            ref.value = uid_bytes
            label = f"Flow UID: {uid}"

        try:
            _post_request_to_router(params, 'force_checkin', rq_proto=ref)

            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'action': 'force_checkin'}
                if record_uid:
                    result['record_uid'] = record_uid
                    result['record_name'] = record.title if record else ''
                else:
                    result['flow_uid'] = uid
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}Record force checked in{bcolors.ENDC}\n")
                print(label)
                print()

        except Exception as e:
            raise CommandError('', f'Failed to force check-in: {sanitize_router_error(e)}')

    @staticmethod
    def _end_by_record(params, record_uid, record, kwargs):
        try:
            state_query = workflow_pb2.WorkflowState()
            state_query.resource.CopyFrom(
                ProtobufRefBuilder.record_ref(utils.base64_url_decode(record_uid), record.title if record else '')
            )
            workflow_state = _post_request_to_router(
                params, 'get_workflow_state',
                rq_proto=state_query, rs_type=workflow_pb2.WorkflowState,
            )
            if not workflow_state or not workflow_state.flowUid:
                raise CommandError(
                    '', 'No active workflow found for this record. '
                        'The workflow may have already ended or never started.',
                )

            flow_ref = ProtobufRefBuilder.workflow_ref(workflow_state.flowUid)
            _post_request_to_router(params, 'end_workflow', rq_proto=flow_ref)

            flow_uid_str = utils.base64_url_encode(workflow_state.flowUid)
            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'flow_uid': flow_uid_str,
                    'record_uid': record_uid,
                    'record_name': record.title if record else '',
                    'action': 'ended',
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}Workflow ended (checked in){bcolors.ENDC}\n")
                if record:
                    print(f"Record: {record.title} ({record_uid})")
                else:
                    print(f"Record: {record_uid}")
                print(f"Flow UID: {flow_uid_str}")
                print("\nCredentials may have been rotated.")
                print()
        except Exception as e:
            raise CommandError('', f'Failed to end workflow: {sanitize_router_error(e)}')

    @staticmethod
    def _end_by_flow_uid(params, uid, kwargs):
        try:
            uid_bytes = utils.base64_url_decode(uid)
            ref = ProtobufRefBuilder.workflow_ref(uid_bytes)
            _post_request_to_router(params, 'end_workflow', rq_proto=ref)

            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'flow_uid': uid, 'action': 'ended'}
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}Workflow ended (checked in){bcolors.ENDC}\n")
                print(f"Flow UID: {uid}")
                print("\nCredentials may have been rotated.")
                print()
        except Exception as e:
            raise CommandError('', f'Failed to end workflow: {sanitize_router_error(e)}')
