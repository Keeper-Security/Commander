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
from datetime import datetime

from ..base import Command, dump_report_data
from ..pam.router_helper import _post_request_to_router
from ...display import bcolors
from ...error import CommandError
from ...params import KeeperParams
from ...proto import workflow_pb2
from ... import utils

from .helpers import RecordResolver, WorkflowFormatter


class WorkflowGetApprovalRequestsCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow pending',
        description='Get pending approval requests',
    )
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowGetApprovalRequestsCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        try:
            response = _post_request_to_router(
                params, 'get_approval_requests',
                rs_type=workflow_pb2.ApprovalRequests,
            )

            if not response or not response.workflows:
                if kwargs.get('format') == 'json':
                    print(json.dumps({'requests': []}, indent=2))
                else:
                    print(f"\n{bcolors.WARNING}No approval requests{bcolors.ENDC}\n")
                return

            wf_data = [
                (wf, self._resolve_status(params, wf))
                for wf in response.workflows
            ]

            if kwargs.get('format') == 'json':
                self._print_json(params, wf_data)
            else:
                self._print_table(params, wf_data)

        except Exception as e:
            raise CommandError('', f'Failed to get approval requests: {str(e)}')

    @staticmethod
    def _resolve_status(params, wf):
        if wf.startedOn:
            return 'Approved'
        try:
            st = workflow_pb2.WorkflowState()
            st.flowUid = wf.flowUid
            ws = _post_request_to_router(
                params, 'get_workflow_state',
                rq_proto=st, rs_type=workflow_pb2.WorkflowState,
            )
            if ws and ws.status and ws.status.stage in (
                workflow_pb2.WS_READY_TO_START, workflow_pb2.WS_STARTED,
            ):
                return 'Approved'
        except Exception:
            pass
        return 'Pending'

    @staticmethod
    def _print_json(params, wf_data):
        result = {
            'requests': [
                {
                    'flow_uid': utils.base64_url_encode(wf.flowUid),
                    'status': status,
                    'requested_by': RecordResolver.resolve_user(params, wf.userId),
                    'record_uid': utils.base64_url_encode(wf.resource.value),
                    'record_name': RecordResolver.resolve_name(params, wf.resource),
                    'started_on': wf.startedOn or None,
                    'expires_on': wf.expiresOn or None,
                    'duration': (
                        WorkflowFormatter.format_duration(wf.expiresOn - wf.startedOn)
                        if wf.expiresOn and wf.startedOn else None
                    ),
                    'reason': wf.reason.decode('utf-8') if wf.reason else None,
                    'external_ref': wf.externalRef.decode('utf-8') if wf.externalRef else None,
                }
                for wf, status in wf_data
            ],
        }
        print(json.dumps(result, indent=2))

    @staticmethod
    def _print_table(params, wf_data):
        rows = []
        for wf, status in wf_data:
            record_uid = utils.base64_url_encode(wf.resource.value) if wf.resource.value else ''
            record_name = RecordResolver.resolve_name(params, wf.resource)
            flow_uid = utils.base64_url_encode(wf.flowUid)
            requested_by = RecordResolver.resolve_user(params, wf.userId)
            started = (
                datetime.fromtimestamp(wf.startedOn / 1000).strftime('%Y-%m-%d %H:%M:%S')
                if wf.startedOn else ''
            )
            expires = (
                datetime.fromtimestamp(wf.expiresOn / 1000).strftime('%Y-%m-%d %H:%M:%S')
                if wf.expiresOn else ''
            )
            duration = (
                WorkflowFormatter.format_duration(wf.expiresOn - wf.startedOn)
                if wf.expiresOn and wf.startedOn else ''
            )
            rows.append([status, record_name, record_uid, flow_uid, requested_by, started, expires, duration])

        headers = ['Status', 'Record Name', 'Record UID', 'Flow UID', 'Requested By', 'Started', 'Expires', 'Duration']
        print()
        dump_report_data(rows, headers=headers, sort_by=0)
        print()


class WorkflowApproveCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow approve',
        description='Approve a workflow access request',
    )
    parser.add_argument('flow_uid', help='Flow UID of the workflow to approve')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowApproveCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        flow_uid = kwargs.get('flow_uid')
        flow_uid_bytes = utils.base64_url_decode(flow_uid)

        approval = workflow_pb2.WorkflowApprovalOrDenial()
        approval.flowUid = flow_uid_bytes
        approval.deny = False

        try:
            _post_request_to_router(params, 'approve_workflow_access', rq_proto=approval)

            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'flow_uid': flow_uid, 'action': 'approved'}
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Access request approved{bcolors.ENDC}\n")
                print(f"Flow UID: {flow_uid}")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to approve request: {str(e)}')


class WorkflowDenyCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow deny',
        description='Deny a workflow access request',
    )
    parser.add_argument('flow_uid', help='Flow UID of the workflow to deny')
    parser.add_argument('-r', '--reason', help='Reason for denial')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowDenyCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        flow_uid = kwargs.get('flow_uid')
        reason = kwargs.get('reason') or ''
        flow_uid_bytes = utils.base64_url_decode(flow_uid)

        denial = workflow_pb2.WorkflowApprovalOrDenial()
        denial.flowUid = flow_uid_bytes
        denial.deny = True
        if reason:
            denial.denialReason = reason

        try:
            _post_request_to_router(params, 'deny_workflow_access', rq_proto=denial)

            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'flow_uid': flow_uid, 'action': 'denied'}
                if reason:
                    result['reason'] = reason
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.WARNING}Access request denied{bcolors.ENDC}\n")
                print(f"Flow UID: {flow_uid}")
                if reason:
                    print(f"Reason: {reason}")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to deny request: {str(e)}')
