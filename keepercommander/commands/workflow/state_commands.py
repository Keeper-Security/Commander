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

from .helpers import RecordResolver, ProtobufRefBuilder, WorkflowFormatter


class WorkflowGetStateCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow state',
        description='Get workflow state for a record or flow',
    )
    _state_group = parser.add_mutually_exclusive_group(required=True)
    _state_group.add_argument('-r', '--record', help='Record UID or name')
    _state_group.add_argument('-f', '--flow-uid', help='Flow UID of active workflow')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowGetStateCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        record_uid = kwargs.get('record')
        flow_uid = kwargs.get('flow_uid')

        state = workflow_pb2.WorkflowState()
        if flow_uid:
            state.flowUid = utils.base64_url_decode(flow_uid)
        else:
            record_uid, record = RecordResolver.resolve(params, record_uid)
            record_uid_bytes = utils.base64_url_decode(record_uid)
            state.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record.title))

        try:
            response = _post_request_to_router(
                params, 'get_workflow_state',
                rq_proto=state, rs_type=workflow_pb2.WorkflowState,
            )

            if response is None:
                if kwargs.get('format') == 'json':
                    print(json.dumps({'status': 'no_workflow', 'message': 'No workflow found'}, indent=2))
                else:
                    print(f"\n{bcolors.WARNING}No workflow found for this record{bcolors.ENDC}\n")
                return

            if kwargs.get('format') == 'json':
                self._print_json(params, response)
            else:
                self._print_table(params, response)

        except Exception as e:
            raise CommandError('', f'Failed to get workflow state: {str(e)}')

    @staticmethod
    def _print_json(params, response):
        result = {
            'flow_uid': utils.base64_url_encode(response.flowUid) if response.flowUid else None,
            'record_uid': utils.base64_url_encode(response.resource.value),
            'record_name': RecordResolver.resolve_name(params, response.resource),
            'stage': WorkflowFormatter.format_stage(response.status.stage),
            'conditions': [WorkflowFormatter.format_conditions([c]) for c in response.status.conditions],
            'escalated': response.status.escalated,
            'started_on': response.status.startedOn or None,
            'expires_on': response.status.expiresOn or None,
            'approved_by': [
                {
                    'user': a.user if a.user else RecordResolver.resolve_user(params, a.userId),
                    'approved_on': a.approvedOn or None,
                }
                for a in response.status.approvedBy
            ],
        }
        print(json.dumps(result, indent=2))

    @staticmethod
    def _print_table(params, response):
        print(f"\n{bcolors.OKBLUE}Workflow State{bcolors.ENDC}\n")
        print(f"Record: {RecordResolver.format_label(params, response.resource)}")
        if response.flowUid:
            print(f"Flow UID: {utils.base64_url_encode(response.flowUid)}")
        print(f"Stage: {WorkflowFormatter.format_stage(response.status.stage)}")
        if response.status.conditions:
            print(f"Conditions: {WorkflowFormatter.format_conditions(response.status.conditions)}")
        if response.status.escalated:
            print("Escalated: Yes")
        if response.status.startedOn:
            started = datetime.fromtimestamp(response.status.startedOn / 1000)
            print(f"Started: {started.strftime('%Y-%m-%d %H:%M:%S')}")
        if response.status.expiresOn:
            expires = datetime.fromtimestamp(response.status.expiresOn / 1000)
            print(f"Expires: {expires.strftime('%Y-%m-%d %H:%M:%S')}")
        if response.status.approvedBy:
            print("Approved by:")
            for a in response.status.approvedBy:
                name = a.user if a.user else RecordResolver.resolve_user(params, a.userId)
                ts = ''
                if a.approvedOn:
                    ts = f" at {datetime.fromtimestamp(a.approvedOn / 1000).strftime('%Y-%m-%d %H:%M:%S')}"
                print(f"  - {name}{ts}")
        print()


class WorkflowGetUserAccessStateCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow my-access',
        description='Get all workflow states for current user',
    )
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowGetUserAccessStateCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        try:
            response = _post_request_to_router(
                params, 'get_user_access_state',
                rs_type=workflow_pb2.UserAccessState,
            )

            if not response or not response.workflows:
                if kwargs.get('format') == 'json':
                    print(json.dumps({'workflows': []}, indent=2))
                else:
                    print(f"\n{bcolors.WARNING}No active workflows{bcolors.ENDC}\n")
                return

            if kwargs.get('format') == 'json':
                self._print_json(params, response)
            else:
                self._print_table(params, response)

        except Exception as e:
            raise CommandError('', f'Failed to get user access state: {str(e)}')

    @staticmethod
    def _print_json(params, response):
        result = {
            'workflows': [
                {
                    'flow_uid': utils.base64_url_encode(wf.flowUid),
                    'record_uid': utils.base64_url_encode(wf.resource.value),
                    'record_name': RecordResolver.resolve_name(params, wf.resource),
                    'stage': WorkflowFormatter.format_stage(wf.status.stage),
                    'conditions': [WorkflowFormatter.format_conditions([c]) for c in wf.status.conditions],
                    'escalated': wf.status.escalated,
                    'started_on': wf.status.startedOn or None,
                    'expires_on': wf.status.expiresOn or None,
                    'approved_by': [
                        {
                            'user': a.user if a.user else RecordResolver.resolve_user(params, a.userId),
                            'approved_on': a.approvedOn or None,
                        }
                        for a in wf.status.approvedBy
                    ],
                }
                for wf in response.workflows
            ],
        }
        print(json.dumps(result, indent=2))

    @staticmethod
    def _print_table(params, response):
        rows = []
        for wf in response.workflows:
            stage = WorkflowFormatter.format_stage(wf.status.stage)
            record_name = RecordResolver.resolve_name(params, wf.resource)
            record_uid = utils.base64_url_encode(wf.resource.value) if wf.resource.value else ''
            flow_uid = utils.base64_url_encode(wf.flowUid) if wf.flowUid else ''
            conditions = WorkflowFormatter.format_conditions(wf.status.conditions) if wf.status.conditions else ''
            started = (
                datetime.fromtimestamp(wf.status.startedOn / 1000).strftime('%Y-%m-%d %H:%M:%S')
                if wf.status.startedOn else ''
            )
            expires = (
                datetime.fromtimestamp(wf.status.expiresOn / 1000).strftime('%Y-%m-%d %H:%M:%S')
                if wf.status.expiresOn else ''
            )
            approved_by = ''
            if wf.status.approvedBy:
                approved_names = [
                    a.user if a.user else RecordResolver.resolve_user(params, a.userId)
                    for a in wf.status.approvedBy
                ]
                approved_by = ', '.join(approved_names)
            rows.append([stage, record_name, record_uid, flow_uid, approved_by, started, expires, conditions])

        headers = ['Stage', 'Record Name', 'Record UID', 'Flow UID', 'Approved By', 'Started', 'Expires', 'Conditions']
        print()
        dump_report_data(rows, headers=headers)
        print()
