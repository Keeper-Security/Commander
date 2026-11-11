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
import logging
from datetime import datetime

from ..base import Command, dump_report_data
from ..pam.router_helper import _post_request_to_router
from ...display import bcolors
from ...error import CommandError
from ...params import KeeperParams
from ...proto import workflow_pb2, enterprise_pb2
from ... import api, crypto, utils

from .helpers import RecordResolver, WorkflowFormatter, sanitize_router_error, DashUidArgsMixin


class WorkflowGetApprovalRequestsCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow pending',
        description='Get pending approval requests',
    )
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')
    parser.add_argument(
        '--include-approvers',
        action='store_true',
        help='Include configured approvers and team member emails in JSON output (use with --format json)',
    )

    def get_parser(self):
        return WorkflowGetApprovalRequestsCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        if kwargs.get('include_approvers') and kwargs.get('format') != 'json':
            raise CommandError('', '--include-approvers requires --format json')
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

            seen_flows = set()
            unique = []
            for wf in response.workflows:
                fuid = bytes(wf.flowUid)
                if fuid not in seen_flows:
                    seen_flows.add(fuid)
                    unique.append(wf)

            pending = []
            workflow_states = {}
            for wf in unique:
                state = self._get_workflow_state(params, wf)
                workflow_states[bytes(wf.flowUid)] = state
                if not self._already_approved_by_me(params, state):
                    pending.append(wf)

            if not pending:
                if kwargs.get('format') == 'json':
                    print(json.dumps({'requests': []}, indent=2))
                else:
                    print(f"\n{bcolors.WARNING}No pending approval requests{bcolors.ENDC}\n")
                return

            if kwargs.get('format') == 'json':
                self._print_json(
                    params,
                    pending,
                    workflow_states=workflow_states,
                    include_approvers=kwargs.get('include_approvers', False),
                )
            else:
                self._print_table(params, pending)

        except Exception as e:
            raise CommandError('', f'Failed to get approval requests: {sanitize_router_error(e)}')

    @staticmethod
    def _get_workflow_state(params, wf):
        try:
            st = workflow_pb2.WorkflowState()
            st.flowUid = wf.flowUid
            return _post_request_to_router(
                params, 'get_workflow_state',
                rq_proto=st, rs_type=workflow_pb2.WorkflowState,
            )
        except Exception:
            logging.debug('Failed to check approval status for flow', exc_info=True)
            return None

    @staticmethod
    def _already_approved_by_me(params, state):
        if state and state.status and state.status.approvedBy:
            current_user = params.user
            return any(a.user == current_user for a in state.status.approvedBy)
        return False

    @staticmethod
    def _extract_param(wf, key):
        for p in wf.workflowParameters:
            if p.key == key:
                return p.data
        return None

    @staticmethod
    def _decrypt_param(params, record_uid, encrypted_bytes):
        if not encrypted_bytes:
            return None
        from ...nested_share_folder.common import get_record_key
        record_key = get_record_key(params, record_uid, raise_on_missing=False)
        if not record_key:
            return 'No permission to view. Only users with record access can view this information.'
        try:
            return crypto.decrypt_aes_v2(encrypted_bytes, record_key).decode('utf-8')
        except Exception:
            logging.debug('Failed to decrypt workflow parameter for record %s', record_uid, exc_info=True)
            return 'Unable to decrypt'

    @staticmethod
    def _print_json(params, workflows, workflow_states=None, include_approvers=False):
        decrypt = WorkflowGetApprovalRequestsCommand._decrypt_param
        extract = WorkflowGetApprovalRequestsCommand._extract_param
        workflow_states = workflow_states or {}
        workflow_configs = {}
        team_members = {}
        requests = []
        for wf in workflows:
            rec_uid = utils.base64_url_encode(wf.resource.value)
            requested_by = wf.user or RecordResolver.resolve_user(params, wf.userId)
            state = workflow_states.get(bytes(wf.flowUid))
            workflow_config = workflow_configs.get(rec_uid)
            if rec_uid not in workflow_configs:
                try:
                    workflow_config = _post_request_to_router(
                        params,
                        'read_workflow_config',
                        rq_proto=wf.resource,
                        rs_type=workflow_pb2.WorkflowConfig,
                    )
                except Exception:
                    logging.debug(
                        'Failed to read workflow config for pending request on %s',
                        rec_uid,
                        exc_info=True,
                    )
                    workflow_config = None
                workflow_configs[rec_uid] = workflow_config

            request = {
                'flow_uid': utils.base64_url_encode(wf.flowUid),
                'requested_by': requested_by,
                'record_uid': rec_uid,
                'record_name': RecordResolver.resolve_name(params, wf.resource),
                'approvals_needed': (
                    workflow_config.parameters.approvalsNeeded
                    if workflow_config and workflow_config.HasField('parameters') else None
                ),
                'approvals_received': (
                    len(state.status.approvedBy)
                    if state and state.HasField('status') else None
                ),
                'started_on': wf.startedOn or None,
                'expires_on': wf.expiresOn or None,
                'escalated': wf.escalated,
                'duration': (
                    WorkflowFormatter.format_duration(wf.expiresOn - wf.startedOn)
                    if wf.expiresOn and wf.startedOn else None
                ),
                'reason': decrypt(params, rec_uid, extract(wf, 'reason')),
                'ticket': decrypt(params, rec_uid, extract(wf, 'ticket')),
            }
            if include_approvers:
                request['approvers'] = (
                    WorkflowGetApprovalRequestsCommand._serialize_approvers(
                        params,
                        workflow_config,
                        team_members,
                    )
                    if workflow_config else []
                )
            requests.append(request)
        print(json.dumps({'requests': requests}, indent=2))

    @staticmethod
    def _serialize_approvers(params, workflow_config, team_members):
        approvers = []
        if not workflow_config:
            return approvers
        for approver in workflow_config.approvers:
            approver_info = {'escalation': approver.escalation}
            if approver.escalationAfterMs:
                approver_info['escalation_after'] = WorkflowFormatter.format_duration(
                    approver.escalationAfterMs
                )
            if approver.HasField('user'):
                approver_info['type'] = 'user'
                approver_info['email'] = approver.user
            elif approver.HasField('userId'):
                approver_info['type'] = 'user_id'
                approver_info['user_id'] = approver.userId
            elif approver.HasField('teamUid'):
                team_uid = utils.base64_url_encode(approver.teamUid)
                approver_info['type'] = 'team'
                approver_info['team_uid'] = team_uid
                approver_info['members'] = (
                    WorkflowGetApprovalRequestsCommand._get_team_member_emails(
                        params,
                        approver.teamUid,
                        team_members,
                    )
                )
            approvers.append(approver_info)
        return approvers

    @staticmethod
    def _get_team_member_emails(params, team_uid_bytes, cache):
        team_uid = utils.base64_url_encode(team_uid_bytes)
        if team_uid in cache:
            return cache[team_uid]
        emails = []
        try:
            request = enterprise_pb2.GetTeamMemberRequest()
            request.teamUid = team_uid_bytes
            response = api.communicate_rest(
                params,
                request,
                'vault/get_team_members',
                rs_type=enterprise_pb2.GetTeamMemberResponse,
            )
            emails = list(dict.fromkeys(
                user.email for user in response.enterpriseUser if user.email
            ))
        except Exception:
            logging.debug(
                'Failed to retrieve members for workflow approver team %s',
                team_uid,
                exc_info=True,
            )
        cache[team_uid] = emails
        return emails

    @staticmethod
    def _print_table(params, workflows):
        decrypt = WorkflowGetApprovalRequestsCommand._decrypt_param
        extract = WorkflowGetApprovalRequestsCommand._extract_param
        rows = []
        for wf in workflows:
            record_uid = utils.base64_url_encode(wf.resource.value) if wf.resource.value else ''
            record_name = RecordResolver.resolve_name(params, wf.resource)
            flow_uid = utils.base64_url_encode(wf.flowUid)
            requested_by = wf.user or RecordResolver.resolve_user(params, wf.userId)
            reason = decrypt(params, record_uid, extract(wf, 'reason')) or ''
            ticket = decrypt(params, record_uid, extract(wf, 'ticket')) or ''
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
            rows.append([record_name, record_uid, flow_uid, requested_by, reason, ticket, started, expires, duration])

        headers = ['Record Name', 'Record UID', 'Flow UID', 'Requested By', 'Reason', 'Ticket', 'Started', 'Expires', 'Duration']
        print()
        dump_report_data(rows, headers=headers)
        print()


class WorkflowApproveCommand(DashUidArgsMixin, Command):
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
        try:
            flow_uid_bytes = utils.base64_url_decode(flow_uid)
        except Exception:
            raise CommandError('', f'Invalid flow UID: "{flow_uid}"')

        approval = workflow_pb2.WorkflowApprovalOrDenial()
        approval.flowUid = flow_uid_bytes
        approval.deny = False

        try:
            _post_request_to_router(params, 'approve_or_deny_workflow_access', rq_proto=approval)

            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'flow_uid': flow_uid, 'action': 'approved'}
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}Access request approved{bcolors.ENDC}\n")
                print(f"Flow UID: {flow_uid}")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to approve request: {sanitize_router_error(e)}')


class WorkflowDenyCommand(DashUidArgsMixin, Command):
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
        try:
            flow_uid_bytes = utils.base64_url_decode(flow_uid)
        except Exception:
            raise CommandError('', f'Invalid flow UID: "{flow_uid}"')

        denial = workflow_pb2.WorkflowApprovalOrDenial()
        denial.flowUid = flow_uid_bytes
        denial.deny = True
        if reason:
            reason_bytes = reason.encode('utf-8')
            encrypted = self._encrypt_denial_reason(params, flow_uid_bytes, reason_bytes)
            if encrypted:
                denial.denialReason = encrypted
            else:
                logging.warning(
                    'Could not encrypt denial reason for the requester — reason will not be attached. '
                    'The denial itself will still be sent.'
                )
                reason = ''

        try:
            _post_request_to_router(params, 'approve_or_deny_workflow_access', rq_proto=denial)

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
            raise CommandError('', f'Failed to deny request: {sanitize_router_error(e)}')

    @staticmethod
    def _encrypt_denial_reason(params, flow_uid_bytes, reason_bytes):
        """Encrypt the denial reason with the requested record's key.

        Workflow request reasons are encrypted with the resource record key,
        so denial reasons must use the same encryption contract for the Vault
        notification to decrypt and display them.
        """
        try:
            response = _post_request_to_router(
                params, 'get_approval_requests',
                rs_type=workflow_pb2.ApprovalRequests,
            )
            if not response or not response.workflows:
                return None

            record_uid = None
            for wf in response.workflows:
                if wf.flowUid == flow_uid_bytes:
                    if wf.resource and wf.resource.value:
                        record_uid = utils.base64_url_encode(wf.resource.value)
                    break

            if not record_uid:
                logging.debug('Could not resolve record UID for workflow denial reason')
                return None

            from ...nested_share_folder.common import get_record_key
            record_key = get_record_key(params, record_uid, raise_on_missing=False)
            if not record_key:
                logging.debug('Record key not available for workflow resource %s', record_uid)
                return None

            return crypto.encrypt_aes_v2(reason_bytes, record_key)
        except Exception:
            logging.debug('Failed to encrypt denial reason with record key', exc_info=True)
        return None
