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
from ...proto import workflow_pb2
from ... import api, crypto, utils

from .helpers import RecordResolver, WorkflowFormatter, sanitize_router_error


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
            raise CommandError('', f'Failed to get approval requests: {sanitize_router_error(e)}')

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
            if ws and ws.status:
                stage = ws.status.stage
                if stage == workflow_pb2.WS_STARTED:
                    return 'Approved'
                if stage == workflow_pb2.WS_READY_TO_START:
                    has_data = (ws.status.conditions or ws.status.approvedBy
                                or ws.status.startedOn or ws.status.expiresOn)
                    if has_data:
                        return 'Approved'
                if stage == workflow_pb2.WS_WAITING:
                    return 'Waiting'
                if stage == workflow_pb2.WS_NEEDS_ACTION:
                    return 'Needs Action'
        except Exception:
            logging.debug('Failed to resolve workflow status for flow', exc_info=True)
        if wf.escalated:
            return 'Escalated'
        return 'Pending'

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
        record_key = params.record_cache.get(record_uid, {}).get('record_key_unencrypted')
        if not record_key:
            return 'No permission to view. Only users with record access can view this information.'
        try:
            return crypto.decrypt_aes_v2(encrypted_bytes, record_key).decode('utf-8')
        except Exception:
            logging.debug('Failed to decrypt workflow parameter for record %s', record_uid, exc_info=True)
            return 'Unable to decrypt'

    @staticmethod
    def _print_json(params, wf_data):
        decrypt = WorkflowGetApprovalRequestsCommand._decrypt_param
        extract = WorkflowGetApprovalRequestsCommand._extract_param
        requests = []
        for wf, status in wf_data:
            rec_uid = utils.base64_url_encode(wf.resource.value)
            requested_by = wf.user or RecordResolver.resolve_user(params, wf.userId)
            requests.append({
                'flow_uid': utils.base64_url_encode(wf.flowUid),
                'status': status,
                'requested_by': requested_by,
                'record_uid': rec_uid,
                'record_name': RecordResolver.resolve_name(params, wf.resource),
                'started_on': wf.startedOn or None,
                'expires_on': wf.expiresOn or None,
                'escalated': wf.escalated,
                'duration': (
                    WorkflowFormatter.format_duration(wf.expiresOn - wf.startedOn)
                    if wf.expiresOn and wf.startedOn else None
                ),
                'reason': decrypt(params, rec_uid, extract(wf, 'reason')),
                'ticket': decrypt(params, rec_uid, extract(wf, 'ticket')),
            })
        print(json.dumps({'requests': requests}, indent=2))

    @staticmethod
    def _print_table(params, wf_data):
        decrypt = WorkflowGetApprovalRequestsCommand._decrypt_param
        extract = WorkflowGetApprovalRequestsCommand._extract_param
        rows = []
        for wf, status in wf_data:
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
            rows.append([status, record_name, record_uid, flow_uid, requested_by, reason, ticket, started, expires, duration])

        headers = ['Status', 'Record Name', 'Record UID', 'Flow UID', 'Requested By', 'Reason', 'Ticket', 'Started', 'Expires', 'Duration']
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
            reason_bytes = reason.encode('utf-8')
            encrypted = self._encrypt_denial_reason(params, flow_uid_bytes, reason_bytes)
            denial.denialReason = encrypted if encrypted else reason_bytes

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
        try:
            response = _post_request_to_router(
                params, 'get_approval_requests',
                rs_type=workflow_pb2.ApprovalRequests,
            )
            if not response or not response.workflows:
                return None

            requester_email = None
            for wf in response.workflows:
                if wf.flowUid == flow_uid_bytes:
                    requester_email = wf.user or RecordResolver.resolve_user(params, wf.userId)
                    break
            if not requester_email or requester_email.startswith('User ID '):
                logging.debug('Could not resolve requester email for flow UID')
                return None

            api.load_user_public_keys(params, [requester_email])
            public_keys = params.key_cache.get(requester_email)
            if not public_keys:
                logging.debug('Public key not available for %s', requester_email)
                return None

            if public_keys.ec:
                ec_key = crypto.load_ec_public_key(public_keys.ec)
                return crypto.encrypt_ec(reason_bytes, ec_key)
            elif public_keys.rsa:
                rsa_key = crypto.load_rsa_public_key(public_keys.rsa)
                return crypto.encrypt_rsa(reason_bytes, rsa_key)
        except Exception:
            logging.debug('Failed to encrypt denial reason with requester public key', exc_info=True)
        return None
