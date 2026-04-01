import argparse
import base64
import json
import logging

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from keepercommander.commands.base import Command, RecordMixin, GroupCommand
from keepercommander.commands.pam.pam_dto import (
    GatewayAction,
    GatewayActionIdpInputs,
    GatewayActionIdpValidateDomain,
)
from keepercommander.commands.pam.router_helper import router_send_action_to_gateway, _post_request_to_router
from keepercommander.commands.pam_cloud.pam_privileged_access import resolve_pam_idp_config
from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (
    get_config_uid_from_record,
    get_gateway_uid_from_record,
)
from keepercommander.error import CommandError
from keepercommander import api, vault
from keepercommander.proto import GraphSync_pb2, pam_pb2, workflow_pb2


ELIGIBLE_RECORD_TYPES = {'pamRemoteBrowser', 'pamDatabase', 'pamMachine', 'pamCloudAccess'}


# --- Command Groups ---

class PAMPrivilegedWorkflowCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('request', PAMRequestAccessCommand(),
                              'Request access for a shared record')
        self.register_command('status', PAMAccessStateCommand(),
                              'List your active access requests and statuses')
        self.register_command('requests', PAMApprovalRequestsCommand(),
                              'List pending workflow approval requests')
        self.register_command('approve', PAMApproveAccessCommand(),
                              'Approve or deny a workflow access request')
        self.register_command('revoke', PAMRevokeAccessCommand(),
                              'Revoke/end an active workflow access session')
        self.register_command('config', PAMWorkflowConfigCommand(),
                              'Read or configure workflow settings for a resource')


class PAMRequestAccessCommand(Command):
    parser = argparse.ArgumentParser(prog='pam workflow request', description='Request access to a shared PAM record')

    parser.add_argument('record', action='store', help='Record UID or title of the shared PAM record')
    parser.add_argument('--message', '-m', dest='message', action='store',
                                           help='Justification message to include with the request')

    def get_parser(self):
        return PAMRequestAccessCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        record = RecordMixin.resolve_single_record(params, record_name)

        if not record:
            raise CommandError('pam-workflow-request-access', f'Record "{record_name}" not found.')

        if not isinstance(record, vault.TypedRecord):
            raise CommandError('pam-workflow-request-access', 'Only typed records are supported.')

        if record.record_type not in ELIGIBLE_RECORD_TYPES:
            allowed = ', '.join(sorted(ELIGIBLE_RECORD_TYPES))
            raise CommandError('pam-workflow-request-access',
                               f'Record type "{record.record_type}" is not eligible. Allowed types: {allowed}')

        # Load share info to find the record owner
        api.get_record_shares(params, [record.record_uid])

        rec_cached = params.record_cache.get(record.record_uid)
        if not rec_cached:
            raise CommandError('pam-workflow-request-access', 'Record not found in cache.')

        shares = rec_cached.get('shares', {})
        user_perms = shares.get('user_permissions', [])

        owner = next((up.get('username') for up in user_perms if up.get('owner')), None)
        if not owner:
            raise CommandError('pam-workflow-request-access', 'Could not determine record owner.')

        if owner == params.user:
            raise CommandError('pam-workflow-request-access', 'You are the owner of this record.')

        # Resolve PAM config and IdP config for this resource
        config_uid = get_config_uid_from_record(params, vault, record.record_uid)
        if not config_uid:
            raise CommandError('pam-workflow-request-access', 'Could not resolve PAM configuration for this resource.')

        gateway_uid = get_gateway_uid_from_record(params, vault, record.record_uid)

        # Validate the requesting user's domain against the IdP
        try:
            idp_config_uid = resolve_pam_idp_config(params, config_uid)
        except CommandError:
            idp_config_uid = config_uid

        inputs = GatewayActionIdpInputs(
            configuration_uid=config_uid,
            idp_config_uid=idp_config_uid,
            user=params.user,
            resourceUid=record.record_uid,
        )
        action = GatewayActionIdpValidateDomain(inputs=inputs)
        conversation_id = GatewayAction.generate_conversation_id()
        action.conversationId = conversation_id

        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=action,
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_uid,
        )

        if router_response:
            response = router_response.get('response', {})
            payload_str = response.get('payload')
            if payload_str:
                payload = json.loads(payload_str)
                data = payload.get('data', {})
                if isinstance(data, dict) and not data.get('success', True):
                    error_msg = data.get('error', 'Domain validation failed')
                    raise CommandError('pam-workflow-request-access', error_msg)

        # Domain validated — submit workflow access request to krouter
        record_uid_bytes = url_safe_str_to_bytes(record.record_uid)

        access_request = workflow_pb2.WorkflowAccessRequest()
        access_request.resource.type = GraphSync_pb2.RFT_REC
        access_request.resource.value = record_uid_bytes

        message = kwargs.get('message')
        if message:
            access_request.reason = message

        try:
            _post_request_to_router(params, 'request_workflow_access', rq_proto=access_request)
        except Exception as e:
            raise CommandError('pam-request-access', f'Failed to submit access request: {e}')

        logging.info(f'Access request submitted for record "{record.title}".')


class PAMAccessStateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam workflow status', description='List your active workflow access requests and their status')

    parser.add_argument('record', nargs='?', action='store', default=None, help='Optional: Record UID to check specific resource workflow state')

    def get_parser(self):
        return PAMAccessStateCommand.parser

    def execute(self, params, **kwargs):
        stage_names = {
            0: 'Ready to Start',
            1: 'Started',
            2: 'Needs Action',
            3: 'Waiting',
        }
        condition_names = {
            0: 'Approval',
            1: 'Check-in',
            2: 'MFA',
            3: 'Time',
            4: 'Reason',
            5: 'Ticket',
        }

        record_uid = kwargs.get('record')

        if record_uid:
            # Use get_workflow_state for a specific resource (more detailed, reads full state)
            record_uid_bytes = url_safe_str_to_bytes(record_uid)
            rq = workflow_pb2.WorkflowState()
            rq.resource.type = GraphSync_pb2.RFT_REC
            rq.resource.value = record_uid_bytes
            try:
                wf = _post_request_to_router(
                    params, 'get_workflow_state',
                    rq_proto=rq,
                    rs_type=workflow_pb2.WorkflowState
                )
            except Exception as e:
                raise CommandError('pam-access-state', f'Failed to get workflow state: {e}')

            if not wf:
                logging.info('No active workflow for this resource.')
                return

            workflows = [wf]
        else:
            # Use get_user_access_state for all workflows
            try:
                response = _post_request_to_router(
                    params, 'get_user_access_state',
                    rs_type=workflow_pb2.UserAccessState
                )
            except Exception as e:
                raise CommandError('pam-access-state', f'Failed to get access state: {e}')

            if not response or not response.workflows:
                logging.info('No active access requests.')
                return

            workflows = response.workflows

        import time
        now_ms = int(time.time() * 1000)

        for wf in workflows:
            flow_uid = base64.urlsafe_b64encode(wf.flowUid).rstrip(b'=').decode()
            resource_uid = base64.urlsafe_b64encode(wf.resource.value).rstrip(b'=').decode() if wf.resource.value else 'N/A'
            stage = stage_names.get(wf.status.stage, str(wf.status.stage)) if wf.status else 'Unknown'
            conditions = ', '.join(condition_names.get(c, str(c)) for c in wf.status.conditions) if wf.status and wf.status.conditions else 'None'
            print(f'  Flow UID:     {flow_uid}')
            print(f'  Resource UID: {resource_uid}')
            print(f'  Stage:        {stage}')
            print(f'  Conditions:   {conditions}')
            if wf.status and wf.status.startedOn:
                from datetime import datetime
                started = datetime.fromtimestamp(wf.status.startedOn / 1000)
                print(f'  Started:      {started.strftime("%Y-%m-%d %H:%M:%S")}')
            if wf.status and wf.status.expiresOn:
                from datetime import datetime
                expires = datetime.fromtimestamp(wf.status.expiresOn / 1000)
                remaining_ms = wf.status.expiresOn - now_ms
                if remaining_ms > 0:
                    remaining_min = remaining_ms // 60000
                    remaining_sec = (remaining_ms % 60000) // 1000
                    print(f'  Expires:      {expires.strftime("%Y-%m-%d %H:%M:%S")} ({remaining_min}m {remaining_sec}s remaining)')
                else:
                    print(f'  Expires:      {expires.strftime("%Y-%m-%d %H:%M:%S")} (expired)')
            print()


class PAMApprovalRequestsCommand(Command):
    parser = argparse.ArgumentParser(prog='pam workflow requests', description='List pending workflow approval requests')

    def get_parser(self):
        return PAMApprovalRequestsCommand.parser

    def execute(self, params, **kwargs):
        try:
            response = _post_request_to_router(
                params, 'get_approval_requests',
                rs_type=workflow_pb2.ApprovalRequests
            )
        except Exception as e:
            raise CommandError('pam-approval-requests', f'Failed to get approval requests: {e}')

        if not response or not response.workflows:
            logging.info('No pending approval requests.')
            return

        for wf in response.workflows:
            flow_uid = base64.urlsafe_b64encode(wf.flowUid).rstrip(b'=').decode()
            resource_uid = base64.urlsafe_b64encode(wf.resource.value).rstrip(b'=').decode() if wf.resource.value else 'N/A'
            reason = wf.reason.decode() if wf.reason else ''
            print(f'  Flow UID:     {flow_uid}')
            print(f'  User ID:      {wf.userId}')
            print(f'  Resource UID: {resource_uid}')
            if reason:
                print(f'  Reason:       {reason}')
            print()


class PAMApproveAccessCommand(Command):
    parser = argparse.ArgumentParser(prog='pam workflow approve', description='Approve a workflow access request')

    parser.add_argument('flow_uid', action='store', help='Flow UID of the request to approve')
    parser.add_argument('--deny', action='store_true', help='Deny instead of approve')
    parser.add_argument('--reason', dest='denial_reason', action='store', help='Reason for denial')

    def get_parser(self):
        return PAMApproveAccessCommand.parser

    def execute(self, params, **kwargs):
        flow_uid_str = kwargs.get('flow_uid')
        deny = kwargs.get('deny', False)

        # Pad base64url if needed
        padding = 4 - len(flow_uid_str) % 4
        if padding != 4:
            flow_uid_str += '=' * padding
        flow_uid_bytes = base64.urlsafe_b64decode(flow_uid_str)

        approval = workflow_pb2.WorkflowApprovalOrDenial()
        approval.flowUid = flow_uid_bytes
        approval.deny = deny

        if deny and kwargs.get('denial_reason'):
            approval.denialReason = kwargs['denial_reason']

        endpoint = 'deny_workflow_access' if deny else 'approve_workflow_access'

        try:
            _post_request_to_router(params, endpoint, rq_proto=approval)
        except Exception as e:
            action = 'deny' if deny else 'approve'
            raise CommandError('pam-approve-access', f'Failed to {action} access request: {e}')

        if deny:
            logging.info(f'Access request denied.')
        else:
            logging.info(f'Access request approved.')


class PAMRevokeAccessCommand(Command):
    parser = argparse.ArgumentParser(prog='pam workflow revoke', description='Revoke/end an active workflow access session')

    parser.add_argument('flow_uid', action='store', help='Flow UID of the active access to revoke')

    def get_parser(self):
        return PAMRevokeAccessCommand.parser

    def execute(self, params, **kwargs):
        flow_uid_str = kwargs.get('flow_uid')

        padding = 4 - len(flow_uid_str) % 4
        if padding != 4:
            flow_uid_str += '=' * padding
        flow_uid_bytes = base64.urlsafe_b64decode(flow_uid_str)

        ref = GraphSync_pb2.GraphSyncRef()
        ref.type = GraphSync_pb2.RFT_WORKFLOW
        ref.value = flow_uid_bytes

        try:
            _post_request_to_router(params, 'end_workflow', rq_proto=ref)
        except Exception as e:
            raise CommandError('pam-revoke-access', f'Failed to revoke access: {e}')

        logging.info(f'Access revoked.')


class PAMWorkflowConfigCommand(Command):
    parser = argparse.ArgumentParser(prog='pam workflow config', description='Read or configure workflow settings for a resource')

    parser.add_argument('record', action='store', help='Record UID of the resource')
    parser.add_argument('--set', action='store_true', help='Create or update workflow config')
    parser.add_argument('--approvals-needed', type=int, default=None, help='Number of approvals required')
    parser.add_argument('--approver', action='append', dest='approvers', help='Approver email (can specify multiple)')
    parser.add_argument('--start-on-approval', action='store_true', default=False, help='Auto-start access on approval')
    parser.add_argument('--access-length', type=int, default=None, help='Access duration in seconds')

    def get_parser(self):
        return PAMWorkflowConfigCommand.parser

    def execute(self, params, **kwargs):
        record_uid = kwargs.get('record')
        record_uid_bytes = url_safe_str_to_bytes(record_uid)

        ref = GraphSync_pb2.GraphSyncRef()
        ref.type = GraphSync_pb2.RFT_REC
        ref.value = record_uid_bytes

        if not kwargs.get('set'):
            # Read current config
            try:
                config = _post_request_to_router(
                    params, 'read_workflow_config',
                    rq_proto=ref,
                    rs_type=workflow_pb2.WorkflowConfig
                )
            except Exception as e:
                raise CommandError('pam-workflow-config', f'Failed to read workflow config: {e}')

            if not config or not config.parameters.approvalsNeeded:
                print('  No workflow configuration found for this resource.')
                return

            p = config.parameters
            print(f'  Approvals Needed:       {p.approvalsNeeded}')
            print(f'  Checkout Needed:        {p.checkoutNeeded}')
            print(f'  Start on Approval:      {p.startAccessOnApproval}')
            print(f'  Require Reason:         {p.requireReason}')
            print(f'  Require Ticket:         {p.requireTicket}')
            print(f'  Require MFA:            {p.requireMFA}')
            print(f'  Access Length:          {p.accessLength // 1000}s' if p.accessLength else '  Access Length:          unlimited')
            if config.approvers:
                print(f'  Approvers:')
                for a in config.approvers:
                    if a.user:
                        print(f'    - {a.user}')
                    elif a.userId:
                        print(f'    - User ID: {a.userId}')
            return

        # Set/update config
        wf_params = workflow_pb2.WorkflowParameters()
        wf_params.resource.type = GraphSync_pb2.RFT_REC
        wf_params.resource.value = record_uid_bytes

        approvals = kwargs.get('approvals_needed')
        if approvals is not None:
            wf_params.approvalsNeeded = approvals
        else:
            wf_params.approvalsNeeded = 1

        wf_params.startAccessOnApproval = kwargs.get('start_on_approval', False)

        access_length_sec = kwargs.get('access_length') or 3600
        wf_params.accessLength = access_length_sec * 1000  # proto field is in milliseconds

        try:
            _post_request_to_router(params, 'create_workflow_config', rq_proto=wf_params)
            logging.info(f'Workflow config created (approvalsNeeded={wf_params.approvalsNeeded}).')
        except Exception as e:
            # Try update if create fails
            try:
                _post_request_to_router(params, 'update_workflow_config', rq_proto=wf_params)
                logging.info(f'Workflow config updated (approvalsNeeded={wf_params.approvalsNeeded}).')
            except Exception as e2:
                raise CommandError('pam-workflow-config', f'Failed to set workflow config: {e2}')

        # Add approvers if specified
        approvers = kwargs.get('approvers')
        if approvers:
            wf_config = workflow_pb2.WorkflowConfig()
            wf_config.parameters.CopyFrom(wf_params)
            for approver_email in approvers:
                a = wf_config.approvers.add()
                a.user = approver_email

            try:
                _post_request_to_router(params, 'add_workflow_approvers', rq_proto=wf_config)
                logging.info(f'Approvers added: {", ".join(approvers)}'  )
            except Exception as e:
                raise CommandError('pam-workflow-config', f'Failed to add approvers: {e}')
