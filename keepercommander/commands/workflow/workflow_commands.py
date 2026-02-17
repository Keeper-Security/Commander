#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
PAM Workflow Command Implementations

This module contains all workflow-related commands for Keeper Commander.
Workflows enable Just-in-Time PAM access with approval processes, check-in/check-out,
time-based access controls, and automatic credential rotation.
"""

import argparse
import json
from datetime import datetime
from typing import List

from ..base import Command, GroupCommand, dump_report_data
from ..pam.router_helper import _post_request_to_router
from ...display import bcolors
from ...error import CommandError
from ...params import KeeperParams
from ...proto import workflow_pb2, GraphSync_pb2
from ... import vault, utils


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_record_uid_bytes(params: KeeperParams, record_uid: str) -> bytes:
    """
    Convert record UID string to bytes and validate it exists.
    
    Args:
        params: Keeper parameters with session info
        record_uid: Record UID as string (e.g., "abc123")
    
    Returns:
        bytes: Record UID as bytes
    
    Raises:
        CommandError: If record not found or invalid
    """
    # Convert UID to bytes
    uid_bytes = utils.base64_url_decode(record_uid)
    
    # Validate record exists in vault
    if record_uid not in params.record_cache:
        raise CommandError('', f'Record {record_uid} not found')
    
    return uid_bytes


def create_record_ref(record_uid_bytes: bytes, record_name: str = '') -> GraphSync_pb2.GraphSyncRef:
    """
    Create a GraphSyncRef for a record.
    
    GraphSyncRef is used throughout Keeper's protobuf APIs to reference
    different types of resources (records, folders, users, workflows, etc.)
    
    Args:
        record_uid_bytes: Record UID as bytes
        record_name: Optional record name/title
    
    Returns:
        GraphSyncRef: Protobuf reference object
    """
    ref = GraphSync_pb2.GraphSyncRef()
    ref.type = GraphSync_pb2.RFT_REC  # RefType.RFT_REC means "Record"
    ref.value = record_uid_bytes
    if record_name:
        ref.name = record_name
    return ref


def create_workflow_ref(flow_uid_bytes: bytes) -> GraphSync_pb2.GraphSyncRef:
    """
    Create a GraphSyncRef for a workflow.
    
    Args:
        flow_uid_bytes: Workflow flow UID as bytes
    
    Returns:
        GraphSyncRef: Protobuf reference object for workflow
    """
    ref = GraphSync_pb2.GraphSyncRef()
    ref.type = GraphSync_pb2.RFT_WORKFLOW  # RefType.RFT_WORKFLOW
    ref.value = flow_uid_bytes
    return ref


def resolve_record_name(params, resource_ref) -> str:
    """
    Resolve the display name for a record from a GraphSyncRef.
    
    The backend doesn't always populate the 'name' field in the GraphSyncRef
    response, so we fall back to looking up the record in the local vault cache.
    
    Args:
        params: KeeperParams instance
        resource_ref: GraphSyncRef protobuf object with value (record UID bytes)
    
    Returns:
        str: Record title, UID, or empty string
    """
    if resource_ref.name:
        return resource_ref.name
    if resource_ref.value:
        rec_uid = utils.base64_url_encode(resource_ref.value)
        rec = vault.KeeperRecord.load(params, rec_uid)
        return rec.title if rec else ''
    return ''


def format_record_label(params, resource_ref) -> str:
    """
    Format a record label as 'Name (UID)' for display.
    If the name can't be resolved, shows just the UID once (no duplication).
    """
    rec_uid = utils.base64_url_encode(resource_ref.value) if resource_ref.value else ''
    rec_name = resolve_record_name(params, resource_ref)
    if rec_name and rec_name != rec_uid:
        return f"{rec_name} ({rec_uid})"
    return rec_uid or 'Unknown'


def validate_team(params: KeeperParams, team_input: str) -> str:
    """
    Resolve and validate a team name or UID.

    Checks params.team_cache for matching UID or name (case-insensitive).

    Args:
        params: KeeperParams instance
        team_input: Team UID or team name

    Returns:
        str: Resolved team UID

    Raises:
        CommandError: If team is not found
    """
    if team_input in params.team_cache:
        return team_input
    for uid, team_data in params.team_cache.items():
        if team_data.get('name', '').casefold() == team_input.casefold():
            return uid
    raise CommandError('', f'Team "{team_input}" not found. Use a valid team UID or team name.')


def resolve_user_name(params: KeeperParams, user_id: int) -> str:
    """
    Resolve an enterprise user ID to email/username.

    Uses params.enterprise['users'] when available (enterprise admin).
    Falls back to displaying the numeric ID.

    Args:
        params: KeeperParams instance
        user_id: Enterprise user ID (int64)

    Returns:
        str: User email or 'User ID <id>' as fallback
    """
    if params.enterprise and 'users' in params.enterprise:
        for u in params.enterprise['users']:
            if u.get('enterprise_user_id') == user_id:
                return u.get('username', f'User ID {user_id}')
    return f'User ID {user_id}'


def check_workflow_access(params: KeeperParams, record_uid: str) -> bool:
    """
    Check whether the current user has active checkout access to a PAM record.

    This function should be called before connecting, tunneling, or launching
    a PAM resource. It verifies:
      1. Whether the record has a workflow configured.
      2. If so, whether the user has an active checked-out session.

    If the user does not have access, a helpful message is printed guiding
    them through the workflow process.

    Args:
        params: KeeperParams instance with session info
        record_uid: Record UID string to check

    Returns:
        True if access is allowed (no workflow, or user has active checkout).
        False if access is blocked by workflow.
    """
    try:
        # Step 1: Check if the record has a workflow configured
        record_uid_bytes = utils.base64_url_decode(record_uid)
        record = vault.KeeperRecord.load(params, record_uid)
        record_name = record.title if record else record_uid

        ref = create_record_ref(record_uid_bytes, record_name)
        config_response = _post_request_to_router(
            params,
            'read_workflow_config',
            rq_proto=ref,
            rs_type=workflow_pb2.WorkflowConfig
        )

        if config_response is None:
            # No workflow configured on this record — access is unrestricted
            return True

        # Step 2: Workflow exists — check user's access state for this record
        state_rq = workflow_pb2.WorkflowState()
        state_rq.resource.CopyFrom(ref)
        state_response = _post_request_to_router(
            params,
            'get_workflow_state',
            rq_proto=state_rq,
            rs_type=workflow_pb2.WorkflowState
        )

        if state_response and state_response.status:
            stage = state_response.status.stage

            if stage == workflow_pb2.WS_STARTED:
                # User has an active checkout — allow access
                return True

            if stage == workflow_pb2.WS_READY_TO_START:
                print(f"\n{bcolors.WARNING}Workflow access approved but not yet checked out.{bcolors.ENDC}")
                print(f"Run: {bcolors.OKBLUE}pam workflow start {record_uid}{bcolors.ENDC} to check out the record.\n")
                return False

            if stage == workflow_pb2.WS_WAITING:
                conditions = state_response.status.conditions
                cond_str = format_access_conditions(conditions) if conditions else 'approval'
                print(f"\n{bcolors.WARNING}Workflow access is pending: waiting for {cond_str}.{bcolors.ENDC}")
                print(f"Your request is being processed. Please wait for approval.\n")
                return False

            if stage == workflow_pb2.WS_NEEDS_ACTION:
                print(f"\n{bcolors.WARNING}Workflow requires additional action before access is granted.{bcolors.ENDC}")
                print(f"Run: {bcolors.OKBLUE}pam workflow state --record {record_uid}{bcolors.ENDC} to see details.\n")
                return False

        # No active workflow state — user hasn't requested access yet
        print(f"\n{bcolors.WARNING}This record is protected by a workflow.{bcolors.ENDC}")
        print(f"You must request access before connecting.")
        print(f"Run: {bcolors.OKBLUE}pam workflow request {record_uid}{bcolors.ENDC} to request access.\n")
        return False

    except Exception:
        # If workflow check fails (e.g. network issue), allow access.
        # The backend/gateway should still enforce restrictions server-side.
        return True


def parse_duration_to_milliseconds(duration_str: str) -> int:
    """
    Parse duration string to milliseconds.
    
    Supports formats:
    - "2h" = 2 hours
    - "30m" = 30 minutes
    - "1d" = 1 day
    - "90" = 90 minutes (default unit)
    
    Args:
        duration_str: Duration string (e.g., "2h", "30m", "1d")
    
    Returns:
        int: Duration in milliseconds
    
    Raises:
        CommandError: If duration format is invalid
    """
    duration_str = duration_str.lower().strip()
    
    try:
        # Check for unit suffix
        if duration_str.endswith('d'):
            # Days
            days = int(duration_str[:-1])
            return days * 24 * 60 * 60 * 1000
        elif duration_str.endswith('h'):
            # Hours
            hours = int(duration_str[:-1])
            return hours * 60 * 60 * 1000
        elif duration_str.endswith('m'):
            # Minutes
            minutes = int(duration_str[:-1])
            return minutes * 60 * 1000
        else:
            # Default to minutes if no unit specified
            minutes = int(duration_str)
            return minutes * 60 * 1000
    except ValueError:
        raise CommandError('', f'Invalid duration format: {duration_str}. Use format like "2h", "30m", or "1d"')


def format_duration_from_milliseconds(milliseconds: int) -> str:
    """
    Format milliseconds to human-readable duration.
    
    Args:
        milliseconds: Duration in milliseconds
    
    Returns:
        str: Formatted duration (e.g., "2 hours", "30 minutes", "1 day")
    """
    seconds = milliseconds // 1000
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24
    
    if days > 0:
        return f"{days} day{'s' if days != 1 else ''}"
    elif hours > 0:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    elif minutes > 0:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    else:
        return f"{seconds} second{'s' if seconds != 1 else ''}"


def format_workflow_stage(stage: int) -> str:
    """
    Convert workflow stage enum to readable string.
    
    Args:
        stage: WorkflowStage enum value
    
    Returns:
        str: Human-readable stage name
    """
    stage_map = {
        workflow_pb2.WS_READY_TO_START: 'Ready to Start',
        workflow_pb2.WS_STARTED: 'Started',
        workflow_pb2.WS_NEEDS_ACTION: 'Needs Action',
        workflow_pb2.WS_WAITING: 'Waiting'
    }
    return stage_map.get(stage, f'Unknown ({stage})')


def format_access_conditions(conditions: List[int]) -> str:
    """
    Convert access condition enums to readable string.
    
    Args:
        conditions: List of AccessCondition enum values
    
    Returns:
        str: Human-readable conditions (comma-separated)
    """
    condition_map = {
        workflow_pb2.AC_APPROVAL: 'Approval Required',
        workflow_pb2.AC_CHECKIN: 'Check-in Required',
        workflow_pb2.AC_MFA: 'MFA Required',
        workflow_pb2.AC_TIME: 'Time Restriction',
        workflow_pb2.AC_REASON: 'Reason Required',
        workflow_pb2.AC_TICKET: 'Ticket Required'
    }
    return ', '.join([condition_map.get(c, f'Unknown ({c})') for c in conditions])


# ============================================================================
# CONFIGURATION COMMANDS
# ============================================================================

class WorkflowCreateCommand(Command):
    """
    Create a new workflow configuration for a PAM record.
    
    This enables Just-in-Time PAM features like:
    - Approval requirements before access
    - Single-user check-in/check-out
    - Time-based access controls
    - MFA requirements
    - Justification requirements
    
    Example:
        pam workflow create <record_uid> --approvals-needed 2 --duration 2h --checkout
    """
    parser = argparse.ArgumentParser(prog='pam workflow create',
                                     description='Create workflow configuration for a PAM record', allow_abbrev=False)
    parser.add_argument('record', help='Record UID or name to configure workflow for')
    parser.add_argument('-n', '--approvals-needed', type=int, default=1,
                        help='Number of approvals required (default: 1)')
    parser.add_argument('-co', '--checkout', action='store_true',
                        help='Enable single-user check-in/check-out mode')
    parser.add_argument('-sa', '--start-on-approval', action='store_true',
                        help='Start access timer when approved (vs when checked out)')
    parser.add_argument('-rr', '--require-reason', action='store_true',
                        help='Require user to provide reason for access')
    parser.add_argument('-rt', '--require-ticket', action='store_true',
                        help='Require user to provide ticket number')
    parser.add_argument('-rm', '--require-mfa', action='store_true',
                        help='Require MFA verification for access')
    parser.add_argument('-d', '--duration', type=str, default='1d',
                        help='Access duration (e.g., "2h", "30m", "1d"). Default: 1d')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowCreateCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow creation."""
        record_uid = kwargs.get('record')
        
        # Resolve record UID if name provided
        if record_uid not in params.record_cache:
            # Try to search for record by name
            records = list(params.record_cache.keys())
            for uid in records:
                rec = vault.KeeperRecord.load(params, uid)
                if rec and rec.title == record_uid:
                    record_uid = uid
                    break
            else:
                raise CommandError('', f'Record "{record_uid}" not found')
        
        # Get record details
        record = vault.KeeperRecord.load(params, record_uid)
        record_uid_bytes = utils.base64_url_decode(record_uid)
        
        # Create workflow parameters - EXPLICITLY SET ALL FIELDS
        # (Protobuf3 defaults can cause issues, so we set everything explicitly)
        parameters = workflow_pb2.WorkflowParameters()
        parameters.resource.CopyFrom(create_record_ref(record_uid_bytes, record.title))
        
        # Set all required fields explicitly
        parameters.approvalsNeeded = kwargs.get('approvals_needed', 1)
        parameters.checkoutNeeded = kwargs.get('checkout', False)
        parameters.startAccessOnApproval = kwargs.get('start_on_approval', False)
        parameters.requireReason = kwargs.get('require_reason', False)
        parameters.requireTicket = kwargs.get('require_ticket', False)
        parameters.requireMFA = kwargs.get('require_mfa', False)
        
        # Parse duration
        duration_str = kwargs.get('duration', '1d')
        parameters.accessLength = parse_duration_to_milliseconds(duration_str)
        
        # IMPORTANT: allowedTimes field (field #9) - leave unset for now
        # If workflow requires time-based restrictions, this would be set
        # For now, leaving it unset means "no time restrictions"
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'create_workflow_config',
                rq_proto=parameters
            )
            
            # Auto-add record owner as the first approver (MRD Req #5:
            # "By Default: The owner of the record must be added to this list")
            owner_email = params.user
            owner_added = False
            if owner_email:
                try:
                    approver_config = workflow_pb2.WorkflowConfig()
                    approver_config.parameters.resource.CopyFrom(
                        create_record_ref(record_uid_bytes, record.title)
                    )
                    approver = workflow_pb2.WorkflowApprover()
                    approver.user = owner_email
                    approver_config.approvers.append(approver)
                    _post_request_to_router(
                        params,
                        'add_workflow_approvers',
                        rq_proto=approver_config
                    )
                    owner_added = True
                except Exception:
                    # Non-fatal: workflow was created, approver add failed
                    pass

            # Success output
            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'workflow_config': {
                        'approvals_needed': parameters.approvalsNeeded,
                        'checkout_needed': parameters.checkoutNeeded,
                        'require_reason': parameters.requireReason,
                        'require_ticket': parameters.requireTicket,
                        'require_mfa': parameters.requireMFA,
                        'access_duration': format_duration_from_milliseconds(parameters.accessLength)
                    },
                    'owner_approver': owner_email if owner_added else None
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Workflow created successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print(f"Approvals needed: {parameters.approvalsNeeded}")
                print(f"Check-in/out: {'Yes' if parameters.checkoutNeeded else 'No'}")
                print(f"Duration: {format_duration_from_milliseconds(parameters.accessLength)}")
                if parameters.requireReason:
                    print(f"Requires reason: Yes")
                if parameters.requireTicket:
                    print(f"Requires ticket: Yes")
                if parameters.requireMFA:
                    print(f"Requires MFA: Yes")
                if owner_added:
                    print(f"\nApprover added: {owner_email} (record owner)")
                else:
                    print(f"\n{bcolors.WARNING}Note: Add approvers with: "
                          f"pam workflow add-approver {record_uid} --user <email>{bcolors.ENDC}")
                print()
                
        except Exception as e:
            raise CommandError('', f'Failed to create workflow: {str(e)}')


class WorkflowUpdateCommand(Command):
    """
    Update an existing workflow configuration.
    
    Reads the current configuration first, then applies only the
    specified changes. Unspecified fields retain their current values.
    
    Example:
        pam workflow update <record_uid> --approvals-needed 3 --duration 4h
    """
    parser = argparse.ArgumentParser(prog='pam workflow update',
                                     description='Update existing workflow configuration. '
                                                 'Only specified fields are changed; unspecified fields '
                                                 'retain their current values.')
    parser.add_argument('record', help='Record UID or name with workflow to update')
    parser.add_argument('-n', '--approvals-needed', type=int, help='Number of approvals required')
    parser.add_argument('-co', '--checkout', type=lambda x: x.lower() == 'true',
                        help='Enable/disable check-in/check-out (true/false)')
    parser.add_argument('-sa', '--start-on-approval', type=lambda x: x.lower() == 'true',
                        help='Start timer on approval vs check-out (true/false)')
    parser.add_argument('-rr', '--require-reason', type=lambda x: x.lower() == 'true',
                        help='Require reason (true/false)')
    parser.add_argument('-rt', '--require-ticket', type=lambda x: x.lower() == 'true',
                        help='Require ticket (true/false)')
    parser.add_argument('-rm', '--require-mfa', type=lambda x: x.lower() == 'true',
                        help='Require MFA (true/false)')
    parser.add_argument('-d', '--duration', type=str, help='Access duration (e.g., "2h", "30m", "1d")')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowUpdateCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow update."""
        record_uid = kwargs.get('record')
        
        # Resolve record UID
        if record_uid not in params.record_cache:
            records = list(params.record_cache.keys())
            for uid in records:
                rec = vault.KeeperRecord.load(params, uid)
                if rec and rec.title == record_uid:
                    record_uid = uid
                    break
            else:
                raise CommandError('', f'Record "{record_uid}" not found')
        
        record = vault.KeeperRecord.load(params, record_uid)
        record_uid_bytes = utils.base64_url_decode(record_uid)
        
        try:
            # Fetch current workflow config using read_workflow_config
            # This ensures we preserve existing values when doing partial updates
            ref = create_record_ref(record_uid_bytes, record.title)
            current_config = _post_request_to_router(
                params,
                'read_workflow_config',
                rq_proto=ref,
                rs_type=workflow_pb2.WorkflowConfig
            )
            
            if not current_config:
                raise CommandError('', 'No workflow found for record. Create one first with "pam workflow create"')
            
            # Start with current config values, then override with user-provided values
            parameters = workflow_pb2.WorkflowParameters()
            parameters.CopyFrom(current_config.parameters)
            
            # Override with user-provided values
            updates_provided = False
            if kwargs.get('approvals_needed') is not None:
                parameters.approvalsNeeded = kwargs['approvals_needed']
                updates_provided = True
            if kwargs.get('checkout') is not None:
                parameters.checkoutNeeded = kwargs['checkout']
                updates_provided = True
            if kwargs.get('start_on_approval') is not None:
                parameters.startAccessOnApproval = kwargs['start_on_approval']
                updates_provided = True
            if kwargs.get('require_reason') is not None:
                parameters.requireReason = kwargs['require_reason']
                updates_provided = True
            if kwargs.get('require_ticket') is not None:
                parameters.requireTicket = kwargs['require_ticket']
                updates_provided = True
            if kwargs.get('require_mfa') is not None:
                parameters.requireMFA = kwargs['require_mfa']
                updates_provided = True
            if kwargs.get('duration') is not None:
                parameters.accessLength = parse_duration_to_milliseconds(kwargs['duration'])
                updates_provided = True
            
            if not updates_provided:
                raise CommandError('', 'No updates provided. Specify at least one option to update (e.g., --approvals-needed, --duration)')
            
            # Make API call
            response = _post_request_to_router(
                params,
                'update_workflow_config',
                rq_proto=parameters
            )
            
            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'record_uid': record_uid, 'record_name': record.title}
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Workflow updated successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print()
                
        except CommandError:
            raise
        except Exception as e:
            raise CommandError('', f'Failed to update workflow: {str(e)}')


class WorkflowReadCommand(Command):
    """
    Read/display workflow configuration.
    
    Shows the complete workflow configuration including all parameters,
    approvers, and metadata.
    
    Example:
        pam workflow read <record_uid>
    """
    parser = argparse.ArgumentParser(prog='pam workflow read',
                                     description='Read and display workflow configuration')
    parser.add_argument('record', help='Record UID or name')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowReadCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow read."""
        record_uid = kwargs.get('record')
        
        # Resolve record UID
        if record_uid not in params.record_cache:
            records = list(params.record_cache.keys())
            for uid in records:
                rec = vault.KeeperRecord.load(params, uid)
                if rec and rec.title == record_uid:
                    record_uid = uid
                    break
            else:
                raise CommandError('', f'Record "{record_uid}" not found')
        
        record = vault.KeeperRecord.load(params, record_uid)
        record_uid_bytes = utils.base64_url_decode(record_uid)
        
        # Create reference to record
        ref = create_record_ref(record_uid_bytes, record.title)
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'read_workflow_config',
                rq_proto=ref,
                rs_type=workflow_pb2.WorkflowConfig
            )
            
            if not response:
                if kwargs.get('format') == 'json':
                    print(json.dumps({'status': 'no_workflow', 'message': 'No workflow configured'}, indent=2))
                else:
                    print(f"\n{bcolors.WARNING}No workflow configured for this record{bcolors.ENDC}\n")
                    print(f"Record: {record.title} ({record_uid})")
                    print(f"\nTo create a workflow, run:")
                    print(f"  pam workflow create {record_uid}")
                    print()
                return
            
            if kwargs.get('format') == 'json':
                # JSON output
                result = {
                    'record_uid': record_uid,
                    'record_name': resolve_record_name(params, response.parameters.resource),
                    'parameters': {
                        'approvals_needed': response.parameters.approvalsNeeded,
                        'checkout_needed': response.parameters.checkoutNeeded,
                        'start_access_on_approval': response.parameters.startAccessOnApproval,
                        'require_reason': response.parameters.requireReason,
                        'require_ticket': response.parameters.requireTicket,
                        'require_mfa': response.parameters.requireMFA,
                        'access_duration': format_duration_from_milliseconds(response.parameters.accessLength)
                    },
                    'approvers': []
                }
                
                # Add approvers
                for approver in response.approvers:
                    approver_info = {'escalation': approver.escalation}
                    if approver.escalationAfterMs:
                        approver_info['escalation_after'] = format_duration_from_milliseconds(approver.escalationAfterMs)
                        approver_info['escalation_after_ms'] = approver.escalationAfterMs
                    if approver.HasField('user'):
                        approver_info['type'] = 'user'
                        approver_info['email'] = approver.user
                    elif approver.HasField('userId'):
                        approver_info['type'] = 'user_id'
                        approver_info['user_id'] = approver.userId
                    elif approver.HasField('teamUid'):
                        approver_info['type'] = 'team'
                        approver_info['team_uid'] = utils.base64_url_encode(approver.teamUid)
                    result['approvers'].append(approver_info)
                
                print(json.dumps(result, indent=2))
            else:
                # Table output
                print(f"\n{bcolors.OKBLUE}Workflow Configuration{bcolors.ENDC}\n")
                print(f"Record: {resolve_record_name(params, response.parameters.resource)}")
                print(f"Record UID: {record_uid}")
                
                # Display creation date if available
                if response.createdOn:
                    created_date = datetime.fromtimestamp(response.createdOn / 1000)
                    print(f"Created: {created_date.strftime('%Y-%m-%d %H:%M:%S')}")
                
                print(f"\n{bcolors.BOLD}Access Parameters:{bcolors.ENDC}")
                print(f"  Approvals needed: {response.parameters.approvalsNeeded}")
                print(f"  Check-in/out required: {'Yes' if response.parameters.checkoutNeeded else 'No'}")
                print(f"  Access duration: {format_duration_from_milliseconds(response.parameters.accessLength)}")
                print(f"  Timer starts: {'On approval' if response.parameters.startAccessOnApproval else 'On check-out'}")
                
                print(f"\n{bcolors.BOLD}Requirements:{bcolors.ENDC}")
                print(f"  Reason required: {'Yes' if response.parameters.requireReason else 'No'}")
                print(f"  Ticket required: {'Yes' if response.parameters.requireTicket else 'No'}")
                print(f"  MFA required: {'Yes' if response.parameters.requireMFA else 'No'}")
                
                # Display approvers
                if response.approvers:
                    print(f"\n{bcolors.BOLD}Approvers ({len(response.approvers)}):{bcolors.ENDC}")
                    for idx, approver in enumerate(response.approvers, 1):
                        escalation = ' (Escalation)' if approver.escalation else ''
                        if approver.escalation and approver.escalationAfterMs:
                            escalation += f' — after {format_duration_from_milliseconds(approver.escalationAfterMs)}'
                        if approver.HasField('user'):
                            print(f"  {idx}. User: {approver.user}{escalation}")
                        elif approver.HasField('userId'):
                            print(f"  {idx}. User: {resolve_user_name(params, approver.userId)}{escalation}")
                        elif approver.HasField('teamUid'):
                            team_uid = utils.base64_url_encode(approver.teamUid)
                            team_data = params.team_cache.get(team_uid, {})
                            team_name = team_data.get('name', '')
                            team_display = f"{team_name} ({team_uid})" if team_name else team_uid
                            print(f"  {idx}. Team: {team_display}{escalation}")
                else:
                    print(f"\n{bcolors.WARNING}⚠ No approvers configured!{bcolors.ENDC}")
                    print(f"Add approvers with: pam workflow add-approver {record_uid} --user <email>")
                
                print()
                
        except Exception as e:
            raise CommandError('', f'Failed to read workflow: {str(e)}')


class WorkflowDeleteCommand(Command):
    """
    Delete a workflow configuration from a record.
    
    This removes all workflow restrictions and returns the record
    to normal access mode.
    
    Example:
        pam workflow delete <record_uid>
    """
    parser = argparse.ArgumentParser(prog='pam workflow delete',
                                     description='Delete workflow configuration from a record')
    parser.add_argument('record', help='Record UID or name to remove workflow from')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowDeleteCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow deletion."""
        record_uid = kwargs.get('record')
        
        # Resolve record UID
        if record_uid not in params.record_cache:
            records = list(params.record_cache.keys())
            for uid in records:
                rec = vault.KeeperRecord.load(params, uid)
                if rec and rec.title == record_uid:
                    record_uid = uid
                    break
            else:
                raise CommandError('', f'Record "{record_uid}" not found')
        
        record = vault.KeeperRecord.load(params, record_uid)
        record_uid_bytes = utils.base64_url_decode(record_uid)
        
        # Create reference to record
        ref = create_record_ref(record_uid_bytes, record.title)
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'delete_workflow_config',
                rq_proto=ref
            )
            
            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'record_uid': record_uid, 'record_name': record.title}
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Workflow deleted successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print()
                
        except Exception as e:
            raise CommandError('', f'Failed to delete workflow: {str(e)}')


# ============================================================================
# APPROVER MANAGEMENT COMMANDS
# ============================================================================

class WorkflowAddApproversCommand(Command):
    """
    Add approvers to a workflow.
    
    Approvers are users or teams who can approve access requests.
    You can mark approvers as "escalated" for handling delayed approvals,
    with an optional auto-escalation delay.
    
    Example:
        pam workflow add-approver <record_uid> --user alice@company.com
        pam workflow add-approver <record_uid> --team <team_uid> --escalation
        pam workflow add-approver <record_uid> --user bob@company.com --escalation --escalation-after 30m
    """
    parser = argparse.ArgumentParser(prog='pam workflow add-approver',
                                     description='Add approvers to a workflow')
    parser.add_argument('record', help='Record UID or name')
    parser.add_argument('-u', '--user', action='append',
                        help='User email to add as approver (can specify multiple times)')
    parser.add_argument('-t', '--team', action='append',
                        help='Team name or UID to add as approver (can specify multiple times)')
    parser.add_argument('-e', '--escalation', action='store_true', help='Mark as escalation approver')
    parser.add_argument('--escalation-after', dest='escalation_after',
                        help='Auto-escalate after duration (e.g. 30m, 1h, 2d). Requires --escalation')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowAddApproversCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute add approvers."""
        record_uid = kwargs.get('record')
        users = kwargs.get('user') or []
        teams = kwargs.get('team') or []
        is_escalation = kwargs.get('escalation', False)
        escalation_after = kwargs.get('escalation_after')

        if escalation_after and not is_escalation:
            raise CommandError('', '--escalation-after requires --escalation flag')

        escalation_after_ms = 0
        if escalation_after:
            escalation_after_ms = parse_duration_to_milliseconds(escalation_after)
            if not escalation_after_ms:
                raise CommandError('', f'Invalid escalation duration: {escalation_after}. Use format like 30m, 1h, 2d')

        if not users and not teams:
            raise CommandError('', 'Must specify at least one --user or --team')
        
        # Resolve record UID
        if record_uid not in params.record_cache:
            records = list(params.record_cache.keys())
            for uid in records:
                rec = vault.KeeperRecord.load(params, uid)
                if rec and rec.title == record_uid:
                    record_uid = uid
                    break
            else:
                raise CommandError('', f'Record "{record_uid}" not found')
        
        record = vault.KeeperRecord.load(params, record_uid)
        record_uid_bytes = utils.base64_url_decode(record_uid)
        
        # Create workflow config with approvers
        config = workflow_pb2.WorkflowConfig()
        config.parameters.resource.CopyFrom(create_record_ref(record_uid_bytes, record.title))
        
        # Add user approvers (email validated by backend)
        for user_email in users:
            approver = workflow_pb2.WorkflowApprover()
            approver.user = user_email
            approver.escalation = is_escalation
            if escalation_after_ms:
                approver.escalationAfterMs = escalation_after_ms
            config.approvers.append(approver)
        
        # Add team approvers (accepts team UID or team name)
        for team_input in teams:
            resolved_team_uid = validate_team(params, team_input)
            approver = workflow_pb2.WorkflowApprover()
            approver.teamUid = utils.base64_url_decode(resolved_team_uid)
            approver.escalation = is_escalation
            if escalation_after_ms:
                approver.escalationAfterMs = escalation_after_ms
            config.approvers.append(approver)
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'add_workflow_approvers',
                rq_proto=config
            )
            
            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'approvers_added': len(users) + len(teams),
                    'escalation': is_escalation,
                    'escalation_after_ms': escalation_after_ms or None
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Approvers added successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print(f"Added {len(users) + len(teams)} approver(s)")
                if is_escalation:
                    print("Type: Escalation approver")
                    if escalation_after_ms:
                        print(f"Escalation after: {format_duration_from_milliseconds(escalation_after_ms)}")
                print()
                
        except Exception as e:
            raise CommandError('', f'Failed to add approvers: {str(e)}')


class WorkflowDeleteApproversCommand(Command):
    """
    Remove approvers from a workflow.
    
    Example:
        pam workflow remove-approver <record_uid> --user alice@company.com
    """
    parser = argparse.ArgumentParser(prog='pam workflow remove-approver',
                                     description='Remove approvers from a workflow')
    parser.add_argument('record', help='Record UID or name')
    parser.add_argument('-u', '--user', action='append', help='User email to remove as approver')
    parser.add_argument('-t', '--team', action='append', help='Team name or UID to remove as approver')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowDeleteApproversCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute delete approvers."""
        record_uid = kwargs.get('record')
        users = kwargs.get('user') or []
        teams = kwargs.get('team') or []
        
        if not users and not teams:
            raise CommandError('', 'Must specify at least one --user or --team')
        
        # Resolve record UID
        if record_uid not in params.record_cache:
            records = list(params.record_cache.keys())
            for uid in records:
                rec = vault.KeeperRecord.load(params, uid)
                if rec and rec.title == record_uid:
                    record_uid = uid
                    break
            else:
                raise CommandError('', f'Record "{record_uid}" not found')
        
        record = vault.KeeperRecord.load(params, record_uid)
        record_uid_bytes = utils.base64_url_decode(record_uid)
        
        # Create workflow config with approvers to remove
        config = workflow_pb2.WorkflowConfig()
        config.parameters.resource.CopyFrom(create_record_ref(record_uid_bytes, record.title))
        
        # Add user approvers to remove (email validated by backend)
        for user_email in users:
            approver = workflow_pb2.WorkflowApprover()
            approver.user = user_email
            config.approvers.append(approver)
        
        # Add team approvers to remove (accepts team UID or team name)
        for team_input in teams:
            resolved_team_uid = validate_team(params, team_input)
            approver = workflow_pb2.WorkflowApprover()
            approver.teamUid = utils.base64_url_decode(resolved_team_uid)
            config.approvers.append(approver)
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'delete_workflow_approvers',
                rq_proto=config
            )
            
            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'approvers_removed': len(users) + len(teams)
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Approvers removed successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print(f"Removed {len(users) + len(teams)} approver(s)")
                print()
                
        except Exception as e:
            raise CommandError('', f'Failed to remove approvers: {str(e)}')


# ============================================================================
# STATE INSPECTION COMMANDS
# ============================================================================

class WorkflowGetStateCommand(Command):
    """
    Get the current state of a workflow.
    
    Shows whether a workflow is ready to start, waiting for approval,
    in progress, etc.
    
    Example:
        pam workflow state --record <record_uid>
        pam workflow state --flow-uid <flow_uid>
    """
    parser = argparse.ArgumentParser(prog='pam workflow state',
                                     description='Get workflow state for a record or flow')
    _state_group = parser.add_mutually_exclusive_group(required=True)
    _state_group.add_argument('-r', '--record', help='Record UID or name')
    _state_group.add_argument('-f', '--flow-uid', help='Flow UID of active workflow')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowGetStateCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute get workflow state."""
        record_uid = kwargs.get('record')
        flow_uid = kwargs.get('flow_uid')
        
        # Create state request
        state = workflow_pb2.WorkflowState()
        
        if flow_uid:
            # Query by flow UID
            state.flowUid = utils.base64_url_decode(flow_uid)
        else:
            # Query by record UID
            if record_uid not in params.record_cache:
                records = list(params.record_cache.keys())
                for uid in records:
                    rec = vault.KeeperRecord.load(params, uid)
                    if rec and rec.title == record_uid:
                        record_uid = uid
                        break
                else:
                    raise CommandError('', f'Record "{record_uid}" not found')
            
            record = vault.KeeperRecord.load(params, record_uid)
            record_uid_bytes = utils.base64_url_decode(record_uid)
            state.resource.CopyFrom(create_record_ref(record_uid_bytes, record.title))
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'get_workflow_state',
                rq_proto=state,
                rs_type=workflow_pb2.WorkflowState
            )
            
            if response is None:
                if kwargs.get('format') == 'json':
                    print(json.dumps({'status': 'no_workflow', 'message': 'No workflow found'}, indent=2))
                else:
                    print(f"\n{bcolors.WARNING}No workflow found for this record{bcolors.ENDC}\n")
                return
            
            if kwargs.get('format') == 'json':
                result = {
                    'flow_uid': utils.base64_url_encode(response.flowUid) if response.flowUid else None,
                    'record_uid': utils.base64_url_encode(response.resource.value),
                    'record_name': resolve_record_name(params, response.resource),
                    'stage': format_workflow_stage(response.status.stage),
                    'conditions': [format_access_conditions([c]) for c in response.status.conditions],
                    'escalated': response.status.escalated,
                    'started_on': response.status.startedOn or None,
                    'expires_on': response.status.expiresOn or None,
                    'approved_by': [
                        {
                            'user': a.user if a.user else resolve_user_name(params, a.userId),
                            'approved_on': a.approvedOn or None
                        }
                        for a in response.status.approvedBy
                    ]
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKBLUE}Workflow State{bcolors.ENDC}\n")
                print(f"Record: {format_record_label(params, response.resource)}")
                if response.flowUid:
                    print(f"Flow UID: {utils.base64_url_encode(response.flowUid)}")
                print(f"Stage: {format_workflow_stage(response.status.stage)}")
                if response.status.conditions:
                    print(f"Conditions: {format_access_conditions(response.status.conditions)}")
                if response.status.escalated:
                    print(f"Escalated: Yes")
                if response.status.startedOn:
                    started = datetime.fromtimestamp(response.status.startedOn / 1000)
                    print(f"Started: {started.strftime('%Y-%m-%d %H:%M:%S')}")
                if response.status.expiresOn:
                    expires = datetime.fromtimestamp(response.status.expiresOn / 1000)
                    print(f"Expires: {expires.strftime('%Y-%m-%d %H:%M:%S')}")
                if response.status.approvedBy:
                    print(f"Approved by:")
                    for a in response.status.approvedBy:
                        name = a.user if a.user else resolve_user_name(params, a.userId)
                        ts = ''
                        if a.approvedOn:
                            ts = f" at {datetime.fromtimestamp(a.approvedOn / 1000).strftime('%Y-%m-%d %H:%M:%S')}"
                        print(f"  - {name}{ts}")
                print()
                
        except Exception as e:
            raise CommandError('', f'Failed to get workflow state: {str(e)}')


class WorkflowGetUserAccessStateCommand(Command):
    """
    Get all workflows for the current user.
    
    Shows all active workflows, pending approvals, and available workflows
    for the logged-in user.
    
    Example:
        pam workflow my-access
    """
    parser = argparse.ArgumentParser(prog='pam workflow my-access',
                                     description='Get all workflow states for current user')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowGetUserAccessStateCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute get user access state."""
        try:
            response = _post_request_to_router(
                params,
                'get_user_access_state',
                rs_type=workflow_pb2.UserAccessState
            )
            
            if not response or not response.workflows:
                if kwargs.get('format') == 'json':
                    print(json.dumps({'workflows': []}, indent=2))
                else:
                    print(f"\n{bcolors.WARNING}No active workflows{bcolors.ENDC}\n")
                return
            
            if kwargs.get('format') == 'json':
                result = {
                    'workflows': [
                        {
                            'flow_uid': utils.base64_url_encode(wf.flowUid),
                            'record_uid': utils.base64_url_encode(wf.resource.value),
                            'record_name': resolve_record_name(params, wf.resource),
                            'stage': format_workflow_stage(wf.status.stage),
                            'conditions': [format_access_conditions([c]) for c in wf.status.conditions],
                            'escalated': wf.status.escalated,
                            'started_on': wf.status.startedOn or None,
                            'expires_on': wf.status.expiresOn or None,
                            'approved_by': [
                                {
                                    'user': a.user if a.user else resolve_user_name(params, a.userId),
                                    'approved_on': a.approvedOn or None
                                }
                                for a in wf.status.approvedBy
                            ]
                        }
                        for wf in response.workflows
                    ]
                }
                print(json.dumps(result, indent=2))
            else:
                rows = []
                for wf in response.workflows:
                    stage = format_workflow_stage(wf.status.stage)
                    record_name = resolve_record_name(params, wf.resource)
                    record_uid = utils.base64_url_encode(wf.resource.value) if wf.resource.value else ''
                    flow_uid = utils.base64_url_encode(wf.flowUid) if wf.flowUid else ''
                    conditions = format_access_conditions(wf.status.conditions) if wf.status.conditions else ''
                    started = datetime.fromtimestamp(wf.status.startedOn / 1000).strftime('%Y-%m-%d %H:%M:%S') if wf.status.startedOn else ''
                    expires = datetime.fromtimestamp(wf.status.expiresOn / 1000).strftime('%Y-%m-%d %H:%M:%S') if wf.status.expiresOn else ''
                    approved_by = ''
                    if wf.status.approvedBy:
                        approved_names = [a.user if a.user else resolve_user_name(params, a.userId) for a in wf.status.approvedBy]
                        approved_by = ', '.join(approved_names)
                    rows.append([stage, record_name, record_uid, flow_uid, approved_by, started, expires, conditions])
                headers = ['Stage', 'Record Name', 'Record UID', 'Flow UID', 'Approved By', 'Started', 'Expires', 'Conditions']
                print()
                dump_report_data(rows, headers=headers)
                print()
                
        except Exception as e:
            raise CommandError('', f'Failed to get user access state: {str(e)}')


class WorkflowGetApprovalRequestsCommand(Command):
    """
    Get pending approval requests for the current user.
    
    Shows all workflows waiting for your approval.
    
    Example:
        pam workflow pending
    """
    parser = argparse.ArgumentParser(prog='pam workflow pending',
                                     description='Get pending approval requests')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowGetApprovalRequestsCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute get approval requests."""
        try:
            response = _post_request_to_router(
                params,
                'get_approval_requests',
                rs_type=workflow_pb2.ApprovalRequests
            )

            if not response or not response.workflows:
                if kwargs.get('format') == 'json':
                    print(json.dumps({'requests': []}, indent=2))
                else:
                    print(f"\n{bcolors.WARNING}No approval requests{bcolors.ENDC}\n")
                return

            # Determine status for each workflow
            # Items with startedOn are approved/active
            # Items without startedOn need a state check for approved-but-not-started
            def _resolve_status(wf):
                if wf.startedOn:
                    return 'Approved'
                try:
                    st = workflow_pb2.WorkflowState()
                    st.flowUid = wf.flowUid
                    ws = _post_request_to_router(
                        params, 'get_workflow_state', rq_proto=st,
                        rs_type=workflow_pb2.WorkflowState
                    )
                    if ws and ws.status and ws.status.stage in (
                        workflow_pb2.WS_READY_TO_START, workflow_pb2.WS_STARTED
                    ):
                        return 'Approved'
                except Exception:
                    pass
                return 'Pending'

            # Resolve status once per workflow
            wf_data = []
            for wf in response.workflows:
                status = _resolve_status(wf)
                wf_data.append((wf, status))

            if kwargs.get('format') == 'json':
                result = {
                    'requests': [
                        {
                            'flow_uid': utils.base64_url_encode(wf.flowUid),
                            'status': status,
                            'requested_by': resolve_user_name(params, wf.userId),
                            'record_uid': utils.base64_url_encode(wf.resource.value),
                            'record_name': resolve_record_name(params, wf.resource),
                            'started_on': wf.startedOn or None,
                            'expires_on': wf.expiresOn or None,
                            'duration': format_duration_from_milliseconds(wf.expiresOn - wf.startedOn) if wf.expiresOn and wf.startedOn else None,
                            'reason': wf.reason.decode('utf-8') if wf.reason else None,
                            'external_ref': wf.externalRef.decode('utf-8') if wf.externalRef else None,
                        }
                        for wf, status in wf_data
                    ]
                }
                print(json.dumps(result, indent=2))
            else:
                rows = []
                for wf, status in wf_data:
                    record_uid = utils.base64_url_encode(wf.resource.value) if wf.resource.value else ''
                    record_name = resolve_record_name(params, wf.resource)
                    flow_uid = utils.base64_url_encode(wf.flowUid)
                    requested_by = resolve_user_name(params, wf.userId)
                    started = datetime.fromtimestamp(wf.startedOn / 1000).strftime('%Y-%m-%d %H:%M:%S') if wf.startedOn else ''
                    expires = datetime.fromtimestamp(wf.expiresOn / 1000).strftime('%Y-%m-%d %H:%M:%S') if wf.expiresOn else ''
                    duration = format_duration_from_milliseconds(wf.expiresOn - wf.startedOn) if wf.expiresOn and wf.startedOn else ''
                    rows.append([status, record_name, record_uid, flow_uid, requested_by, started, expires, duration])
                headers = ['Status', 'Record Name', 'Record UID', 'Flow UID', 'Requested By', 'Started', 'Expires', 'Duration']
                print()
                dump_report_data(rows, headers=headers, sort_by=0)
                print()

        except Exception as e:
            raise CommandError('', f'Failed to get approval requests: {str(e)}')


# ============================================================================
# ACTION COMMANDS
# ============================================================================

class WorkflowStartCommand(Command):
    """
    Start a workflow (check-out).
    
    Explicitly starts a workflow and checks out the resource for use.
    Can also be started automatically by approval or when attempting
    to access a PAM resource.
    
    Example:
        pam workflow start <record_uid>
        pam workflow start <flow_uid>
    """
    parser = argparse.ArgumentParser(prog='pam workflow start',
                                     description='Start a workflow (check-out). '
                                                 'Can use either record UID/name or flow UID.')
    parser.add_argument('uid', help='Record UID, record name, or Flow UID')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowStartCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow start."""
        uid = kwargs.get('uid')
        
        # Try as record UID or name first
        record_uid = None
        record = None
        if uid in params.record_cache:
            record_uid = uid
        else:
            for cache_uid in params.record_cache:
                rec = vault.KeeperRecord.load(params, cache_uid)
                if rec and rec.title == uid:
                    record_uid = cache_uid
                    break
        
        if record_uid:
            record = vault.KeeperRecord.load(params, record_uid)
            record_uid_bytes = utils.base64_url_decode(record_uid)
            state = workflow_pb2.WorkflowState()
            state.resource.CopyFrom(create_record_ref(record_uid_bytes, record.title))
        else:
            # Treat as flow UID — query state to get record info, then start
            uid_bytes = utils.base64_url_decode(uid)
            state = workflow_pb2.WorkflowState()
            state.flowUid = uid_bytes
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'start_workflow',
                rq_proto=state
            )

            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'action': 'checked_out'}
                if record:
                    result['record_uid'] = record_uid
                    result['record_name'] = record.title
                else:
                    result['flow_uid'] = uid
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Workflow started (checked out){bcolors.ENDC}\n")
                if record:
                    print(f"Record: {record.title} ({record_uid})")
                else:
                    print(f"Flow UID: {uid}")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to start workflow: {str(e)}')


class WorkflowRequestAccessCommand(Command):
    """
    Request access to a PAM resource with workflow.
    
    Sends approval request to configured approvers.
    
    Example:
        pam workflow request <record_uid> --reason "Fix bug" --ticket INC-1234
    """
    parser = argparse.ArgumentParser(prog='pam workflow request',
                                     description='Request access to a PAM resource')
    parser.add_argument('record', help='Record UID or name')
    parser.add_argument('-r', '--reason', help='Reason for access request')
    parser.add_argument('-t', '--ticket', help='External ticket/reference number')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowRequestAccessCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow access request."""
        record_uid = kwargs.get('record')
        reason = kwargs.get('reason') or ''
        ticket = kwargs.get('ticket') or ''
        
        # Resolve record UID
        if record_uid not in params.record_cache:
            records = list(params.record_cache.keys())
            for uid in records:
                rec = vault.KeeperRecord.load(params, uid)
                if rec and rec.title == record_uid:
                    record_uid = uid
                    break
            else:
                raise CommandError('', f'Record "{record_uid}" not found')
        
        record = vault.KeeperRecord.load(params, record_uid)
        record_uid_bytes = utils.base64_url_decode(record_uid)
        
        # Use WorkflowAccessRequest which supports reason and ticket
        access_request = workflow_pb2.WorkflowAccessRequest()
        access_request.resource.CopyFrom(create_record_ref(record_uid_bytes, record.title))
        if reason:
            access_request.reason = reason.encode('utf-8') if isinstance(reason, str) else reason
        if ticket:
            access_request.ticket = ticket.encode('utf-8') if isinstance(ticket, str) else ticket
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'request_workflow_access',
                rq_proto=access_request
            )
            
            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'message': 'Access request sent to approvers'
                }
                if reason:
                    result['reason'] = reason
                if ticket:
                    result['ticket'] = ticket
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Access request sent{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                if reason:
                    print(f"Reason: {reason}")
                if ticket:
                    print(f"Ticket: {ticket}")
                print("\nApprovers have been notified.")
                print()
                
        except Exception as e:
            raise CommandError('', f'Failed to request access: {str(e)}')


class WorkflowApproveCommand(Command):
    """
    Approve a workflow access request.
    
    Example:
        pam workflow approve <flow_uid>
    """
    parser = argparse.ArgumentParser(prog='pam workflow approve',
                                     description='Approve a workflow access request')
    parser.add_argument('flow_uid', help='Flow UID of the workflow to approve')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowApproveCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow approval."""
        flow_uid = kwargs.get('flow_uid')
        flow_uid_bytes = utils.base64_url_decode(flow_uid)
        
        # Create WorkflowApprovalOrDenial with deny=False for approval
        approval = workflow_pb2.WorkflowApprovalOrDenial()
        approval.resource.CopyFrom(create_workflow_ref(flow_uid_bytes))
        approval.deny = False
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'approve_workflow_access',
                rq_proto=approval
            )
            
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
    """
    Deny a workflow access request.
    
    Example:
        pam workflow deny <flow_uid>
    """
    parser = argparse.ArgumentParser(prog='pam workflow deny',
                                     description='Deny a workflow access request')
    parser.add_argument('flow_uid', help='Flow UID of the workflow to deny')
    parser.add_argument('-r', '--reason', help='Reason for denial')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowDenyCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow denial."""
        flow_uid = kwargs.get('flow_uid')
        reason = kwargs.get('reason') or ''
        flow_uid_bytes = utils.base64_url_decode(flow_uid)
        
        # Create WorkflowApprovalOrDenial with deny=True for denial
        denial = workflow_pb2.WorkflowApprovalOrDenial()
        denial.resource.CopyFrom(create_workflow_ref(flow_uid_bytes))
        denial.deny = True
        if reason:
            denial.denialReason = reason
        
        # Make API call
        try:
            response = _post_request_to_router(
                params,
                'deny_workflow_access',
                rq_proto=denial
            )
            
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


class WorkflowEndCommand(Command):
    """
    End a workflow (check-in).
    
    Explicitly ends the workflow and triggers side effects like
    credential rotation.
    
    Example:
        pam workflow end <flow_uid>
        pam workflow end <record_uid>
        pam workflow end "Record Name"
    """
    parser = argparse.ArgumentParser(prog='pam workflow end',
                                     description='End a workflow (check-in). '
                                                 'Can use flow UID, record UID, or record name.')
    parser.add_argument('uid', help='Flow UID, Record UID, or record name of the workflow to end')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format')

    def get_parser(self):
        return WorkflowEndCommand.parser
    
    def execute(self, params: KeeperParams, **kwargs):
        """Execute workflow end."""
        uid = kwargs.get('uid')

        # Try as record UID or name first
        record_uid = None
        record = None
        if uid in params.record_cache:
            record_uid = uid
        else:
            for cache_uid in params.record_cache:
                rec = vault.KeeperRecord.load(params, cache_uid)
                if rec and rec.title == uid:
                    record_uid = cache_uid
                    break

        if record_uid:
            # Record found — look up active workflow, then end it
            record = vault.KeeperRecord.load(params, record_uid)
            try:
                state_query = workflow_pb2.WorkflowState()
                state_query.resource.CopyFrom(
                    create_record_ref(utils.base64_url_decode(record_uid), record.title if record else '')
                )
                workflow_state = _post_request_to_router(
                    params, 'get_workflow_state', rq_proto=state_query,
                    rs_type=workflow_pb2.WorkflowState
                )
                if not workflow_state or not workflow_state.flowUid:
                    raise CommandError('', 'No active workflow found for this record. '
                                          'The workflow may have already ended or never started.')

                flow_ref = create_workflow_ref(workflow_state.flowUid)
                _post_request_to_router(params, 'end_workflow', rq_proto=flow_ref)

                flow_uid_str = utils.base64_url_encode(workflow_state.flowUid)
                if kwargs.get('format') == 'json':
                    result = {
                        'status': 'success',
                        'flow_uid': flow_uid_str,
                        'record_uid': record_uid,
                        'record_name': record.title if record else '',
                        'action': 'ended'
                    }
                    print(json.dumps(result, indent=2))
                else:
                    print(f"\n{bcolors.OKGREEN}✓ Workflow ended (checked in){bcolors.ENDC}\n")
                    if record:
                        print(f"Record: {record.title} ({record_uid})")
                    else:
                        print(f"Record: {record_uid}")
                    print(f"Flow UID: {flow_uid_str}")
                    print("\nCredentials may have been rotated.")
                    print()
            except CommandError:
                raise
            except Exception as e:
                raise CommandError('', f'Failed to end workflow: {str(e)}')
        else:
            # Treat as flow UID
            try:
                uid_bytes = utils.base64_url_decode(uid)
                ref = create_workflow_ref(uid_bytes)
                _post_request_to_router(params, 'end_workflow', rq_proto=ref)

                if kwargs.get('format') == 'json':
                    result = {'status': 'success', 'flow_uid': uid, 'action': 'ended'}
                    print(json.dumps(result, indent=2))
                else:
                    print(f"\n{bcolors.OKGREEN}✓ Workflow ended (checked in){bcolors.ENDC}\n")
                    print(f"Flow UID: {uid}")
                    print("\nCredentials may have been rotated.")
                    print()
            except Exception as e:
                raise CommandError('', f'Failed to end workflow: {str(e)}')


# ============================================================================
# GROUP COMMAND (for PAM hierarchy)
# ============================================================================

class PAMWorkflowCommand(GroupCommand):
    """
    PAM Workflow management commands.
    
    Groups all workflow-related commands under 'pam workflow' hierarchy.
    """
    
    def __init__(self):
        super(PAMWorkflowCommand, self).__init__()
        
        # --- Admin / Approver commands ---
        self.register_command('create', WorkflowCreateCommand(), 'Create workflow configuration', 'c')
        self.register_command('read', WorkflowReadCommand(), 'Read workflow configuration', 'r')
        self.register_command('update', WorkflowUpdateCommand(), 'Update workflow configuration', 'u')
        self.register_command('delete', WorkflowDeleteCommand(), 'Delete workflow configuration', 'd')
        self.register_command('add-approver', WorkflowAddApproversCommand(), 'Add approvers', 'aa')
        self.register_command('remove-approver', WorkflowDeleteApproversCommand(), 'Remove approvers', 'ra')
        self.register_command('pending', WorkflowGetApprovalRequestsCommand(), 'Get pending approvals', 'p')
        self.register_command('approve', WorkflowApproveCommand(), 'Approve access request', 'a')
        self.register_command('deny', WorkflowDenyCommand(), 'Deny access request', 'dn')
        
        # --- User commands ---
        self.register_command('request', WorkflowRequestAccessCommand(), 'Request access', 'rq')
        self.register_command('start', WorkflowStartCommand(), 'Start workflow (check-out)', 's')
        self.register_command('end', WorkflowEndCommand(), 'End workflow (check-in)', 'e')
        self.register_command('my-access', WorkflowGetUserAccessStateCommand(), 'Get my access state', 'ma')
        self.register_command('state', WorkflowGetStateCommand(), 'Get workflow state', 'st')
        
        self.default_verb = 'state'

