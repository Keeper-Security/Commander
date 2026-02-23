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

from ..base import Command
from ..pam.router_helper import _post_request_to_router
from ...display import bcolors
from ...error import CommandError
from ...params import KeeperParams
from ...proto import workflow_pb2
from ... import utils

from .helpers import RecordResolver, ProtobufRefBuilder, WorkflowFormatter


class WorkflowCreateCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow create',
        description='Create workflow configuration for a PAM record',
        allow_abbrev=False,
    )
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
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowCreateCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        record_uid_bytes = utils.base64_url_decode(record_uid)

        parameters = workflow_pb2.WorkflowParameters()
        parameters.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record.title))
        parameters.approvalsNeeded = kwargs.get('approvals_needed', 1)
        parameters.checkoutNeeded = kwargs.get('checkout', False)
        parameters.startAccessOnApproval = kwargs.get('start_on_approval', False)
        parameters.requireReason = kwargs.get('require_reason', False)
        parameters.requireTicket = kwargs.get('require_ticket', False)
        parameters.requireMFA = kwargs.get('require_mfa', False)
        parameters.accessLength = WorkflowFormatter.parse_duration(kwargs.get('duration', '1d'))

        try:
            _post_request_to_router(params, 'create_workflow_config', rq_proto=parameters)

            owner_email = params.user
            owner_added = False
            if owner_email:
                try:
                    approver_config = workflow_pb2.WorkflowConfig()
                    approver_config.parameters.resource.CopyFrom(
                        ProtobufRefBuilder.record_ref(record_uid_bytes, record.title)
                    )
                    approver = workflow_pb2.WorkflowApprover()
                    approver.user = owner_email
                    approver_config.approvers.append(approver)
                    _post_request_to_router(params, 'add_workflow_approvers', rq_proto=approver_config)
                    owner_added = True
                except Exception:
                    pass

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
                        'access_duration': WorkflowFormatter.format_duration(parameters.accessLength),
                    },
                    'owner_approver': owner_email if owner_added else None,
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Workflow created successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print(f"Approvals needed: {parameters.approvalsNeeded}")
                print(f"Check-in/out: {'Yes' if parameters.checkoutNeeded else 'No'}")
                print(f"Duration: {WorkflowFormatter.format_duration(parameters.accessLength)}")
                if parameters.requireReason:
                    print("Requires reason: Yes")
                if parameters.requireTicket:
                    print("Requires ticket: Yes")
                if parameters.requireMFA:
                    print("Requires MFA: Yes")
                if owner_added:
                    print(f"\nApprover added: {owner_email} (record owner)")
                else:
                    print(f"\n{bcolors.WARNING}Note: Add approvers with: "
                          f"pam workflow add-approver {record_uid} --user <email>{bcolors.ENDC}")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to create workflow: {str(e)}')


class WorkflowReadCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow read',
        description='Read and display workflow configuration',
    )
    parser.add_argument('record', help='Record UID or name')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowReadCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        record_uid_bytes = utils.base64_url_decode(record_uid)
        ref = ProtobufRefBuilder.record_ref(record_uid_bytes, record.title)

        try:
            response = _post_request_to_router(
                params, 'read_workflow_config',
                rq_proto=ref, rs_type=workflow_pb2.WorkflowConfig,
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
                self._print_json(params, response, record_uid)
            else:
                self._print_table(params, response, record_uid)

        except Exception as e:
            raise CommandError('', f'Failed to read workflow: {str(e)}')

    @staticmethod
    def _print_json(params, response, record_uid):
        result = {
            'record_uid': record_uid,
            'record_name': RecordResolver.resolve_name(params, response.parameters.resource),
            'parameters': {
                'approvals_needed': response.parameters.approvalsNeeded,
                'checkout_needed': response.parameters.checkoutNeeded,
                'start_access_on_approval': response.parameters.startAccessOnApproval,
                'require_reason': response.parameters.requireReason,
                'require_ticket': response.parameters.requireTicket,
                'require_mfa': response.parameters.requireMFA,
                'access_duration': WorkflowFormatter.format_duration(response.parameters.accessLength),
            },
            'approvers': [],
        }

        for approver in response.approvers:
            approver_info = {'escalation': approver.escalation}
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

    @staticmethod
    def _print_table(params, response, record_uid):
        print(f"\n{bcolors.OKBLUE}Workflow Configuration{bcolors.ENDC}\n")
        print(f"Record: {RecordResolver.resolve_name(params, response.parameters.resource)}")
        print(f"Record UID: {record_uid}")

        if response.createdOn:
            created_date = datetime.fromtimestamp(response.createdOn / 1000)
            print(f"Created: {created_date.strftime('%Y-%m-%d %H:%M:%S')}")

        p = response.parameters
        print(f"\n{bcolors.BOLD}Access Parameters:{bcolors.ENDC}")
        print(f"  Approvals needed: {p.approvalsNeeded}")
        print(f"  Check-in/out required: {'Yes' if p.checkoutNeeded else 'No'}")
        print(f"  Access duration: {WorkflowFormatter.format_duration(p.accessLength)}")
        print(f"  Timer starts: {'On approval' if p.startAccessOnApproval else 'On check-out'}")

        print(f"\n{bcolors.BOLD}Requirements:{bcolors.ENDC}")
        print(f"  Reason required: {'Yes' if p.requireReason else 'No'}")
        print(f"  Ticket required: {'Yes' if p.requireTicket else 'No'}")
        print(f"  MFA required: {'Yes' if p.requireMFA else 'No'}")

        if response.approvers:
            print(f"\n{bcolors.BOLD}Approvers ({len(response.approvers)}):{bcolors.ENDC}")
            for idx, approver in enumerate(response.approvers, 1):
                escalation = ' (Escalation)' if approver.escalation else ''
                if approver.HasField('user'):
                    print(f"  {idx}. User: {approver.user}{escalation}")
                elif approver.HasField('userId'):
                    print(f"  {idx}. User: {RecordResolver.resolve_user(params, approver.userId)}{escalation}")
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


class WorkflowUpdateCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow update',
        description='Update existing workflow configuration. '
                    'Only specified fields are changed; unspecified fields retain their current values.',
    )
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
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowUpdateCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        record_uid_bytes = utils.base64_url_decode(record_uid)

        try:
            ref = ProtobufRefBuilder.record_ref(record_uid_bytes, record.title)
            current_config = _post_request_to_router(
                params, 'read_workflow_config',
                rq_proto=ref, rs_type=workflow_pb2.WorkflowConfig,
            )

            if not current_config:
                raise CommandError('', 'No workflow found for record. Create one first with "pam workflow create"')

            parameters = workflow_pb2.WorkflowParameters()
            parameters.CopyFrom(current_config.parameters)

            updatable_fields = {
                'approvals_needed': 'approvalsNeeded',
                'checkout': 'checkoutNeeded',
                'start_on_approval': 'startAccessOnApproval',
                'require_reason': 'requireReason',
                'require_ticket': 'requireTicket',
                'require_mfa': 'requireMFA',
            }

            updates_provided = False
            for kwarg_key, proto_field in updatable_fields.items():
                if kwargs.get(kwarg_key) is not None:
                    setattr(parameters, proto_field, kwargs[kwarg_key])
                    updates_provided = True

            if kwargs.get('duration') is not None:
                parameters.accessLength = WorkflowFormatter.parse_duration(kwargs['duration'])
                updates_provided = True

            if not updates_provided:
                raise CommandError(
                    '', 'No updates provided. Specify at least one option to update '
                        '(e.g., --approvals-needed, --duration)',
                )

            _post_request_to_router(params, 'update_workflow_config', rq_proto=parameters)

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


class WorkflowDeleteCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow delete',
        description='Delete workflow configuration from a record',
    )
    parser.add_argument('record', help='Record UID or name to remove workflow from')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowDeleteCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        record_uid_bytes = utils.base64_url_decode(record_uid)
        ref = ProtobufRefBuilder.record_ref(record_uid_bytes, record.title)

        try:
            _post_request_to_router(params, 'delete_workflow_config', rq_proto=ref)

            if kwargs.get('format') == 'json':
                result = {'status': 'success', 'record_uid': record_uid, 'record_name': record.title}
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Workflow deleted successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to delete workflow: {str(e)}')


class WorkflowAddApproversCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow add-approver',
        description='Add approvers to a workflow',
    )
    parser.add_argument('record', help='Record UID or name')
    parser.add_argument('-u', '--user', action='append',
                        help='User email to add as approver (can specify multiple times)')
    parser.add_argument('-t', '--team', action='append',
                        help='Team name or UID to add as approver (can specify multiple times)')
    parser.add_argument('-e', '--escalation', action='store_true', help='Mark as escalation approver')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowAddApproversCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        users = kwargs.get('user') or []
        teams = kwargs.get('team') or []
        is_escalation = kwargs.get('escalation', False)

        if not users and not teams:
            raise CommandError('', 'Must specify at least one --user or --team')

        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        record_uid_bytes = utils.base64_url_decode(record_uid)

        config = workflow_pb2.WorkflowConfig()
        config.parameters.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record.title))

        for user_email in users:
            approver = workflow_pb2.WorkflowApprover()
            approver.user = user_email
            approver.escalation = is_escalation
            config.approvers.append(approver)

        for team_input in teams:
            resolved_team_uid = RecordResolver.validate_team(params, team_input)
            approver = workflow_pb2.WorkflowApprover()
            approver.teamUid = utils.base64_url_decode(resolved_team_uid)
            approver.escalation = is_escalation
            config.approvers.append(approver)

        try:
            _post_request_to_router(params, 'add_workflow_approvers', rq_proto=config)

            total = len(users) + len(teams)
            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'approvers_added': total,
                    'escalation': is_escalation,
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Approvers added successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print(f"Added {total} approver(s)")
                if is_escalation:
                    print("Type: Escalation approver")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to add approvers: {str(e)}')


class WorkflowDeleteApproversCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam workflow remove-approver',
        description='Remove approvers from a workflow',
    )
    parser.add_argument('record', help='Record UID or name')
    parser.add_argument('-u', '--user', action='append', help='User email to remove as approver')
    parser.add_argument('-t', '--team', action='append', help='Team name or UID to remove as approver')
    parser.add_argument('--format', dest='format', action='store',
                        choices=['table', 'json'], default='table', help='Output format')

    def get_parser(self):
        return WorkflowDeleteApproversCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        users = kwargs.get('user') or []
        teams = kwargs.get('team') or []

        if not users and not teams:
            raise CommandError('', 'Must specify at least one --user or --team')

        record_uid, record = RecordResolver.resolve(params, kwargs.get('record'))
        record_uid_bytes = utils.base64_url_decode(record_uid)

        config = workflow_pb2.WorkflowConfig()
        config.parameters.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record.title))

        for user_email in users:
            approver = workflow_pb2.WorkflowApprover()
            approver.user = user_email
            config.approvers.append(approver)

        for team_input in teams:
            resolved_team_uid = RecordResolver.validate_team(params, team_input)
            approver = workflow_pb2.WorkflowApprover()
            approver.teamUid = utils.base64_url_decode(resolved_team_uid)
            config.approvers.append(approver)

        try:
            _post_request_to_router(params, 'delete_workflow_approvers', rq_proto=config)

            total = len(users) + len(teams)
            if kwargs.get('format') == 'json':
                result = {
                    'status': 'success',
                    'record_uid': record_uid,
                    'record_name': record.title,
                    'approvers_removed': total,
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"\n{bcolors.OKGREEN}✓ Approvers removed successfully{bcolors.ENDC}\n")
                print(f"Record: {record.title} ({record_uid})")
                print(f"Removed {total} approver(s)")
                print()

        except Exception as e:
            raise CommandError('', f'Failed to remove approvers: {str(e)}')
