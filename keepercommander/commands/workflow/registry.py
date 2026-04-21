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

import logging
from urllib.parse import urlparse

from ..base import GroupCommand, dump_report_data
from ...display import bcolors
from .helpers import _ENFORCEMENT_KEY

from .config_commands import (
    WorkflowCreateCommand,
    WorkflowReadCommand,
    WorkflowUpdateCommand,
    WorkflowDeleteCommand,
    WorkflowAddApproversCommand,
    WorkflowDeleteApproversCommand,
)
from .approver_commands import (
    WorkflowGetApprovalRequestsCommand,
    WorkflowApproveCommand,
    WorkflowDenyCommand,
)
from .state_commands import (
    WorkflowGetStateCommand,
    WorkflowGetUserAccessStateCommand,
)
from .requester_commands import (
    WorkflowRequestAccessCommand,
    WorkflowStartCommand,
    WorkflowEndCommand,
)


class PAMWorkflowCommand(GroupCommand):

    NOTICE_MSG = 'Notice: PAM Workflow commands are not in production yet. They will be available soon.'
    _ALLOWED_PREFIXES = ('dev.', 'qa.')
    _ADMIN_VERBS = frozenset({'create', 'update', 'delete', 'add-approver', 'remove-approver'})

    @staticmethod
    def _is_allowed_server(params):
        hostname = urlparse(params.rest_context.server_base).hostname or ''
        return any(hostname.startswith(p) for p in PAMWorkflowCommand._ALLOWED_PREFIXES)

    @staticmethod
    def _can_manage_workflows(params):
        enforcements = getattr(params, 'enforcements', None)
        if not enforcements or 'booleans' not in enforcements:
            return False
        return any(
            b.get('value') for b in enforcements['booleans']
            if b.get('key') == _ENFORCEMENT_KEY
        )

    def execute_args(self, params, args, **kwargs):
        if not self._is_allowed_server(params):
            logging.warning(f"{bcolors.WARNING}{self.NOTICE_MSG}{bcolors.ENDC}")
            return

        self._current_params = params

        pos = args.find(' ') if args else -1
        verb = (args[:pos].strip() if pos > 0 else args.strip()).lower() if args else ''
        resolved_verb = self._aliases.get(verb, verb)

        if resolved_verb in self._ADMIN_VERBS and not self._can_manage_workflows(params):
            print(
                f"\n{bcolors.WARNING}You do not have permission to manage workflow settings.{bcolors.ENDC}\n"
                f"The '{bcolors.BOLD}{resolved_verb}{bcolors.ENDC}' command requires the "
                f"'{bcolors.BOLD}Can manage workflow settings{bcolors.ENDC}' enforcement policy.\n"
                f"Contact your Keeper administrator to enable this for your role.\n"
            )
            return

        return super().execute_args(params, args, **kwargs)

    def print_help(self, **kwargs):
        params = getattr(self, '_current_params', None)
        is_admin = params and self._can_manage_workflows(params)

        print(f'{kwargs.get("command")} command [--options]')
        table = []
        headers = ['Command', 'Description']
        for verb in self._commands.keys():
            if verb in self._ADMIN_VERBS and not is_admin:
                continue
            row = [verb, self._command_info.get(verb) or '']
            table.append(row)
        print('')
        dump_report_data(table, headers=headers)
        print('')

    def __init__(self):
        super(PAMWorkflowCommand, self).__init__()

        # Configuration (admin — requires 'Can manage workflow settings' enforcement)
        self.register_command('create', WorkflowCreateCommand(), 'Create workflow configuration', 'c')
        self.register_command('read', WorkflowReadCommand(), 'Read workflow configuration', 'r')
        self.register_command('update', WorkflowUpdateCommand(), 'Update workflow configuration', 'u')
        self.register_command('delete', WorkflowDeleteCommand(), 'Delete workflow configuration', 'd')
        self.register_command('add-approver', WorkflowAddApproversCommand(), 'Add approvers', 'aa')
        self.register_command('remove-approver', WorkflowDeleteApproversCommand(), 'Remove approvers', 'ra')

        # Approver actions
        self.register_command('pending', WorkflowGetApprovalRequestsCommand(), 'Get pending approvals', 'p')
        self.register_command('approve', WorkflowApproveCommand(), 'Approve access request', 'a')
        self.register_command('deny', WorkflowDenyCommand(), 'Deny access request', 'dn')

        # Requester actions
        self.register_command('request', WorkflowRequestAccessCommand(), 'Request or escalate access', 'rq')
        self.register_command('start', WorkflowStartCommand(), 'Start workflow (check-out)', 's')
        self.register_command('end', WorkflowEndCommand(), 'End workflow (check-in)', 'e')

        # State inspection
        self.register_command('state', WorkflowGetStateCommand(), 'Get workflow state', 'st')
        self.register_command('my-access', WorkflowGetUserAccessStateCommand(), 'Get my access state', 'ma')

        self.default_verb = 'state'
