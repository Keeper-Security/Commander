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

from ..base import GroupCommand
from ...display import bcolors

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

    @staticmethod
    def _is_dev_server(params):
        hostname = urlparse(params.rest_context.server_base).hostname or ''
        return hostname.startswith('dev.')

    def execute_args(self, params, args, **kwargs):
        if not self._is_dev_server(params):
            logging.warning(f"{bcolors.WARNING}{self.NOTICE_MSG}{bcolors.ENDC}")
            return
        return super().execute_args(params, args, **kwargs)

    def __init__(self):
        super(PAMWorkflowCommand, self).__init__()

        # Configuration (admin)
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
        self.register_command('request', WorkflowRequestAccessCommand(), 'Request access', 'rq')
        self.register_command('start', WorkflowStartCommand(), 'Start workflow (check-out)', 's')
        self.register_command('end', WorkflowEndCommand(), 'End workflow (check-in)', 'e')

        # State inspection
        self.register_command('state', WorkflowGetStateCommand(), 'Get workflow state', 'st')
        self.register_command('my-access', WorkflowGetUserAccessStateCommand(), 'Get my access state', 'ma')

        self.default_verb = 'state'
