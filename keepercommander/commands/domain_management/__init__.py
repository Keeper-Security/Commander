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

"""domain_management package – CLI surface for enterprise domain operations.

Package layout (follows Single Responsibility Principle)
--------------------------------------------------------
parsers.py         – All argparse parser definitions (no business logic)
helper.py          – DomainManagementHelper (validation, error handling, output formatting)
domain_commands.py – ListDomainsCommand, ReserveDomainCommand (domain CRUD)
alias_commands.py  – DomainAliasCommand, Get/Create/Delete alias commands
__init__.py        – DomainCommand router, register_commands / register_command_info
"""

import re

from ..enterprise_common import EnterpriseCommand
from .helper import DomainManagementHelper
from .parsers import domain_parser
from .domain_commands import ListDomainsCommand, ReserveDomainCommand
from .alias_commands import DomainAliasCommand


class DomainCommand(EnterpriseCommand):
    """Top-level router that delegates to list / reserve / alias sub-commands."""

    def __init__(self):
        super().__init__()
        self.list_cmd = ListDomainsCommand()
        self.reserve_cmd = ReserveDomainCommand()
        self.alias_cmd = DomainAliasCommand()

    def get_parser(self):
        return domain_parser

    def execute_args(self, params, args, **kwargs):
        import shlex
        from ..base import ParseError, expand_cmd_args, normalize_output_param

        try:
            d = {}
            d.update(kwargs)
            self.extra_parameters = ''
            parser = self._get_parser_safe()
            envvars = params.environment_variables
            args = '' if args is None else args

            if parser:
                args = expand_cmd_args(args, envvars)
                args = normalize_output_param(args)
                opts = parser.parse_args(shlex.split(args))
                d.update(opts.__dict__)

            return self.execute(params, **d)

        except ParseError as e:
            error_str = str(e)
            if 'invalid choice' in error_str:
                match = re.search(r"invalid choice: '([^']+)'", error_str)
                if match:
                    invalid_cmd = match.group(1)
                    output_format = kwargs.get('format', 'text')
                    DomainManagementHelper.handle_invalid_subcommand(invalid_cmd, output_format)
                    return None
            import logging
            logging.error(error_str)
            return None

    def execute(self, params, **kwargs):
        subcommand = kwargs.get('subcommand')

        if not subcommand:
            self.get_parser().print_help()
            return

        if subcommand == 'list':
            return self.list_cmd.execute(params, **kwargs)
        elif subcommand == 'reserve':
            return self.reserve_cmd.execute(params, **kwargs)
        elif subcommand == 'alias':
            return self.alias_cmd.execute(params, **kwargs)
        else:
            output_format = kwargs.get('format', 'text')
            DomainManagementHelper.handle_invalid_subcommand(subcommand, output_format)
            return None


def register_commands(commands):
    commands['domain'] = DomainCommand()


def register_command_info(aliases, command_info):
    aliases['dl'] = ('domain', 'list')
    aliases['dr'] = ('domain', 'reserve')
    aliases['dal'] = ('domain', 'alias', 'list')
    aliases['dac'] = ('domain', 'alias', 'create')
    aliases['dad'] = ('domain', 'alias', 'delete')
    command_info['domain'] = domain_parser.description
