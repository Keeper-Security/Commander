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

"""Domain alias commands – list, create, and delete domain aliases."""

import logging

from ... import api
from ...error import KeeperApiError
from ...proto import enterprise_pb2
from ..enterprise_common import EnterpriseCommand
from .constants import API_ENDPOINTS
from .helper import DomainManagementHelper
from .parsers import (
    domain_alias_parser,
    domain_alias_list_parser,
    domain_alias_create_parser,
    domain_alias_delete_parser,
)


class DomainAliasCommand(EnterpriseCommand):
    """Routes ``domain alias <list|create|delete>`` to the appropriate command."""

    def __init__(self):
        super().__init__()
        self.list_cmd = GetDomainAliasCommand()
        self.create_cmd = CreateDomainAliasCommand()
        self.delete_cmd = DeleteDomainAliasCommand()

    def get_parser(self):
        return domain_alias_parser

    def execute(self, params, **kwargs):
        alias_subcommand = kwargs.get('alias_subcommand')

        if not alias_subcommand:
            self.get_parser().print_help()
            return

        if alias_subcommand == 'list':
            return self.list_cmd.execute(params, **kwargs)
        elif alias_subcommand == 'create':
            return self.create_cmd.execute(params, **kwargs)
        elif alias_subcommand == 'delete':
            return self.delete_cmd.execute(params, **kwargs)
        else:
            output_format = kwargs.get('format', 'text')
            DomainManagementHelper.handle_invalid_subcommand(
                f'alias {alias_subcommand}', output_format,
            )
            return None


class GetDomainAliasCommand(EnterpriseCommand):
    """List all domain aliases for the enterprise."""

    def get_parser(self):
        return domain_alias_list_parser

    def execute(self, params, **kwargs):
        output_format = kwargs.get('format') or 'text'
        try:
            rs = api.communicate_rest(
                params, None, API_ENDPOINTS['get_domain_alias'],
                rs_type=enterprise_pb2.DomainAliasResponse,
            )

            if not rs.domainAlias:
                logging.info('No domain aliases found for this enterprise.')
                return

            return DomainManagementHelper.render_alias_response(rs, output_format, kwargs)

        except KeeperApiError as e:
            DomainManagementHelper.handle_alias_api_error(e, output_format, 'retrieving')


class CreateDomainAliasCommand(EnterpriseCommand):
    """Create one or more domain aliases for a domain owned by the enterprise."""

    def get_parser(self):
        return domain_alias_create_parser

    def execute(self, params, **kwargs):
        domain = kwargs.get('domain', '')
        aliases = kwargs.get('alias', [])
        output_format = kwargs.get('format', 'text')

        if not domain:
            DomainManagementHelper.output_error('Domain name is required.', output_format)
            return
        if not aliases:
            DomainManagementHelper.output_error('At least one alias is required.', output_format)
            return

        is_valid, domain, error_msg = DomainManagementHelper.validate_domain(domain)
        if not is_valid:
            DomainManagementHelper.output_error(error_msg, output_format)
            return

        normalized_aliases = DomainManagementHelper.validate_aliases(domain, aliases, output_format)
        if normalized_aliases is None:
            return

        try:
            rq = DomainManagementHelper.build_alias_request(domain, normalized_aliases)
            rs = api.communicate_rest(
                params, rq, API_ENDPOINTS['create_domain_alias'],
                rs_type=enterprise_pb2.DomainAliasResponse,
            )
            return DomainManagementHelper.render_alias_response(
                rs, output_format, kwargs,
                status_messages=DomainManagementHelper.CREATE_ALIAS_STATUS_MESSAGES,
                action='create',
            )

        except KeeperApiError as e:
            DomainManagementHelper.handle_alias_api_error(e, output_format, 'creating')


class DeleteDomainAliasCommand(EnterpriseCommand):
    """Delete one or more domain aliases for a domain owned by the enterprise."""

    def get_parser(self):
        return domain_alias_delete_parser

    def execute(self, params, **kwargs):
        domain = kwargs.get('domain', '')
        aliases = kwargs.get('alias', [])
        output_format = kwargs.get('format', 'text')
        force = kwargs.get('force', False)

        if not domain:
            DomainManagementHelper.output_error('Domain name is required.', output_format)
            return
        if not aliases:
            DomainManagementHelper.output_error('At least one alias is required.', output_format)
            return

        is_valid, domain, error_msg = DomainManagementHelper.validate_domain(domain)
        if not is_valid:
            DomainManagementHelper.output_error(error_msg, output_format)
            return

        normalized_aliases = DomainManagementHelper.validate_aliases(domain, aliases, output_format)
        if normalized_aliases is None:
            return

        existing_aliases = self._get_existing_aliases(params)
        not_found = [a for a in normalized_aliases if (domain, a) not in existing_aliases]
        if not_found:
            for alias in not_found:
                DomainManagementHelper.output_error(
                    f"Domain alias '{alias}' for domain '{domain}' does not exist.", output_format,
                )
            return

        if not force:
            alias_list_str = ', '.join(normalized_aliases)
            try:
                confirm = input(
                    f'Are you sure you want to delete alias(es) [{alias_list_str}] for domain "{domain}"? (y/N): '
                )
            except (KeyboardInterrupt, EOFError):
                logging.info('Delete cancelled.')
                return
            if confirm.strip().lower() not in ('y', 'yes'):
                logging.info('Delete cancelled.')
                return

        try:
            rq = DomainManagementHelper.build_alias_request(domain, normalized_aliases)
            rs = api.communicate_rest(
                params, rq, API_ENDPOINTS['delete_domain_alias'],
                rs_type=enterprise_pb2.DomainAliasResponse,
            )
            return DomainManagementHelper.render_alias_response(
                rs, output_format, kwargs,
                status_messages=DomainManagementHelper.DELETE_ALIAS_STATUS_MESSAGES,
                action='delete',
            )

        except KeeperApiError as e:
            DomainManagementHelper.handle_alias_api_error(e, output_format, 'deleting')

    @staticmethod
    def _get_existing_aliases(params):
        """Fetch current domain aliases and return as a set of (domain, alias) tuples."""
        try:
            rs = api.communicate_rest(
                params, None, API_ENDPOINTS['get_domain_alias'],
                rs_type=enterprise_pb2.DomainAliasResponse,
            )
            return {(da.domain, da.alias) for da in rs.domainAlias} if rs.domainAlias else set()
        except KeeperApiError:
            return set()
