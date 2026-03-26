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

"""Domain list and reserve commands."""

import json
import logging

from ... import api
from ...display import bcolors
from ...error import KeeperApiError
from ...proto import enterprise_pb2
from ..base import dump_report_data
from ..enterprise_common import EnterpriseCommand
from .constants import API_ENDPOINTS
from .helper import DomainManagementHelper
from .parsers import domain_list_parser, domain_reserve_parser


class ListDomainsCommand(EnterpriseCommand):
    """List all reserved domains for the enterprise."""

    def get_parser(self):
        return domain_list_parser

    def execute(self, params, **kwargs):
        try:
            rs = api.communicate_rest(
                params, None, API_ENDPOINTS['list_domains'],
                rs_type=enterprise_pb2.ListDomainsResponse,
            )

            fmt = kwargs.get('format', '')

            if not rs.domain:
                logging.info('No reserved domains found for this enterprise.')
                return

            if fmt == 'json':
                domains_list = list(rs.domain)
                print(json.dumps(domains_list, indent=2))
            else:
                headers = ['Domain Name']
                table = [[domain] for domain in rs.domain]
                return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))

        except KeeperApiError as e:
            error_code = e.result_code if hasattr(e, 'result_code') else 'Unknown'

            if DomainManagementHelper.is_feature_unavailable(error_code):
                result = DomainManagementHelper.handle_unavailable_feature(kwargs.get('format') or 'text')
                if result:
                    print(result)
                return

            logging.error(f'Error listing domains: {e}')
            raise


class ReserveDomainCommand(EnterpriseCommand):
    """Reserve, verify, or delete a domain for the enterprise."""

    ACTION_MAP = {
        'token': enterprise_pb2.DOMAIN_TOKEN,
        'add': enterprise_pb2.DOMAIN_ADD,
        'delete': enterprise_pb2.DOMAIN_DELETE,
    }

    def get_parser(self):
        return domain_reserve_parser

    def execute(self, params, **kwargs):
        action = kwargs.get('action')
        domain = kwargs.get('domain')
        output_format = kwargs.get('format', 'text')
        force = kwargs.get('force', False)

        if not self._validate_inputs(action, domain, output_format):
            return

        is_valid, domain, error_msg = DomainManagementHelper.validate_domain(domain)
        if not is_valid:
            DomainManagementHelper.output_error(error_msg, output_format, domain=domain or '', status='failed')
            return

        try:
            result = self._execute_action(params, action, domain, output_format, force=force)
            if result:
                return result

        except KeeperApiError as e:
            return self._handle_api_error(e, domain, action, output_format)

        except Exception as e:
            error_msg = f'Unexpected error: {str(e)}'
            DomainManagementHelper.output_error(error_msg, output_format, domain=domain, action=action)
            logging.debug(f'Exception details: {e}', exc_info=True)

    def _validate_inputs(self, action, domain, output_format):
        if not action:
            DomainManagementHelper.output_error('Action is required', output_format, status='failed')
            return False

        if action not in self.ACTION_MAP:
            DomainManagementHelper.output_error(
                f'Invalid action: {action}. Must be one of: {", ".join(self.ACTION_MAP.keys())}',
                output_format, status='failed',
            )
            return False

        if not domain:
            DomainManagementHelper.output_error('Domain is required', output_format, status='failed')
            return False

        return True

    def _execute_action(self, params, action, domain, output_format, force=False):
        if not action or not domain:
            DomainManagementHelper.output_error('Action and domain are required', output_format, status='failed')
            return

        rq = self._create_request(action, domain)

        if action == 'token':
            return self._handle_token_action(params, rq, domain, output_format)
        elif action == 'add':
            return self._handle_add_action(params, rq, domain, output_format)
        elif action == 'delete':
            return self._handle_delete_action(params, rq, domain, output_format, force=force)

    def _create_request(self, action, domain):
        rq = enterprise_pb2.ReserveDomainRequest()
        rq.reserveDomainAction = self.ACTION_MAP[action]
        rq.domain = domain
        return rq

    def _handle_token_action(self, params, rq, domain, output_format):
        rs = api.communicate_rest(
            params, rq, API_ENDPOINTS['reserve_domain'],
            rs_type=enterprise_pb2.ReserveDomainResponse,
        )

        if not rs or not hasattr(rs, 'token') or not rs.token:
            DomainManagementHelper.output_error(
                'Failed to generate token: empty response from server',
                output_format, domain=domain,
            )
            return

        if output_format == 'json':
            return json.dumps({'token': rs.token, 'domain': domain}, indent=2)

        self._display_token_instructions(domain, rs.token)

    def _handle_add_action(self, params, rq, domain, output_format):
        api.communicate_rest(params, rq, API_ENDPOINTS['reserve_domain'])

        if output_format == 'json':
            return json.dumps({
                'message': 'Domain successfully added to enterprise',
                'domain': domain,
                'action': 'add',
            }, indent=2)

        logging.info(f'Domain "{domain}" has been reserved for the enterprise')
        self._refresh_enterprise_data(params, 'added')

    def _handle_delete_action(self, params, rq, domain, output_format, force=False):
        if not force and output_format != 'json':
            domain_exists = self._check_domain_exists(params, domain)
            if domain_exists:
                confirm = input(
                    f'\n{bcolors.WARNING}Are you sure you want to delete domain "{domain}"? (y/n): {bcolors.ENDC}'
                )
                if confirm.lower() not in ['yes', 'y']:
                    logging.info('Domain deletion cancelled')
                    return

        api.communicate_rest(params, rq, API_ENDPOINTS['reserve_domain'])

        if output_format == 'json':
            return json.dumps({
                'message': 'Domain removed from enterprise',
                'domain': domain,
                'action': 'delete',
            }, indent=2)

        logging.info(f'Domain "{domain}" has been removed from the enterprise')
        self._refresh_enterprise_data(params, 'removed')

    def _check_domain_exists(self, params, domain):
        rs = api.communicate_rest(
            params, None, API_ENDPOINTS['list_domains'],
            rs_type=enterprise_pb2.ListDomainsResponse,
        )
        return domain in rs.domain if rs.domain else False

    def _display_token_instructions(self, domain, token):
        logging.info(f'\n{bcolors.OKGREEN}Token generated successfully!{bcolors.ENDC}\n')
        logging.info(f'Domain: {bcolors.BOLD}{domain}{bcolors.ENDC}')
        logging.info(f'Token:  {bcolors.BOLD}{token}{bcolors.ENDC}\n')
        logging.info('Next steps:')
        logging.info('1. Log into your domain registrar or DNS provider')
        logging.info(f'2. Add a TXT record for domain "{domain}" with value:')
        logging.info(f'   {bcolors.WARNING}{token}{bcolors.ENDC}')
        logging.info('3. Wait for DNS propagation (may take a few minutes)')
        logging.info(f'4. Run: domain reserve --action add --domain {domain}')

    def _refresh_enterprise_data(self, params, action_past_tense):
        try:
            api.query_enterprise(params)
        except Exception as refresh_error:
            logging.warning(
                f'Successfully {action_past_tense} domain but failed to refresh enterprise data: {refresh_error}'
            )

    def _handle_api_error(self, error, domain, action, output_format):
        error_code = error.result_code if hasattr(error, 'result_code') else 'Unknown'

        if DomainManagementHelper.is_feature_unavailable(error_code):
            result = DomainManagementHelper.handle_unavailable_feature(output_format)
            if result:
                return result
            return

        error_msg = DomainManagementHelper.get_error_message(error_code, domain, action)

        if output_format == 'json':
            return json.dumps({
                'message': error_msg,
                'domain': domain,
                'action': action,
            }, indent=2)

        logging.error(error_msg)
