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

import json
import logging
import re

from ...display import bcolors
from ...proto import enterprise_pb2
from ..base import dump_report_data
from .constants import (
    MAX_DOMAIN_LENGTH,
    MAX_LABEL_LENGTH,
    MIN_TLD_LENGTH,
    DOMAIN_PATTERN,
    NOTICE_MSG,
    ERROR_MESSAGES,
    ALIAS_ACCESS_DENIED_MSG,
    CREATE_ALIAS_STATUS_MESSAGES,
    DELETE_ALIAS_STATUS_MESSAGES,
)


class DomainManagementHelper:
    """Shared utilities for domain management commands.
    """

    MAX_DOMAIN_LENGTH = MAX_DOMAIN_LENGTH
    MAX_LABEL_LENGTH = MAX_LABEL_LENGTH
    MIN_TLD_LENGTH = MIN_TLD_LENGTH
    NOTICE_MSG = NOTICE_MSG
    DOMAIN_PATTERN = DOMAIN_PATTERN
    ERROR_MESSAGES = ERROR_MESSAGES
    ALIAS_ACCESS_DENIED_MSG = ALIAS_ACCESS_DENIED_MSG
    CREATE_ALIAS_STATUS_MESSAGES = CREATE_ALIAS_STATUS_MESSAGES
    DELETE_ALIAS_STATUS_MESSAGES = DELETE_ALIAS_STATUS_MESSAGES


    @staticmethod
    def get_error_code(e):
        """Return the result_code from a KeeperApiError, or 'Unknown' if absent."""
        return e.result_code if hasattr(e, 'result_code') else 'Unknown'

    @staticmethod
    def is_feature_unavailable(error_code):
        return error_code == 404 or error_code == '404' or error_code == 'invalid_path_or_method'

    @staticmethod
    def handle_unavailable_feature(output_format='text'):
        if output_format == 'json':
            notice_output = {
                'notice': DomainManagementHelper.NOTICE_MSG,
            }
            return json.dumps(notice_output, indent=2)
        else:
            logging.warning(f"{bcolors.WARNING}{DomainManagementHelper.NOTICE_MSG}{bcolors.ENDC}")
            return None

    @staticmethod
    def output_error(error_msg, output_format='text', **additional_fields):
        if output_format == 'json':
            error_output = {'error': error_msg}
            error_output.update(additional_fields)
            print(json.dumps(error_output, indent=2))
        else:
            logging.error(error_msg)

    @staticmethod
    def handle_invalid_subcommand(subcommand, output_format='text'):
        error_message = (
            f"Invalid subcommand: '{subcommand}'. "
            f"Use 'domain --help' for more information."
        )

        if output_format == 'json':
            error_output = {
                'error': error_message,
            }
            print(json.dumps(error_output, indent=2))
        else:
            logging.error(error_message)


    @staticmethod
    def validate_domain(domain):
        """Validate domain name format and requirements.

        Returns:
            tuple: (is_valid, normalized_domain, error_message_or_None)
        """
        if not domain:
            return False, None, 'Domain name is required'

        domain = domain.strip().lower()

        if not domain or len(domain) > DomainManagementHelper.MAX_DOMAIN_LENGTH:
            return (
                False, domain,
                f'Invalid domain name: must be between 1 and {DomainManagementHelper.MAX_DOMAIN_LENGTH} characters',
            )

        if not re.match(DomainManagementHelper.DOMAIN_PATTERN, domain):
            return False, domain, 'Invalid domain format: domain must contain only letters, numbers, hyphens, and dots'

        if '.' not in domain:
            return False, domain, 'Invalid domain: must contain at least one dot (e.g., example.com)'

        labels = domain.split('.')
        for label in labels:
            if len(label) > DomainManagementHelper.MAX_LABEL_LENGTH:
                return (
                    False, domain,
                    f'Invalid domain: label "{label}" exceeds {DomainManagementHelper.MAX_LABEL_LENGTH} characters',
                )

        if len(labels[-1]) < DomainManagementHelper.MIN_TLD_LENGTH:
            return (
                False, domain,
                f'Invalid domain: TLD must be at least {DomainManagementHelper.MIN_TLD_LENGTH} characters',
            )

        return True, domain, None

    @staticmethod
    def get_error_message(error_code, domain, action):
        """Get user-friendly error message using class constant dictionary."""
        if error_code == 'invalid_token' and action == 'add':
            return (
                f'Failed to verify domain "{domain}". Please ensure you have added the TXT '
                f'record with the correct token to your DNS settings and try again.'
            )

        if error_code in ('exists', 'domain_exists'):
            if action == 'token':
                return f'Domain "{domain}" already exists in the enterprise. Use action "delete" to remove it first.'
            elif action == 'add':
                return f'Domain "{domain}" already exists in the enterprise. It may have already been added successfully.'

        if error_code in ('not_exists', 'domain_not_found', 'doesnt_exist') and action == 'delete':
            return f'Domain "{domain}" does not exist. Use action "token" to start the domain reservation process.'

        message_template = DomainManagementHelper.ERROR_MESSAGES.get(error_code)
        if message_template:
            if '{domain}' in message_template:
                return message_template.format(domain=domain)
            return message_template

        return f'Unable to {action} domain "{domain}". Please try again or contact support if the issue persists.'


    @staticmethod
    def validate_aliases(domain, aliases, output_format):
        """Validate a list of alias names and check none equals the domain.

        Returns a list of normalized alias strings on success, or None if any
        validation fails (error is already reported via output_error).
        """
        normalized = []
        for alias_name in aliases:
            valid, normalized_alias, err = DomainManagementHelper.validate_domain(alias_name)
            if not valid:
                DomainManagementHelper.output_error(f'{err}', output_format)
                return None
            if normalized_alias == domain:
                DomainManagementHelper.output_error(
                    f'Alias cannot be the same as the domain ("{domain}").', output_format
                )
                return None
            normalized.append(normalized_alias)
        return normalized

    @staticmethod
    def build_alias_request(domain, normalized_aliases):
        """Build a DomainAliasRequest protobuf from a validated domain and alias list."""
        rq = enterprise_pb2.DomainAliasRequest()
        for alias in normalized_aliases:
            da = enterprise_pb2.DomainAlias()
            da.domain = domain
            da.alias = alias
            rq.domainAlias.append(da)
        return rq

    @staticmethod
    def render_alias_response(rs, output_format, kwargs, status_messages=None, action=None):
        """Render a DomainAliasResponse as text or JSON.

        When status_messages is None the response is treated as a listing
        (domain + alias only).  When provided, a simple message is shown per
        alias for text format, or a status object for JSON format.
        """
        if status_messages is not None:
            if output_format == 'json':
                results = [
                    {
                        'domain': da.domain,
                        'alias': da.alias,
                        'status': da.status,
                        'status_message': status_messages.get(da.status, f'Unknown status: {da.status}'),
                    }
                    for da in rs.domainAlias
                ]
                print(json.dumps(results, indent=2))
            else:
                for da in rs.domainAlias:
                    status_msg = status_messages.get(da.status, f'Unknown ({da.status})')
                    if da.status == 0:
                        if action == 'create':
                            logging.info(f"Created domain alias '{da.alias}' for domain '{da.domain}'")
                        elif action == 'delete':
                            logging.info(f"Deleted domain alias '{da.alias}' for domain '{da.domain}'")
                        else:
                            logging.info(f"Domain alias '{da.alias}' for domain '{da.domain}': {status_msg}")
                    else:
                        if action == 'delete':
                            logging.error(f"Failed to delete domain alias '{da.alias}' for domain '{da.domain}': {status_msg}")
                        elif action == 'create':
                            logging.error(f"Failed to create domain alias '{da.alias}' for domain '{da.domain}': {status_msg}")
                        else:
                            logging.error(f"Domain alias '{da.alias}' for domain '{da.domain}': {status_msg}")
        else:
            headers = ['Domain', 'Alias']
            table = [[da.domain, da.alias] for da in rs.domainAlias]
            return dump_report_data(table, headers, fmt=output_format, filename=kwargs.get('output'))

    @staticmethod
    def handle_alias_api_error(e, output_format, operation):
        """Shared KeeperApiError handler for alias commands."""
        error_code = DomainManagementHelper.get_error_code(e)

        if DomainManagementHelper.is_feature_unavailable(error_code):
            result = DomainManagementHelper.handle_unavailable_feature(output_format)
            if result:
                print(result)
            return

        if error_code == 'access_denied':
            DomainManagementHelper.output_error(
                DomainManagementHelper.ALIAS_ACCESS_DENIED_MSG, output_format
            )
            return

        logging.error(f'Error {operation} domain aliases: {e}')
        raise
