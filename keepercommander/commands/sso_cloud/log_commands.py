#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""SAML log commands: log, log-clear."""

import json
import logging
import os

from typing import Any

from ... import api
from ...error import CommandError
from ...proto import ssocloud_pb2 as ssocloud
from ..base import dump_report_data
from ..enterprise_common import EnterpriseCommand

from .parsers import sso_cloud_log_parser, sso_cloud_log_clear_parser
from .mixin import SsoCloudMixin


class SsoCloudLogCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_log_parser

    def execute(self, params, **kwargs):
        # type: (Any, **Any) -> Any
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']

        rq = ssocloud.SsoCloudSAMLLogRequest()
        rq.ssoServiceProviderId = sp_id

        rs = api.communicate_rest(
            params, rq, 'sso/config/sso_cloud_log_saml_get',
            rs_type=ssocloud.SsoCloudSAMLLogResponse)

        if not rs.entry:
            logging.info('No SAML log entries found for SP "%s".', svc.get('name', target))
            return

        fmt = kwargs.get('format')
        verbose = kwargs.get('verbose', False)

        if fmt == 'json':
            entries = []
            for entry in rs.entry:
                e = {
                    'server_time': entry.serverTime,
                    'direction': entry.direction,
                    'message_type': entry.messageType,
                    'message_issued': entry.messageIssued,
                    'from_entity_id': entry.fromEntityId,
                    'saml_status': entry.samlStatus,
                    'is_signed': entry.isSigned,
                    'is_ok': entry.isOK,
                }
                if verbose:
                    e['relay_state'] = entry.relayState
                    e['saml_content'] = entry.samlContent
                entries.append(e)
            output = json.dumps(entries, indent=2)
            output_path = kwargs.get('output')
            if output_path:
                try:
                    with open(os.path.expanduser(output_path), 'w') as f:
                        f.write(output)
                    logging.info('Log output written to %s', output_path)
                except IOError as e:
                    raise CommandError('sso-cloud', f'Failed to write log output file "{output_path}": {e}')
            else:
                print(output)
            return

        table = []
        headers = ['time', 'direction', 'type', 'status', 'signed', 'ok']
        if verbose:
            headers.append('from_entity')
        for entry in rs.entry:
            row = [
                entry.serverTime,
                entry.direction,
                entry.messageType,
                entry.samlStatus,
                'Yes' if entry.isSigned else 'No',
                'Yes' if entry.isOK else 'No',
            ]
            if verbose:
                row.append(entry.fromEntityId)
            table.append(row)

        dump_report_data(table, headers=headers, fmt=fmt, filename=kwargs.get('output'))

        if verbose:
            logging.info('')
            for i, entry in enumerate(rs.entry):
                logging.info('--- Entry %d: %s %s ---', i + 1, entry.direction, entry.messageType)
                if entry.relayState:
                    logging.info('Relay State: %s', entry.relayState)
                if entry.samlContent:
                    logging.info('SAML Content:\n%s', entry.samlContent)
                logging.info('')


class SsoCloudLogClearCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_log_clear_parser

    def execute(self, params, **kwargs):
        # type: (Any, **Any) -> Any
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']

        rq = ssocloud.SsoCloudSAMLLogRequest()
        rq.ssoServiceProviderId = sp_id

        api.communicate_rest(
            params, rq, 'sso/config/sso_cloud_log_saml_clear',
            rs_type=ssocloud.SsoCloudSAMLLogResponse)

        logging.info('SAML log entries cleared for SP "%s".', svc.get('name', target))
