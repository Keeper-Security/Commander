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

"""SAML metadata exchange commands: upload, download."""

import logging
import os

from typing import Any

import requests as http_requests

from ... import api
from ...error import CommandError
from ...params import KeeperParams
from ...proto import ssocloud_pb2 as ssocloud
from ..enterprise_common import EnterpriseCommand

from .parsers import sso_cloud_upload_parser, sso_cloud_download_parser
from .mixin import SsoCloudMixin


class SsoCloudUploadMetadataCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_upload_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **Any) -> Any
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']
        self.ensure_cloud_sso(svc, target)

        filepath = kwargs.get('file', '')
        filepath = os.path.expanduser(filepath)
        if not os.path.isfile(filepath):
            raise CommandError('sso-cloud', f'File not found: "{filepath}"')

        with open(filepath, 'rb') as f:
            file_content = f.read()

        filename = os.path.basename(filepath)

        config_rs = self.get_selected_configuration(params, sp_id, config_target=kwargs.get('config'))
        config_id = config_rs.ssoSpConfigurationId

        rq = ssocloud.SsoCloudIdpMetadataRequest()
        rq.ssoSpConfigurationId = config_id
        rq.filename = filename
        rq.content = file_content

        rs = api.communicate_rest(
            params, rq, 'sso/config/sso_cloud_upload_idp_metadata',
            rs_type=ssocloud.SsoCloudConfigurationValidationResponse)

        has_errors = False
        for vc in rs.validationContent:
            if vc.isSuccessful:
                logging.info('IdP metadata uploaded and validated successfully for configuration %s.',
                             vc.ssoSpConfigurationId)
            else:
                has_errors = True
                logging.warning('Validation errors for configuration %s:', vc.ssoSpConfigurationId)
                for msg in vc.errorMessage:
                    logging.warning('  - %s', msg)

        if not has_errors:
            logging.info('File "%s" uploaded to configuration "%s" (ID: %s).',
                         filename, config_rs.name, config_id)

        if kwargs.get('force_authn'):
            setting_rq = ssocloud.SsoCloudConfigurationRequest()
            setting_rq.ssoServiceProviderId = sp_id
            setting_rq.ssoSpConfigurationId = config_id
            action = ssocloud.SsoCloudSettingAction()
            action.settingName = 'sso_idp_force_login_mode'
            action.operation = ssocloud.SET
            action.value = 'true'
            setting_rq.ssoCloudSettingAction.append(action)
            api.communicate_rest(
                params, setting_rq, 'sso/config/sso_cloud_configuration_setting_set',
                rs_type=ssocloud.SsoCloudConfigurationResponse)
            logging.info('ForceAuthn enabled.')


class SsoCloudDownloadMetadataCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_download_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **Any) -> Any
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']
        self.ensure_cloud_sso(svc, target)

        server_base = params.rest_context.server_base
        if not server_base.endswith('/'):
            server_base += '/'
        metadata_url = f'{server_base}sso/saml/metadata/{sp_id}'

        rs = http_requests.get(metadata_url, timeout=30)
        if rs.status_code != 200:
            raise CommandError('sso-cloud',
                               f'Failed to download SP metadata (HTTP {rs.status_code}): {rs.text[:200]}')

        xml_content = rs.text
        output_path = kwargs.get('output')
        if output_path:
            output_path = os.path.expanduser(output_path)
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(xml_content)
                logging.info('SP metadata saved to: %s', output_path)
            except IOError as e:
                raise CommandError('sso-cloud', f'Failed to write metadata file "{output_path}": {e}')
        else:
            print(xml_content)
