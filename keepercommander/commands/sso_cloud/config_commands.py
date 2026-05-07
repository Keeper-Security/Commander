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

"""Configuration commands: get, set, validate, guide."""

import logging

from typing import Any

from ... import api
from ...error import CommandError
from ...proto import ssocloud_pb2 as ssocloud
from ..enterprise_common import EnterpriseCommand

from .parsers import (
    sso_cloud_get_parser, sso_cloud_set_parser,
    sso_cloud_validate_parser, sso_cloud_guide_parser,
)
from .mixin import SsoCloudMixin


class SsoCloudGetCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_get_parser

    def execute(self, params, **kwargs):
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']
        self.ensure_cloud_sso(svc, target)

        config_rs = self.get_selected_configuration(params, sp_id, config_target=kwargs.get('config'))
        self.dump_configuration(config_rs, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class SsoCloudGuideCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_guide_parser

    def execute(self, params, **kwargs):
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']
        self.ensure_cloud_sso(svc, target)

        config_rs = self.get_selected_configuration(params, sp_id, config_target=kwargs.get('config'))
        self.show_idp_guidance(config_rs, sp_name=svc.get('name', target))


class SsoCloudSetCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_set_parser

    def execute(self, params, **kwargs):
        # type: (Any, **Any) -> Any
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']
        self.ensure_cloud_sso(svc, target)

        settings_to_set = kwargs.get('setting') or []
        settings_to_reset = kwargs.get('reset') or []

        if not settings_to_set and not settings_to_reset:
            raise CommandError('sso-cloud', 'Provide at least one --set KEY=VALUE or --reset KEY argument.')

        config_rs = self.get_selected_configuration(params, sp_id, config_target=kwargs.get('config'))
        config_id = config_rs.ssoSpConfigurationId

        available_settings = {}
        for sv in config_rs.ssoCloudSettingValue:
            available_settings[sv.settingName.lower()] = sv

        rq = ssocloud.SsoCloudConfigurationRequest()
        rq.ssoServiceProviderId = sp_id
        rq.ssoSpConfigurationId = config_id

        for setting_str in settings_to_set:
            pos = setting_str.find('=')
            if pos < 1:
                raise CommandError('sso-cloud', f'Invalid setting format "{setting_str}". Expected KEY=VALUE.')

            key = setting_str[:pos].strip()
            value = setting_str[pos + 1:].strip()

            existing = available_settings.get(key.lower())
            if not existing:
                raise CommandError('sso-cloud', f'Unknown setting: "{key}". '
                                   f'Use "sso-cloud get" to see available settings.')
            if not existing.isEditable:
                raise CommandError('sso-cloud', f'Setting "{key}" is read-only.')

            action = ssocloud.SsoCloudSettingAction()
            action.settingName = existing.settingName
            action.operation = ssocloud.SET
            action.value = value
            rq.ssoCloudSettingAction.append(action)

        for key in settings_to_reset:
            existing = available_settings.get(key.strip().lower())
            if not existing:
                raise CommandError('sso-cloud', f'Unknown setting: "{key}".')
            if not existing.isEditable:
                raise CommandError('sso-cloud', f'Setting "{key}" is read-only.')

            action = ssocloud.SsoCloudSettingAction()
            action.settingName = existing.settingName
            action.operation = ssocloud.RESET_TO_DEFAULT
            rq.ssoCloudSettingAction.append(action)

        updated_rs = api.communicate_rest(
            params, rq, 'sso/config/sso_cloud_configuration_setting_set',
            rs_type=ssocloud.SsoCloudConfigurationResponse)

        logging.info('Configuration updated successfully.')
        self.dump_configuration(updated_rs)


class SsoCloudValidateCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_validate_parser

    def execute(self, params, **kwargs):
        # type: (Any, **Any) -> Any
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']
        self.ensure_cloud_sso(svc, target)

        config_rs = self.get_selected_configuration(params, sp_id, config_target=kwargs.get('config'))
        config_id = config_rs.ssoSpConfigurationId

        rq = ssocloud.SsoCloudConfigurationValidationRequest()
        rq.ssoSpConfigurationId.append(config_id)

        rs = api.communicate_rest(
            params, rq, 'sso/config/sso_cloud_configuration_validate',
            rs_type=ssocloud.SsoCloudConfigurationValidationResponse)

        all_valid = True
        for vc in rs.validationContent:
            if vc.isSuccessful:
                logging.info('Configuration "%s" (ID: %s) is valid.',
                             config_rs.name, vc.ssoSpConfigurationId)
            else:
                all_valid = False
                logging.warning('Configuration "%s" (ID: %s) has validation errors:',
                                config_rs.name, vc.ssoSpConfigurationId)
                for msg in vc.errorMessage:
                    logging.warning('  - %s', msg)

        if all_valid:
            logging.info('SSO Cloud configuration is ready for use.')
