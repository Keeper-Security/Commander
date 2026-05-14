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

"""SP lifecycle commands: list, config-list, create, delete."""

import logging

from typing import Any

from ... import api, crypto, utils
from ...error import CommandError
from ...params import KeeperParams
from ...proto import ssocloud_pb2 as ssocloud
from ..base import dump_report_data, field_to_title, user_choice
from ..enterprise_common import EnterpriseCommand

from .parsers import (
    sso_cloud_list_parser, sso_cloud_config_list_parser,
    sso_cloud_create_parser, sso_cloud_delete_parser,
)
from .constants import IDP_TYPE_NAMES, IDP_TYPE_NAME_TO_ENUM
from .mixin import SsoCloudMixin


class SsoCloudListCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_list_parser

    def execute(self, params, **kwargs):
        return self.dump_sso_services(params, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class SsoCloudConfigListCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_config_list_parser

    def execute(self, params, **kwargs):
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']

        list_rq = ssocloud.SsoCloudServiceProviderConfigurationListRequest()
        list_rq.ssoServiceProviderId = sp_id
        list_rs = api.communicate_rest(
            params, list_rq, 'sso/config/sso_cloud_sp_configuration_get',
            rs_type=ssocloud.SsoCloudServiceProviderConfigurationListResponse)

        table = []
        headers = ['config_id', 'name', 'is_selected']
        fmt = kwargs.get('format')
        if fmt and fmt != 'json':
            headers = [field_to_title(x) for x in headers]
        for item in list_rs.configurationItem:
            if item.ssoServiceProviderId and sp_id not in item.ssoServiceProviderId:
                continue
            table.append([item.ssoSpConfigurationId, item.name, item.isSelected])
        return dump_report_data(table, headers=headers, fmt=fmt, filename=kwargs.get('output'))


class SsoCloudCreateCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_create_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **Any) -> Any
        name = kwargs.get('name')
        if not name:
            logging.warning('"--name" option is required for "create" command')
            return

        node_name = kwargs.get('node')
        nodes = list(self.resolve_nodes(params, node_name))
        if len(nodes) == 0:
            raise CommandError('sso-cloud', f'Node "{node_name}" not found.')
        if len(nodes) > 1:
            raise CommandError('sso-cloud', f'Node name "{node_name}" is not unique. Use Node ID.')
        target_node = nodes[0]
        node_id = target_node['node_id']

        existing = params.enterprise.get('sso_services', [])
        for svc in existing:
            if svc.get('node_id') == node_id:
                raise CommandError('sso-cloud',
                                   f'Node already has an SSO service provider: '
                                   f'"{svc.get("name")}" (ID: {svc.get("sso_service_provider_id")})')

        tree_key = params.enterprise.get('unencrypted_tree_key')
        if not tree_key:
            raise CommandError('sso-cloud', 'Enterprise tree key not available. Ensure enterprise data is loaded.')

        sp_data_key = crypto.get_random_bytes(32)
        encrypted_sp_data_key = crypto.encrypt_aes_v1(sp_data_key, tree_key)

        rq = {
            'command': 'sso_service_provider_add',
            'sso_service_provider_id': self.get_enterprise_id(params),
            'node_id': node_id,
            'name': name,
            'sp_data_key': utils.base64_url_encode(encrypted_sp_data_key),
            'invite_new_users': True,
            'is_cloud': True,
        }
        rs = api.communicate(params, rq)
        sp_id = rs.get('sso_service_provider_id') or rq['sso_service_provider_id']
        logging.info('SSO Service Provider created: %s (ID: %s)', name, sp_id)

        config_name = kwargs.get('config_name') or 'Default'
        config_rq = ssocloud.SsoCloudConfigurationRequest()
        config_rq.ssoServiceProviderId = sp_id
        config_rq.name = config_name
        config_rq.ssoAuthProtocolType = ssocloud.SAML2

        config_rs = api.communicate_rest(
            params, config_rq, 'sso/config/sso_cloud_configuration_add',
            rs_type=ssocloud.SsoCloudConfigurationResponse)

        config_id = config_rs.ssoSpConfigurationId
        logging.info('SAML2 Configuration created: "%s" (ID: %s)', config_name, config_id)

        setting_rq = ssocloud.SsoCloudConfigurationRequest()
        setting_rq.ssoServiceProviderId = sp_id
        setting_rq.ssoSpConfigurationId = config_id

        idp_type_name = kwargs['idp_type']
        idp_type_enum = IDP_TYPE_NAME_TO_ENUM.get(idp_type_name.lower())
        if idp_type_enum is not None:
            action = ssocloud.SsoCloudSettingAction()
            action.settingName = 'sso_idp_type_id'
            action.operation = ssocloud.SET
            action.value = str(idp_type_enum)
            setting_rq.ssoCloudSettingAction.append(action)

        domain = kwargs.get('domain')
        if domain:
            action = ssocloud.SsoCloudSettingAction()
            action.settingName = 'sso_sp_domain'
            action.operation = ssocloud.SET
            action.value = domain
            setting_rq.ssoCloudSettingAction.append(action)

        if setting_rq.ssoCloudSettingAction:
            api.communicate_rest(
                params, setting_rq, 'sso/config/sso_cloud_configuration_setting_set',
                rs_type=ssocloud.SsoCloudConfigurationResponse)
            if idp_type_enum is not None:
                logging.info('IdP type set to: %s', IDP_TYPE_NAMES.get(idp_type_enum, idp_type_name))
            if domain:
                logging.info('Enterprise domain set to: %s', domain)

        api.query_enterprise(params, force=True)

        fmt = kwargs.get('format')
        if fmt == 'json':
            import json as json_mod
            result = {
                'sso_service_provider_id': sp_id,
                'name': name,
                'node_id': node_id,
                'config_id': config_id,
                'config_name': config_name,
                'idp_type': idp_type_name,
            }
            if domain:
                result['domain'] = domain
            try:
                config_rs = self.get_selected_configuration(params, sp_id)
                settings = {}
                for sv in config_rs.ssoCloudSettingValue:
                    settings[sv.settingName] = sv.value or ''
                result['settings'] = settings
            except Exception as e:
                logging.debug('Failed to fetch settings for JSON output: %s', e)
            print(json_mod.dumps(result, indent=2))
        else:
            logging.info('')
            logging.info('Next steps:')
            logging.info('  sso-cloud guide "%s"     View IdP-specific setup instructions', name)
            logging.info('  sso-cloud get "%s"       View configuration details & endpoints', name)


class SsoCloudDeleteCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_delete_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **Any) -> Any
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']
        sp_name = svc.get('name', target)
        self.ensure_cloud_sso(svc, target)

        config_target = kwargs.get('config')
        if config_target:
            self._delete_configuration(params, sp_id, config_target, kwargs.get('force'))
        else:
            self._delete_service_provider(params, sp_id, sp_name, kwargs.get('force'))

    @staticmethod
    def _delete_configuration(params, sp_id, config_target, force):
        # type: (KeeperParams, int, str, bool) -> None
        config_rs = SsoCloudMixin.get_selected_configuration(params, sp_id, config_target=config_target)
        config_id = config_rs.ssoSpConfigurationId
        config_name = config_rs.name

        if not force:
            answer = user_choice(
                f'Are you sure you want to delete configuration "{config_name}" (ID: {config_id})?',
                'yn', default='n')
            if answer.lower() != 'y':
                logging.info('Delete cancelled.')
                return

        rq = ssocloud.SsoCloudConfigurationRequest()
        rq.ssoServiceProviderId = sp_id
        rq.ssoSpConfigurationId = config_id

        api.communicate_rest(
            params, rq, 'sso/config/sso_cloud_configuration_delete',
            rs_type=ssocloud.SsoCloudConfigurationResponse)

        logging.info('Configuration "%s" (ID: %s) deleted.', config_name, config_id)
        api.query_enterprise(params, force=True)

    @staticmethod
    def _delete_service_provider(params, sp_id, sp_name, force):
        # type: (KeeperParams, int, str, bool) -> None
        if not force:
            answer = user_choice(
                f'Are you sure you want to delete SSO Service Provider "{sp_name}" (ID: {sp_id}) '
                f'and ALL its configurations?', 'yn', default='n')
            if answer.lower() != 'y':
                logging.info('Delete cancelled.')
                return

        rq = {
            'command': 'sso_service_provider_delete',
            'sso_service_provider_id': sp_id,
        }
        api.communicate(params, rq)

        logging.info('SSO Service Provider "%s" (ID: %s) deleted.', sp_name, sp_id)
        api.query_enterprise(params, force=True)
