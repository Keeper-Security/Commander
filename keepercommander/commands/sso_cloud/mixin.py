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

import json
import logging

from typing import Optional, Dict

from ... import api
from ...error import CommandError
from ...params import KeeperParams
from ...proto import ssocloud_pb2 as ssocloud
from ..base import dump_report_data, field_to_title

from .constants import (
    IDP_TYPE_NAMES, IDP_ENUM_TO_KEY, SETTING_GROUPS,
    AUTH0_SAML_JSON_TEMPLATE, IDP_SETUP_GUIDANCE,
)


class SsoCloudMixin(object):
    @staticmethod
    def find_sso_service(params, target):
        # type: (KeeperParams, str) -> dict
        """Resolve an SSO service provider by ID or name from enterprise data."""
        if not target:
            raise CommandError('sso-cloud', 'SSO Service Provider name or ID is required.')

        sso_services = params.enterprise.get('sso_services', [])
        if not sso_services:
            raise CommandError('sso-cloud', 'No SSO Cloud service providers found in this enterprise.')

        try:
            target_id = int(target)
            for svc in sso_services:
                if svc.get('sso_service_provider_id') == target_id:
                    return svc
        except (ValueError, TypeError):
            logging.debug('Target "%s" is not numeric, searching by name.', target)

        target_lower = target.lower()
        matches = [s for s in sso_services if s.get('name', '').lower() == target_lower]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise CommandError('sso-cloud',
                               f'Multiple SSO service providers match "{target}". Use the SP ID instead.')

        raise CommandError('sso-cloud',
                           f'SSO Service Provider "{target}" not found. '
                           f'Run "ed -f" to refresh enterprise data, then "sso list" to verify.')

    @staticmethod
    def ensure_cloud_sso(svc, target=''):
        # type: (dict, str) -> None
        """Warn if the SP doesn't appear as Cloud SSO in cached enterprise data."""
        if not svc.get('is_cloud'):
            logging.debug('SSO Service Provider "%s" is_cloud flag is not set in enterprise cache. '
                          'Proceeding anyway — the server will enforce if invalid.',
                          svc.get('name', target))

    @staticmethod
    def get_node_name(params, node_id):
        # type: (KeeperParams, int) -> str
        """Resolve a node ID to its display name."""
        for node in params.enterprise.get('nodes', []):
            if node['node_id'] == node_id:
                if node.get('parent_id', 0) > 0:
                    return node['data'].get('displayname') or str(node_id)
                else:
                    return params.enterprise.get('enterprise_name', str(node_id))
        return str(node_id)

    @staticmethod
    def get_selected_configuration(params, sp_id, config_target=None):
        # type: (KeeperParams, int, Optional[str]) -> ssocloud.SsoCloudConfigurationResponse
        """Fetch the active or specified configuration for a service provider."""
        list_rq = ssocloud.SsoCloudServiceProviderConfigurationListRequest()
        list_rq.ssoServiceProviderId = sp_id
        list_rs = api.communicate_rest(
            params, list_rq, 'sso/config/sso_cloud_sp_configuration_get',
            rs_type=ssocloud.SsoCloudServiceProviderConfigurationListResponse)

        owned = [c for c in list_rs.configurationItem
                 if not c.ssoServiceProviderId or sp_id in c.ssoServiceProviderId]

        if not owned:
            raise CommandError('sso-cloud', f'No configurations found for SP ID {sp_id}.')

        config_item = None
        if config_target:
            try:
                config_id = int(config_target)
                config_item = next(
                    (c for c in owned if c.ssoSpConfigurationId == config_id), None)
            except ValueError:
                pass

            if not config_item:
                config_lower = config_target.lower()
                matches = [c for c in owned if c.name.lower() == config_lower]
                if len(matches) == 1:
                    config_item = matches[0]
                elif len(matches) > 1:
                    raise CommandError('sso-cloud',
                                       f'Multiple configurations match "{config_target}". Use Configuration ID.')

            if not config_item:
                raise CommandError('sso-cloud', f'Configuration "{config_target}" not found.')
        else:
            config_item = next((c for c in owned if c.isSelected), None)
            if not config_item:
                config_item = owned[0]

        get_rq = ssocloud.SsoCloudConfigurationRequest()
        get_rq.ssoServiceProviderId = sp_id
        get_rq.ssoSpConfigurationId = config_item.ssoSpConfigurationId
        return api.communicate_rest(
            params, get_rq, 'sso/config/sso_cloud_configuration_get',
            rs_type=ssocloud.SsoCloudConfigurationResponse)

    @staticmethod
    def format_setting_value(setting):
        # type: (ssocloud.SsoCloudSettingValue) -> str
        """Format a setting value for display, handling special cases."""
        value = setting.value or ''
        if setting.isFromFile:
            if value and len(value) > 80:
                return f'[{len(value)} bytes]'
        if setting.settingName == 'sso_idp_type_id':
            try:
                idp_type = int(value)
                return IDP_TYPE_NAMES.get(idp_type, f'Unknown ({value})')
            except (ValueError, TypeError):
                pass
        return value

    @staticmethod
    def _extract_sp_values(config_rs):
        # type: (ssocloud.SsoCloudConfigurationResponse) -> dict
        keys = ('sso_sp_entity_id', 'sso_sp_acs_endpoint', 'sso_sp_login_endpoint',
                'sso_sp_logout_endpoint', 'sso_sp_slo_endpoint',
                'sso_idp_initiated_login_endpoint', 'sso_sp_domain')
        result = {}
        for sv in config_rs.ssoCloudSettingValue:
            if sv.settingName in keys:
                result[sv.settingName] = sv.value or ''
        return result

    @staticmethod
    def _get_idp_type_name(config_rs):
        # type: (ssocloud.SsoCloudConfigurationResponse) -> Optional[str]
        for sv in config_rs.ssoCloudSettingValue:
            if sv.settingName == 'sso_idp_type_id' and sv.value:
                try:
                    return IDP_ENUM_TO_KEY.get(int(sv.value))
                except (ValueError, TypeError):
                    pass
        return None

    @staticmethod
    def show_idp_guidance(config_rs, sp_name=''):
        # type: (ssocloud.SsoCloudConfigurationResponse, str) -> None
        """Show IdP-specific setup guidance with formatted output."""
        idp_type_name = SsoCloudMixin._get_idp_type_name(config_rs)
        if not idp_type_name:
            return
        guidance = IDP_SETUP_GUIDANCE.get(idp_type_name)
        if not guidance:
            return

        sp = SsoCloudMixin._extract_sp_values(config_rs)
        portal = guidance['portal_name']
        display_name = sp_name or str(config_rs.ssoServiceProviderId)

        vals = {
            'name': display_name,
            'entity_id': sp.get('sso_sp_entity_id', ''),
            'acs_endpoint': sp.get('sso_sp_acs_endpoint', ''),
            'login_endpoint': sp.get('sso_sp_login_endpoint', ''),
            'idp_login_endpoint': sp.get('sso_idp_initiated_login_endpoint', ''),
            'slo_endpoint': sp.get('sso_sp_slo_endpoint', ''),
            'auth0_json': AUTH0_SAML_JSON_TEMPLATE.format(
                entity_id=sp.get('sso_sp_entity_id', '<ENTITY_ID>')),
        }

        BAR = '\u2500' * 60
        CMD_TAG = '[Commander]'
        IDP_TAG = f'[{portal}]'

        print('')
        print(f'{portal} SSO Setup Guide')
        print(BAR)
        print(guidance.get('portal_url', ''))
        print('')

        step_num = 0
        for kind, text in guidance['steps']:
            filled = text.format(**vals)

            if kind == 'value':
                print(f'   {filled}')
                print('')
            elif kind == 'json':
                for json_line in filled.splitlines():
                    print(f'   {json_line}')
                print('')
            elif kind == 'note':
                print(f'   * {filled}')
            elif kind == 'cmd':
                step_num += 1
                print(f'{step_num:>2}. {CMD_TAG}  My Vault> {filled}')
            else:
                step_num += 1
                print(f'{step_num:>2}. {IDP_TAG}  {filled}')

        print('')

    @staticmethod
    def dump_configuration(config_rs, fmt=None, filename=None):
        # type: (ssocloud.SsoCloudConfigurationResponse, Optional[str], Optional[str]) -> None
        """Display configuration details."""
        logging.info('')
        logging.info('{0:>40s}: {1}'.format('Service Provider ID', config_rs.ssoServiceProviderId))
        logging.info('{0:>40s}: {1}'.format('Configuration ID', config_rs.ssoSpConfigurationId))
        logging.info('{0:>40s}: {1}'.format('Configuration Name', config_rs.name))
        logging.info('{0:>40s}: {1}'.format('Protocol', config_rs.protocol))
        logging.info('{0:>40s}: {1}'.format('Last Modified', config_rs.lastModified))

        if fmt == 'json':
            settings_list = []
            for sv in config_rs.ssoCloudSettingValue:
                settings_list.append({
                    'setting_id': sv.settingId,
                    'setting_name': sv.settingName,
                    'label': sv.label,
                    'value': sv.value,
                    'editable': sv.isEditable,
                    'required': sv.isRequired,
                    'from_file': sv.isFromFile,
                    'last_modified': sv.lastModified,
                })
            output = json.dumps({
                'sso_service_provider_id': config_rs.ssoServiceProviderId,
                'sso_sp_configuration_id': config_rs.ssoSpConfigurationId,
                'name': config_rs.name,
                'protocol': config_rs.protocol,
                'last_modified': config_rs.lastModified,
                'settings': settings_list
            }, indent=2)
            if filename:
                try:
                    with open(filename, 'w') as f:
                        f.write(output)
                    logging.info('Output written to %s', filename)
                except IOError as e:
                    raise CommandError('sso-cloud', f'Failed to write output file "{filename}": {e}')
            else:
                print(output)
            return

        settings_by_name = {}  # type: Dict[str, ssocloud.SsoCloudSettingValue]
        for sv in config_rs.ssoCloudSettingValue:
            settings_by_name[sv.settingName] = sv

        for group_label, setting_names in SETTING_GROUPS.items():
            group_settings = [settings_by_name.get(name) for name in setting_names]
            group_settings = [s for s in group_settings if s is not None]
            if not group_settings:
                continue

            logging.info('')
            logging.info('  --- %s ---', group_label)
            for sv in group_settings:
                if sv.isFromFile and sv.value and len(sv.value) > 80:
                    display_value = f'[{len(sv.value)} bytes]'
                else:
                    display_value = SsoCloudMixin.format_setting_value(sv)

                editable_marker = '' if sv.isEditable else ' (read-only)'
                required_marker = ' *' if sv.isRequired else ''
                logging.info('{0:>40s}: {1}{2}{3}'.format(
                    sv.label or sv.settingName, display_value, required_marker, editable_marker))

        ungrouped_names = set()
        for group_names in SETTING_GROUPS.values():
            ungrouped_names.update(group_names)
        ungrouped = [sv for name, sv in settings_by_name.items() if name not in ungrouped_names]
        if ungrouped:
            logging.info('')
            logging.info('  --- Other Settings ---')
            for sv in ungrouped:
                display_value = SsoCloudMixin.format_setting_value(sv)
                logging.info('{0:>40s}: {1}'.format(sv.label or sv.settingName, display_value))

        logging.info('')

    @staticmethod
    def dump_sso_services(params, fmt=None, filename=None):
        # type: (KeeperParams, Optional[str], Optional[str]) -> None
        """Display all SSO service providers as a table."""
        sso_services = params.enterprise.get('sso_services', [])
        table = []
        headers = ['sp_id', 'name', 'node_id', 'node_name', 'active', 'is_cloud']
        if fmt and fmt != 'json':
            headers = [field_to_title(x) for x in headers]
        for svc in sso_services:
            sp_id = svc.get('sso_service_provider_id')
            name = svc.get('name', '')
            node_id = svc.get('node_id', 0)
            node_name = SsoCloudMixin.get_node_name(params, node_id) if node_id else 'N/A'
            active = svc.get('active', False)
            is_cloud = svc.get('is_cloud', False)
            table.append([sp_id, name, node_id, node_name, active, is_cloud])
        return dump_report_data(table, headers=headers, fmt=fmt, filename=filename)
