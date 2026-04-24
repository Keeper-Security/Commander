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

import argparse
import logging
import os

from typing import Optional, Dict

import requests as http_requests

from .. import api, crypto, utils
from ..error import CommandError
from ..params import KeeperParams

from .base import GroupCommand, dump_report_data, report_output_parser, field_to_title, user_choice
from .enterprise_common import EnterpriseCommand

IDP_TYPE_CHOICES = [
    'generic', 'f5', 'google', 'okta', 'adfs', 'azure', 'onelogin', 'aws',
    'centrify', 'duo', 'ibm', 'jumpcloud', 'ping', 'pingone', 'rsa',
    'secureauth', 'thales', 'auth0', 'beyond', 'hypr', 'cas',
]

from ..proto import ssocloud_pb2 as ssocloud


# --- Parsers ---

sso_cloud_list_parser = argparse.ArgumentParser(
    prog='sso-cloud-list', description='List SSO Cloud service providers.', parents=[report_output_parser])

sso_cloud_get_parser = argparse.ArgumentParser(
    prog='sso-cloud-get', description='View SSO Cloud configuration details.')
sso_cloud_get_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_get_parser.add_argument(
    '--config', dest='config', action='store',
    help='Configuration ID or Name. Defaults to the active configuration.')
sso_cloud_get_parser.add_argument(
    '--format', dest='format', action='store', choices=['table', 'json'], default='table',
    help='Output format.')
sso_cloud_get_parser.add_argument(
    '--output', dest='output', action='store', help='Path to output file.')

sso_cloud_guide_parser = argparse.ArgumentParser(
    prog='sso-cloud-guide', description='Show IdP-specific setup guide for an SSO Cloud configuration.')
sso_cloud_guide_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_guide_parser.add_argument(
    '--config', dest='config', action='store',
    help='Configuration ID or Name. Defaults to the active configuration.')

sso_cloud_config_list_parser = argparse.ArgumentParser(
    prog='sso-cloud-config-list', description='List configurations for an SSO Cloud service provider.')
sso_cloud_config_list_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_config_list_parser.add_argument(
    '--format', dest='format', action='store', choices=['table', 'json'], default='table',
    help='Output format.')
sso_cloud_config_list_parser.add_argument(
    '--output', dest='output', action='store', help='Path to output file.')

sso_cloud_create_parser = argparse.ArgumentParser(
    prog='sso-cloud-create', description='Create a new SSO Cloud service provider and SAML2 configuration.')
sso_cloud_create_parser.add_argument('--name', dest='name', required=True, action='store',
                                     help='Name for the new SSO service provider.')
sso_cloud_create_parser.add_argument('--node', dest='node', required=True,
                                     help='Node Name or ID to create the SSO SP on.')
sso_cloud_create_parser.add_argument('--config-name', dest='config_name', action='store',
                                     default='Default',
                                     help='Name for the SAML2 configuration (default: "Default").')
sso_cloud_create_parser.add_argument('--domain', dest='domain', action='store',
                                     help='SSO Enterprise Domain (used for "Enterprise SSO Login").')
sso_cloud_create_parser.add_argument('--idp-type', dest='idp_type', action='store', required=True,
                                     choices=IDP_TYPE_CHOICES,
                                     help='Identity provider type.')
sso_cloud_create_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                                     default='table', help='Output format.')

sso_cloud_upload_parser = argparse.ArgumentParser(
    prog='sso-cloud-upload', description='Upload IdP metadata XML file to an SSO Cloud configuration.')
sso_cloud_upload_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_upload_parser.add_argument('--file', dest='file', required=True,
                                     help='Path to the IdP metadata XML file.')
sso_cloud_upload_parser.add_argument('--config', dest='config', action='store',
                                     help='Configuration ID or Name. Defaults to active configuration.')
sso_cloud_upload_parser.add_argument('--force-authn', dest='force_authn', action='store_true',
                                     help='Enable ForceAuthn (forces new IdP login session each time).')

sso_cloud_download_parser = argparse.ArgumentParser(
    prog='sso-cloud-download', description='Download Keeper SP metadata XML file.')
sso_cloud_download_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_download_parser.add_argument('--output', dest='output', action='store',
                                       help='Path to save the SP metadata XML file. Prints to stdout if omitted.')

sso_cloud_set_parser = argparse.ArgumentParser(
    prog='sso-cloud-set', description='Update SSO Cloud configuration settings.')
sso_cloud_set_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_set_parser.add_argument('--config', dest='config', action='store',
                                  help='Configuration ID or Name. Defaults to active configuration.')
sso_cloud_set_parser.add_argument('--set', dest='setting', metavar='KEY=VALUE', action='append',
                                  help='Set a configuration setting. Can be repeated.')
sso_cloud_set_parser.add_argument('--reset', dest='reset', metavar='KEY', action='append',
                                  help='Reset a setting to its default value. Can be repeated.')

sso_cloud_log_parser = argparse.ArgumentParser(
    prog='sso-cloud-log', description='View SAML log entries for an SSO Cloud service provider.')
sso_cloud_log_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_log_parser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                                  help='Show full SAML XML content for each entry.')
sso_cloud_log_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                                  default='table', help='Output format.')
sso_cloud_log_parser.add_argument('--output', dest='output', action='store', help='Path to output file.')

sso_cloud_log_clear_parser = argparse.ArgumentParser(
    prog='sso-cloud-log-clear', description='Clear SAML log entries for an SSO Cloud service provider.')
sso_cloud_log_clear_parser.add_argument('target', help='SSO Service Provider ID or Name.')

sso_cloud_delete_parser = argparse.ArgumentParser(
    prog='sso-cloud-delete', description='Delete an SSO Cloud service provider or a single configuration.')
sso_cloud_delete_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_delete_parser.add_argument('--config', dest='config', action='store',
                                     help='Configuration ID or Name to delete (only that config, not the SP).')
sso_cloud_delete_parser.add_argument('--force', '-f', dest='force', action='store_true',
                                     help='Delete without confirmation.')

sso_cloud_validate_parser = argparse.ArgumentParser(
    prog='sso-cloud-validate', description='Validate an SSO Cloud configuration.')
sso_cloud_validate_parser.add_argument('target', help='SSO Service Provider ID or Name.')
sso_cloud_validate_parser.add_argument('--config', dest='config', action='store',
                                       help='Configuration ID or Name. Defaults to active configuration.')

# Map of SsoIdpType enum values to human-readable names
IDP_TYPE_NAMES = {
    ssocloud.XX_UNUSED: 'Unused',
    ssocloud.GENERIC: 'Generic',
    ssocloud.F5: 'F5',
    ssocloud.GOOGLE: 'Google Workspace',
    ssocloud.OKTA: 'Okta',
    ssocloud.ADFS: 'Microsoft ADFS',
    ssocloud.AZURE: 'Entra ID (Azure AD)',
    ssocloud.ONELOGIN: 'OneLogin',
    ssocloud.AWS: 'Amazon AWS',
    ssocloud.CENTRIFY: 'Centrify',
    ssocloud.DUO: 'Duo SSO',
    ssocloud.IBM: 'IBM',
    ssocloud.JUMPCLOUD: 'JumpCloud',
    ssocloud.PING: 'Ping Identity',
    ssocloud.PINGONE: 'PingOne',
    ssocloud.RSA: 'RSA SecurID Access',
    ssocloud.SECUREAUTH: 'SecureAuth',
    ssocloud.THALES: 'Thales',
    ssocloud.AUTH0: 'Auth0',
    ssocloud.BEYOND: 'BeyondTrust',
    ssocloud.HYPR: 'HYPR',
    ssocloud.PUREID: 'PureID',
    ssocloud.SDO: 'SDO',
    ssocloud.TRAIT: 'Trait',
    ssocloud.TRANSMIT: 'Transmit',
    ssocloud.TRUSONA: 'Trusona',
    ssocloud.VERIDIUM: 'Veridium',
    ssocloud.CAS: 'CAS',
}

SETTING_GROUPS = {
    'Service Provider': [
        'sso_sp_entity_id',
        'sso_sp_domain',
        'sso_sp_login_endpoint',
        'sso_sp_logout_endpoint',
        'sso_sp_acs_endpoint',
        'sso_sp_slo_endpoint',
    ],
    'Identity Provider': [
        'sso_idp_type_id',
        'sso_idp_entity_id',
        'sso_idp_sso_post_endpoint',
        'sso_idp_sso_redirect_endpoint',
        'sso_idp_slo_post_endpoint',
        'sso_idp_slo_redirect_endpoint',
        'sso_idp_initiated_login_endpoint',
        'sso_idp_passive_mode',
        'sso_idp_force_login_mode',
    ],
    'Attribute Mapping': [
        'sso_attribute_map_first_name',
        'sso_attribute_map_last_name',
        'sso_attribute_map_email',
        'sso_attribute_map_alias',
    ],
    'Options': [
        'sso_invite_new_users',
        'sso_login_method_preference',
        'sso_logout_method_preference',
        'sso_sign_messages',
    ],
    'Metadata & Certificates': [
        'sso_idp_metadata',
        'sso_idp_metadata_filename',
        'sso_idp_metadata_signing_key_description',
        'sso_idp_metadata_signing_key_is_expiring',
        'sso_signing_keypair',
        'sso_signing_keypair_filename',
        'sso_signing_keypair_description',
        'sso_signing_keypair_is_expiring',
    ],
}


def register_commands(commands):
    commands['sso-cloud'] = SsoCloudCommand()


def register_command_info(aliases, command_info):
    command_info['sso-cloud'] = 'Manage SSO Cloud Connect service providers and configurations'
    aliases['sso'] = 'sso-cloud'


class SsoCloudCommand(GroupCommand):
    def __init__(self):
        super(SsoCloudCommand, self).__init__()
        self.register_command('create', SsoCloudCreateCommand(),
                              'Create a new SSO Cloud service provider and configuration.')
        self.register_command('get', SsoCloudGetCommand(), 'View SSO Cloud configuration details.')
        self.register_command('guide', SsoCloudGuideCommand(),
                              'Show IdP-specific setup guide.')
        self.register_command('list', SsoCloudListCommand(), 'List SSO Cloud service providers.')
        self.register_command('config-list', SsoCloudConfigListCommand(),
                              'List configurations for an SSO service provider.')
        self.register_command('upload', SsoCloudUploadMetadataCommand(),
                              'Upload IdP metadata XML to an SSO configuration.')
        self.register_command('download', SsoCloudDownloadMetadataCommand(),
                              'Download Keeper SP metadata XML.')
        self.register_command('set', SsoCloudSetCommand(),
                              'Update SSO configuration settings.')
        self.register_command('validate', SsoCloudValidateCommand(),
                              'Validate an SSO configuration.')
        self.register_command('delete', SsoCloudDeleteCommand(),
                              'Delete an SSO configuration.')
        self.register_command('log', SsoCloudLogCommand(),
                              'View SAML log entries.')
        self.register_command('log-clear', SsoCloudLogClearCommand(),
                              'Clear SAML log entries.')
        self.default_verb = 'list'


AUTH0_SAML_JSON_TEMPLATE = """\
{{
  "audience": "{entity_id}",
  "mappings": {{
    "email": "Email",
    "given_name": "First",
    "family_name": "Last"
  }},
  "createUpnClaim": false,
  "passthroughClaimsWithNoMapping": false,
  "mapUnknownClaimsAsIs": false,
  "mapIdentities": false,
  "nameIdentifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "nameIdentifierProbes": [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
  ]
}}"""

IDP_SETUP_GUIDANCE = {
    'auth0': {
        'portal_name': 'Auth0',
        'portal_url': 'https://manage.auth0.com',
        'steps': [
            ('idp',   'Go to Applications > Create Application > Regular Web App'),
            ('idp',   'Enable Addons > SAML2 WEB APP'),
            ('idp',   'In the Usage tab > Download IdP Metadata XML'),
            ('idp',   'In the Settings tab > paste the ACS Endpoint into "Application Callback URL":'),
            ('value', '{acs_endpoint}'),
            ('idp',   'Replace the Settings editor JSON with the below (Entity ID pre-filled in audience):'),
            ('json',  '{auth0_json}'),
            ('idp',   'Click "Debug" to verify, then Save'),
            ('cmd',   'sso-cloud upload "{name}" --file <downloaded-metadata.xml>'),
        ],
    },
    'azure': {
        'portal_name': 'Azure Entra ID',
        'portal_url': 'https://portal.azure.com',
        'steps': [
            ('cmd',   'sso-cloud download "{name}" --output sp-metadata.xml'),
            ('idp',   'In Azure portal, navigate to Microsoft Entra ID'),
            ('idp',   'Go to Enterprise Applications > New Application'),
            ('idp',   'Search "Keeper Password Manager" > Create'),
            ('idp',   'Go to Set up Single sign-on > SAML'),
            ('idp',   'Click "Upload metadata file" and upload sp-metadata.xml'),
            ('note',  'Azure auto-fills Entity ID and Reply URL from the metadata'),
            ('idp',   'Paste the IdP Initiated Login Endpoint into "Sign on URL":'),
            ('value', '{idp_login_endpoint}'),
            ('idp',   'Save the Basic SAML Configuration'),
            ('idp',   'Click on "No, I\'ll test later" when asked for the test SSO login'),
            ('idp',   'In Attributes & Claims card> Edit: delete the 4 extra Additional Claims'),
            ('note',  'Verify: NameID/Email = user.userprincipalname (or user.mail)'),
            ('idp',   'Reload page, under SAML Signing Certificate > Download "Federation Metadata XML"'),
            ('cmd',   'sso-cloud upload "{name}" --file <federation-metadata.xml> --force-authn'),
        ],
    },
    'okta': {
        'portal_name': 'Okta',
        'portal_url': 'https://login.okta.com',
        'steps': [
            ('idp',   'Go to Applications > Create App Integration > SAML 2.0'),
            ('idp',   'Paste the ACS Endpoint into "Single sign-on URL":'),
            ('value', '{acs_endpoint}'),
            ('idp',   'Paste the Entity ID into "Audience URI (SP Entity ID)":'),
            ('value', '{entity_id}'),
            ('idp',   'Set Name ID format to EmailAddress'),
            ('idp',   'Add attribute statements: Email, First, Last'),
            ('idp',   'Finish, then go to Sign On tab > Download IdP Metadata'),
            ('cmd',   'sso-cloud upload "{name}" --file <metadata.xml>'),
        ],
    },
    'google': {
        'portal_name': 'Google Workspace',
        'portal_url': 'https://admin.google.com',
        'steps': [
            ('idp',   'Go to Apps > Web and mobile apps > Add App > Add custom SAML app'),
            ('idp',   'Download IdP Metadata from the Google IdP Information step'),
            ('idp',   'Paste the ACS Endpoint into "ACS URL":'),
            ('value', '{acs_endpoint}'),
            ('idp',   'Paste the Entity ID into "Entity ID":'),
            ('value', '{entity_id}'),
            ('idp',   'Set Name ID format to EMAIL'),
            ('idp',   'Add attribute mappings for email, first name, last name'),
            ('cmd',   'sso-cloud upload "{name}" --file <google-idp-metadata.xml>'),
        ],
    },
    'jumpcloud': {
        'portal_name': 'JumpCloud',
        'portal_url': 'https://console.jumpcloud.com',
        'steps': [
            ('idp',   'Go to SSO Applications > Add New Application > Custom SAML App'),
            ('idp',   'Paste the ACS Endpoint into "ACS URL":'),
            ('value', '{acs_endpoint}'),
            ('idp',   'Paste the Entity ID into "SP Entity ID":'),
            ('value', '{entity_id}'),
            ('idp',   'Set SAMLSubject NameID to email'),
            ('idp',   'Add attribute mappings for email, first name, last name'),
            ('idp',   'Activate the application, then download IdP Metadata'),
            ('cmd',   'sso-cloud upload "{name}" --file <metadata.xml>'),
        ],
    },
}

IDP_TYPE_NAME_TO_ENUM = {
    'generic': ssocloud.GENERIC,
    'f5': ssocloud.F5,
    'google': ssocloud.GOOGLE,
    'okta': ssocloud.OKTA,
    'adfs': ssocloud.ADFS,
    'azure': ssocloud.AZURE,
    'onelogin': ssocloud.ONELOGIN,
    'aws': ssocloud.AWS,
    'centrify': ssocloud.CENTRIFY,
    'duo': ssocloud.DUO,
    'ibm': ssocloud.IBM,
    'jumpcloud': ssocloud.JUMPCLOUD,
    'ping': ssocloud.PING,
    'pingone': ssocloud.PINGONE,
    'rsa': ssocloud.RSA,
    'secureauth': ssocloud.SECUREAUTH,
    'thales': ssocloud.THALES,
    'auth0': ssocloud.AUTH0,
    'beyond': ssocloud.BEYOND,
    'hypr': ssocloud.HYPR,
    'cas': ssocloud.CAS,
}

IDP_ENUM_TO_KEY = {v: k for k, v in IDP_TYPE_NAME_TO_ENUM.items()}


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
        except ValueError:
            pass

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
            filename_setting = setting.settingName + '_filename'
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

        BAR = '─' * 60
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
            import json
            output = json.dumps({
                'sso_service_provider_id': config_rs.ssoServiceProviderId,
                'sso_sp_configuration_id': config_rs.ssoSpConfigurationId,
                'name': config_rs.name,
                'protocol': config_rs.protocol,
                'last_modified': config_rs.lastModified,
                'settings': settings_list
            }, indent=2)
            if filename:
                with open(filename, 'w') as f:
                    f.write(output)
                logging.info('Output written to %s', filename)
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
            node_name = SsoCloudMixin.get_node_name(params, node_id)
            active = svc.get('active', False)
            is_cloud = svc.get('is_cloud', False)
            table.append([sp_id, name, node_id, node_name, active, is_cloud])
        return dump_report_data(table, headers=headers, fmt=fmt, filename=filename)


class SsoCloudListCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_list_parser

    def execute(self, params, **kwargs):
        return self.dump_sso_services(params, fmt=kwargs.get('format'), filename=kwargs.get('output'))


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
        # type: (KeeperParams, **any) -> any
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

        # Step 1: Create SSO service provider via legacy JSON v2 API
        sp_data_key = crypto.get_random_bytes(32)
        encrypted_sp_data_key = crypto.encrypt_aes_v1(sp_data_key, params.enterprise['unencrypted_tree_key'])

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

        # Step 2: Create SAML2 configuration via protobuf REST API
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

        # Step 3: Set initial configuration settings (IdP type, domain)
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

        # Refresh enterprise data to pick up the new SP
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
            except Exception:
                pass
            print(json_mod.dumps(result, indent=2))
        else:
            logging.info('')
            logging.info('Next steps:')
            logging.info('  sso-cloud guide "%s"     View IdP-specific setup instructions', name)
            logging.info('  sso-cloud get "%s"       View configuration details & endpoints', name)


class SsoCloudUploadMetadataCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_upload_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **any) -> any
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
        # type: (KeeperParams, **any) -> any
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
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(xml_content)
            logging.info('SP metadata saved to: %s', output_path)
        else:
            print(xml_content)


class SsoCloudSetCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_set_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **any) -> any
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
        # type: (KeeperParams, **any) -> any
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


class SsoCloudDeleteCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_delete_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **any) -> any
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


class SsoCloudLogCommand(EnterpriseCommand, SsoCloudMixin):
    def get_parser(self):
        return sso_cloud_log_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **any) -> any
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
            import json
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
                with open(os.path.expanduser(output_path), 'w') as f:
                    f.write(output)
                logging.info('Log output written to %s', output_path)
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
        # type: (KeeperParams, **any) -> any
        target = kwargs.get('target')
        svc = self.find_sso_service(params, target)
        sp_id = svc['sso_service_provider_id']

        rq = ssocloud.SsoCloudSAMLLogRequest()
        rq.ssoServiceProviderId = sp_id

        api.communicate_rest(
            params, rq, 'sso/config/sso_cloud_log_saml_clear',
            rs_type=ssocloud.SsoCloudSAMLLogResponse)

        logging.info('SAML log entries cleared for SP "%s".', svc.get('name', target))
