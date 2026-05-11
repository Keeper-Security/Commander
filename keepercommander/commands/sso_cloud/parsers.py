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

import argparse

from ..base import report_output_parser
from .constants import IDP_TYPE_CHOICES

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
