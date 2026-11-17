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

"""ServiceNow MID Server Docker service mode setup command."""

import argparse
from dataclasses import asdict

from ...commands.base import raise_parse_exception, suppress_exit
from ...error import CommandError
from ..config.service_config import ServiceConfig as RuntimeServiceConfig
from ..docker import (
    DockerComposeBuilder,
    DockerSetupConstants,
    DockerSetupPrinter,
    ServiceConfig as DockerServiceConfig,
    SetupResult,
)
from ..util.exceptions import ValidationError
from .integrations.command_policy import sanitize_commands
from .service_docker_setup import ServiceDockerSetupCommand


class ServiceNowSetupConstants:
    """Defaults and allowlist for service-now-app-setup."""
    DEFAULT_FOLDER_NAME = 'Commander Service Mode - ServiceNow'
    DEFAULT_APP_NAME = 'Commander Service Mode - ServiceNow KSM App'
    DEFAULT_RECORD_NAME = 'Commander Service Mode ServiceNow Config'
    DEFAULT_TIMEOUT = DockerSetupConstants.DEFAULT_TIMEOUT
    COMMANDER_SERVICE_NAME = 'commander-servicenow'
    COMMANDER_CONTAINER_NAME = 'keeper-service-servicenow'
    # Identifies this integration for runtime command allowlist enforcement.
    SERVICENOW_RECORD_ENV = 'SERVICENOW_RECORD'

    SERVICE_COMMANDS_LIST = (
        'ls', 'get', 'search', 'sync-down', 'list-sf', 'record-add', 'record-update',
        'nsf-record-add', 'nsf-record-update', 'nsf-share-record', 'nsf-share-folder',
        'share-folder', 'share-record', 'one-time-share', 'epm',
    )
    SERVICE_COMMANDS = ','.join(SERVICE_COMMANDS_LIST)


service_now_app_setup_parser = argparse.ArgumentParser(
    prog='service-now-app-setup',
    description=(
        'Automate Docker service mode setup for the ServiceNow MID Server '
        '(API v2 queue always enabled)'
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
service_now_app_setup_parser.add_argument(
    '--folder-name', dest='folder_name', type=str,
    default=ServiceNowSetupConstants.DEFAULT_FOLDER_NAME,
    help=f'Name for the shared folder '
         f'(default: "{ServiceNowSetupConstants.DEFAULT_FOLDER_NAME}")',
)
service_now_app_setup_parser.add_argument(
    '--app-name', dest='app_name', type=str,
    default=ServiceNowSetupConstants.DEFAULT_APP_NAME,
    help=f'Name for the secrets manager app '
         f'(default: "{ServiceNowSetupConstants.DEFAULT_APP_NAME}")',
)
service_now_app_setup_parser.add_argument(
    '--record-name', dest='record_name', type=str,
    default=ServiceNowSetupConstants.DEFAULT_RECORD_NAME,
    help=f'Name for the config record '
         f'(default: "{ServiceNowSetupConstants.DEFAULT_RECORD_NAME}")',
)
service_now_app_setup_parser.add_argument(
    '--config-path', dest='config_path', type=str,
    help='Path to config.json file (default: active session config file)',
)
service_now_app_setup_parser.add_argument(
    '--timeout', dest='timeout', type=str,
    default=ServiceNowSetupConstants.DEFAULT_TIMEOUT,
    help=f'Device timeout setting (default: {ServiceNowSetupConstants.DEFAULT_TIMEOUT})',
)
service_now_app_setup_parser.add_argument(
    '--skip-device-setup', dest='skip_device_setup', action='store_true',
    help='Skip device registration and setup if already configured',
)
service_now_app_setup_parser.error = raise_parse_exception
service_now_app_setup_parser.exit = suppress_exit


class ServiceNowAppSetupCommand(ServiceDockerSetupCommand):
    """service-docker-setup flow with ServiceNow defaults and fixed allowlist."""

    def get_parser(self):
        return service_now_app_setup_parser

    def execute(self, params, **kwargs):
        # setdefault covers programmatic execute() without argparse defaults.
        kwargs.setdefault('folder_name', ServiceNowSetupConstants.DEFAULT_FOLDER_NAME)
        kwargs.setdefault('app_name', ServiceNowSetupConstants.DEFAULT_APP_NAME)
        kwargs.setdefault('record_name', ServiceNowSetupConstants.DEFAULT_RECORD_NAME)
        kwargs.setdefault('timeout', ServiceNowSetupConstants.DEFAULT_TIMEOUT)
        # Fail closed before any setup; _get_commands_config re-validates locally.
        self._validate_service_now_commands(params)
        return super().execute(params, **kwargs)

    def _validate_service_now_commands(self, params) -> str:
        try:
            validated = RuntimeServiceConfig().validate_command_list(
                ServiceNowSetupConstants.SERVICE_COMMANDS, params
            )
        except ValidationError as e:
            raise CommandError(
                self.get_parser().prog,
                f'ServiceNow command allowlist validation failed: {e}',
            )
        return sanitize_commands(validated, ServiceNowSetupConstants.SERVICE_COMMANDS_LIST)

    def _get_commands_config(self, params) -> str:
        return self._validate_service_now_commands(params)

    def _get_queue_config(self) -> bool:
        return True

    def get_service_configuration(self, params) -> DockerServiceConfig:
        """Collect MID Server service settings without offering tunnel options."""
        DockerSetupPrinter.print_header("Service Mode Configuration")
        port = self._get_port_config()
        commands = self._get_commands_config(params)
        security_config = self._get_advanced_security_config()

        return DockerServiceConfig(
            port=port,
            commands=commands,
            queue_enabled=True,
            ngrok_enabled=False,
            ngrok_auth_token='',
            ngrok_custom_domain='',
            ngrok_public_url='',
            cloudflare_enabled=False,
            cloudflare_tunnel_token='',
            cloudflare_custom_domain='',
            cloudflare_public_url='',
            tailscale_enabled=False,
            tailscale_auth_key='',
            tailscale_advertise_tags='',
            tailscale_public_url='',
            allowed_ip=security_config['allowed_ip'],
            denied_ip=security_config['denied_ip'],
            rate_limit=security_config['rate_limit'],
            encryption_enabled=security_config['encryption_enabled'],
            encryption_key=security_config['encryption_key'],
            token_expiration=security_config['token_expiration'],
        )

    def generate_docker_compose_yaml(
        self, setup_result: SetupResult, config: DockerServiceConfig
    ) -> str:
        builder = DockerComposeBuilder(
            setup_result,
            asdict(config),
            commander_service_name=ServiceNowSetupConstants.COMMANDER_SERVICE_NAME,
            commander_container_name=ServiceNowSetupConstants.COMMANDER_CONTAINER_NAME,
            commander_environment={
                ServiceNowSetupConstants.SERVICENOW_RECORD_ENV: setup_result.record_uid
            },
        )
        return builder.build()

    def _print_next_steps(self, config: DockerServiceConfig, config_path: str) -> None:
        DockerSetupPrinter.print_common_deployment_steps(
            str(config.port),
            config_path,
            container_name=ServiceNowSetupConstants.COMMANDER_CONTAINER_NAME,
        )
        print()
