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
from dataclasses import asdict, dataclass

from ...commands.base import raise_parse_exception, suppress_exit
from ...display import bcolors
from ...error import CommandError
from ..config.service_config import ServiceConfig as RuntimeServiceConfig
from ..docker import (
    DockerComposeBuilder, DockerLoginMode,
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
    SERVICENOW_SERVICE_TYPE_ENV = 'SERVICENOW_SERVICE_TYPE'

    SERVICE_TYPE_WORKFLOW = 'workflow'
    SERVICE_TYPE_CMDB = 'cmdb'
    SERVICE_TYPE_BOTH = 'both'

    SERVICE_COMMANDS_LIST = (
        'ls', 'get', 'search', 'sync-down', 'list-sf', 'record-add', 'record-update',
        'nsf-record-add', 'nsf-record-update', 'nsf-share-record', 'nsf-share-folder',
        'share-folder', 'share-record', 'one-time-share', 'epm',
    )
    SERVICE_COMMANDS = ','.join(SERVICE_COMMANDS_LIST)
    CMDB_COMMANDS_LIST = ('whoami', 'pam')
    CMDB_COMMANDS = ','.join(CMDB_COMMANDS_LIST)
    BOTH_SERVICE_COMMANDS_LIST = SERVICE_COMMANDS_LIST + CMDB_COMMANDS_LIST
    BOTH_SERVICE_COMMANDS = ','.join(BOTH_SERVICE_COMMANDS_LIST)

    @classmethod
    def get_commands_list(cls, service_type: str):
        if service_type == cls.SERVICE_TYPE_WORKFLOW:
            return cls.SERVICE_COMMANDS_LIST
        if service_type == cls.SERVICE_TYPE_CMDB:
            return cls.CMDB_COMMANDS_LIST
        if service_type == cls.SERVICE_TYPE_BOTH:
            return cls.BOTH_SERVICE_COMMANDS_LIST
        raise ValueError(f'Unknown ServiceNow service type: {service_type}')


@dataclass
class ServiceNowDockerServiceConfig(DockerServiceConfig):
    """Docker configuration with the selected ServiceNow integration type."""

    service_type: str = ServiceNowSetupConstants.SERVICE_TYPE_WORKFLOW


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
ServiceDockerSetupCommand.add_login_flow_arguments(service_now_app_setup_parser)
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
        # Validate every command that may be selected before provisioning resources.
        # The selected service's narrower list is validated again after the prompt.
        self._validate_service_now_commands(
            params, ServiceNowSetupConstants.SERVICE_TYPE_BOTH
        )
        return super().execute(params, **kwargs)

    def _validate_service_now_commands(self, params, service_type: str) -> str:
        allowed_commands = ServiceNowSetupConstants.get_commands_list(service_type)
        command_list = ','.join(allowed_commands)
        try:
            validated = RuntimeServiceConfig().validate_command_list(
                command_list, params
            )
        except ValidationError as e:
            raise CommandError(
                self.get_parser().prog,
                f'ServiceNow command allowlist validation failed: {e}',
            )
        return sanitize_commands(validated, allowed_commands)

    def _get_commands_config(
        self, params, service_type: str = ServiceNowSetupConstants.SERVICE_TYPE_WORKFLOW
    ) -> str:
        return self._validate_service_now_commands(params, service_type)

    def _get_service_type(self) -> str:
        """Prompt for the ServiceNow service(s) this MID Server will support."""
        print(f"\n{bcolors.BOLD}ServiceNow Services:{bcolors.ENDC}")
        print("  Choose which ServiceNow integration this Commander service will support:")
        print("    1. ServiceNow Workflow")
        print("    2. ServiceNow CMDB")
        print("    3. Both Workflow and CMDB")

        selections = {
            '1': ServiceNowSetupConstants.SERVICE_TYPE_WORKFLOW,
            '2': ServiceNowSetupConstants.SERVICE_TYPE_CMDB,
            '3': ServiceNowSetupConstants.SERVICE_TYPE_BOTH,
        }
        while True:
            selection = input(
                f"{bcolors.OKBLUE}Selection [1-3]:{bcolors.ENDC} "
            ).strip()
            if selection in selections:
                return selections[selection]
            print(f"{bcolors.FAIL}Please enter 1, 2, or 3.{bcolors.ENDC}")

    def _get_queue_config(self) -> bool:
        return True

    def get_service_configuration(self, params) -> DockerServiceConfig:
        """Collect MID Server service settings without offering tunnel options."""
        DockerSetupPrinter.print_header("Service Mode Configuration")
        port = self._get_port_config()
        service_type = self._get_service_type()
        commands = self._get_commands_config(params, service_type)
        security_config = self._get_advanced_security_config()

        return ServiceNowDockerServiceConfig(
            port=port,
            commands=commands,
            service_type=service_type,
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
        # Default to Workflow when called with an older/general ServiceConfig.
        service_type = getattr(
            config, 'service_type', ServiceNowSetupConstants.SERVICE_TYPE_WORKFLOW
        )
        try:
            ServiceNowSetupConstants.get_commands_list(service_type)
        except ValueError as e:
            raise CommandError(self.get_parser().prog, str(e))

        docker_config = asdict(config)
        docker_config.pop('service_type', None)
        builder = DockerComposeBuilder(
            setup_result,
            docker_config,
            commander_service_name=ServiceNowSetupConstants.COMMANDER_SERVICE_NAME,
            commander_container_name=ServiceNowSetupConstants.COMMANDER_CONTAINER_NAME,
            commander_environment={
                ServiceNowSetupConstants.SERVICENOW_RECORD_ENV: setup_result.record_uid,
                ServiceNowSetupConstants.SERVICENOW_SERVICE_TYPE_ENV: service_type,
            },
        )
        return builder.build()

    def _print_next_steps(self, config: DockerServiceConfig, config_path: str,
                          setup_result: SetupResult = None) -> None:
        DockerSetupPrinter.print_common_deployment_steps(
            str(config.port),
            config_path,
            container_name=ServiceNowSetupConstants.COMMANDER_CONTAINER_NAME,
            login_mode=setup_result.login_mode if setup_result else DockerLoginMode.KSM,
            cleanup_paths=setup_result.cleanup_paths if setup_result else None,
        )
        print()
