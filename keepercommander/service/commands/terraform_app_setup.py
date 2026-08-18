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

"""Terraform provider Docker service mode setup command."""

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
from ..decorators.min_commander_version import TERRAFORM_DOCKER_ENV
from ..util.exceptions import ValidationError
from .service_docker_setup import ServiceDockerSetupCommand


class TerraformSetupConstants:
    """Defaults and allowlist for terraform-app-setup."""
    DEFAULT_FOLDER_NAME = 'Commander Service Mode - Terraform'
    DEFAULT_APP_NAME = 'Commander Service Mode - Terraform KSM App'
    DEFAULT_RECORD_NAME = 'Commander Service Mode Terraform Config'
    DEFAULT_TIMEOUT = DockerSetupConstants.DEFAULT_TIMEOUT
    COMMANDER_SERVICE_NAME = 'commander-terraform'
    COMMANDER_CONTAINER_NAME = 'keeper-service-terraform'

    SERVICE_COMMANDS_LIST = (
        'this-device', 'sync-down', 'switch-to-mc', 'switch-to-msp',
        'msp-add', 'msp-down', 'msp-info', 'msp-remove', 'msp-update',
        'enterprise-info', 'enterprise-node', 'enterprise-user', 'enterprise-role',
        'enterprise-team', 'enterprise-down', 'enterprise-push', 'team-approve',
        'record-add', 'record-update', 'rm', 'get', 'list', 'record-type-info',
        'share-folder', 'rmdir', 'rndir', 'mkdir', 'epm', 'scim', 'mv', 'pam',
        'secrets-manager', 'ln', 'share-record',
        'nsf-mkdir', 'nsf-get', 'nsf-rmdir', 'nsf-record-add', 'nsf-record-update',
        'nsf-rm', 'nsf-rndir', 'nsf-share-folder', 'nsf-share-record', 'nsf-ln',
    )
    SERVICE_COMMANDS = ','.join(SERVICE_COMMANDS_LIST)


terraform_app_setup_parser = argparse.ArgumentParser(
    prog='terraform-app-setup',
    description=(
        'Automate Docker service mode setup for the Terraform provider '
        '(API v2 queue always enabled)'
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
terraform_app_setup_parser.add_argument(
    '--folder-name', dest='folder_name', type=str,
    default=TerraformSetupConstants.DEFAULT_FOLDER_NAME,
    help=f'Name for the shared folder '
         f'(default: "{TerraformSetupConstants.DEFAULT_FOLDER_NAME}")',
)
terraform_app_setup_parser.add_argument(
    '--app-name', dest='app_name', type=str,
    default=TerraformSetupConstants.DEFAULT_APP_NAME,
    help=f'Name for the secrets manager app '
         f'(default: "{TerraformSetupConstants.DEFAULT_APP_NAME}")',
)
terraform_app_setup_parser.add_argument(
    '--record-name', dest='record_name', type=str,
    default=TerraformSetupConstants.DEFAULT_RECORD_NAME,
    help=f'Name for the config record '
         f'(default: "{TerraformSetupConstants.DEFAULT_RECORD_NAME}")',
)
terraform_app_setup_parser.add_argument(
    '--config-path', dest='config_path', type=str,
    help='Path to config.json file (default: active session config file)',
)
terraform_app_setup_parser.add_argument(
    '--timeout', dest='timeout', type=str,
    default=TerraformSetupConstants.DEFAULT_TIMEOUT,
    help=f'Device timeout setting (default: {TerraformSetupConstants.DEFAULT_TIMEOUT})',
)
terraform_app_setup_parser.add_argument(
    '--skip-device-setup', dest='skip_device_setup', action='store_true',
    help='Skip device registration and setup if already configured',
)
terraform_app_setup_parser.error = raise_parse_exception
terraform_app_setup_parser.exit = suppress_exit


class TerraformAppSetupCommand(ServiceDockerSetupCommand):
    """service-docker-setup flow with Terraform defaults: always queue, fixed allowlist."""

    def get_parser(self):
        return terraform_app_setup_parser

    def execute(self, params, **kwargs):
        # setdefault covers programmatic execute() without argparse defaults.
        kwargs.setdefault('folder_name', TerraformSetupConstants.DEFAULT_FOLDER_NAME)
        kwargs.setdefault('app_name', TerraformSetupConstants.DEFAULT_APP_NAME)
        kwargs.setdefault('record_name', TerraformSetupConstants.DEFAULT_RECORD_NAME)
        kwargs.setdefault('timeout', TerraformSetupConstants.DEFAULT_TIMEOUT)
        # Fail closed before any setup; _get_commands_config re-validates locally.
        self._validate_terraform_commands(params)
        return super().execute(params, **kwargs)

    def _validate_terraform_commands(self, params) -> str:
        try:
            return RuntimeServiceConfig().validate_command_list(
                TerraformSetupConstants.SERVICE_COMMANDS, params
            )
        except ValidationError as e:
            raise CommandError(
                self.get_parser().prog,
                f'Terraform command allowlist validation failed: {e}',
            )

    def _get_commands_config(self, params) -> str:
        return self._validate_terraform_commands(params)

    def _get_queue_config(self) -> bool:
        return True

    def generate_docker_compose_yaml(self, setup_result: SetupResult, config: DockerServiceConfig) -> str:
        builder = DockerComposeBuilder(
            setup_result,
            asdict(config),
            commander_service_name=TerraformSetupConstants.COMMANDER_SERVICE_NAME,
            commander_container_name=TerraformSetupConstants.COMMANDER_CONTAINER_NAME,
            commander_environment={TERRAFORM_DOCKER_ENV: '1'},
        )
        return builder.build()

    def _print_next_steps(self, config: DockerServiceConfig, config_path: str) -> None:
        DockerSetupPrinter.print_common_deployment_steps(
            str(config.port),
            config_path,
            container_name=TerraformSetupConstants.COMMANDER_CONTAINER_NAME,
        )
        print()
