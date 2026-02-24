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

"""Base class for integration setup commands (Slack, Teams, etc.)."""

import argparse
import os
import re
from abc import ABC, abstractmethod
from dataclasses import asdict
from typing import Any, Dict, List, Tuple

from ....commands.base import Command, raise_parse_exception, suppress_exit
from ....display import bcolors
from ....error import CommandError
from .... import api, vault, utils, record_management
from ..service_docker_setup import ServiceDockerSetupCommand
from ...config.config_validation import ConfigValidator, ValidationError
from ...docker import (
    SetupResult, DockerSetupPrinter, DockerSetupConstants,
    ServiceConfig, DockerComposeBuilder, DockerSetupBase
)

UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


class IntegrationSetupCommand(Command, DockerSetupBase, ABC):
    """Base for integration setup commands. All naming conventions are
    derived from get_integration_name(). Subclasses only implement
    config collection, record fields, and display."""

    _parser_cache: Dict[type, argparse.ArgumentParser] = {}

    # -- Abstract (subclasses must implement) -----------------------

    @abstractmethod
    def get_integration_name(self) -> str:
        """e.g. 'Slack', 'Teams' -- drives all naming conventions."""

    @abstractmethod
    def collect_integration_config(self) -> Any:
        """Prompt user for config values, return a config dataclass."""

    @abstractmethod
    def build_record_custom_fields(self, config) -> List:
        """Return list of vault.TypedField for the config record."""

    @abstractmethod
    def print_integration_specific_resources(self, config) -> None:
        """Print integration-specific resource lines."""

    @abstractmethod
    def print_integration_commands(self) -> None:
        """Print available bot commands for this integration."""

    # -- Convention defaults (derived from name, override if needed) -

    def get_command_name(self) -> str:
        return f'{self.get_integration_name().lower()}-app-setup'

    def get_default_folder_name(self) -> str:
        return f'Commander Service Mode - {self.get_integration_name()} App'

    def get_default_record_name(self) -> str:
        return f'Commander Service Mode {self.get_integration_name()} App Config'

    def get_docker_service_name(self) -> str:
        return f'{self.get_integration_name().lower()}-app'

    def get_docker_container_name(self) -> str:
        return f'keeper-{self.get_integration_name().lower()}-app'

    def get_docker_image(self) -> str:
        return f'keeper/{self.get_integration_name().lower()}-app:latest'

    def get_record_env_key(self) -> str:
        return f'{self.get_integration_name().upper()}_RECORD'

    def get_commander_service_name(self) -> str:
        return f'commander-{self.get_integration_name().lower()}'

    def get_commander_container_name(self) -> str:
        return f'keeper-service-{self.get_integration_name().lower()}'

    def get_service_commands(self) -> str:
        return 'search,share-record,share-folder,record-add,one-time-share,epm,pedm,device-approve,get,server'

    # -- Parser (auto-built from name, cached per subclass) ----------

    def get_parser(self):
        cls = type(self)
        if cls not in IntegrationSetupCommand._parser_cache:
            IntegrationSetupCommand._parser_cache[cls] = self._build_parser()
        return IntegrationSetupCommand._parser_cache[cls]

    def _build_parser(self) -> argparse.ArgumentParser:
        name = self.get_integration_name()
        name_lower = name.lower()
        default_folder = self.get_default_folder_name()
        default_record = self.get_default_record_name()

        parser = argparse.ArgumentParser(
            prog=f'{name_lower}-app-setup',
            description=f'Automate {name} App integration setup with Commander Service Mode',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument(
            '--folder-name', dest='folder_name', type=str, default=default_folder,
            help=f'Name for the shared folder (default: "{default_folder}")'
        )
        parser.add_argument(
            '--app-name', dest='app_name', type=str, default=DockerSetupConstants.DEFAULT_APP_NAME,
            help=f'Name for the secrets manager app (default: "{DockerSetupConstants.DEFAULT_APP_NAME}")'
        )
        parser.add_argument(
            '--config-record-name', dest='config_record_name', type=str,
            default=DockerSetupConstants.DEFAULT_RECORD_NAME,
            help=f'Name for the config record (default: "{DockerSetupConstants.DEFAULT_RECORD_NAME}")'
        )
        parser.add_argument(
            f'--{name_lower}-record-name', dest='integration_record_name', type=str,
            default=default_record,
            help=f'Name for the {name} config record (default: "{default_record}")'
        )
        parser.add_argument(
            '--config-path', dest='config_path', type=str,
            help='Path to config.json file (default: ~/.keeper/config.json)'
        )
        parser.add_argument(
            '--timeout', dest='timeout', type=str, default=DockerSetupConstants.DEFAULT_TIMEOUT,
            help=f'Device timeout setting (default: {DockerSetupConstants.DEFAULT_TIMEOUT})'
        )
        parser.add_argument(
            '--skip-device-setup', dest='skip_device_setup', action='store_true',
            help='Skip device registration and setup if already configured'
        )
        parser.error = raise_parse_exception
        parser.exit = suppress_exit
        return parser

    # -- Main flow ---------------------------------------------------

    def execute(self, params, **kwargs):
        name = self.get_integration_name()

        # Phase 1 -- Docker service mode setup
        print(f"\n{bcolors.BOLD}Phase 1: Running Docker Service Mode Setup{bcolors.ENDC}")
        setup_result, service_config, config_path = self._run_base_docker_setup(params, kwargs)
        DockerSetupPrinter.print_completion("Service Mode Configuration Complete!")

        # Phase 2 -- Integration-specific setup
        print(f"\n{bcolors.BOLD}Phase 2: {name} App Integration Setup{bcolors.ENDC}")
        record_name = kwargs.get('integration_record_name', self.get_default_record_name())
        record_uid, config = self._run_integration_setup(
            params, setup_result, service_config, record_name
        )

        # Consolidated success output
        self._print_success_message(setup_result, service_config, record_uid, config, config_path)

    # -- Phase 1 (docker service mode) --------------------------------

    def _run_base_docker_setup(self, params, kwargs: Dict[str, Any]) -> Tuple[SetupResult, ServiceConfig, str]:
        docker_cmd = ServiceDockerSetupCommand()

        config_path = kwargs.get('config_path') or os.path.expanduser('~/.keeper/config.json')
        if not os.path.isfile(config_path):
            raise CommandError(self.get_command_name(), f'Config file not found: {config_path}')

        DockerSetupPrinter.print_header("Docker Setup")

        setup_result = docker_cmd.run_setup_steps(
            params=params,
            folder_name=kwargs.get('folder_name', self.get_default_folder_name()),
            app_name=kwargs.get('app_name', DockerSetupConstants.DEFAULT_APP_NAME),
            record_name=kwargs.get('config_record_name', DockerSetupConstants.DEFAULT_RECORD_NAME),
            config_path=config_path,
            timeout=kwargs.get('timeout', DockerSetupConstants.DEFAULT_TIMEOUT),
            skip_device_setup=kwargs.get('skip_device_setup', False)
        )

        DockerSetupPrinter.print_completion("Docker Setup Complete!")

        service_config = self._get_integration_service_configuration()

        return setup_result, service_config, config_path

    def _get_integration_service_configuration(self) -> ServiceConfig:
        DockerSetupPrinter.print_header("Service Mode Configuration")

        print(f"{bcolors.BOLD}Port:{bcolors.ENDC}")
        print(f"  The port on which Commander Service will listen")
        while True:
            port_input = (
                input(f"{bcolors.OKBLUE}Port [Press Enter for {DockerSetupConstants.DEFAULT_PORT}]:{bcolors.ENDC} ").strip()
                or str(DockerSetupConstants.DEFAULT_PORT)
            )
            try:
                port = ConfigValidator.validate_port(port_input)
                break
            except ValidationError as e:
                print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")

        ngrok_config = self._get_ngrok_config()

        if not ngrok_config['ngrok_enabled']:
            cloudflare_config = self._get_cloudflare_config()
        else:
            cloudflare_config = {
                'cloudflare_enabled': False, 'cloudflare_tunnel_token': '',
                'cloudflare_custom_domain': '', 'cloudflare_public_url': ''
            }

        return ServiceConfig(
            port=port,
            commands=self.get_service_commands(),
            queue_enabled=True,
            ngrok_enabled=ngrok_config['ngrok_enabled'],
            ngrok_auth_token=ngrok_config['ngrok_auth_token'],
            ngrok_custom_domain=ngrok_config['ngrok_custom_domain'],
            ngrok_public_url=ngrok_config.get('ngrok_public_url', ''),
            cloudflare_enabled=cloudflare_config['cloudflare_enabled'],
            cloudflare_tunnel_token=cloudflare_config['cloudflare_tunnel_token'],
            cloudflare_custom_domain=cloudflare_config['cloudflare_custom_domain'],
            cloudflare_public_url=cloudflare_config.get('cloudflare_public_url', '')
        )

    # -- Phase 2 (integration-specific) --------------------------------

    def _run_integration_setup(self, params, setup_result: SetupResult,
                               service_config: ServiceConfig,
                               record_name: str) -> Tuple[str, Any]:
        name = self.get_integration_name()

        DockerSetupPrinter.print_header(f"{name} App Configuration")
        config = self.collect_integration_config()

        DockerSetupPrinter.print_step(1, 2, f"Creating {name} config record '{record_name}'...")
        custom_fields = self.build_record_custom_fields(config)
        record_uid = self._create_integration_record(params, record_name, setup_result.folder_uid, custom_fields)

        DockerSetupPrinter.print_step(2, 2, f"Updating docker-compose.yml with {name} App service...")
        self._update_docker_compose(setup_result, service_config, record_uid)

        return record_uid, config

    # -- Record management ---------------------------------------------

    def _create_integration_record(self, params, record_name: str,
                                   folder_uid: str, custom_fields: List) -> str:
        record_uid = self._find_record_in_folder(params, folder_uid, record_name)

        if record_uid:
            DockerSetupPrinter.print_success("Using existing record (will update with custom fields)")
        else:
            record_uid = self._create_login_record(params, folder_uid, record_name)

        self._update_record_custom_fields(params, record_uid, custom_fields)

        name = self.get_integration_name()
        DockerSetupPrinter.print_success(f"{name} config record ready (UID: {record_uid})")
        return record_uid

    def _find_record_in_folder(self, params, folder_uid: str, record_name: str):
        if folder_uid in params.subfolder_record_cache:
            for rec_uid in params.subfolder_record_cache[folder_uid]:
                rec = api.get_record(params, rec_uid)
                if rec.title == record_name:
                    return rec_uid
        return None

    def _create_login_record(self, params, folder_uid: str, record_name: str) -> str:
        try:
            record = vault.KeeperRecord.create(params, 'login')
            record.record_uid = utils.generate_uid()
            record.record_key = utils.generate_aes_key()
            record.title = record_name
            record.type_name = 'login'
            record_management.add_record_to_folder(params, record, folder_uid)
            api.sync_down(params)
            return record.record_uid
        except Exception as e:
            raise CommandError(self.get_command_name(), f'Failed to create record: {str(e)}')

    def _update_record_custom_fields(self, params, record_uid: str, custom_fields: List) -> None:
        try:
            record = vault.KeeperRecord.load(params, record_uid)
            record.custom = custom_fields
            record_management.update_record(params, record)
            params.sync_data = True
            api.sync_down(params)
        except Exception as e:
            raise CommandError(self.get_command_name(), f'Failed to update record fields: {str(e)}')

    # -- Docker Compose update -----------------------------------------

    def _update_docker_compose(self, setup_result: SetupResult,
                               service_config: ServiceConfig,
                               record_uid: str) -> None:
        compose_file = os.path.join(os.getcwd(), 'docker-compose.yml')
        service_name = self.get_docker_service_name()

        if os.path.exists(compose_file):
            with open(compose_file, 'r') as f:
                content = f.read()

            if f'{service_name}:' in content:
                DockerSetupPrinter.print_warning(f"{service_name} service already exists in docker-compose.yml")
                return

        try:
            builder = DockerComposeBuilder(
                setup_result, asdict(service_config),
                commander_service_name=self.get_commander_service_name(),
                commander_container_name=self.get_commander_container_name()
            )
            yaml_content = builder.add_integration_service(
                service_name=service_name,
                container_name=self.get_docker_container_name(),
                image=self.get_docker_image(),
                record_uid=record_uid,
                record_env_key=self.get_record_env_key()
            ).build()

            with open(compose_file, 'w') as f:
                f.write(yaml_content)

            DockerSetupPrinter.print_success("docker-compose.yml updated successfully")
        except Exception as e:
            raise CommandError(self.get_command_name(), f'Failed to update docker-compose.yml: {str(e)}')

    # -- Success output ------------------------------------------------

    def _print_success_message(self, setup_result: SetupResult,
                               service_config: ServiceConfig,
                               record_uid: str, config, config_path: str) -> None:
        name = self.get_integration_name()

        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ {name} App Integration Setup Complete!{bcolors.ENDC}\n")

        print(f"{bcolors.BOLD}Resources Created:{bcolors.ENDC}")
        print(f"  {bcolors.BOLD}Phase 1 - Commander Service:{bcolors.ENDC}")
        DockerSetupPrinter.print_phase1_resources(setup_result, indent="    ")
        print(f"  {bcolors.BOLD}Phase 2 - {name} App:{bcolors.ENDC}")
        self._print_integration_resources(record_uid, config)

        DockerSetupPrinter.print_common_deployment_steps(str(service_config.port), config_path)

        container = self.get_docker_container_name()
        print(f"  {bcolors.OKGREEN}docker logs {container}{bcolors.ENDC} - View {name} App logs")

        self.print_integration_commands()

    def _print_integration_resources(self, record_uid: str, config) -> None:
        name = self.get_integration_name()
        print(f"    • {name} Config Record: {bcolors.OKBLUE}{record_uid}{bcolors.ENDC}")
        self.print_integration_specific_resources(config)
        print(f"    • PEDM Integration: {bcolors.OKBLUE}{'true' if config.pedm_enabled else 'false'}{bcolors.ENDC}")
        print(f"    • Device Approval: {bcolors.OKBLUE}{'true' if config.device_approval_enabled else 'false'}{bcolors.ENDC}")

    # -- Optional feature collectors -----------------------------------

    def _collect_pedm_config(self) -> Tuple[bool, int]:
        print(f"\n{bcolors.BOLD}PEDM (Endpoint Privilege Manager) Integration (optional):{bcolors.ENDC}")
        print(f"  Integrate with Keeper PEDM for privilege elevation")
        enabled = input(f"{bcolors.OKBLUE}Enable PEDM? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        interval = 120
        if enabled:
            interval_input = input(f"{bcolors.OKBLUE}PEDM polling interval in seconds [Press Enter for 120]:{bcolors.ENDC} ").strip()
            interval = int(interval_input) if interval_input else 120
        return enabled, interval

    def _collect_device_approval_config(self) -> Tuple[bool, int]:
        name = self.get_integration_name()
        print(f"\n{bcolors.BOLD}SSO Cloud Device Approval Integration (optional):{bcolors.ENDC}")
        print(f"  Approve SSO Cloud device registrations via {name}")
        enabled = input(f"{bcolors.OKBLUE}Enable Device Approval? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        interval = 120
        if enabled:
            interval_input = input(f"{bcolors.OKBLUE}Device approval polling interval in seconds [Press Enter for 120]:{bcolors.ENDC} ").strip()
            interval = int(interval_input) if interval_input else 120
        return enabled, interval

    # -- Input / validation --------------------------------------------

    def _prompt_with_validation(self, prompt: str, validator, error_msg: str) -> str:
        while True:
            value = input(f"{bcolors.OKBLUE}{prompt}{bcolors.ENDC} ").strip()
            if validator(value):
                return value
            print(f"{bcolors.FAIL}Error: {error_msg}{bcolors.ENDC}")

    @staticmethod
    def is_valid_uuid(value: str) -> bool:
        return bool(UUID_PATTERN.match(value or ''))
