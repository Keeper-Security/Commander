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

"""
Standalone Docker service mode setup command.
"""

import argparse
import os
from dataclasses import asdict

from ...commands.base import Command, raise_parse_exception, suppress_exit
from ...display import bcolors
from ..config.config_validation import ConfigValidator, ValidationError
from ..docker import (
    DockerSetupBase, DockerSetupConstants, DockerSetupPrinter,
    SetupResult, ServiceConfig, DockerComposeBuilder
)


service_docker_setup_parser = argparse.ArgumentParser(
    prog='service-docker-setup',
    description='Automate Docker service mode setup with KSM configuration',
    formatter_class=argparse.RawDescriptionHelpFormatter
)
service_docker_setup_parser.add_argument(
    '--folder-name', dest='folder_name', type=str, default=DockerSetupConstants.DEFAULT_FOLDER_NAME,
    help=f'Name for the shared folder (default: "{DockerSetupConstants.DEFAULT_FOLDER_NAME}")'
)
service_docker_setup_parser.add_argument(
    '--app-name', dest='app_name', type=str, default=DockerSetupConstants.DEFAULT_APP_NAME,
    help=f'Name for the secrets manager app (default: "{DockerSetupConstants.DEFAULT_APP_NAME}")'
)
service_docker_setup_parser.add_argument(
    '--record-name', dest='record_name', type=str, default=DockerSetupConstants.DEFAULT_RECORD_NAME,
    help=f'Name for the config record (default: "{DockerSetupConstants.DEFAULT_RECORD_NAME}")'
)
service_docker_setup_parser.add_argument(
    '--config-path', dest='config_path', type=str,
    help='Path to config.json file (default: active session config file)'
)
service_docker_setup_parser.add_argument(
    '--timeout', dest='timeout', type=str, default=DockerSetupConstants.DEFAULT_TIMEOUT,
    help=f'Device timeout setting (default: {DockerSetupConstants.DEFAULT_TIMEOUT})'
)
service_docker_setup_parser.add_argument(
    '--skip-device-setup', dest='skip_device_setup', action='store_true',
    help='Skip device registration and setup if already configured'
)
service_docker_setup_parser.error = raise_parse_exception
service_docker_setup_parser.exit = suppress_exit


class ServiceDockerSetupCommand(Command, DockerSetupBase):
    """Automated Docker service mode setup command"""

    def get_parser(self):
        return service_docker_setup_parser

    def execute(self, params, **kwargs):
        """Main execution flow for standalone command"""
        command_name = self.get_parser().prog
        self._require_file_based_config(params, command_name)

        config_path = self._require_commander_config_file(
            command_name,
            kwargs.get('config_path'),
            params,
        )

        DockerSetupPrinter.print_header("Docker Setup")

        setup_result = self.run_setup_steps(
            params=params,
            folder_name=kwargs.get('folder_name', DockerSetupConstants.DEFAULT_FOLDER_NAME),
            app_name=kwargs.get('app_name', DockerSetupConstants.DEFAULT_APP_NAME),
            record_name=kwargs.get('record_name', DockerSetupConstants.DEFAULT_RECORD_NAME),
            config_path=config_path,
            timeout=kwargs.get('timeout', DockerSetupConstants.DEFAULT_TIMEOUT),
            skip_device_setup=kwargs.get('skip_device_setup', False)
        )

        DockerSetupPrinter.print_completion("Docker Setup Complete!")
        service_config = self.get_service_configuration(params)

        self.generate_and_save_docker_compose(setup_result, service_config)
        DockerSetupPrinter.print_completion("Service Mode Configuration Complete!")
        self.print_standalone_success_message(setup_result, service_config, config_path)

    def get_service_configuration(self, params) -> ServiceConfig:
        """Interactively get service configuration from user"""
        DockerSetupPrinter.print_header("Service Mode Configuration")
        
        # Port
        port = self._get_port_config()
        
        # Commands
        commands = self._get_commands_config(params)
        
        # Queue mode
        queue_enabled = self._get_queue_config()
        
        # Tunneling options (ngrok/cloudflare are mutually exclusive)
        ngrok_config = self._get_ngrok_config()
        
        if not ngrok_config['ngrok_enabled']:
            cloudflare_config = self._get_cloudflare_config()
        else:
            cloudflare_config = {
                'cloudflare_enabled': False, 'cloudflare_tunnel_token': '', 
                'cloudflare_custom_domain': '', 'cloudflare_public_url': ''
            }
        
        # Advanced security options
        security_config = self._get_advanced_security_config()
        
        return ServiceConfig(
            port=port,
            commands=commands,
            queue_enabled=queue_enabled,
            ngrok_enabled=ngrok_config['ngrok_enabled'],
            ngrok_auth_token=ngrok_config['ngrok_auth_token'],
            ngrok_custom_domain=ngrok_config['ngrok_custom_domain'],
            ngrok_public_url=ngrok_config.get('ngrok_public_url', ''),
            cloudflare_enabled=cloudflare_config['cloudflare_enabled'],
            cloudflare_tunnel_token=cloudflare_config['cloudflare_tunnel_token'],
            cloudflare_custom_domain=cloudflare_config['cloudflare_custom_domain'],
            cloudflare_public_url=cloudflare_config.get('cloudflare_public_url', ''),
            allowed_ip=security_config['allowed_ip'],
            denied_ip=security_config['denied_ip'],
            rate_limit=security_config['rate_limit'],
            encryption_enabled=security_config['encryption_enabled'],
            encryption_key=security_config['encryption_key'],
            token_expiration=security_config['token_expiration']
        )

    def generate_docker_compose_yaml(self, setup_result: SetupResult, config: ServiceConfig) -> str:
        """Generate docker-compose.yml content for Commander service"""
        builder = DockerComposeBuilder(setup_result, asdict(config))
        return builder.build()

    def generate_and_save_docker_compose(self, setup_result: SetupResult, config: ServiceConfig) -> str:
        """Generate and save docker-compose.yml file"""
        print(f"\n{bcolors.BOLD}Generating docker-compose.yml...{bcolors.ENDC}")
        yaml_content = self.generate_docker_compose_yaml(setup_result, config)
        compose_file = os.path.join(os.getcwd(), 'docker-compose.yml')
        
        with open(compose_file, 'w') as f:
            f.write(yaml_content)
        
        DockerSetupPrinter.print_success(f"docker-compose.yml created at {compose_file}", indent=True)
        
        return compose_file

    def print_standalone_success_message(self, setup_result: SetupResult, config: ServiceConfig, config_path: str) -> None:
        """Print success message for standalone service-docker-setup command"""
        print(f"\n{bcolors.BOLD}Resources Created:{bcolors.ENDC}")
        DockerSetupPrinter.print_phase1_resources(setup_result)
        
        self._print_next_steps(config, config_path)

    def _print_next_steps(self, config: ServiceConfig, config_path: str) -> None:
        """Print next steps for deployment"""
        DockerSetupPrinter.print_common_deployment_steps(str(config.port), config_path)
        print()  # Add trailing newline

    # ========================
    # Configuration Input Methods
    # ========================

    def _get_port_config(self) -> int:
        """Get and validate port configuration"""
        print(f"{bcolors.BOLD}\nPort:{bcolors.ENDC}")
        print(f"  The port on which Commander Service will listen")
        while True:
            port_input = input(f"{bcolors.OKBLUE}Port [Press Enter for {DockerSetupConstants.DEFAULT_PORT}]:{bcolors.ENDC} ").strip() or str(DockerSetupConstants.DEFAULT_PORT)
            try:
                return ConfigValidator.validate_port(port_input)
            except ValidationError as e:
                print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")

    def _get_commands_config(self, params) -> str:
        """Get and validate commands configuration"""
        from ..config.service_config import ServiceConfig
        
        service_config = ServiceConfig()
        
        print(f"\n{bcolors.BOLD}Allowed Commands:{bcolors.ENDC}")
        print(f"  Enter comma-separated commands (e.g., search,share-record,record-add)")
        
        while True:
            commands = input(f"{bcolors.OKBLUE}Commands [Press Enter for '{DockerSetupConstants.DEFAULT_COMMANDS}']:{bcolors.ENDC} ").strip() or DockerSetupConstants.DEFAULT_COMMANDS
            
            try:
                return service_config.validate_command_list(commands, params)
            except ValidationError as e:
                print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                print(f"{bcolors.WARNING}Please try again with valid commands.{bcolors.ENDC}")

    def _get_queue_config(self) -> bool:
        """Get queue mode configuration"""
        print(f"\n{bcolors.BOLD}Queue Mode:{bcolors.ENDC}")
        print(f"  Queue mode enables async API (v2) for better performance")
        queue_input = input(f"{bcolors.OKBLUE}Enable queue mode? [Press Enter for Yes] (y/n):{bcolors.ENDC} ").strip().lower()
        return queue_input != 'n'
