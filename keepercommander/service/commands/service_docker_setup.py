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
from typing import Dict, Any

from ...commands.base import Command, raise_parse_exception, suppress_exit
from ...display import bcolors
from ...error import CommandError
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
    help='Path to config.json file (default: ~/.keeper/config.json)'
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
        # Parse arguments
        config_path = self._get_config_path(kwargs.get('config_path'))
        
        # Print header
        DockerSetupPrinter.print_header("Docker Setup")
        
        # Run core setup steps (inherited from DockerSetupBase)
        setup_result = self.run_setup_steps(
            params=params,
            folder_name=kwargs.get('folder_name', DockerSetupConstants.DEFAULT_FOLDER_NAME),
            app_name=kwargs.get('app_name', DockerSetupConstants.DEFAULT_APP_NAME),
            record_name=kwargs.get('record_name', DockerSetupConstants.DEFAULT_RECORD_NAME),
            config_path=config_path,
            timeout=kwargs.get('timeout', DockerSetupConstants.DEFAULT_TIMEOUT),
            skip_device_setup=kwargs.get('skip_device_setup', False)
        )
        
        # Get service configuration
        DockerSetupPrinter.print_completion("Docker Setup Complete!")
        service_config = self.get_service_configuration(params)
        
        # Generate docker-compose.yml
        self.generate_and_save_docker_compose(setup_result, service_config)
        DockerSetupPrinter.print_completion("Service Mode Configuration Complete!")
        
        # Print success message
        self.print_standalone_success_message(setup_result, service_config, config_path)
        
        return

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


    def _get_advanced_security_config(self) -> Dict[str, Any]:
        """Get advanced security configuration"""
        print(f"\n{bcolors.BOLD}Advanced Security (optional):{bcolors.ENDC}")
        print(f"  Configure IP filtering, rate limiting, and response encryption")
        enable_advanced = input(f"{bcolors.OKBLUE}Enable advanced security? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {
            'allowed_ip': '0.0.0.0/0,::/0',
            'denied_ip': '',
            'rate_limit': '',
            'encryption_enabled': False,
            'encryption_key': '',
            'token_expiration': ''
        }
        
        if enable_advanced:
            # IP Allowed List
            config.update(self._get_ip_allowed_config())
            
            # IP Denied List
            config.update(self._get_ip_denied_config())
            
            # Rate Limiting
            config.update(self._get_rate_limit_config())
            
            # Encryption
            config.update(self._get_encryption_config())
            
            # Token Expiration
            config.update(self._get_token_expiration_config())
        
        return config

    def _get_ip_allowed_config(self) -> Dict[str, str]:
        """Get allowed IP configuration"""
        print(f"\n{bcolors.BOLD}IP Allowed List:{bcolors.ENDC}")
        print(f"  Comma-separated IPs or CIDR ranges (e.g., 192.168.1.0/24,10.0.0.1)")
        
        ip_list = input(f"{bcolors.OKBLUE}Allowed IPs [Press Enter for all]:{bcolors.ENDC} ").strip()
        
        if ip_list:
            while True:
                try:
                    return {'allowed_ip': ConfigValidator.validate_ip_list(ip_list)}
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                    ip_list = input(f"{bcolors.OKBLUE}Allowed IPs [Press Enter for all]:{bcolors.ENDC} ").strip()
                    if not ip_list:
                        break
        
        return {'allowed_ip': '0.0.0.0/0,::/0'}

    def _get_ip_denied_config(self) -> Dict[str, str]:
        """Get denied IP configuration"""
        print(f"\n{bcolors.BOLD}IP Denied List:{bcolors.ENDC}")
        print(f"  Comma-separated IPs or CIDR ranges to block")
        
        ip_list = input(f"{bcolors.OKBLUE}Denied IPs [Press Enter to skip]:{bcolors.ENDC} ").strip()
        
        if ip_list:
            while True:
                try:
                    return {'denied_ip': ConfigValidator.validate_ip_list(ip_list)}
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                    ip_list = input(f"{bcolors.OKBLUE}Denied IPs [Press Enter to skip]:{bcolors.ENDC} ").strip()
                    if not ip_list:
                        break
        
        return {'denied_ip': ''}

    def _get_rate_limit_config(self) -> Dict[str, str]:
        """Get rate limiting configuration"""
        print(f"\n{bcolors.BOLD}Rate Limiting:{bcolors.ENDC}")
        print(f"  Format: <number>/<period> (e.g., 10/minute, 100/hour, 1000/day)")
        
        rate_limit = input(f"{bcolors.OKBLUE}Rate limit [Press Enter to skip]:{bcolors.ENDC} ").strip()
        
        if rate_limit:
            while True:
                try:
                    return {'rate_limit': ConfigValidator.validate_rate_limit(rate_limit)}
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                    rate_limit = input(f"{bcolors.OKBLUE}Rate limit [Press Enter to skip]:{bcolors.ENDC} ").strip()
                    if not rate_limit:
                        break
        
        return {'rate_limit': ''}

    def _get_encryption_config(self) -> Dict[str, Any]:
        """Get encryption configuration"""
        print(f"\n{bcolors.BOLD}Response Encryption:{bcolors.ENDC}")
        print(f"  Enable AES-256 encryption for API responses")
        enable_encryption = input(f"{bcolors.OKBLUE}Enable encryption? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {'encryption_enabled': enable_encryption, 'encryption_key': ''}
        
        if enable_encryption:
            print(f"  Encryption key must be exactly 32 alphanumeric characters")
            while True:
                key = input(f"{bcolors.OKBLUE}Encryption key (32 chars):{bcolors.ENDC} ").strip()
                try:
                    config['encryption_key'] = ConfigValidator.validate_encryption_key(key)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
        
        return config

    def _get_token_expiration_config(self) -> Dict[str, str]:
        """Get token expiration configuration"""
        print(f"\n{bcolors.BOLD}API Token Expiration:{bcolors.ENDC}")
        print(f"  Format: Xm (minutes), Xh (hours), Xd (days) - e.g., 30m, 24h, 7d")
        
        expiration = input(f"{bcolors.OKBLUE}Token expiration [Press Enter for never]:{bcolors.ENDC} ").strip()
        
        if expiration:
            while True:
                try:
                    ConfigValidator.parse_expiration_time(expiration)
                    return {'token_expiration': expiration}
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                    expiration = input(f"{bcolors.OKBLUE}Token expiration [Press Enter for never]:{bcolors.ENDC} ").strip()
                    if not expiration:
                        break
        
        return {'token_expiration': ''}

    def _get_config_path(self, config_path: str = None) -> str:
        """Get and validate config file path"""
        if not config_path:
            config_path = os.path.expanduser('~/.keeper/config.json')
        
        if not os.path.isfile(config_path):
            raise CommandError('service-docker-setup', f'Config file not found: {config_path}')
        
        return config_path
