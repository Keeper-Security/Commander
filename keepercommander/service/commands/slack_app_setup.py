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
import os
from dataclasses import asdict
from typing import Dict, Any, Tuple, Optional

from ...commands.base import Command, raise_parse_exception, suppress_exit
from ...display import bcolors
from ...error import CommandError
from ... import api, vault, record_management
from .service_docker_setup import ServiceDockerSetupCommand
from ..config.config_validation import ConfigValidator, ValidationError
from ..docker import (
    SetupResult, DockerSetupPrinter, DockerSetupConstants,
    ServiceConfig, SlackConfig, DockerComposeBuilder, DockerSetupBase
)

slack_app_setup_parser = argparse.ArgumentParser(
    prog='slack-app-setup',
    description='Automate Slack App integration setup with Commander Service Mode',
    formatter_class=argparse.RawDescriptionHelpFormatter
)
slack_app_setup_parser.add_argument(
    '--folder-name', dest='folder_name', type=str, default=DockerSetupConstants.DEFAULT_SLACK_FOLDER_NAME,
    help=f'Name for the shared folder (default: "{DockerSetupConstants.DEFAULT_SLACK_FOLDER_NAME}")'
)
slack_app_setup_parser.add_argument(
    '--app-name', dest='app_name', type=str, default=DockerSetupConstants.DEFAULT_APP_NAME,
    help=f'Name for the secrets manager app (default: "{DockerSetupConstants.DEFAULT_APP_NAME}")'
)
slack_app_setup_parser.add_argument(
    '--config-record-name', dest='config_record_name', type=str, default=DockerSetupConstants.DEFAULT_RECORD_NAME,
    help=f'Name for the config record (default: "{DockerSetupConstants.DEFAULT_RECORD_NAME}")'
)
slack_app_setup_parser.add_argument(
    '--slack-record-name', dest='slack_record_name', type=str, default=DockerSetupConstants.DEFAULT_SLACK_RECORD_NAME,
    help=f'Name for the Slack config record (default: "{DockerSetupConstants.DEFAULT_SLACK_RECORD_NAME}")'
)
slack_app_setup_parser.add_argument(
    '--config-path', dest='config_path', type=str,
    help='Path to config.json file (default: ~/.keeper/config.json)'
)
slack_app_setup_parser.add_argument(
    '--timeout', dest='timeout', type=str, default=DockerSetupConstants.DEFAULT_TIMEOUT,
    help=f'Device timeout setting (default: {DockerSetupConstants.DEFAULT_TIMEOUT})'
)
slack_app_setup_parser.add_argument(
    '--skip-device-setup', dest='skip_device_setup', action='store_true',
    help='Skip device registration and setup if already configured'
)
slack_app_setup_parser.error = raise_parse_exception
slack_app_setup_parser.exit = suppress_exit


class SlackAppSetupCommand(Command, DockerSetupBase):
    """Automated Slack App integration setup command"""

    def get_parser(self):
        return slack_app_setup_parser

    def execute(self, params, **kwargs):
        """Main execution flow for Slack integration setup"""
        # Phase 1: Run base Docker setup
        print(f"\n{bcolors.BOLD}Phase 1: Running Docker Service Mode Setup{bcolors.ENDC}")
        
        setup_result, service_config, config_path = self._run_base_docker_setup(params, kwargs)
        
        DockerSetupPrinter.print_completion("Service Mode Configuration Complete!")

        # Phase 2: Slack-specific setup
        print(f"\n{bcolors.BOLD}Phase 2: Slack App Integration Setup{bcolors.ENDC}")
        
        slack_record_uid, slack_config = self._run_slack_setup(
            params,
            setup_result,
            service_config,
            kwargs.get('slack_record_name', DockerSetupConstants.DEFAULT_SLACK_RECORD_NAME)
        )

        # Print consolidated success message
        self._print_success_message(setup_result, service_config, slack_record_uid, slack_config, config_path)

        return

    def _run_base_docker_setup(self, params, kwargs: Dict[str, Any]) -> Tuple[SetupResult, Dict[str, Any], str]:
        """
        Run the base Docker setup using ServiceDockerSetupCommand.
        Returns (SetupResult, service_config, config_path)
        """
        docker_cmd = ServiceDockerSetupCommand()
        
        # Determine config path
        config_path = kwargs.get('config_path') or os.path.expanduser('~/.keeper/config.json')
        if not os.path.isfile(config_path):
            raise CommandError('slack-app-setup', f'Config file not found: {config_path}')

        # Print header
        DockerSetupPrinter.print_header("Docker Setup")

        # Run core setup steps (Steps 1-7)
        setup_result = docker_cmd.run_setup_steps(
            params=params,
            folder_name=kwargs.get('folder_name', DockerSetupConstants.DEFAULT_SLACK_FOLDER_NAME),
            app_name=kwargs.get('app_name', DockerSetupConstants.DEFAULT_APP_NAME),
            record_name=kwargs.get('config_record_name', DockerSetupConstants.DEFAULT_RECORD_NAME),
            config_path=config_path,
            timeout=kwargs.get('timeout', DockerSetupConstants.DEFAULT_TIMEOUT),
            skip_device_setup=kwargs.get('skip_device_setup', False)
        )
        
        DockerSetupPrinter.print_completion("Docker Setup Complete!")
        
        # Get simplified service configuration for Slack App
        service_config = self._get_slack_service_configuration()
        
        # Generate initial docker-compose.yml
        docker_cmd.generate_and_save_docker_compose(setup_result, service_config)
        
        return setup_result, service_config, config_path

    def _get_slack_service_configuration(self) -> ServiceConfig:
        """Get service configuration for Slack App (port + tunneling options)"""
        DockerSetupPrinter.print_header("Service Mode Configuration")

        # Port configuration
        print(f"{bcolors.BOLD}Port:{bcolors.ENDC}")
        print(f"  The port on which Commander Service will listen")
        while True:
            port_input = input(f"{bcolors.OKBLUE}Port [Press Enter for {DockerSetupConstants.DEFAULT_PORT}]:{bcolors.ENDC} ").strip() or str(DockerSetupConstants.DEFAULT_PORT)
            try:
                port = ConfigValidator.validate_port(port_input)
                break
            except ValidationError as e:
                print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
        
        # Get tunneling configuration
        ngrok_config = self._get_ngrok_config()
        
        # Only ask for Cloudflare if ngrok is not enabled
        if not ngrok_config['ngrok_enabled']:
            cloudflare_config = self._get_cloudflare_config()
        else:
            cloudflare_config = {'cloudflare_enabled': False, 'cloudflare_tunnel_token': '', 
                                'cloudflare_custom_domain': '', 'cloudflare_public_url': ''}
        
        return ServiceConfig(
            port=port,
            commands='search,share-record,share-folder,record-add,one-time-share,epm,pedm,device-approve,get,server',
            queue_enabled=True,  # Always enable queue mode (v2 API)
            ngrok_enabled=ngrok_config['ngrok_enabled'],
            ngrok_auth_token=ngrok_config['ngrok_auth_token'],
            ngrok_custom_domain=ngrok_config['ngrok_custom_domain'],
            ngrok_public_url=ngrok_config.get('ngrok_public_url', ''),
            cloudflare_enabled=cloudflare_config['cloudflare_enabled'],
            cloudflare_tunnel_token=cloudflare_config['cloudflare_tunnel_token'],
            cloudflare_custom_domain=cloudflare_config['cloudflare_custom_domain'],
            cloudflare_public_url=cloudflare_config.get('cloudflare_public_url', '')
        )

    def _run_slack_setup(self, params, setup_result: SetupResult, service_config: ServiceConfig,
                        slack_record_name: str) -> Tuple[str, SlackConfig]:
        """
        Run Slack-specific setup steps.
        Returns (slack_record_uid, slack_config)
        """
        # Get Slack configuration
        DockerSetupPrinter.print_header("Slack App Configuration")
        slack_config = self._get_slack_configuration()
        
        # Create Slack record
        DockerSetupPrinter.print_step(1, 2, f"Creating Slack config record '{slack_record_name}'...")
        slack_record_uid = self._create_slack_record(
            params,
            slack_record_name,
            setup_result.folder_uid,
            slack_config
        )
        
        # Update docker-compose.yml
        DockerSetupPrinter.print_step(2, 2, "Updating docker-compose.yml with Slack App service...")
        self._update_docker_compose_yaml(setup_result, service_config, slack_record_uid)
        
        return slack_record_uid, slack_config

    def _get_slack_configuration(self) -> SlackConfig:
        """Interactively get Slack configuration from user"""
        # Slack App Token
        print(f"\n{bcolors.BOLD}SLACK_APP_TOKEN:{bcolors.ENDC}")
        print(f"  App-level token for Slack App")
        slack_app_token = self._prompt_with_validation(
            "Token (starts with xapp-):",
            lambda t: t and t.startswith('xapp-') and len(t) >= 90,
            "Invalid Slack App Token (must start with 'xapp-' and be at least 90 chars)"
        )
        
        # Slack Bot Token
        print(f"\n{bcolors.BOLD}SLACK_BOT_TOKEN:{bcolors.ENDC}")
        print(f"  Bot token for Slack workspace")
        slack_bot_token = self._prompt_with_validation(
            "Token (starts with xoxb-):",
            lambda t: t and t.startswith('xoxb-') and len(t) >= 50,
            "Invalid Slack Bot Token (must start with 'xoxb-' and be at least 50 chars)"
        )
        
        # Slack Signing Secret
        print(f"\n{bcolors.BOLD}SLACK_SIGNING_SECRET:{bcolors.ENDC}")
        print(f"  Signing secret for verifying Slack requests")
        slack_signing_secret = self._prompt_with_validation(
            "Secret:",
            lambda s: s and len(s) == 32,
            "Invalid Slack Signing Secret (must be exactly 32 characters)"
        )
        
        # Approvals Channel ID
        print(f"\n{bcolors.BOLD}APPROVALS_CHANNEL_ID:{bcolors.ENDC}")
        print(f"  Slack channel ID for approval notifications")
        approvals_channel_id = self._prompt_with_validation(
            "Channel ID (starts with C):",
            lambda c: c and c.startswith('C'),
            "Invalid Approvals Channel ID (must start with 'C')"
        )
        
        # PEDM Integration (optional)
        print(f"\n{bcolors.BOLD}PEDM (Endpoint Privilege Manager) Integration (optional):{bcolors.ENDC}")
        print(f"  Integrate with Keeper PEDM for privilege elevation")
        pedm_enabled = input(f"{bcolors.OKBLUE}Enable PEDM? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        pedm_polling_interval = 120
        if pedm_enabled:
            interval_input = input(f"{bcolors.OKBLUE}PEDM polling interval in seconds [Press Enter for 120]:{bcolors.ENDC} ").strip()
            pedm_polling_interval = int(interval_input) if interval_input else 120
        
        # Device Approval Integration (optional)
        print(f"\n{bcolors.BOLD}SSO Cloud Device Approval Integration (optional):{bcolors.ENDC}")
        print(f"  Approve SSO Cloud device registrations via Slack")
        device_approval_enabled = input(f"{bcolors.OKBLUE}Enable Device Approval? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        device_approval_polling_interval = 120
        if device_approval_enabled:
            interval_input = input(f"{bcolors.OKBLUE}Device approval polling interval in seconds [Press Enter for 120]:{bcolors.ENDC} ").strip()
            device_approval_polling_interval = int(interval_input) if interval_input else 120
        
        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Slack Configuration Complete!{bcolors.ENDC}")
        
        return SlackConfig(
            slack_app_token=slack_app_token,
            slack_bot_token=slack_bot_token,
            slack_signing_secret=slack_signing_secret,
            approvals_channel_id=approvals_channel_id,
            pedm_enabled=pedm_enabled,
            pedm_polling_interval=pedm_polling_interval,
            device_approval_enabled=device_approval_enabled,
            device_approval_polling_interval=device_approval_polling_interval
        )

    def _prompt_with_validation(self, prompt: str, validator, error_msg: str) -> str:
        """Helper method to prompt user input with validation"""
        while True:
            value = input(f"{bcolors.OKBLUE}{prompt}{bcolors.ENDC} ").strip()
            if validator(value):
                return value
            print(f"{bcolors.FAIL}Error: {error_msg}{bcolors.ENDC}")

    def _create_slack_record(self, params, record_name: str, folder_uid: str,
                            slack_config: SlackConfig) -> str:
        """Create or update Slack configuration record"""
        # Check if record exists
        record_uid = self._find_existing_record(params, folder_uid, record_name)
        
        if record_uid:
            DockerSetupPrinter.print_success("Using existing record (will update with custom fields)")
        else:
            # Create new record
            record_uid = self._create_basic_slack_record(params, folder_uid, record_name)
        
        # Update record with custom fields
        self._update_slack_record_fields(params, record_uid, slack_config)
        
        DockerSetupPrinter.print_success(f"Slack config record ready (UID: {record_uid})")
        return record_uid

    def _find_existing_record(self, params, folder_uid: str, record_name: str) -> Optional[str]:
        """Find existing record by name in folder"""
        if folder_uid in params.subfolder_record_cache:
            for rec_uid in params.subfolder_record_cache[folder_uid]:
                rec = api.get_record(params, rec_uid)
                if rec.title == record_name:
                    return rec_uid
        return None

    def _create_basic_slack_record(self, params, folder_uid: str, record_name: str) -> str:
        """Create a basic login record for Slack configuration"""
        try:
            from ..config.cli_handler import CommandHandler
            
            cli_handler = CommandHandler()
            cmd_add = f"record-add --folder='{folder_uid}' --title='{record_name}' --record-type=login"
            cli_handler.execute_cli_command(params, cmd_add)
            
            api.sync_down(params)
            
            # Find the created record
            record_uid = self._find_existing_record(params, folder_uid, record_name)
            if not record_uid:
                raise CommandError('slack-app-setup', 'Failed to find created Slack record')
            
            return record_uid
        except Exception as e:
            raise CommandError('slack-app-setup', f'Failed to create Slack record: {str(e)}')

    def _update_slack_record_fields(self, params, record_uid: str, slack_config: SlackConfig) -> None:
        """Update record with Slack configuration custom fields"""
        try:
            record = vault.KeeperRecord.load(params, record_uid)
            
            # Add custom fields (secret fields are masked, text fields are visible)
            record.custom = [
                vault.TypedField.new_field('secret', slack_config.slack_app_token, 'slack_app_token'),
                vault.TypedField.new_field('secret', slack_config.slack_bot_token, 'slack_bot_token'),
                vault.TypedField.new_field('secret', slack_config.slack_signing_secret, 'slack_signing_secret'),
                vault.TypedField.new_field('text', slack_config.approvals_channel_id, 'approvals_channel_id'),
                vault.TypedField.new_field('text', 'true' if slack_config.pedm_enabled else 'false', 'pedm_enabled'),
                vault.TypedField.new_field('text', str(slack_config.pedm_polling_interval), 'pedm_polling_interval'),
                vault.TypedField.new_field('text', 'true' if slack_config.device_approval_enabled else 'false', 'device_approval_enabled'),
                vault.TypedField.new_field('text', str(slack_config.device_approval_polling_interval), 'device_approval_polling_interval'),
            ]
            
            record_management.update_record(params, record)
            params.sync_data = True
            api.sync_down(params)
            
        except Exception as e:
            raise CommandError('slack-app-setup', f'Failed to update Slack record fields: {str(e)}')

    def _update_docker_compose_yaml(self, setup_result: SetupResult, service_config: ServiceConfig, 
                                     slack_record_uid: str) -> None:
        """Regenerate docker-compose.yml with Slack app service"""
        compose_file = os.path.join(os.getcwd(), 'docker-compose.yml')
        
        if not os.path.exists(compose_file):
            raise CommandError('slack-app-setup', f'docker-compose.yml not found at {compose_file}')
        
        try:
            # Check if slack-app already exists
            with open(compose_file, 'r') as f:
                content = f.read()
            
            if 'slack-app:' in content:
                DockerSetupPrinter.print_warning("slack-app service already exists in docker-compose.yml")
                return
            
            # Regenerate docker-compose.yml with both Commander and Slack App
            builder = DockerComposeBuilder(setup_result, asdict(service_config))
            yaml_content = builder.add_slack_service(slack_record_uid).build()
            
            with open(compose_file, 'w') as f:
                f.write(yaml_content)
            
            DockerSetupPrinter.print_success("docker-compose.yml updated successfully")
            
        except Exception as e:
            raise CommandError('slack-app-setup', f'Failed to update docker-compose.yml: {str(e)}')

    def _print_success_message(self, setup_result: SetupResult, service_config: ServiceConfig,
                               slack_record_uid: str, slack_config: SlackConfig, config_path: str) -> None:
        """Print consolidated success message for both phases"""
        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Slack App Integration Setup Complete!{bcolors.ENDC}\n")

        # Resources created
        print(f"{bcolors.BOLD}Resources Created:{bcolors.ENDC}")
        print(f"  {bcolors.BOLD}Phase 1 - Commander Service:{bcolors.ENDC}")
        DockerSetupPrinter.print_phase1_resources(setup_result, indent="    ")
        print(f"  {bcolors.BOLD}Phase 2 - Slack App:{bcolors.ENDC}")
        print(f"    • Slack Config Record: {bcolors.OKBLUE}{slack_record_uid}{bcolors.ENDC}")
        print(f"    • Approvals Channel: {bcolors.OKBLUE}{slack_config.approvals_channel_id}{bcolors.ENDC}")
        print(f"    • PEDM Integration: {bcolors.OKBLUE}{'true' if slack_config.pedm_enabled else 'false'}{bcolors.ENDC}")
        print(f"    • Device Approval: {bcolors.OKBLUE}{'true' if slack_config.device_approval_enabled else 'false'}{bcolors.ENDC}")
        
        # Next steps
        self._print_next_steps(service_config, config_path)

    def _print_next_steps(self, service_config: ServiceConfig, config_path: str) -> None:
        """Print deployment next steps for Slack integration"""
        DockerSetupPrinter.print_common_deployment_steps(str(service_config.port), config_path)
        
        # Slack-specific logs
        print(f"  {bcolors.OKGREEN}docker logs keeper-slack-app{bcolors.ENDC} - View Slack App logs")

        # Slack-specific commands
        print(f"\n{bcolors.BOLD}Slack Commands Available:{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}• /keeper-request-record{bcolors.ENDC} - Request access to a record")
        print(f"  {bcolors.OKGREEN}• /keeper-request-folder{bcolors.ENDC} - Request access to a folder")
        print(f"  {bcolors.OKGREEN}• /keeper-one-time-share{bcolors.ENDC} - Request a one-time share link\n")
