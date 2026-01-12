#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import json
import os
from typing import Dict, Any

from ...commands.base import Command, raise_parse_exception, suppress_exit
from ...commands.folder import FolderMakeCommand
from ...commands.ksm import KSMCommand
from ... import api, vault, utils, attachment, record_management, loginv3
from ...display import bcolors
from ...error import CommandError
from ..config.config_validation import ConfigValidator, ValidationError

service_docker_setup_parser = argparse.ArgumentParser(
    prog='service-docker-setup',
    description='Automate Docker service mode setup with KSM configuration',
    formatter_class=argparse.RawDescriptionHelpFormatter
)
service_docker_setup_parser.add_argument(
    '--folder-name', dest='folder_name', type=str, default='CSMD Folder',
    help='Name for the shared folder (default: "CSMD Folder")'
)
service_docker_setup_parser.add_argument(
    '--app-name', dest='app_name', type=str, default='CSMD KSM App',
    help='Name for the secrets manager app (default: "CSMD KSM App")'
)
service_docker_setup_parser.add_argument(
    '--record-name', dest='record_name', type=str, default='CSMD Config',
    help='Name for the config record (default: "CSMD Config")'
)
service_docker_setup_parser.add_argument(
    '--config-path', dest='config_path', type=str,
    help='Path to config.json file (default: ~/.keeper/config.json)'
)
service_docker_setup_parser.add_argument(
    '--timeout', dest='timeout', type=str, default='30d',
    help='Device timeout setting (default: 30d)'
)
service_docker_setup_parser.add_argument(
    '--skip-device-setup', dest='skip_device_setup', action='store_true',
    help='Skip device registration and setup if already configured'
)
service_docker_setup_parser.add_argument(
    '--force', dest='force', action='store_true',
    help='Force recreation even if resources already exist'
)
service_docker_setup_parser.error = raise_parse_exception
service_docker_setup_parser.exit = suppress_exit


class SetupResult:
    """Container for setup results that can be reused by integration commands"""
    def __init__(self, folder_uid: str, folder_name: str, app_uid: str, app_name: str,
                 record_uid: str, b64_config: str):
        self.folder_uid = folder_uid
        self.folder_name = folder_name
        self.app_uid = app_uid
        self.app_name = app_name
        self.record_uid = record_uid
        self.b64_config = b64_config


class DockerSetupPrinter:
    """Utility class for consistent formatting across docker setup commands"""
    
    @staticmethod
    def print_header(title: str) -> None:
        """Print a formatted header"""
        print(f"\n{bcolors.BOLD}═══════════════════════════════════════════════════════════{bcolors.ENDC}")
        print(f"{bcolors.BOLD}    {title}{bcolors.ENDC}")
        print(f"{bcolors.BOLD}═══════════════════════════════════════════════════════════{bcolors.ENDC}")
    
    @staticmethod
    def print_step(step_num: int, total_steps: int, message: str) -> None:
        """Print a step indicator"""
        print(f"\n{bcolors.OKBLUE}[{step_num}/{total_steps}]{bcolors.ENDC} {message}")
    
    @staticmethod
    def print_success(message: str, indent: bool = True) -> None:
        """Print a success message"""
        prefix = "  " if indent else ""
        print(f"{prefix}{bcolors.OKGREEN}✓{bcolors.ENDC}  {message}")
    
    @staticmethod
    def print_warning(message: str, indent: bool = True) -> None:
        """Print a warning message"""
        prefix = "  " if indent else ""
        print(f"{prefix}{bcolors.WARNING}⚠{bcolors.ENDC}  {message}")
    
    @staticmethod
    def print_completion(message: str) -> None:
        """Print a completion message"""
        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ {message}{bcolors.ENDC}")
    
    @staticmethod
    def print_phase1_resources(setup_result: 'SetupResult', indent: str = "  ") -> None:
        """Print Phase 1 resources created (folder, app, record, config)"""
        print(f"{indent}• Shared Folder: {bcolors.OKBLUE}{setup_result.folder_name}{bcolors.ENDC}")
        print(f"{indent}• KSM App: {bcolors.OKBLUE}{setup_result.app_name}{bcolors.ENDC} (with edit permissions)")
        print(f"{indent}• Config Record: {bcolors.OKBLUE}{setup_result.record_uid}{bcolors.ENDC}")
        print(f"{indent}• KSM Base64 Config: {bcolors.OKGREEN}✓ Generated{bcolors.ENDC}")
    
    @staticmethod
    def print_common_deployment_steps(port: str) -> None:
        """Print common deployment steps (header + steps 1-5)"""
        DockerSetupPrinter.print_header("Next Steps to Deploy")
        
        print(f"\n{bcolors.BOLD}Step 1: Quit from this session{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}quit{bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}Step 2: Delete the local config.json file{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}rm ~/.keeper/config.json{bcolors.ENDC}")
        print(f"  Why? Prevents device token conflicts - Docker will download its own config.")
        
        print(f"\n{bcolors.BOLD}Step 3: Review docker-compose.yml{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}cat docker-compose.yml{bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}Step 4: Start the services{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}docker compose up -d{bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}Step 5: Check services health{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}docker ps{bcolors.ENDC} - View container status")
        print(f"  {bcolors.OKGREEN}docker logs keeper-service{bcolors.ENDC} - View Commander logs")
        print(f"  {bcolors.OKGREEN}curl http://localhost:{port}/health{bcolors.ENDC} - Test health endpoint")


class ServiceDockerSetupCommand(Command):
    """Automated Docker service mode setup command"""

    def get_parser(self):
        return service_docker_setup_parser

    def execute(self, params, **kwargs):
        """Main execution flow for standalone command"""
        # Parse arguments
        config_path = self._get_config_path(kwargs.get('config_path'))
        
        # Print header
        DockerSetupPrinter.print_header("Docker Setup")
        
        # Run core setup steps
        setup_result = self.run_setup_steps(
            params=params,
            folder_name=kwargs.get('folder_name', 'CSMD Folder'),
            app_name=kwargs.get('app_name', 'CSMD KSM App'),
            record_name=kwargs.get('record_name', 'CSMD Config'),
            config_path=config_path,
            timeout=kwargs.get('timeout', '30d'),
            skip_device_setup=kwargs.get('skip_device_setup', False),
            force=kwargs.get('force', False)
        )
        
        # Get service configuration
        DockerSetupPrinter.print_completion("Docker Setup Complete!")
        service_config = self.get_service_configuration()
        
        # Generate docker-compose.yml
        self.generate_and_save_docker_compose(setup_result, service_config)
        DockerSetupPrinter.print_completion("Service Mode Configuration Complete!")
        
        # Print success message
        self.print_standalone_success_message(setup_result, service_config)
        
        return ''

    def run_setup_steps(self, params, folder_name: str, app_name: str, record_name: str,
                       config_path: str, timeout: str, skip_device_setup: bool = False,
                       force: bool = False) -> SetupResult:
        """
        Core setup steps that can be reused by integration commands.
        Returns a SetupResult object containing all the created resources.
        """
        # Step 1: Device setup
        if not skip_device_setup:
            DockerSetupPrinter.print_step(1, 7, "Checking device settings...")
            self._setup_device(params, timeout)
        else:
            DockerSetupPrinter.print_step(1, 7, "Skipping device setup (--skip-device-setup)")

        # Step 2: Create shared folder
        DockerSetupPrinter.print_step(2, 7, f"Creating shared folder '{folder_name}'...")
        folder_uid = self._create_shared_folder(params, folder_name, force)

        # Step 3: Create config record
        DockerSetupPrinter.print_step(3, 7, f"Creating record '{record_name}'...")
        record_uid = self._create_config_record(params, record_name, folder_uid, force)

        # Step 4: Upload config file
        DockerSetupPrinter.print_step(4, 7, "Uploading config.json attachment...")
        self._upload_config_file(params, record_uid, config_path)

        # Step 5: Create KSM app
        DockerSetupPrinter.print_step(5, 7, f"Creating Secrets Manager app '{app_name}'...")
        app_uid = self._create_ksm_app(params, app_name, force)

        # Step 6: Share folder with app
        DockerSetupPrinter.print_step(6, 7, "Sharing folder with app...")
        self._share_folder_with_app(params, app_uid, folder_uid)

        # Step 7: Create client device
        DockerSetupPrinter.print_step(7, 7, "Creating client device and generating config...")
        b64_config = self._create_client_device(params, app_uid, app_name)

        return SetupResult(
            folder_uid=folder_uid,
            folder_name=folder_name,
            app_uid=app_uid,
            app_name=app_name,
            record_uid=record_uid,
            b64_config=b64_config
        )

    def get_service_configuration(self) -> Dict[str, Any]:
        """Interactively get service configuration from user"""
        DockerSetupPrinter.print_header("Service Mode Configuration")
        
        config = {}
        
        # Port
        config['port'] = self._get_port_config()
        
        # Commands
        config['commands'] = self._get_commands_config()
        
        # Queue mode
        config['queue_enabled'] = self._get_queue_config()
        
        # Tunneling options (ngrok/cloudflare are mutually exclusive)
        ngrok_config = self._get_ngrok_config()
        config.update(ngrok_config)
        
        if not config['ngrok_enabled']:
            cloudflare_config = self._get_cloudflare_config()
            config.update(cloudflare_config)
            
            # TLS only if no tunneling
            if not config['cloudflare_enabled']:
                tls_config = self._get_tls_config()
                config.update(tls_config)
            else:
                config.update({'tls_enabled': False, 'cert_file': '', 'cert_password': ''})
        else:
            config.update({
                'cloudflare_enabled': False, 'cloudflare_token': '', 'cloudflare_domain': '',
                'tls_enabled': False, 'cert_file': '', 'cert_password': ''
            })
        
        return config

    def generate_docker_compose_yaml(self, setup_result: SetupResult, config: Dict[str, Any]) -> str:
        """Generate docker-compose.yml content for Commander service"""
        port = config['port']
        commands = config['commands']
        
        # Build service-create command
        service_cmd_parts = [
            f"service-create -p {port}",
            f"-c '{commands}'",
            "-f json",
            f"-q {'y' if config['queue_enabled'] else 'n'}"
        ]
        
        # Add optional configurations
        if config['ngrok_enabled'] and config['ngrok_token']:
            service_cmd_parts.append(f"-ng {config['ngrok_token']}")
            if config['ngrok_domain']:
                service_cmd_parts.append(f"-cd {config['ngrok_domain']}")
        
        if config['cloudflare_enabled'] and config['cloudflare_token']:
            service_cmd_parts.append(f"-cf {config['cloudflare_token']}")
            if config['cloudflare_domain']:
                service_cmd_parts.append(f"-cfd {config['cloudflare_domain']}")
        
        # TLS configuration
        volumes_section = ""
        if config['tls_enabled'] and config['cert_file']:
            cert_basename = os.path.basename(config['cert_file'])
            service_cmd_parts.append(f"-crtf /certs/{cert_basename}")
            if config['cert_password']:
                service_cmd_parts.append(f"-crtp {config['cert_password']}")
            volumes_section = f"""
        volumes:
            - {config['cert_file']}:/certs/{cert_basename}:ro"""
        
        # Docker-specific parameters
        service_cmd_parts.extend([
            f"--update-vault-record {setup_result.record_uid}",
            f"--ksm-config {setup_result.b64_config}",
            f"--record {setup_result.record_uid}"
        ])
        
        service_cmd = " ".join(service_cmd_parts)
        
        yaml_content = f"""services:
    commander:
        container_name: keeper-service
        ports:
            - {port}:{port}
        image: keeper/commander:latest{volumes_section}
        command: >
            {service_cmd}
        healthcheck:
            test:
                - CMD-SHELL
                - |
                  python - <<'PY'
                  import sys
                  import urllib.request

                  url = "http://localhost:{port}/health"
                  try:
                    r = urllib.request.urlopen(url, timeout=2)
                    sys.exit(0 if r.status == 200 else 1)
                  except Exception:
                    sys.exit(1)
                  PY
            interval: 60s
            timeout: 3s
            start_period: 10s
            retries: 30
        restart: unless-stopped
"""
        return yaml_content

    def generate_and_save_docker_compose(self, setup_result: SetupResult, config: Dict[str, Any]) -> str:
        """Generate and save docker-compose.yml file"""
        print(f"\n{bcolors.BOLD}Generating docker-compose.yml...{bcolors.ENDC}")
        yaml_content = self.generate_docker_compose_yaml(setup_result, config)
        compose_file = os.path.join(os.getcwd(), 'docker-compose.yml')
        
        with open(compose_file, 'w') as f:
            f.write(yaml_content)
        
        DockerSetupPrinter.print_success(f"docker-compose.yml created at {compose_file}", indent=True)
        
        return compose_file

    def print_standalone_success_message(self, setup_result: SetupResult, config: Dict[str, Any]) -> None:
        """Print success message for standalone service-docker-setup command"""
        print(f"\n{bcolors.BOLD}Resources Created:{bcolors.ENDC}")
        DockerSetupPrinter.print_phase1_resources(setup_result)
        
        self._print_next_steps(config)

    def _print_next_steps(self, config: Dict[str, Any]) -> None:
        """Print next steps for deployment"""
        DockerSetupPrinter.print_common_deployment_steps(config['port'])
        print()  # Add trailing newline

    # ========================
    # Configuration Input Methods
    # ========================

    def _get_port_config(self) -> str:
        """Get and validate port configuration"""
        print(f"{bcolors.BOLD}\nPort:{bcolors.ENDC}")
        print(f"  The port on which Commander Service will listen")
        while True:
            port_input = input(f"{bcolors.OKBLUE}Port [Press Enter for 8900]:{bcolors.ENDC} ").strip() or "8900"
            try:
                return str(ConfigValidator.validate_port(port_input))
            except ValidationError as e:
                print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")

    def _get_commands_config(self) -> str:
        """Get and validate commands configuration"""
        print(f"\n{bcolors.BOLD}Allowed Commands:{bcolors.ENDC}")
        print(f"  Enter comma-separated commands (e.g., search,share-record,record-add)")
        while True:
            commands = input(f"{bcolors.OKBLUE}Commands [Press Enter for 'tree,ls']:{bcolors.ENDC} ").strip() or "tree,ls"
            if commands:
                return commands
            print(f"{bcolors.FAIL}Error: Commands cannot be empty{bcolors.ENDC}")

    def _get_queue_config(self) -> bool:
        """Get queue mode configuration"""
        print(f"\n{bcolors.BOLD}Queue Mode:{bcolors.ENDC}")
        print(f"  Queue mode enables async API (v2) for better performance")
        queue_input = input(f"{bcolors.OKBLUE}Enable queue mode? [Press Enter for Yes] (y/n):{bcolors.ENDC} ").strip().lower()
        return queue_input != 'n'

    def _get_ngrok_config(self) -> Dict[str, Any]:
        """Get ngrok configuration"""
        print(f"\n{bcolors.BOLD}Ngrok Tunneling (optional):{bcolors.ENDC}")
        print(f"  Generate a public URL for your service using ngrok")
        use_ngrok = input(f"{bcolors.OKBLUE}Enable ngrok? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {'ngrok_enabled': use_ngrok, 'ngrok_token': '', 'ngrok_domain': ''}
        
        if use_ngrok:
            while True:
                token = input(f"{bcolors.OKBLUE}Ngrok auth token:{bcolors.ENDC} ").strip()
                try:
                    config['ngrok_token'] = ConfigValidator.validate_ngrok_token(token)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
            config['ngrok_domain'] = input(f"{bcolors.OKBLUE}Ngrok custom domain [Press Enter to skip]:{bcolors.ENDC} ").strip()
        
        return config

    def _get_cloudflare_config(self) -> Dict[str, Any]:
        """Get Cloudflare configuration"""
        print(f"\n{bcolors.BOLD}Cloudflare Tunneling (optional):{bcolors.ENDC}")
        print(f"  Generate a public URL for your service using Cloudflare")
        use_cloudflare = input(f"{bcolors.OKBLUE}Enable Cloudflare? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {'cloudflare_enabled': use_cloudflare, 'cloudflare_token': '', 'cloudflare_domain': ''}
        
        if use_cloudflare:
            while True:
                token = input(f"{bcolors.OKBLUE}Cloudflare tunnel token:{bcolors.ENDC} ").strip()
                try:
                    config['cloudflare_token'] = ConfigValidator.validate_cloudflare_token(token)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
            
            while True:
                domain = input(f"{bcolors.OKBLUE}Cloudflare custom domain:{bcolors.ENDC} ").strip()
                try:
                    config['cloudflare_domain'] = ConfigValidator.validate_domain(domain)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
        
        return config

    def _get_tls_config(self) -> Dict[str, Any]:
        """Get TLS configuration"""
        print(f"\n{bcolors.BOLD}TLS Certificate (optional):{bcolors.ENDC}")
        print(f"  Use custom TLS certificate for HTTPS")
        use_tls = input(f"{bcolors.OKBLUE}Enable TLS? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {'tls_enabled': use_tls, 'cert_file': '', 'cert_password': ''}
        
        if use_tls:
            while True:
                cert_file = input(f"{bcolors.OKBLUE}Certificate file path:{bcolors.ENDC} ").strip()
                try:
                    if cert_file and os.path.exists(cert_file):
                        config['cert_file'] = ConfigValidator.validate_cert_file(cert_file)
                        break
                    print(f"{bcolors.FAIL}Error: Certificate file not found{bcolors.ENDC}")
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
            
            config['cert_password'] = input(f"{bcolors.OKBLUE}Certificate password [Press Enter if none]:{bcolors.ENDC} ").strip()
        
        return config

    # ========================
    # Core Setup Methods
    # ========================

    def _get_config_path(self, config_path: str = None) -> str:
        """Get and validate config file path"""
        if not config_path:
            config_path = os.path.expanduser('~/.keeper/config.json')
        
        if not os.path.isfile(config_path):
            raise CommandError('service-docker-setup', f'Config file not found: {config_path}')
        
        return config_path

    def _setup_device(self, params, timeout: str) -> None:
        """Check and setup device registration, persistent login, and timeout"""
        from ...commands.utils import ThisDeviceCommand
        
        try:
            device_info = ThisDeviceCommand.get_device_info(params)
            
            # Device registration
            if not device_info.get('data_key_present', False):
                DockerSetupPrinter.print_warning("Device not registered")
                loginv3.LoginV3API.register_encrypted_data_key_for_device(params)
                DockerSetupPrinter.print_success("Device registered successfully")
            else:
                DockerSetupPrinter.print_success("Device already registered")

            # Persistent login
            if not device_info.get('persistent_login', False):
                DockerSetupPrinter.print_warning("Persistent login disabled")
                loginv3.LoginV3API.set_user_setting(params, 'persistent_login', '1')
                DockerSetupPrinter.print_success("Persistent login enabled")
            else:
                DockerSetupPrinter.print_success("Persistent login already enabled")

            # Timeout
            DockerSetupPrinter.print_success(f"Setting logout timeout to {timeout}...")
            ThisDeviceCommand().execute(params, ops=['timeout', timeout])

        except Exception as e:
            raise CommandError('service-docker-setup', f'Device setup failed: {str(e)}')

    def _create_shared_folder(self, params, folder_name: str, force: bool) -> str:
        """Create shared folder or return existing one"""
        # Check if folder exists
        for folder_uid, folder in params.folder_cache.items():
            if folder.name == folder_name and folder_uid in params.shared_folder_cache:
                msg = "Folder already exists, using existing (use different name to create new)" if force else "Using existing shared folder"
                if force:
                    DockerSetupPrinter.print_warning(msg)
                else:
                    DockerSetupPrinter.print_success(msg)
                return folder_uid

        # Create new folder
        try:
            folder_cmd = FolderMakeCommand()
            folder_uid = folder_cmd.execute(
                params,
                folder=folder_name,
                shared_folder=True,
                manage_users=True,
                manage_records=True,
                can_edit=True,
                can_share=True
            )
            api.sync_down(params)
            DockerSetupPrinter.print_success(f"Shared folder created successfully (UID: {folder_uid})")
            return folder_uid
        except Exception as e:
            raise CommandError('service-docker-setup', f'Failed to create shared folder: {str(e)}')

    def _create_config_record(self, params, record_name: str, folder_uid: str, force: bool) -> str:
        """Create a config record or return existing one"""
        # Check if record exists
        if folder_uid in params.subfolder_record_cache:
            for rec_uid in params.subfolder_record_cache[folder_uid]:
                rec = api.get_record(params, rec_uid)
                if rec.title == record_name:
                    msg = "Record already exists, using existing" if force else "Using existing record"
                    if force:
                        DockerSetupPrinter.print_warning(msg)
                    else:
                        DockerSetupPrinter.print_success(msg)
                    return rec_uid

        # Create new record
        try:
            record = vault.KeeperRecord.create(params, 'serverCredentials')
            record.record_uid = utils.generate_uid()
            record.record_key = utils.generate_aes_key()
            record.title = record_name
            record.type_name = 'serverCredentials'
            
            record_management.add_record_to_folder(params, record, folder_uid)
            api.sync_down(params)
            
            DockerSetupPrinter.print_success(f"Record created successfully (UID: {record.record_uid})")
            return record.record_uid
        except Exception as e:
            raise CommandError('service-docker-setup', f'Failed to create record: {str(e)}')

    def _upload_config_file(self, params, record_uid: str, config_path: str) -> None:
        """Upload config.json as attachment to the record"""
        temp_config_path = None
        try:
            # Clean the config first
            cleaned_config_path = self._clean_config_json(config_path)
            if cleaned_config_path != config_path:
                temp_config_path = cleaned_config_path
            
            record = vault.KeeperRecord.load(params, record_uid)
            if not isinstance(record, (vault.PasswordRecord, vault.TypedRecord)):
                raise CommandError('service-docker-setup', 'Invalid record type for attachments')

            # Upload attachment
            upload_task = attachment.FileUploadTask(cleaned_config_path)
            upload_task.title = 'config.json'
            
            attachment.upload_attachments(params, record, [upload_task])
            record_management.update_record(params, record)
            params.sync_data = True
            api.sync_down(params)
            
            DockerSetupPrinter.print_success("Config file uploaded successfully")
        except Exception as e:
            raise CommandError('service-docker-setup', f'Failed to upload config file: {str(e)}')
        finally:
            if temp_config_path and os.path.exists(temp_config_path):
                try:
                    os.unlink(temp_config_path)
                except:
                    pass

    def _clean_config_json(self, config_path: str) -> str:
        """Clean config.json by keeping only essential authentication keys"""
        import tempfile
        
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            # Essential keys for authentication
            essential_keys = {
                'server', 'user', 'device_token', 'private_key',
                'device_id', 'clone_code', 'session_token', 'data_key'
            }
            
            cleaned_config = {k: v for k, v in config_data.items() if k in essential_keys}
            removed_count = len(config_data) - len(cleaned_config)
            
            if removed_count > 0:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                    json.dump(cleaned_config, tmp_file, indent=2)
                    temp_path = tmp_file.name
                
                DockerSetupPrinter.print_success(
                    f"Config cleaned (kept {len(cleaned_config)} essential keys, removed {removed_count} non-essential)"
                )
                return temp_path
            else:
                DockerSetupPrinter.print_success("Config is already minimal")
                return config_path
                
        except Exception as e:
            DockerSetupPrinter.print_warning(f"Could not clean config: {str(e)}")
            return config_path

    def _create_ksm_app(self, params, app_name: str, force: bool) -> str:
        """Create KSM app or return existing one"""
        # Check if app exists
        existing_app = KSMCommand.get_app_record(params, app_name)
        if existing_app:
            msg = "App already exists, using existing" if force else "Using existing app"
            if force:
                DockerSetupPrinter.print_warning(msg)
            else:
                DockerSetupPrinter.print_success(msg)
            return existing_app.get('record_uid')

        # Create new app
        try:
            import sys
            import io
            
            # Suppress KSM command output
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                KSMCommand.add_new_v5_app(params, app_name, force_to_add=False, format_type='table')
            finally:
                sys.stdout = old_stdout
            
            api.sync_down(params)
            
            app_rec = KSMCommand.get_app_record(params, app_name)
            if not app_rec:
                raise CommandError('service-docker-setup', 'Failed to retrieve created app')
            
            app_uid = app_rec.get('record_uid')
            DockerSetupPrinter.print_success(f"App created successfully (UID: {app_uid})")
            return app_uid
        except Exception as e:
            raise CommandError('service-docker-setup', f'Failed to create KSM app: {str(e)}')

    def _share_folder_with_app(self, params, app_uid: str, folder_uid: str) -> None:
        """Share the folder with the KSM app"""
        try:
            import sys
            import io
            
            app_rec = KSMCommand.get_app_record(params, app_uid)
            if not app_rec:
                raise CommandError('service-docker-setup', 'App not found')

            # Suppress output
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                KSMCommand.add_app_share(
                    params,
                    secret_uids=[folder_uid],
                    app_name_or_uid=app_uid,
                    is_editable=True
                )
            finally:
                sys.stdout = old_stdout
            
            DockerSetupPrinter.print_success("Folder shared with app successfully")
        except Exception as e:
            raise CommandError('service-docker-setup', f'Failed to share folder with app: {str(e)}')

    def _create_client_device(self, params, app_uid: str, app_name: str) -> str:
        """Create client device and return b64 config"""
        try:
            client_name = f"{app_name} Docker Client"
            
            tokens_and_devices = KSMCommand.add_client(
                params=params,
                app_name_or_uid=app_uid,
                count=1,
                unlock_ip=True,
                first_access_expire_on=60,
                access_expire_in_min=None,
                client_name=client_name,
                config_init='b64',
                silent=True
            )
            
            if not tokens_and_devices or len(tokens_and_devices) == 0:
                raise CommandError('service-docker-setup', 'Failed to generate client device')

            b64_config = tokens_and_devices[0]['config']
            DockerSetupPrinter.print_success("Client device created successfully")
            
            return b64_config
        except Exception as e:
            raise CommandError('service-docker-setup', f'Failed to create client device: {str(e)}')
