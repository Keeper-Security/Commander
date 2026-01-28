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
Core setup logic for Docker-based integrations.

This module provides the reusable base class for setting up
Commander Service Mode with Docker and KSM.
"""

import io
import json
import logging
import os
import sys
import tempfile
from typing import Dict, Any

from ...commands.folder import FolderMakeCommand
from ...commands.ksm import KSMCommand
from ... import api, vault, utils, attachment, record_management, loginv3
from ...display import bcolors
from ...error import CommandError

from .models import SetupResult, SetupStep, DockerSetupConstants
from .printer import DockerSetupPrinter
from ..config.config_validation import ConfigValidator, ValidationError


class DockerSetupBase:
    """Base class for Docker setup with reusable core logic"""

    def run_setup_steps(self, params, folder_name: str, app_name: str, record_name: str,
                       config_path: str, timeout: str, skip_device_setup: bool = False) -> SetupResult:
        """
        Core setup steps that can be reused by integration commands.
        Returns a SetupResult object containing all the created resources.
        """
        # Total number of steps
        total_steps = len(SetupStep)
        
        # Step 1: Device setup
        if not skip_device_setup:
            DockerSetupPrinter.print_step(SetupStep.DEVICE_SETUP.value, total_steps, "Checking device settings...")
            self._setup_device(params, timeout)
        else:
            DockerSetupPrinter.print_step(SetupStep.DEVICE_SETUP.value, total_steps, "Skipping device setup (--skip-device-setup)")

        # Step 2: Create shared folder
        DockerSetupPrinter.print_step(SetupStep.CREATE_FOLDER.value, total_steps, f"Creating shared folder '{folder_name}'...")
        folder_uid = self._create_shared_folder(params, folder_name)

        # Step 3: Create config record
        DockerSetupPrinter.print_step(SetupStep.CREATE_RECORD.value, total_steps, f"Creating record '{record_name}'...")
        record_uid = self._create_config_record(params, record_name, folder_uid)

        # Step 4: Upload config file
        DockerSetupPrinter.print_step(SetupStep.UPLOAD_CONFIG.value, total_steps, "Uploading config.json attachment...")
        self._upload_config_file(params, record_uid, config_path)

        # Step 5: Create KSM app
        DockerSetupPrinter.print_step(SetupStep.CREATE_KSM_APP.value, total_steps, f"Creating Secrets Manager app '{app_name}'...")
        app_uid = self._create_ksm_app(params, app_name)

        # Step 6: Share folder with app
        DockerSetupPrinter.print_step(SetupStep.SHARE_FOLDER.value, total_steps, "Sharing folder with app...")
        self._share_folder_with_app(params, app_uid, folder_uid)

        # Step 7: Create client device
        DockerSetupPrinter.print_step(SetupStep.CREATE_CLIENT.value, total_steps, "Creating client device and generating config...")
        b64_config = self._create_client_device(params, app_uid, app_name)

        return SetupResult(
            folder_uid=folder_uid,
            folder_name=folder_name,
            app_uid=app_uid,
            app_name=app_name,
            record_uid=record_uid,
            b64_config=b64_config
        )

    # ========================
    # Core Setup Methods
    # ========================

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
            # Suppress command output
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                ThisDeviceCommand().execute(params, ops=['timeout', timeout])
            finally:
                sys.stdout = old_stdout

        except Exception as e:
            raise CommandError('docker-setup', f'Device setup failed: {str(e)}')

    def _create_shared_folder(self, params, folder_name: str) -> str:
        """Create shared folder or return existing one"""
        # Check if folder exists
        for folder_uid, folder in params.folder_cache.items():
            if folder.name == folder_name and folder_uid in params.shared_folder_cache:
                DockerSetupPrinter.print_success("Using existing shared folder")
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
            raise CommandError('docker-setup', f'Failed to create shared folder: {str(e)}')

    def _create_config_record(self, params, record_name: str, folder_uid: str) -> str:
        """Create a config record or return existing one"""
        # Check if record exists
        if folder_uid in params.subfolder_record_cache:
            for rec_uid in params.subfolder_record_cache[folder_uid]:
                rec = api.get_record(params, rec_uid)
                if rec.title == record_name:
                    DockerSetupPrinter.print_success("Using existing record")
                    return rec_uid

        # Create new record
        try:
            record = vault.KeeperRecord.create(params, 'login')
            record.record_uid = utils.generate_uid()
            record.record_key = utils.generate_aes_key()
            record.title = record_name
            record.type_name = 'login'
            
            record_management.add_record_to_folder(params, record, folder_uid)
            api.sync_down(params)
            
            DockerSetupPrinter.print_success(f"Record created successfully (UID: {record.record_uid})")
            return record.record_uid
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to create record: {str(e)}')

    def _upload_config_file(self, params, record_uid: str, config_path: str) -> None:
        """Upload config.json as attachment to the record"""
        temp_config_path = None
        try:
            # Clean the config first
            cleaned_config_path = self._clean_config_json(config_path)
            if cleaned_config_path != config_path:
                temp_config_path = cleaned_config_path
            
            record = vault.KeeperRecord.load(params, record_uid)
            if not isinstance(record, vault.TypedRecord):
                raise CommandError('docker-setup', 'Invalid record type for attachments')
            # Delete existing config.json attachments to prevent duplicates
            self._delete_existing_config_attachments(record, params)

            # Upload attachment
            upload_task = attachment.FileUploadTask(cleaned_config_path)
            upload_task.title = 'config.json'
            
            attachment.upload_attachments(params, record, [upload_task])
            record_management.update_record(params, record)
            params.sync_data = True
            api.sync_down(params)
            
            DockerSetupPrinter.print_success("Config file uploaded successfully")
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to upload config file: {str(e)}')
        finally:
            if temp_config_path and os.path.exists(temp_config_path):
                try:
                    os.unlink(temp_config_path)
                except OSError as e:
                    # Log or handle specifically
                    print(f"Warning: Could not delete temporary config file: {e}")
                    pass

    def _delete_existing_config_attachments(self, record, params) -> None:
        """Delete any existing config.json attachments to prevent duplicates"""
        # Modern records use TypedRecord with fileRef system
        from ...record_facades import FileRefRecordFacade
        facade = FileRefRecordFacade()
        facade.record = record
        
        file_uids_to_remove = []
        for file_uid in facade.file_ref:
            if file_uid in params.record_cache:
                file_record = vault.KeeperRecord.load(params, file_uid)
                if isinstance(file_record, vault.FileRecord):
                    if file_record.name.lower() == 'config.json' or file_record.title.lower() == 'config.json':
                        file_uids_to_remove.append(file_uid)
        
        if file_uids_to_remove:
            for file_uid in file_uids_to_remove:
                facade.file_ref.remove(file_uid)
            DockerSetupPrinter.print_success(f"Removed {len(file_uids_to_remove)} existing config.json attachment(s)")

    
    def _clean_config_json(self, config_path: str) -> str:
        """Clean config.json by keeping only essential authentication keys"""
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

    def _create_ksm_app(self, params, app_name: str) -> str:
        """Create KSM app or return existing one"""
        # Check if app exists
        existing_app = KSMCommand.get_app_record(params, app_name)
        if existing_app:
            DockerSetupPrinter.print_success("Using existing app")
            return existing_app.get('record_uid')

        # Create new app
        try:
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
                raise CommandError('docker-setup', 'Failed to retrieve created app')
            
            app_uid = app_rec.get('record_uid')
            DockerSetupPrinter.print_success(f"App created successfully (UID: {app_uid})")
            return app_uid
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to create KSM app: {str(e)}')

    def _share_folder_with_app(self, params, app_uid: str, folder_uid: str) -> None:
        """Share the folder with the KSM app"""
        try:
            app_rec = KSMCommand.get_app_record(params, app_uid)
            if not app_rec:
                raise CommandError('docker-setup', 'App not found')

            # Suppress all output (stdout and logging)
            old_stdout = sys.stdout
            old_log_level = logging.root.level
            
            sys.stdout = io.StringIO()
            logging.root.setLevel(logging.CRITICAL + 1)  # Disable all logging
            try:
                KSMCommand.add_app_share(
                    params,
                    secret_uids=[folder_uid],
                    app_name_or_uid=app_uid,
                    is_editable=True
                )
            finally:
                sys.stdout = old_stdout
                logging.root.setLevel(old_log_level)     
            DockerSetupPrinter.print_success("Folder shared with app")
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to share folder with app: {str(e)}')

    def _create_client_device(self, params, app_uid: str, app_name: str) -> str:
        """Create client device and return b64 config"""
        try:
            client_name = DockerSetupConstants.DEFAULT_CLIENT_NAME
            
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
                raise CommandError('docker-setup', 'Failed to generate client device')

            b64_config = tokens_and_devices[0]['config']
            DockerSetupPrinter.print_success("Client device created successfully")
            
            return b64_config
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to create client device: {str(e)}')

    # ========================
    # Shared Configuration Methods
    # ========================

    def _get_ngrok_config(self) -> Dict[str, Any]:
        """Get ngrok configuration"""
        print(f"\n{bcolors.BOLD}Ngrok Tunneling (optional):{bcolors.ENDC}")
        print(f"  Generate a public URL for your service using ngrok")
        use_ngrok = input(f"{bcolors.OKBLUE}Enable ngrok? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {'ngrok_enabled': use_ngrok, 'ngrok_auth_token': '', 'ngrok_custom_domain': '', 'ngrok_public_url': ''}
        
        if use_ngrok:
            while True:
                token = input(f"{bcolors.OKBLUE}Ngrok auth token:{bcolors.ENDC} ").strip()
                try:
                    config['ngrok_auth_token'] = ConfigValidator.validate_ngrok_token(token)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
            
            # Validate custom domain if provided (ngrok allows subdomain prefixes)
            domain = input(f"{bcolors.OKBLUE}Ngrok custom domain [Press Enter to skip]:{bcolors.ENDC} ").strip()
            if domain:
                while True:
                    try:
                        config['ngrok_custom_domain'] = ConfigValidator.validate_domain(domain, require_tld=False)
                        # Construct ngrok public URL
                        if '.' not in config['ngrok_custom_domain']:
                            config['ngrok_public_url'] = f"https://{config['ngrok_custom_domain']}.ngrok.io"
                        else:
                            config['ngrok_public_url'] = f"https://{config['ngrok_custom_domain']}"
                        break
                    except ValidationError as e:
                        print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                        domain = input(f"{bcolors.OKBLUE}Ngrok custom domain [Press Enter to skip]:{bcolors.ENDC} ").strip()
                        if not domain:
                            break
        
        return config

    def _get_cloudflare_config(self) -> Dict[str, Any]:
        """Get Cloudflare configuration"""
        print(f"\n{bcolors.BOLD}Cloudflare Tunneling (optional):{bcolors.ENDC}")
        print(f"  Generate a public URL for your service using Cloudflare")
        use_cloudflare = input(f"{bcolors.OKBLUE}Enable Cloudflare? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {'cloudflare_enabled': use_cloudflare, 'cloudflare_tunnel_token': '', 
                  'cloudflare_custom_domain': '', 'cloudflare_public_url': ''}
        
        if use_cloudflare:
            while True:
                token = input(f"{bcolors.OKBLUE}Cloudflare tunnel token:{bcolors.ENDC} ").strip()
                try:
                    config['cloudflare_tunnel_token'] = ConfigValidator.validate_cloudflare_token(token)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
            
            while True:
                domain = input(f"{bcolors.OKBLUE}Cloudflare custom domain:{bcolors.ENDC} ").strip()
                try:
                    config['cloudflare_custom_domain'] = ConfigValidator.validate_domain(domain)
                    # Construct cloudflare public URL
                    config['cloudflare_public_url'] = f"https://{config['cloudflare_custom_domain']}"
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
        
        return config
