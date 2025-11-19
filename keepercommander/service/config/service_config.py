#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import logging
from pathlib import Path
import shutil
from typing import Dict, Any, Optional
from configparser import ConfigParser

import yaml
from .file_handler import ConfigFormatHandler
from .models import ServiceConfigData
from ..decorators.logging import logger, debug_decorator
from ..util.exceptions import ValidationError
from ... import resources, utils
from ...params import KeeperParams


VALID_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".key"}
class ServiceConfig:
    def __init__(self, title: str = 'Commander Service Mode'):
        self.title = title
        
        self.config = ConfigParser()

        config_ini_path = Path(resources.__file__).parent / 'service_config.ini'
        self.config.read(config_ini_path)
        self.messages = self.config['Messages']
        self.validation_messages = self.config['Validation_Messages']

        default_path = utils.get_default_path()

        self.format_handler = ConfigFormatHandler(
            config_dir=default_path,
            messages=self.messages,
            validation_messages=self.validation_messages
        )
        self.config_path = self.format_handler.config_path

        self._validator = None
        self._cli_handler = None
        self._command_validator = None
        self._record_handler = None

    @property
    def validator(self):
        if self._validator is None:
            from .config_validation import ConfigValidator
            self._validator = ConfigValidator()
        return self._validator

    @property
    def cli_handler(self):
        if self._cli_handler is None:
            from .cli_handler import CommandHandler
            self._cli_handler = CommandHandler()
        return self._cli_handler

    @property
    def command_validator(self):
        if self._command_validator is None:
            from .command_validator import CommandValidator
            self._command_validator = CommandValidator()
        return self._command_validator

    @property
    def record_handler(self):
        if self._record_handler is None:
            from .record_handler import RecordHandler
            self._record_handler = RecordHandler()
        return self._record_handler

    @debug_decorator
    def create_default_config(self) -> Dict[str, Any]:
        """Create default configuration structure."""
        config = ServiceConfigData(
            title=self.title,
            port=None,
            ngrok="n",
            ngrok_auth_token="",
            ngrok_custom_domain="",
            ngrok_public_url="",
            cloudflare="n",
            cloudflare_tunnel_token="",
            cloudflare_custom_domain="",
            cloudflare_public_url="",
            tls_certificate="n",
            certfile="",
            certpassword="",
            is_advanced_security_enabled="n",
            rate_limiting="",
            ip_allowed_list="",
            ip_denied_list="",
            encryption="",
            encryption_private_key="",
            fileformat="yaml",
            run_mode="foreground",
            queue_enabled="y",
            records=[]
        ).__dict__
        return config

    def save_config(self, config_data: Dict[str, Any], save_type: str = None) -> Path:
        """Save configuration to file."""
        self._validate_config_structure(config_data)
        return self.format_handler.save_config(config_data, save_type)

    

    def get_cert_paths(self, config_data: Dict[str, Any]) -> Dict[str, Path]:
        """Retrieve certificate file paths with validation."""
        cert_paths = {}
        for key in ["certfile", "certpassword"]:
            if config_data.get(key):
                file_path = Path(config_data[key])
                if file_path.suffix in VALID_CERT_EXTENSIONS:
                    cert_paths[key] = file_path
                else:
                    raise ValueError(f"Invalid file format for {key}: {file_path}. Allowed: {VALID_CERT_EXTENSIONS}")
        return cert_paths

    def update_service_config(self, updates: Dict[str, str]) -> None:
        """
        Update specified keys in the service configuration file (.json or .yml).

        Args:
            updates: Dictionary where each key is a config field (like 'certfile')
                    and value is the **certificate file name** stored in `.keeper`.
        """
        try:
            config_dir = utils.get_default_path()
            config_dir.mkdir(parents=True, exist_ok=True)  # Ensure directory exists

            # Find any service_config file
            config_path = None
            file_format = None

            for file in config_dir.glob("service_config.*"):
                ext = file.suffix.lower()
                if ext in [".json", ".yml", ".yaml"]:
                    config_path = file
                    file_format = "json" if ext == ".json" else "yaml"
                    break

            if config_path: 
                self.read_plain_text_config_file(config_path, file_format, updates)
            else:
                logging.info("No existing service_config file found.")

        except Exception as e:
            logging.info(f"Error updating service configuration: {e}")
    
    # Read plain text config file and update configuration
    def read_plain_text_config_file(self, config_path: str, file_format: str, updates: Dict[str, str]) -> None:
        """ Read plain text config file and update configuration """
        with open(config_path, "r") as f:
                     config_data = json.load(f) if file_format == "json" else yaml.safe_load(f) or {}
        config_data.update(updates)
        # Save updated configuration
        with open(config_path, "w") as f:
            if file_format == "json":
                    json.dump(config_data, f, indent=4)
            else:
                yaml.safe_dump(config_data, f, default_flow_style=False)
        utils.set_file_permissions(config_path)
 
        logging.info(f"Updated keys in {config_path.name}: {', '.join(updates.keys())}")

    def save_cert_data(self, config_data: Dict[str, Any], save_type: str = None) -> Path:
        """Save certificate and password files in the .keeper folder and update service_config.json/.yml."""
        try:
            keeper_dir = utils.get_default_path()
            keeper_dir.mkdir(parents=True, exist_ok=True)

            cert_paths = self.get_cert_paths(config_data)
            
            if not cert_paths:
                return keeper_dir

            updated_names = {}
            saved_files = []

            for key, src_path in cert_paths.items():
                dest_path = keeper_dir / src_path.name
                if src_path.exists():
                    shutil.copy(src_path, dest_path)
                    utils.set_file_permissions(str(dest_path))
                    saved_files.append(dest_path)
                    updated_names[key] = src_path.name  # Store only the filename, not the full path
                else:
                    raise FileNotFoundError(f"File not found: {src_path}")

            self.update_service_config(updated_names)

            if saved_files:
                logging.info(f"Certificates saved in {keeper_dir}: {', '.join(str(f.name) for f in saved_files)}")
            return keeper_dir

        except Exception as e:
            logging.info(f"Error saving certificate data: {e}")
            return None

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        config = self.format_handler.load_config()
        
        # Add backwards compatibility for missing queue_enabled field
        if 'queue_enabled' not in config:
            config['queue_enabled'] = 'y'  # Default to enabled for existing configs
            logger.debug("Added default queue_enabled=y for backwards compatibility")

        # Add backwards compatibility for missing Cloudflare fields
        if 'cloudflare' not in config:
            config['cloudflare'] = 'n'  # Default to disabled for existing configs
            logger.debug("Added default cloudflare=n for backwards compatibility")
        
        if 'cloudflare_tunnel_token' not in config:
            config['cloudflare_tunnel_token'] = ''
            logger.debug("Added default cloudflare_tunnel_token for backwards compatibility")
        
        if 'cloudflare_custom_domain' not in config:
            config['cloudflare_custom_domain'] = ''
            logger.debug("Added default cloudflare_custom_domain for backwards compatibility")
        
        if 'cloudflare_public_url' not in config:
            config['cloudflare_public_url'] = ''
            logger.debug("Added default cloudflare_public_url for backwards compatibility")
        
        self._validate_config_structure(config)
        return config

    @debug_decorator
    def _validate_config_structure(self, config: Dict[str, Any]) -> None:
        """Validate the configuration structure."""
        try:
            config_data = ServiceConfigData(**config)
        except TypeError as e:
            raise ValidationError(f"Invalid configuration structure: {str(e)}")

        if config_data.ngrok == 'y':
            logger.debug("Validating ngrok configuration")
            self.validator.validate_ngrok_token(config_data.ngrok_auth_token)

        if config_data.cloudflare == 'y':
            logger.debug("Validating cloudflare configuration")
            self.validator.validate_cloudflare_token(config_data.cloudflare_tunnel_token)
            self.validator.validate_domain(config_data.cloudflare_custom_domain)

        if config_data.is_advanced_security_enabled == 'y':
            logger.debug("Validating advanced security settings")
            self.validator.validate_rate_limit(config_data.rate_limiting)
            self.validator.validate_ip_list(config_data.ip_allowed_list)
            self.validator.validate_ip_list(config_data.ip_denied_list)

        if config_data.encryption == 'y':
            logger.debug("Validating encryption settings")
            self.validator.validate_encryption_key(config_data.encryption_private_key)

    def _get_yes_no_input(self, prompt: str) -> str:
        logger.debug(f"Requesting y/n input with prompt: {prompt}")
        while True:
            if (user_input := input(prompt).lower()) in ['y', 'n']:
                logger.debug(f"Received valid input: {user_input}")
                return user_input
            print(self.validation_messages['invalid_input'])

    def validate_command_list(self, commands: str, params: KeeperParams = None) -> str:
        """Validate command list against available Keeper Commander commands."""
        if not commands:
            raise ValidationError("Command list cannot be empty")
        help_output = self.cli_handler.get_help_output(params)
        valid_commands, command_info = self.command_validator.parse_help_output(help_output)
        validated_commands, invalid_commands = self.command_validator.validate_command_list(commands, valid_commands)
        
        if invalid_commands:
            error_msg = self.command_validator.generate_command_error_message(invalid_commands, command_info)
            raise ValidationError(error_msg)

        return validated_commands

    def _get_validated_commands(self, params: KeeperParams) -> str:
        """Get and validate command list from user input."""
        while True:
            try:
                command_list = input(self.messages['command_list_prompt'])
                return self.validate_command_list(command_list, params)
            except ValidationError as e:
                print(f"\nError: {str(e)}")
                print("\nPlease try again with valid commands.")

    def create_record(self, is_advanced_security_enabled: str, params: KeeperParams, commands: Optional[str] = None) -> Dict[str, Any]:
        """Create a new configuration record."""
        commands = self.validate_command_list(commands, params) if commands else self._get_validated_commands(params)
        return self.record_handler.create_record(is_advanced_security_enabled, commands)

    def update_or_add_record(self, params: KeeperParams) -> None:
        """Update existing record or add new one."""
        self.record_handler.update_or_add_record(params, self.title, self.format_handler.config_path)
        logger.debug(f" Uploaded file remote success.")
        self.format_handler.encrypt_config_file(self.format_handler.config_path, self.format_handler.config_dir)
        logger.debug(f" Local file encryption success.")
        try:
            config = self.load_config()
            if config.get("tls_certificate") == "y":
                self.record_handler.update_or_add_cert_record(params, self.title)
                logger.debug(f" Uploaded TLS certificate at remote.")
            else:
                logger.debug(f" TLS certificate upload skipped - TLS not enabled.")
        except Exception as e:
            logger.debug(f"Error checking TLS configuration: {e}")