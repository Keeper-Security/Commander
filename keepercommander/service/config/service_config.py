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
from typing import Dict, Any, List, Optional
from configparser import ConfigParser

import yaml
from keepercommander.params import KeeperParams
from .file_handler import ConfigFormatHandler
from ..decorators.logging import logger, debug_decorator
from ..util.exceptions import ValidationError
from .models import ServiceConfigData
from keepercommander import resources, utils
from .file_handler import ConfigFormatHandler


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

    # decrypt the ecnrypted config file , and update configuration and encrypt agin
    def read_decrypted_config_file(self, config_path: str, file_format: str, updates: Dict[str, str]):
         """ decrypt the ecnrypted config file , and update configuration and encrypt agin """
         config_dir = utils.get_default_path()
         decrypted_content = ConfigFormatHandler.decrypt_config_file(config_path.read_bytes(), config_dir)
         config_data = json.loads(decrypted_content) if file_format == "json" else yaml.safe_load(decrypted_content) or {}
         config_data.update(updates)
         encrypted_content = ConfigFormatHandler.encrypted_content(config_data, config_path, config_dir)
         with open(config_path, "wb") as f:
               f.write(encrypted_content)
    
    # Read plain text config file and update configuration
    def read_plain_text_config_file(self, config_path: str, file_format: str, updates: Dict[str, str]) -> None:
        """ Read plain text config file and update configuration """
        with open(config_path, "r") as f:
                     config_data = json.load(f) if file_format == "json" else yaml.safe_load(f) or {}
        # Save updated configuration
        with open(config_path, "w") as f:
            if file_format == "json":
                    json.dump(config_data, f, indent=4)
            else:
                yaml.safe_dump(config_data, f, default_flow_style=False)
 
        logging.info(f"Updated keys in {config_path.name}: {', '.join(updates.keys())}")

    def save_cert_data(self, config_data: Dict[str, Any], save_type: str = None) -> Path:
        """Save certificate and password files in the .keeper folder and update service_config.json/.yml."""
        try:
            keeper_dir = utils.get_default_path()
            keeper_dir.mkdir(parents=True, exist_ok=True)

            cert_paths = self.get_cert_paths(config_data)

            updated_names = {}
            saved_files = []

            for key, src_path in cert_paths.items():
                dest_path = keeper_dir / src_path.name
                if src_path.exists():
                    shutil.copy(src_path, dest_path)
                    saved_files.append(dest_path)
                    updated_names[key] = src_path.name  # Store only the filename, not the full path
                else:
                    raise FileNotFoundError(f"File not found: {src_path}")

            self.update_service_config(updated_names)

            logging.info(f"Certificates saved in {keeper_dir}: {', '.join(str(f.name) for f in saved_files)}")
            return keeper_dir

        except Exception as e:
            logging.info(f"Error saving certificate data: {e}")
            return None

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        config = self.format_handler.load_config()
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
        self.record_handler.update_or_add_cert_record(params, self.title)
        logger.debug(f" Uploaded TLS certificate at remote.")