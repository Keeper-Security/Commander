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
import yaml
from pathlib import Path
from typing import Dict, Any
from .cli_handler import CommandHandler
from ..decorators.logging import logger
from ..util.exceptions import ValidationError

class ConfigFormatHandler:
    def __init__(self, config_dir: Path, messages: Dict, validation_messages: Dict):
        self.config_dir = config_dir
        self.messages = messages
        self.validation_messages = validation_messages
        self.cli_handler = CommandHandler()
        self._config_path = None

    @property
    def config_path(self) -> Path:
        """Get the current configuration path based on existing files."""
        self._config_path = self._get_config_path()
        return self._config_path

    def _get_config_path(self) -> Path:
        """Get the configuration file path based on what exists."""
        format_type = self.get_config_format()
        logger.debug(f"Getting config path for format: {format_type}")
        base_path = self.config_dir / 'service_config'
        return base_path.with_suffix(f'.{format_type}')

    def get_config_format(self, save_type: str = None) -> str:
        """Get configuration format based on existing files."""
        json_path = self.config_dir / 'service_config.json'
        yaml_path = self.config_dir / 'service_config.yaml'
        
        if json_path.exists():
            return 'json'
        if yaml_path.exists():
            return 'yaml'
            
        from ..core.globals import get_current_params
        if params := get_current_params():
            if self.cli_handler.download_config_from_vault(params, 'Commander Service Mode', self.config_dir):
                if json_path.exists():
                    self.encrypt_config_file(json_path, self.config_dir)
                    return 'json'
                if yaml_path.exists():
                    self.encrypt_config_file(yaml_path, self.config_dir)
                    return 'yaml'
        
        return self._get_format_input() if save_type == 'create' else 'json'
    
    def _get_format_input(self) -> str:
        """Get format input from user during service creation."""
        while True:
            format_type = input(self.messages['config_format_prompt']).strip().lower()
            if format_type in ['json', 'yaml']:
                return format_type
            print(self.validation_messages['invalid_format'])

    def save_config(self, config_data: Dict[str, Any], save_type: str = None) -> Path:
        """Save configuration to file in the current format."""
        if save_type in ("json", "yaml"):
            format_type = save_type
        else:
            format_type = self.get_config_format(save_type)
        logger.debug(f"Saving config in format: {format_type}")

        base_path = self.config_dir / 'service_config'
        config_path = base_path.with_suffix(f'.{format_type}')
        
        try:
            if format_type == 'json':
                logger.debug(f"Saving Configuration to JSON")
                base_path.with_suffix(f'.yaml').unlink(missing_ok=True)
                return self._save_json(config_data, config_path)
            logger.debug(f"Saving Configuration to YAML")
            base_path.with_suffix(f'.json').unlink(missing_ok=True)
            return self._save_yaml(config_data, config_path)
        except IOError as e:
            raise ValidationError(f"Failed to save configuration: {str(e)}")

    def _save_json(self, config_data: Dict[str, Any], config_path) -> Path:
        """Save configuration as JSON."""
        config_path.write_text(json.dumps(config_data, indent=4))
        from ... import utils
        utils.set_file_permissions(str(config_path))
        logger.debug(f"Configuration saved to {config_path}")
        # self.encrypt_config_file(config_path, self.config_dir)
        return config_path

    def _save_yaml(self, config_data: Dict[str, Any], config_path) -> Path:
        """Save configuration as YAML."""
        with open(config_path, 'w') as yaml_file:
            yaml.dump(config_data, yaml_file, default_flow_style=False)
        from ... import utils
        utils.set_file_permissions(str(config_path))
        logger.debug(f"Configuration saved to {config_path}")
        # self.encrypt_config_file(config_path, self.config_dir)
        return config_path

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file in current format."""
        config_path = self.config_path
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        from ... import utils
        utils.ensure_config_permissions(str(config_path))
        
        format_type = self.get_config_format()
        try:
            if format_type == 'json':
                return self._load_json()
            return self._load_yaml()
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise ValidationError(f"Invalid {format_type.upper()} format: {str(e)}")

    def _load_json(self) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            decrypted_content = self.decrypt_config_file(self.config_path.read_bytes(), self.config_dir)
            return json.loads(decrypted_content)
        except Exception as e:
            raise ValidationError(f"Failed to decrypt configuration file: {str(e)}")
    
    def _load_yaml(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            decrypted_content = self.decrypt_config_file(self.config_path.read_bytes(), self.config_dir)
            yaml_content = yaml.safe_load(decrypted_content)
            if not isinstance(yaml_content, dict):
                raise ValidationError("Invalid YAML structure. Expected a dictionary.")
            return yaml_content
        except Exception as e:
            raise ValidationError(f"Failed to decrypt configuration file: {str(e)}")

    @staticmethod
    def encrypted_content(plaintext, config_path: Path, config_dir ) -> bytes:
        """Encrypt the content of the configuration file."""
        from hashlib import sha256
        from ...crypto import encrypt_aes_v2
        config_json = config_dir / "config.json"
        if not config_json.exists():
            raise FileNotFoundError(f"Config.json file not found: {config_json}")
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        try:
            with open(config_json, 'r') as json_file:
                config_json_data = json.load(json_file)
            private_key = config_json_data.get("private_key")
            if not private_key:
                raise ValidationError("Field 'private_key' not found in the configuration file.")
            hashed_key = sha256(private_key.encode('utf-8')).digest()
            if isinstance(plaintext, dict):
                plaintext = json.dumps(plaintext)
            encrypted_content = encrypt_aes_v2(plaintext.encode('utf-8'), hashed_key)
            return encrypted_content
        except Exception as e:
            raise ValidationError(f"Failed to encrypt configuration file: {str(e)}")
            
    @staticmethod
    def encrypt_config_file(config_path: Path, config_dir: Path) -> None:
        """Encrypt the content of the configuration file and save it back."""
        encrypted_content = ConfigFormatHandler.encrypted_content(config_path.read_text(), config_path, config_dir)
        with open(config_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_content)
        logger.debug(f" {config_path} File encryption success. ")
        
        
    @staticmethod
    def decrypt_config_file(encrypted_content: bytes, config_dir: Path) -> str:
        """Decrypt the content of the configuration file and return it as a string."""
        from hashlib import sha256
        from ...crypto import decrypt_aes_v2
        config_json = config_dir / "config.json"
        if not config_json.exists():
            raise FileNotFoundError(f"Config.json file not found: {config_json}")
        try:
            with open(config_json, 'r') as json_file:
                config_json_data = json.load(json_file)
            private_key = config_json_data.get("private_key")
            if not private_key:
                raise ValidationError("Field 'private_key' not found in the configuration file.")
            hashed_key = sha256(private_key.encode('utf-8')).digest()
            return decrypt_aes_v2(encrypted_content, hashed_key).decode('utf-8')
        except Exception as e:
            raise ValidationError(f"Failed to decrypt configuration file: {str(e)}")