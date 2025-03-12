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
from ..decorators.logging import logger
from ..util.exceptions import ValidationError
from .cli_handler import CommandHandler

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
                    return 'json'
                if yaml_path.exists():
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
        format_type = self.get_config_format(save_type)
        logger.debug(f"Saving config in format: {format_type}")

        base_path = self.config_dir / 'service_config'
        config_path = base_path.with_suffix(f'.{format_type}')
        
        try:
            if format_type == 'json':
                return self._save_json(config_data, config_path)
            return self._save_yaml(config_data, config_path)
        except IOError as e:
            raise ValidationError(f"Failed to save configuration: {str(e)}")

    def _save_json(self, config_data: Dict[str, Any], config_path) -> Path:
        """Save configuration as JSON."""
        config_path.write_text(json.dumps(config_data, indent=4))
        logger.debug(f"Configuration saved to {config_path}")
        return config_path

    def _save_yaml(self, config_data: Dict[str, Any], config_path) -> Path:
        """Save configuration as YAML."""
        with open(config_path, 'w') as yaml_file:
            yaml.dump(config_data, yaml_file, default_flow_style=False)
        logger.debug(f"Configuration saved to {config_path}")
        return config_path

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file in current format."""
        config_path = self.config_path
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        format_type = self.get_config_format()
        try:
            if format_type == 'json':
                return self._load_json()
            return self._load_yaml()
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise ValidationError(f"Invalid {format_type.upper()} format: {str(e)}")

    def _load_json(self) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        config = json.loads(self.config_path.read_text())
        if not isinstance(config, dict):
            raise ValidationError("Invalid JSON structure. Expected a dictionary.")
        return config

    def _load_yaml(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        with open(self.config_path, 'r') as yaml_file:
            config = yaml.safe_load(yaml_file)
        if not isinstance(config, dict):
            raise ValidationError("Invalid YAML structure. Expected a dictionary.")
        return config