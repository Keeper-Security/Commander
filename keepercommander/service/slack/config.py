#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander - Slack Integration
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Configuration management for Keeper Slack Integration."""

import os
import yaml
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class SlackConfig:
    """Slack application configuration."""
    
    app_token: str
    """App-level token for Socket Mode (xapp-1-...)"""
    
    bot_token: str
    """Bot user OAuth token (xoxb-...)"""
    
    signing_secret: str
    """Signing secret for verifying requests from Slack"""
    
    approvals_channel_id: str
    """Channel ID where approval requests are posted"""


@dataclass
class KeeperConfig:
    """Keeper Service Mode configuration."""
    
    service_url: str
    """URL of Keeper Commander Service Mode server"""
    
    api_key: Optional[str] = None
    """API key for authenticating with Service Mode (if required)"""


class Config:
    """
    Application configuration manager.
    
    Loads configuration from YAML file and environment variables.
    Environment variables take precedence over file configuration.
    
    Example config file (slack_config.yaml):
        slack:
          app_token: ${SLACK_APP_TOKEN}
          bot_token: ${SLACK_BOT_TOKEN}
          signing_secret: ${SLACK_SIGNING_SECRET}
          approvals_channel_id: ${APPROVALS_CHANNEL_ID}
        
        keeper:
          service_url: ${KEEPER_SERVICE_URL}
          api_key: ${KEEPER_API_KEY}
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.
        """
        self._data = {}
        
        # Try to load from file
        if config_path and os.path.exists(config_path):
            self._load_from_file(config_path)
        else:
            # Try default locations
            self._try_default_locations()
        
        # Override with environment variables
        self._load_from_env()
        
        # Validate required fields
        self._validate()
    
    def _load_from_file(self, config_path: str):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f)
                if file_config:
                    self._data.update(file_config)
        except Exception as e:
            print(f"Warning: Could not load config file {config_path}: {e}")
    
    def _try_default_locations(self):
        """Try to load configuration from default locations."""
        default_paths = [
            os.path.expanduser("~/.keeper/slack_config.yaml"),
            "./slack_config.yaml",
            "./config/slack_config.yaml"
        ]
        
        for path in default_paths:
            if os.path.exists(path):
                self._load_from_file(path)
                break
    
    def _load_from_env(self):
        """Load and override configuration from environment variables."""
        env_mappings = {
            'SLACK_APP_TOKEN': ('slack', 'app_token'),
            'SLACK_BOT_TOKEN': ('slack', 'bot_token'),
            'SLACK_SIGNING_SECRET': ('slack', 'signing_secret'),
            'APPROVALS_CHANNEL_ID': ('slack', 'approvals_channel_id'),
            'KEEPER_SERVICE_URL': ('keeper', 'service_url'),
            'KEEPER_API_KEY': ('keeper', 'api_key'),
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                if section not in self._data:
                    self._data[section] = {}
                self._data[section][key] = value
    
    def _validate(self):
        """Validate required configuration fields."""
        required_fields = [
            ('slack', 'app_token', 'SLACK_APP_TOKEN'),
            ('slack', 'bot_token', 'SLACK_BOT_TOKEN'),
            ('slack', 'signing_secret', 'SLACK_SIGNING_SECRET'),
            ('slack', 'approvals_channel_id', 'APPROVALS_CHANNEL_ID'),
            ('keeper', 'service_url', 'KEEPER_SERVICE_URL'),
        ]
        
        missing = []
        for section, key, env_var in required_fields:
            if section not in self._data or key not in self._data[section]:
                missing.append(env_var)
        
        if missing:
            raise ValueError(
                f"Missing required configuration: {', '.join(missing)}\n\n"
                f"Set these via environment variables or in slack_config.yaml\n"
                f"See SLACK_SETUP.md for detailed instructions."
            )
    
    @property
    def slack(self) -> SlackConfig:
        """Get Slack configuration."""
        slack_data = self._data['slack']
        return SlackConfig(
            app_token=slack_data['app_token'],
            bot_token=slack_data['bot_token'],
            signing_secret=slack_data['signing_secret'],
            approvals_channel_id=slack_data['approvals_channel_id']
        )
    
    @property
    def keeper(self) -> KeeperConfig:
        """Get Keeper configuration."""
        keeper_data = self._data.get('keeper', {})
        return KeeperConfig(
            service_url=keeper_data.get('service_url', 'http://localhost:8080'),
            api_key=keeper_data.get('api_key')
        )
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        return self._data.get(key, default)

