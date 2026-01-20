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
Data models and constants for Docker setup.
"""

from dataclasses import dataclass
from enum import Enum


# ========================
# Constants
# ========================

class DockerSetupConstants:
    """Constants for Docker setup command"""
    # Default resource names for service-docker-setup
    DEFAULT_FOLDER_NAME = 'Commander Service Mode - Docker'
    DEFAULT_APP_NAME = 'Commander Service Mode - KSM App'
    DEFAULT_RECORD_NAME = 'Commander Service Mode Docker Config'
    DEFAULT_CLIENT_NAME = 'Commander Service Mode - KSM App Client'
    
    # Default resource names for slack-app-setup
    DEFAULT_SLACK_FOLDER_NAME = 'Commander Service Mode - Slack App'
    DEFAULT_SLACK_RECORD_NAME = 'Commander Service Mode Slack App Config'
    
    # Default service configuration
    DEFAULT_PORT = 8900
    DEFAULT_COMMANDS = 'tree,ls'
    DEFAULT_TIMEOUT = '30d'
    
    # Essential config keys
    RECORD_UID_KEY = 'record_uid'
    KSM_CONFIG_KEY = 'ksm_config'


# ========================
# Enums
# ========================


class SetupStep(Enum):
    """Enumeration for setup steps"""
    DEVICE_SETUP = 1
    CREATE_FOLDER = 2
    CREATE_RECORD = 3
    UPLOAD_CONFIG = 4
    CREATE_KSM_APP = 5
    SHARE_FOLDER = 6
    CREATE_CLIENT = 7


# ========================
# Data Classes
# ========================

@dataclass
class SetupResult:
    """Container for setup results that can be reused by integration commands"""
    folder_uid: str
    folder_name: str
    app_uid: str
    app_name: str
    record_uid: str
    b64_config: str


@dataclass
class ServiceConfig:
    """Service configuration for Docker deployment"""
    port: int
    commands: str
    queue_enabled: bool
    ngrok_enabled: bool
    ngrok_auth_token: str
    ngrok_custom_domain: str
    cloudflare_enabled: bool
    cloudflare_tunnel_token: str
    cloudflare_custom_domain: str
    allowed_ip: str = '0.0.0.0/0,::/0'
    denied_ip: str = ''
    rate_limit: str = ''
    encryption_enabled: bool = False
    encryption_key: str = ''
    token_expiration: str = ''
    ngrok_public_url: str = ''
    cloudflare_public_url: str = ''


@dataclass
class SlackConfig:
    """Slack App configuration for Docker deployment"""
    slack_app_token: str
    slack_bot_token: str
    slack_signing_secret: str
    approvals_channel_id: str
    pedm_enabled: bool = False
    pedm_polling_interval: int = 120
    device_approval_enabled: bool = False
    device_approval_polling_interval: int = 120

