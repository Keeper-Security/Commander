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

"""Docker setup data models and constants."""

from dataclasses import dataclass
from enum import Enum


# ========================
# Constants
# ========================

class DockerSetupConstants:
    """Defaults for docker setup."""
    DEFAULT_FOLDER_NAME = 'Commander Service Mode - Docker'
    DEFAULT_APP_NAME = 'Commander Service Mode - KSM App'
    DEFAULT_RECORD_NAME = 'Commander Service Mode Docker Config'
    DEFAULT_CLIENT_NAME = 'Commander Service Mode - KSM App Client'
    
    # Default service configuration
    DEFAULT_PORT = 8900
    DEFAULT_COMMANDS = 'tree,ls'
    DEFAULT_TIMEOUT = '30d'
    
    RECORD_UID_KEY = 'record_uid'
    KSM_CONFIG_KEY = 'ksm_config'


class SetupStep(Enum):
    """Enumeration for setup steps"""
    DEVICE_SETUP = 1
    CREATE_FOLDER = 2
    CREATE_RECORD = 3
    UPLOAD_CONFIG = 4
    CREATE_KSM_APP = 5
    SHARE_FOLDER = 6
    CREATE_CLIENT = 7


@dataclass
class SetupResult:
    folder_uid: str
    folder_name: str
    app_uid: str
    app_name: str
    record_uid: str
    b64_config: str


@dataclass
class ServiceConfig:
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
    slack_app_token: str
    slack_bot_token: str
    slack_signing_secret: str
    approvals_channel_id: str
    pedm_enabled: bool = False
    pedm_polling_interval: int = 120
    device_approval_enabled: bool = False
    device_approval_polling_interval: int = 120


@dataclass
class TeamsConfig:
    client_id: str
    client_secret: str
    tenant_id: str
    approvals_channel_id: str
    approvals_team_id: str
    pedm_enabled: bool = False
    pedm_polling_interval: int = 120
    device_approval_enabled: bool = False
    device_approval_polling_interval: int = 120

