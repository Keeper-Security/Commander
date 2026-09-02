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

from dataclasses import dataclass, field
from enum import Enum
from typing import List


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
class ApproverTeam:
    team_uid: str
    name: str
    channel_id: str
    folder_uids: List[str] = field(default_factory=list)
    record_uids: List[str] = field(default_factory=list)


@dataclass
class ApprovalsConfig:
    multi_channel_enabled: bool
    single_channel_id: str = ''
    teams: List[ApproverTeam] = field(default_factory=list)


@dataclass
class SlackConfig:
    slack_app_token: str
    slack_bot_token: str
    slack_signing_secret: str
    approvals: ApprovalsConfig
    pedm_enabled: bool = False
    pedm_polling_interval: int = 120
    device_approval_enabled: bool = False
    device_approval_polling_interval: int = 120

    @property
    def approvals_channel_id(self) -> str:
        return self.approvals.single_channel_id


@dataclass
class TeamsConfig:
    client_id: str
    client_secret: str
    tenant_id: str
    approvals_channel_id: str
    approvals_team_id: str
    bot_port: int = 3978
    pedm_enabled: bool = False
    pedm_polling_interval: int = 120
    device_approval_enabled: bool = False
    device_approval_polling_interval: int = 120


@dataclass
class SailPointConfig:
    allow_folders: bool = True
    allow_records: bool = True
    allow_roles: bool = True
    allow_teams: bool = True
    transfer_target_email: str = ''
    # Keep in sync with sailpoint.constants.DEFAULT_POLL_INTERVAL_SECONDS
    poll_interval_seconds: int = 60


class GChatConstants:
    """Defaults and field labels for Google Chat app setup."""
    INTEGRATION_NAME = 'GChat'
    DISPLAY_NAME = 'Google Chat'
    DEFAULT_FOLDER_NAME = 'Commander Service Mode - Google Chat App'
    DEFAULT_RECORD_NAME = 'Commander Service Mode Google Chat App Config'

    FIELD_SERVICE_ACCOUNT_JSON = 'google_service_account_json'
    FIELD_PROJECT_ID = 'google_project_id'
    FIELD_SUBSCRIPTION_ID = 'google_subscription_id'
    FIELD_TOPIC_ID = 'google_topic_id'
    FIELD_APPROVALS_SPACE_ID = 'chat_approvals_space_id'
    FIELD_COMMAND_REQUEST_RECORD_ID = 'chat_command_request_record_id'
    FIELD_COMMAND_REQUEST_FOLDER_ID = 'chat_command_request_folder_id'
    FIELD_COMMAND_EXTERNAL_SHARE_ID = 'chat_command_external_share_id'
    FIELD_COMMAND_CREATE_SECRET_ID = 'chat_command_create_secret_id'
    FIELD_PEDM_ENABLED = 'pedm_enabled'
    FIELD_PEDM_POLLING_INTERVAL = 'pedm_polling_interval'
    FIELD_DEVICE_APPROVAL_ENABLED = 'device_approval_enabled'
    FIELD_DEVICE_APPROVAL_POLLING_INTERVAL = 'device_approval_polling_interval'
    FIELD_MULTI_CHANNEL_ENABLED = 'multi_channel_approvers_enabled'
    FIELD_APPROVALS_TEAMS = 'approvals_teams'

    DEFAULT_COMMAND_REQUEST_RECORD_ID = '1'
    DEFAULT_COMMAND_REQUEST_FOLDER_ID = '2'
    DEFAULT_COMMAND_EXTERNAL_SHARE_ID = '3'
    DEFAULT_COMMAND_CREATE_SECRET_ID = '4'

    SPACE_ID_PREFIX = 'spaces/'
    SERVICE_ACCOUNT_TYPE = 'service_account'
    SERVICE_ACCOUNT_REQUIRED_KEYS = (
        'type',
        'project_id',
        'private_key',
        'client_email',
    )


@dataclass
class GChatConfig:
    google_service_account_json: str
    google_project_id: str
    google_subscription_id: str
    google_topic_id: str
    chat_approvals_space_id: str
    chat_command_request_record_id: str = GChatConstants.DEFAULT_COMMAND_REQUEST_RECORD_ID
    chat_command_request_folder_id: str = GChatConstants.DEFAULT_COMMAND_REQUEST_FOLDER_ID
    chat_command_external_share_id: str = GChatConstants.DEFAULT_COMMAND_EXTERNAL_SHARE_ID
    chat_command_create_secret_id: str = GChatConstants.DEFAULT_COMMAND_CREATE_SECRET_ID
    approvals: ApprovalsConfig = field(default_factory=lambda: ApprovalsConfig(
        multi_channel_enabled=False, single_channel_id=''
    ))
    pedm_enabled: bool = False
    pedm_polling_interval: int = 120
    device_approval_enabled: bool = False
    device_approval_polling_interval: int = 120
