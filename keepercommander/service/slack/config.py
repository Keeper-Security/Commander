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

import os
from typing import Optional, List
from ..decorators.logging import logger


class SlackConfig:
    """Configuration management for Slack integration."""
    
    def __init__(self):
        self._bot_token = None
        self._signing_secret = None
        self._approval_channel = None
        self._vault_url = None
        self._eligible_requestors = None
        self._approvers = None
        self._required_approvals = None
        
    @property
    def bot_token(self) -> Optional[str]:
        """Get Slack bot token from service config."""
        if self._bot_token is None:
            try:
                from ..config.service_config import ServiceConfig
                service_config = ServiceConfig()
                config_data = service_config.load_config()
                self._bot_token = config_data.get('slack_bot_token', '')
            except Exception as e:
                logger.warning(f"Could not load bot token from config: {e}")
                # Fallback to environment variable
                self._bot_token = os.getenv('SLACK_BOT_TOKEN', '')
        return self._bot_token if self._bot_token else None
    
    @property
    def signing_secret(self) -> Optional[str]:
        """Get Slack signing secret from service config."""
        if self._signing_secret is None:
            try:
                from ..config.service_config import ServiceConfig
                service_config = ServiceConfig()
                config_data = service_config.load_config()
                self._signing_secret = config_data.get('slack_signing_secret', '')
            except Exception as e:
                logger.warning(f"Could not load signing secret from config: {e}")
                # Fallback to environment variable
                self._signing_secret = os.getenv('SLACK_SIGNING_SECRET', '')
        return self._signing_secret if self._signing_secret else None
    
    @property
    def approval_channel(self) -> Optional[str]:
        """Get Slack approval channel ID from service config."""
        if self._approval_channel is None:
            try:
                from ..config.service_config import ServiceConfig
                service_config = ServiceConfig()
                config_data = service_config.load_config()
                self._approval_channel = config_data.get('slack_approval_channel', '')
            except Exception as e:
                logger.warning(f"Could not load approval channel from config: {e}")
                # Fallback to environment variable
                self._approval_channel = os.getenv('SLACK_APPROVAL_CHANNEL', '')
        return self._approval_channel if self._approval_channel else None
    
    @property
    def vault_url(self) -> str:
        """Get Keeper vault URL, defaults to keepersecurity.com."""
        if self._vault_url is None:
            self._vault_url = os.getenv('KEEPER_VAULT_URL', 'https://keepersecurity.com/vault')
        return self._vault_url
    
    @property
    def eligible_requestors(self) -> Optional[List[str]]:
        """Get list of eligible requestors from service config."""
        if self._eligible_requestors is None:
            try:
                from ..config.service_config import ServiceConfig
                service_config = ServiceConfig()
                config_data = service_config.load_config()
                self._eligible_requestors = config_data.get('slack_eligible_requestors', [])
            except Exception as e:
                logger.warning(f"Could not load eligible requestors from config: {e}")
                self._eligible_requestors = []
        return self._eligible_requestors if self._eligible_requestors else None
    
    @property
    def approvers(self) -> Optional[List[str]]:
        """Get list of approvers from service config."""
        if self._approvers is None:
            try:
                from ..config.service_config import ServiceConfig
                service_config = ServiceConfig()
                config_data = service_config.load_config()
                self._approvers = config_data.get('slack_approvers', [])
            except Exception as e:
                logger.warning(f"Could not load approvers from config: {e}")
                self._approvers = []
        return self._approvers if self._approvers else None
    
    @property
    def required_approvals(self) -> int:
        """Get number of required approvals from service config, defaults to 1."""
        if self._required_approvals is None:
            try:
                from ..config.service_config import ServiceConfig
                service_config = ServiceConfig()
                config_data = service_config.load_config()
                self._required_approvals = config_data.get('slack_required_approvals', 1)
            except Exception as e:
                logger.warning(f"Could not load required approvals from config: {e}")
                self._required_approvals = 1
        return self._required_approvals
    
    def is_configured(self) -> bool:
        """Check if basic Slack configuration is present."""
        return bool(self.bot_token and self.signing_secret and self.approval_channel)
    
    def is_eligible_requestor(self, email: str) -> bool:
        """Check if email is in eligible requestors list, or if list is empty (allow all)."""
        eligible = self.eligible_requestors
        if eligible is None or len(eligible) == 0:
            return True  # If no list specified, allow all users
        return email.lower() in [e.lower() for e in eligible]
    
    def is_approver(self, email: str) -> bool:
        """Check if email is in approvers list, or if list is empty (allow all in channel)."""
        approvers = self.approvers
        if approvers is None or len(approvers) == 0:
            return True  # If no list specified, allow all users in approval channel
        return email.lower() in [e.lower() for e in approvers]
    
    def reset_cache(self):
        """Reset cached configuration values to force reload."""
        self._eligible_requestors = None
        self._approvers = None
        self._required_approvals = None


# Global configuration instance
slack_config = SlackConfig()
