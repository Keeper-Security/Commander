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
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional
from ..decorators.logging import logger
from .config import slack_config


class SlackClient:
    """Slack Web API client wrapper."""
    
    def __init__(self):
        self.base_url = "https://slack.com/api"
        
    def _make_request(self, method: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make a request to Slack API."""
        if not slack_config.bot_token:
            raise ValueError("Slack bot token not configured")
            
        url = f"{self.base_url}/{method}"
        headers = {
            'Authorization': f'Bearer {slack_config.bot_token}',
            'Content-Type': 'application/json; charset=utf-8'
        }
        
        try:
            json_data = json.dumps(data).encode('utf-8')
            req = urllib.request.Request(url, data=json_data, headers=headers)
            
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                
            if not response_data.get('ok'):
                error = response_data.get('error', 'Unknown error')
                logger.error(f"Slack API error for {method}: {error}")
                raise SlackAPIError(f"Slack API error: {error}")
                
            return response_data
            
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP error calling Slack API {method}: {e}")
            raise SlackAPIError(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"Error calling Slack API {method}: {e}")
            raise SlackAPIError(f"Request error: {e}")
    
    def post_message(self, channel: str, text: str = None, blocks: list = None, 
                    thread_ts: str = None) -> Dict[str, Any]:
        """Post a message to a Slack channel."""
        data = {
            'channel': channel
        }
        
        if text:
            data['text'] = text
        if blocks:
            data['blocks'] = blocks
        if thread_ts:
            data['thread_ts'] = thread_ts
            
        return self._make_request('chat.postMessage', data)
    
    def post_ephemeral(self, channel: str, user: str, text: str = None, 
                      blocks: list = None) -> Dict[str, Any]:
        """Post an ephemeral (private) message to a user in a channel."""
        data = {
            'channel': channel,
            'user': user
        }
        
        if text:
            data['text'] = text
        if blocks:
            data['blocks'] = blocks
            
        return self._make_request('chat.postEphemeral', data)
    
    def update_message(self, channel: str, ts: str, text: str = None, 
                      blocks: list = None) -> Dict[str, Any]:
        """Update an existing message."""
        data = {
            'channel': channel,
            'ts': ts
        }
        
        if text:
            data['text'] = text
        if blocks:
            data['blocks'] = blocks
            
        return self._make_request('chat.update', data)
    
    def get_user_info(self, user: str) -> Dict[str, Any]:
        """Get information about a user."""
        data = {'user': user}
        return self._make_request('users.info', data)
    
    def get_user_by_email(self, email: str) -> Dict[str, Any]:
        """Get user information by email address."""
        data = {'email': email}
        return self._make_request('users.lookupByEmail', data)
    
    def get_channel_info(self, channel: str) -> Dict[str, Any]:
        """Get information about a channel."""
        data = {'channel': channel}
        return self._make_request('conversations.info', data)


class SlackAPIError(Exception):
    """Exception raised for Slack API errors."""
    pass


# Global client instance
slack_client = SlackClient()
