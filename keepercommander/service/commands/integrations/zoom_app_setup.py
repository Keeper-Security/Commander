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

"""Zoom Chat App integration setup command."""

import ipaddress
import re
from urllib.parse import urlsplit
from typing import List

from .... import vault
from ....display import bcolors
from ...docker import ZoomConfig, ZoomConstants
from .integration_setup_base import IntegrationSetupCommand


_DOMAIN_LABEL = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$')


def is_valid_public_endpoint_url(value: str) -> bool:
    """Return whether value is an absolute HTTPS URL with a public hostname."""
    if not value or any(char.isspace() for char in value):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False

    if parsed.scheme.lower() != 'https' or not parsed.netloc or not parsed.hostname:
        return False
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        return False
    if parsed.netloc.endswith(':') or (port is not None and port < 1):
        return False

    hostname = parsed.hostname.rstrip('.')
    try:
        return ipaddress.ip_address(hostname).is_global
    except ValueError:
        pass

    if hostname.lower() == 'localhost' or '.' not in hostname:
        return False
    return all(_DOMAIN_LABEL.fullmatch(label) for label in hostname.split('.'))


class ZoomAppSetupCommand(IntegrationSetupCommand):
    """Automate Commander Service Mode setup for a Zoom Chat app."""

    def get_integration_name(self):
        return ZoomConstants.INTEGRATION_NAME

    def get_integration_display_name(self) -> str:
        return ZoomConstants.DISPLAY_NAME

    def get_default_folder_name(self) -> str:
        return ZoomConstants.DEFAULT_FOLDER_NAME

    def get_default_record_name(self) -> str:
        return ZoomConstants.DEFAULT_RECORD_NAME

    def get_integration_config_marker_field(self) -> str:
        return ZoomConstants.FIELD_CLIENT_ID

    def get_integration_service_ports(self, config) -> List[str]:
        return [f'{ZoomConstants.BOT_PORT}:{ZoomConstants.BOT_PORT}']

    def collect_integration_config(self, params) -> ZoomConfig:
        print(f"\n{bcolors.BOLD}ZOOM_CLIENT_ID:{bcolors.ENDC}")
        print("  Client ID from Zoom App Basic Information")
        client_id = self._prompt_with_validation(
            'Client ID:',
            lambda value: bool(value),
            'Client ID is required',
        )

        print(f"\n{bcolors.BOLD}ZOOM_CLIENT_SECRET:{bcolors.ENDC}")
        print("  Client Secret from Zoom App Basic Information")
        client_secret = self._prompt_with_validation(
            'Client Secret:',
            lambda value: bool(value),
            'Client Secret is required',
            hide_input=True,
        )

        print(f"\n{bcolors.BOLD}ZOOM_BOT_JID:{bcolors.ENDC}")
        print("  Bot JID from Zoom App Features → Surface")
        bot_jid = self._prompt_with_validation(
            'Bot JID:',
            lambda value: bool(value),
            'Bot JID is required',
        )

        print(f"\n{bcolors.BOLD}ZOOM_SECRET_TOKEN:{bcolors.ENDC}")
        print("  Secret Token from Zoom App Features → Access")
        secret_token = self._prompt_with_validation(
            'Secret Token:',
            lambda value: bool(value),
            'Secret Token is required',
            hide_input=True,
        )

        print(f"\n{bcolors.BOLD}CHAT COMMAND IDs:{bcolors.ENDC}")
        print("  Slash command IDs configured for the Zoom Chat app")
        chat_command_request_record_id = self._prompt_command_id(
            '/keeper-request-record',
            ZoomConstants.DEFAULT_COMMAND_REQUEST_RECORD_ID,
        )
        chat_command_request_folder_id = self._prompt_command_id(
            '/keeper-request-folder',
            ZoomConstants.DEFAULT_COMMAND_REQUEST_FOLDER_ID,
        )
        chat_command_external_share_id = self._prompt_command_id(
            '/keeper-one-time-share',
            ZoomConstants.DEFAULT_COMMAND_EXTERNAL_SHARE_ID,
        )
        chat_command_create_secret_id = self._prompt_command_id(
            '/keeper-create-secret',
            ZoomConstants.DEFAULT_COMMAND_CREATE_SECRET_ID,
        )

        print(f"\n{bcolors.BOLD}ZOOM_APPROVALS_CHANNEL_JID:{bcolors.ENDC}")
        print("  Channel JID from Zoom Team Chat channel settings")
        approvals_channel_jid = self._prompt_with_validation(
            'Approvals Channel JID:',
            lambda value: bool(value),
            'Approvals Channel JID is required',
        )

        print(f"\n{bcolors.BOLD}ZOOM_PUBLIC_ENDPOINT_URL:{bcolors.ENDC}")
        print("  Public HTTPS URL configured for the Zoom bot endpoint")
        public_endpoint_url = self._prompt_with_validation(
            'Public Endpoint URL:',
            is_valid_public_endpoint_url,
            'Enter an absolute HTTPS URL with a public hostname (for example, https://xyz.ngrok.app/zoom/webhook)',
        )

        pedm_enabled, pedm_interval = self._collect_pedm_config()
        device_approval_enabled, device_approval_interval = self._collect_device_approval_config()

        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Zoom Chat Configuration Complete!{bcolors.ENDC}")
        return ZoomConfig(
            client_id=client_id,
            client_secret=client_secret,
            bot_jid=bot_jid,
            secret_token=secret_token,
            approvals_channel_jid=approvals_channel_jid,
            public_endpoint_url=public_endpoint_url,
            chat_command_request_record_id=chat_command_request_record_id,
            chat_command_request_folder_id=chat_command_request_folder_id,
            chat_command_external_share_id=chat_command_external_share_id,
            chat_command_create_secret_id=chat_command_create_secret_id,
            pedm_enabled=pedm_enabled,
            pedm_polling_interval=pedm_interval,
            device_approval_enabled=device_approval_enabled,
            device_approval_polling_interval=device_approval_interval,
        )

    def build_record_custom_fields(self, config: ZoomConfig):
        return [
            vault.TypedField.new_field(
                'text', config.client_id, ZoomConstants.FIELD_CLIENT_ID
            ),
            vault.TypedField.new_field(
                'secret', config.client_secret, ZoomConstants.FIELD_CLIENT_SECRET
            ),
            vault.TypedField.new_field(
                'text', config.bot_jid, ZoomConstants.FIELD_BOT_JID
            ),
            vault.TypedField.new_field(
                'secret', config.secret_token, ZoomConstants.FIELD_SECRET_TOKEN
            ),
            vault.TypedField.new_field(
                'text',
                config.approvals_channel_jid,
                ZoomConstants.FIELD_APPROVALS_CHANNEL_JID,
            ),
            vault.TypedField.new_field(
                'url',
                config.public_endpoint_url,
                ZoomConstants.FIELD_PUBLIC_ENDPOINT_URL,
            ),
            vault.TypedField.new_field(
                'text',
                config.chat_command_request_record_id,
                ZoomConstants.FIELD_COMMAND_REQUEST_RECORD_ID,
            ),
            vault.TypedField.new_field(
                'text',
                config.chat_command_request_folder_id,
                ZoomConstants.FIELD_COMMAND_REQUEST_FOLDER_ID,
            ),
            vault.TypedField.new_field(
                'text',
                config.chat_command_external_share_id,
                ZoomConstants.FIELD_COMMAND_EXTERNAL_SHARE_ID,
            ),
            vault.TypedField.new_field(
                'text',
                config.chat_command_create_secret_id,
                ZoomConstants.FIELD_COMMAND_CREATE_SECRET_ID,
            ),
            vault.TypedField.new_field(
                'text',
                'true' if config.pedm_enabled else 'false',
                ZoomConstants.FIELD_PEDM_ENABLED,
            ),
            vault.TypedField.new_field(
                'text',
                str(config.pedm_polling_interval),
                ZoomConstants.FIELD_PEDM_POLLING_INTERVAL,
            ),
            vault.TypedField.new_field(
                'text',
                'true' if config.device_approval_enabled else 'false',
                ZoomConstants.FIELD_DEVICE_APPROVAL_ENABLED,
            ),
            vault.TypedField.new_field(
                'text',
                str(config.device_approval_polling_interval),
                ZoomConstants.FIELD_DEVICE_APPROVAL_POLLING_INTERVAL,
            ),
        ]

    def print_integration_specific_resources(self, config: ZoomConfig):
        print(f"    • Zoom Client ID: {bcolors.OKBLUE}{config.client_id}{bcolors.ENDC}")
        print(f"    • Bot JID: {bcolors.OKBLUE}{config.bot_jid}{bcolors.ENDC}")
        print(
            f"    • /keeper-request-record ID: "
            f"{bcolors.OKBLUE}{config.chat_command_request_record_id}{bcolors.ENDC}"
        )
        print(
            f"    • /keeper-request-folder ID: "
            f"{bcolors.OKBLUE}{config.chat_command_request_folder_id}{bcolors.ENDC}"
        )
        print(
            f"    • /keeper-one-time-share ID: "
            f"{bcolors.OKBLUE}{config.chat_command_external_share_id}{bcolors.ENDC}"
        )
        print(
            f"    • /keeper-create-secret ID: "
            f"{bcolors.OKBLUE}{config.chat_command_create_secret_id}{bcolors.ENDC}"
        )
        print(
            f"    • Approvals Channel JID: "
            f"{bcolors.OKBLUE}{config.approvals_channel_jid}{bcolors.ENDC}"
        )
        print(
            f"    • Public Endpoint URL: "
            f"{bcolors.OKBLUE}{config.public_endpoint_url}{bcolors.ENDC}"
        )

    def print_integration_commands(self):
        print(f"\n{bcolors.BOLD}Zoom Chat Commands Available:{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}• /keeper-request-record{bcolors.ENDC} - Request access to a record")
        print(f"  {bcolors.OKGREEN}• /keeper-request-folder{bcolors.ENDC} - Request access to a folder")
        print(f"  {bcolors.OKGREEN}• /keeper-one-time-share{bcolors.ENDC} - Request a one-time share link")
        print(f"  {bcolors.OKGREEN}• /keeper-create-secret{bcolors.ENDC} - Request creation of a secret")

    def _prompt_command_id(self, command_name: str, default: str) -> str:
        while True:
            value = input(
                f"{bcolors.OKBLUE}{command_name} command ID "
                f"[Press Enter for {default}]:{bcolors.ENDC} "
            ).strip() or default
            if value.isdigit() and int(value) >= 1:
                return value
            print(
                f"{bcolors.FAIL}Error: Slash command ID must be a positive integer{bcolors.ENDC}"
            )


__all__ = ['ZoomAppSetupCommand', 'is_valid_public_endpoint_url']
