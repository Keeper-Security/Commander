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

"""Google Chat App integration setup command."""

import json
import os
import re
from typing import Any, Dict, Optional, Tuple

from .... import vault
from ....display import bcolors
from ...docker import GChatConfig
from .integration_setup_base import IntegrationSetupCommand

_SERVICE_ACCOUNT_REQUIRED_KEYS = (
    'type',
    'project_id',
    'private_key',
    'client_email',
)
# Short Pub/Sub IDs, or full resource names:
#   projects/{project}/subscriptions/{subscription}
#   projects/{project}/topics/{topic}
_PUBSUB_ID_PATTERN = re.compile(r'^[A-Za-z][\w.-]{2,}$')
_SUBSCRIPTION_RESOURCE_PATTERN = re.compile(
    r'^projects/([^/]+)/subscriptions/([A-Za-z][\w.-]{2,})$'
)
_TOPIC_RESOURCE_PATTERN = re.compile(
    r'^projects/([^/]+)/topics/([A-Za-z][\w.-]{2,})$'
)


class GChatAppSetupCommand(IntegrationSetupCommand):
    """Google Chat App integration setup."""

    def get_integration_name(self):
        return 'GChat'

    def get_integration_display_name(self) -> str:
        return 'Google Chat'

    def get_default_folder_name(self) -> str:
        return 'Commander Service Mode - Google Chat App'

    def get_default_record_name(self) -> str:
        return 'Commander Service Mode Google Chat App Config'

    def get_integration_config_marker_field(self) -> str:
        return 'google_service_account_json'

    # ── Google Chat-specific configuration ────────────────────────

    def collect_integration_config(self, params):
        print(f"\n{bcolors.BOLD}GOOGLE_SERVICE_ACCOUNT_JSON:{bcolors.ENDC}")
        print(f"  Path to the Google Cloud service account JSON key file")
        print(f"  (used for Pub/Sub pull and Google Chat API)")
        google_service_account_json, project_from_json = self._prompt_service_account_json()

        print(f"\n{bcolors.BOLD}GOOGLE_PROJECT_ID:{bcolors.ENDC}")
        print(f"  Google Cloud project ID for Pub/Sub and Chat")
        default_hint = f' [Press Enter for {project_from_json}]' if project_from_json else ''
        while True:
            project_input = input(
                f"{bcolors.OKBLUE}Project ID{default_hint}:{bcolors.ENDC} "
            ).strip()
            google_project_id = project_input or project_from_json
            if google_project_id:
                break
            print(
                f"{bcolors.FAIL}Error: Google Project ID is required "
                f"(enter a value or provide a valid service account JSON){bcolors.ENDC}"
            )

        print(f"\n{bcolors.BOLD}GOOGLE_TOPIC_ID:{bcolors.ENDC}")
        print(f"  Pub/Sub topic that receives Google Chat events")
        print(f"  Accepts a short ID or full path projects/{{project}}/topics/{{id}}")
        google_topic_id = self._prompt_pubsub_id(
            'Topic ID:',
            self._normalize_topic_id,
        )

        print(f"\n{bcolors.BOLD}GOOGLE_SUBSCRIPTION_ID:{bcolors.ENDC}")
        print(f"  Pub/Sub subscription used to pull Google Chat events")
        print(f"  Accepts a short ID or full path projects/{{project}}/subscriptions/{{id}}")
        google_subscription_id = self._prompt_pubsub_id(
            'Subscription ID:',
            self._normalize_subscription_id,
        )

        print(f"\n{bcolors.BOLD}CHAT_APPROVALS_SPACE_ID:{bcolors.ENDC}")
        print(f"  Google Chat space where approval cards are posted")
        chat_approvals_space_id = self._prompt_with_validation(
            "Space ID (starts with spaces/):",
            self._is_valid_space_id,
            "Invalid Approvals Space ID (must start with 'spaces/' and include a space name)"
        )

        print(f"\n{bcolors.BOLD}CHAT COMMAND IDs:{bcolors.ENDC}")
        print(f"  Slash command IDs configured for the Google Chat app")
        chat_command_request_record_id = self._prompt_command_id(
            '/keeper-request-record', '1'
        )
        chat_command_request_folder_id = self._prompt_command_id(
            '/keeper-request-folder', '2'
        )
        chat_command_one_time_share_id = self._prompt_command_id(
            '/keeper-one-time-share', '3'
        )

        pedm_enabled, pedm_interval = self._collect_pedm_config()
        da_enabled, da_interval = self._collect_device_approval_config()

        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Google Chat Configuration Complete!{bcolors.ENDC}")

        return GChatConfig(
            google_service_account_json=google_service_account_json,
            google_project_id=google_project_id,
            google_subscription_id=google_subscription_id,
            google_topic_id=google_topic_id,
            chat_approvals_space_id=chat_approvals_space_id,
            chat_command_request_record_id=chat_command_request_record_id,
            chat_command_request_folder_id=chat_command_request_folder_id,
            chat_command_one_time_share_id=chat_command_one_time_share_id,
            pedm_enabled=pedm_enabled,
            pedm_polling_interval=pedm_interval,
            device_approval_enabled=da_enabled,
            device_approval_polling_interval=da_interval,
        )

    def build_record_custom_fields(self, config):
        return [
            vault.TypedField.new_field(
                'secret', config.google_service_account_json, 'google_service_account_json'
            ),
            vault.TypedField.new_field('text', config.google_project_id, 'google_project_id'),
            vault.TypedField.new_field('text', config.google_subscription_id, 'google_subscription_id'),
            vault.TypedField.new_field('text', config.google_topic_id, 'google_topic_id'),
            vault.TypedField.new_field(
                'text', config.chat_approvals_space_id, 'chat_approvals_space_id'
            ),
            vault.TypedField.new_field(
                'text', config.chat_command_request_record_id, 'chat_command_request_record_id'
            ),
            vault.TypedField.new_field(
                'text', config.chat_command_request_folder_id, 'chat_command_request_folder_id'
            ),
            vault.TypedField.new_field(
                'text', config.chat_command_one_time_share_id, 'chat_command_one_time_share_id'
            ),
            vault.TypedField.new_field('text', 'true' if config.pedm_enabled else 'false', 'pedm_enabled'),
            vault.TypedField.new_field('text', str(config.pedm_polling_interval), 'pedm_polling_interval'),
            vault.TypedField.new_field(
                'text',
                'true' if config.device_approval_enabled else 'false',
                'device_approval_enabled',
            ),
            vault.TypedField.new_field(
                'text',
                str(config.device_approval_polling_interval),
                'device_approval_polling_interval',
            ),
        ]

    # ── Display ───────────────────────────────────────────────────

    def print_integration_specific_resources(self, config):
        print(f"    • Google Project ID: {bcolors.OKBLUE}{config.google_project_id}{bcolors.ENDC}")
        print(f"    • Pub/Sub Topic: {bcolors.OKBLUE}{config.google_topic_id}{bcolors.ENDC}")
        print(
            f"    • Pub/Sub Subscription: "
            f"{bcolors.OKBLUE}{config.google_subscription_id}{bcolors.ENDC}"
        )
        print(
            f"    • Approvals Space: "
            f"{bcolors.OKBLUE}{config.chat_approvals_space_id}{bcolors.ENDC}"
        )
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
            f"{bcolors.OKBLUE}{config.chat_command_one_time_share_id}{bcolors.ENDC}"
        )

    def print_integration_commands(self):
        print(f"\n{bcolors.BOLD}Google Chat Commands Available:{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}• /keeper-request-record{bcolors.ENDC} - Request access to a record")
        print(f"  {bcolors.OKGREEN}• /keeper-request-folder{bcolors.ENDC} - Request access to a folder")
        print(
            f"  {bcolors.OKGREEN}• /keeper-one-time-share{bcolors.ENDC} "
            f"- Request a one-time share link\n"
        )

    # ── Validation helpers ────────────────────────────────────────

    def _prompt_service_account_json(self) -> Tuple[str, str]:
        while True:
            path = input(
                f"{bcolors.OKBLUE}Path to service account JSON file:{bcolors.ENDC} "
            ).strip()
            parsed, error = self._load_service_account_json(path)
            if parsed is not None:
                return json.dumps(parsed, separators=(',', ':')), parsed.get('project_id', '')
            print(f"{bcolors.FAIL}Error: {error}{bcolors.ENDC}")

    def _prompt_pubsub_id(self, prompt: str, normalizer) -> str:
        while True:
            value = input(f"{bcolors.OKBLUE}{prompt}{bcolors.ENDC} ").strip()
            normalized, error = normalizer(value)
            if normalized is not None:
                return normalized
            print(f"{bcolors.FAIL}Error: {error}{bcolors.ENDC}")

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

    @classmethod
    def _load_service_account_json(cls, path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not path:
            return None, 'Service account JSON path is required'

        expanded = os.path.expanduser(path)
        if not os.path.isfile(expanded):
            return None, f'Service account JSON file not found: {path}'

        try:
            with open(expanded, 'r', encoding='utf-8') as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            return None, f'Invalid service account JSON: {exc}'
        except OSError as exc:
            return None, f'Unable to read service account JSON: {exc}'

        return cls._validate_service_account_dict(data)

    @staticmethod
    def _validate_service_account_dict(
        data: Any,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not isinstance(data, dict):
            return None, 'Service account JSON must be a JSON object'

        missing = [key for key in _SERVICE_ACCOUNT_REQUIRED_KEYS if not data.get(key)]
        if missing:
            return None, (
                'Invalid service account JSON '
                f'(missing required fields: {", ".join(missing)})'
            )

        if data.get('type') != 'service_account':
            return None, "Invalid service account JSON (type must be 'service_account')"

        return data, None

    @staticmethod
    def _normalize_pubsub_id(
        value: str,
        resource_pattern: re.Pattern,
        label: str,
        resource_hint: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        if not value:
            return None, f'{label} is required'

        resource_match = resource_pattern.match(value)
        if resource_match:
            return resource_match.group(2), None

        if _PUBSUB_ID_PATTERN.match(value):
            return value, None

        return None, (
            f'Invalid {label} '
            f'(use a short ID like keeper-chat-events, or {resource_hint})'
        )

    @classmethod
    def _normalize_subscription_id(cls, value: str) -> Tuple[Optional[str], Optional[str]]:
        return cls._normalize_pubsub_id(
            value,
            _SUBSCRIPTION_RESOURCE_PATTERN,
            'Pub/Sub Subscription ID',
            'projects/{project}/subscriptions/{id}',
        )

    @classmethod
    def _normalize_topic_id(cls, value: str) -> Tuple[Optional[str], Optional[str]]:
        return cls._normalize_pubsub_id(
            value,
            _TOPIC_RESOURCE_PATTERN,
            'Pub/Sub Topic ID',
            'projects/{project}/topics/{id}',
        )

    @staticmethod
    def _is_valid_subscription_id(value: str) -> bool:
        normalized, _ = GChatAppSetupCommand._normalize_subscription_id(value)
        return normalized is not None

    @staticmethod
    def _is_valid_space_id(value: str) -> bool:
        return bool(value and value.startswith('spaces/') and len(value) > len('spaces/'))
