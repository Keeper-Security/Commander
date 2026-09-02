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

from __future__ import annotations

import json
import os
import re

from .... import vault
from ....display import bcolors
from ....error import CommandError
from ...docker import GChatConfig, GChatConstants
from .approvals_setup import (
    ApprovalsChannelProfile,
    approvals_config_to_record_fields,
    print_approvals_config,
)
from .integration_setup_base import IntegrationSetupCommand

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

def _validate_gchat_space_id(space_id: str) -> bool:
    prefix = GChatConstants.SPACE_ID_PREFIX
    return bool(space_id and space_id.startswith(prefix) and len(space_id) > len(prefix))


GCHAT_APPROVALS_PROFILE = ApprovalsChannelProfile(
    channel_header='APPROVALS_SPACE_ID',
    single_channel_description='Google Chat space ID for approval notifications',
    channel_description='Google Chat space where approval requests for this approver team are sent',
    default_channel_description=(
        'Default space for EPM privilege requests, SSO Cloud device approvals, '
        'and approval requests from users not assigned to an approver team'
    ),
    channel_prompt='Space ID (starts with spaces/):',
    validate_channel=_validate_gchat_space_id,
    channel_error="Invalid Approvals Space ID (must start with 'spaces/' and include a space name)",
)


class GChatAppSetupCommand(IntegrationSetupCommand):
    """Google Chat App integration setup."""

    def get_integration_name(self):
        return GChatConstants.INTEGRATION_NAME

    def get_integration_display_name(self) -> str:
        return GChatConstants.DISPLAY_NAME

    def get_default_folder_name(self) -> str:
        return GChatConstants.DEFAULT_FOLDER_NAME

    def get_default_record_name(self) -> str:
        return GChatConstants.DEFAULT_RECORD_NAME

    def get_integration_config_marker_field(self) -> str:
        return GChatConstants.FIELD_SERVICE_ACCOUNT_JSON

    def get_approvals_profile(self):
        return GCHAT_APPROVALS_PROFILE

    # ── Google Chat-specific configuration ────────────────────────

    def collect_integration_config(self, params):
        print(f"\n{bcolors.BOLD}GOOGLE_SERVICE_ACCOUNT_JSON:{bcolors.ENDC}")
        print(f"  Path to the Google Cloud service account JSON key file")
        print(f"  (used for Pub/Sub pull and Google Chat API)")
        google_service_account_json, project_from_json = self._prompt_service_account_json()

        print(f"\n{bcolors.BOLD}GOOGLE_PROJECT_ID:{bcolors.ENDC}")
        print(f"  Google Cloud project ID for Pub/Sub and Chat")
        google_project_id = self._prompt_google_project_id(project_from_json)

        print(f"\n{bcolors.BOLD}GOOGLE_TOPIC_ID:{bcolors.ENDC}")
        print(f"  Pub/Sub topic that receives Google Chat events")
        print(f"  Accepts a short ID or full path projects/{{project}}/topics/{{id}}")
        google_topic_id = self._prompt_pubsub_id(
            'Topic ID:',
            self._normalize_topic_id,
            google_project_id,
        )

        print(f"\n{bcolors.BOLD}GOOGLE_SUBSCRIPTION_ID:{bcolors.ENDC}")
        print(f"  Pub/Sub subscription used to pull Google Chat events")
        print(f"  Accepts a short ID or full path projects/{{project}}/subscriptions/{{id}}")
        google_subscription_id = self._prompt_pubsub_id(
            'Subscription ID:',
            self._normalize_subscription_id,
            google_project_id,
        )

        print(f"\n{bcolors.BOLD}CHAT COMMAND IDs:{bcolors.ENDC}")
        print(f"  Slash command IDs configured for the Google Chat app")
        chat_command_request_record_id = self._prompt_command_id(
            '/keeper-request-record',
            GChatConstants.DEFAULT_COMMAND_REQUEST_RECORD_ID,
        )
        chat_command_request_folder_id = self._prompt_command_id(
            '/keeper-request-folder',
            GChatConstants.DEFAULT_COMMAND_REQUEST_FOLDER_ID,
        )
        chat_command_external_share_id = self._prompt_command_id(
            '/keeper-external-share',
            GChatConstants.DEFAULT_COMMAND_EXTERNAL_SHARE_ID,
        )
        chat_command_create_secret_id = self._prompt_command_id(
            '/keeper-create-secret',
            GChatConstants.DEFAULT_COMMAND_CREATE_SECRET_ID,
        )

        profile = self.get_approvals_profile()
        if profile is None:
            raise CommandError(
                self.get_command_name(),
                'Internal error: Google Chat approvals profile not configured'
            )
        approvals = self._collect_approvals_config(params, profile)

        pedm_enabled, pedm_interval = self._collect_pedm_config()
        da_enabled, da_interval = self._collect_device_approval_config()

        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Google Chat Configuration Complete!{bcolors.ENDC}")

        return GChatConfig(
            google_service_account_json=google_service_account_json,
            google_project_id=google_project_id,
            google_subscription_id=google_subscription_id,
            google_topic_id=google_topic_id,
            approvals=approvals,
            chat_command_request_record_id=chat_command_request_record_id,
            chat_command_request_folder_id=chat_command_request_folder_id,
            chat_command_external_share_id=chat_command_external_share_id,
            chat_command_create_secret_id=chat_command_create_secret_id,
            pedm_enabled=pedm_enabled,
            pedm_polling_interval=pedm_interval,
            device_approval_enabled=da_enabled,
            device_approval_polling_interval=da_interval,
        )

    def build_record_custom_fields(self, config):
        return [
            vault.TypedField.new_field(
                'secret',
                config.google_service_account_json,
                GChatConstants.FIELD_SERVICE_ACCOUNT_JSON,
            ),
            vault.TypedField.new_field(
                'text', config.google_project_id, GChatConstants.FIELD_PROJECT_ID
            ),
            vault.TypedField.new_field(
                'text', config.google_subscription_id, GChatConstants.FIELD_SUBSCRIPTION_ID
            ),
            vault.TypedField.new_field(
                'text', config.google_topic_id, GChatConstants.FIELD_TOPIC_ID
            ),
            vault.TypedField.new_field(
                'text',
                config.chat_command_request_record_id,
                GChatConstants.FIELD_COMMAND_REQUEST_RECORD_ID,
            ),
            vault.TypedField.new_field(
                'text',
                config.chat_command_request_folder_id,
                GChatConstants.FIELD_COMMAND_REQUEST_FOLDER_ID,
            ),
            vault.TypedField.new_field(
                'text',
                config.chat_command_external_share_id,
                GChatConstants.FIELD_COMMAND_EXTERNAL_SHARE_ID,
            ),
            vault.TypedField.new_field(
                'text',
                config.chat_command_create_secret_id,
                GChatConstants.FIELD_COMMAND_CREATE_SECRET_ID,
            ),
            *approvals_config_to_record_fields(config.approvals),
            vault.TypedField.new_field(
                'text',
                'true' if config.pedm_enabled else 'false',
                GChatConstants.FIELD_PEDM_ENABLED,
            ),
            vault.TypedField.new_field(
                'text',
                str(config.pedm_polling_interval),
                GChatConstants.FIELD_PEDM_POLLING_INTERVAL,
            ),
            vault.TypedField.new_field(
                'text',
                'true' if config.device_approval_enabled else 'false',
                GChatConstants.FIELD_DEVICE_APPROVAL_ENABLED,
            ),
            vault.TypedField.new_field(
                'text',
                str(config.device_approval_polling_interval),
                GChatConstants.FIELD_DEVICE_APPROVAL_POLLING_INTERVAL,
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
            f"    • /keeper-request-record ID: "
            f"{bcolors.OKBLUE}{config.chat_command_request_record_id}{bcolors.ENDC}"
        )
        print(
            f"    • /keeper-request-folder ID: "
            f"{bcolors.OKBLUE}{config.chat_command_request_folder_id}{bcolors.ENDC}"
        )
        print(
            f"    • /keeper-external-share ID: "
            f"{bcolors.OKBLUE}{config.chat_command_external_share_id}{bcolors.ENDC}"
        )
        print(
            f"    • /keeper-create-secret ID: "
            f"{bcolors.OKBLUE}{config.chat_command_create_secret_id}{bcolors.ENDC}"
        )
        print_approvals_config(config.approvals)

    def print_integration_commands(self):
        print(f"\n{bcolors.BOLD}Google Chat Commands Available:{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}• /keeper-request-record{bcolors.ENDC} - Request access to a record")
        print(f"  {bcolors.OKGREEN}• /keeper-request-folder{bcolors.ENDC} - Request access to a folder")
        print(
            f"  {bcolors.OKGREEN}• /keeper-external-share{bcolors.ENDC} "
            f"- Request an external share link"
        )
        print(
            f"  {bcolors.OKGREEN}• /keeper-create-secret{bcolors.ENDC} "
            f"- Request creation of a secret\n"
        )

    # ── Validation helpers ────────────────────────────────────────

    def _prompt_service_account_json(self) -> tuple[str, str]:
        while True:
            path = input(
                f"{bcolors.OKBLUE}Path to service account JSON file:{bcolors.ENDC} "
            ).strip()
            parsed, error = self._load_service_account_json(path)
            if parsed is not None:
                return json.dumps(parsed, separators=(',', ':')), parsed.get('project_id', '')
            print(f"{bcolors.FAIL}Error: {error}{bcolors.ENDC}")

    def _prompt_google_project_id(self, project_from_json: str) -> str:
        default_hint = f' [Press Enter for {project_from_json}]' if project_from_json else ''
        while True:
            project_input = input(
                f"{bcolors.OKBLUE}Project ID{default_hint}:{bcolors.ENDC} "
            ).strip()
            google_project_id = project_input or project_from_json
            if not google_project_id:
                print(
                    f"{bcolors.FAIL}Error: Google Project ID is required "
                    f"(enter a value or provide a valid service account JSON){bcolors.ENDC}"
                )
                continue

            if project_from_json and google_project_id != project_from_json:
                print(
                    f"{bcolors.WARNING}Warning: Project ID \"{google_project_id}\" differs from "
                    f"service account project_id \"{project_from_json}\"{bcolors.ENDC}"
                )
                if not self._prompt_yes_no(
                    'Continue with this Project ID anyway?',
                    default=False,
                ):
                    continue

            return google_project_id

    def _prompt_pubsub_id(self, prompt: str, normalizer, google_project_id: str) -> str:
        while True:
            value = input(f"{bcolors.OKBLUE}{prompt}{bcolors.ENDC} ").strip()
            normalized, error = normalizer(value, google_project_id)
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
    def _load_service_account_json(cls, path: str) -> tuple[dict | None, str | None]:
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
    def _validate_service_account_dict(data: object) -> tuple[dict | None, str | None]:
        if not isinstance(data, dict):
            return None, 'Service account JSON must be a JSON object'

        missing = [
            key for key in GChatConstants.SERVICE_ACCOUNT_REQUIRED_KEYS if not data.get(key)
        ]
        if missing:
            return None, (
                'Invalid service account JSON '
                f'(missing required fields: {", ".join(missing)})'
            )

        if data.get('type') != GChatConstants.SERVICE_ACCOUNT_TYPE:
            return None, (
                f"Invalid service account JSON "
                f"(type must be '{GChatConstants.SERVICE_ACCOUNT_TYPE}')"
            )

        return data, None

    @staticmethod
    def _normalize_pubsub_id(
        value: str,
        resource_pattern: re.Pattern[str],
        label: str,
        resource_hint: str,
        google_project_id: str = '',
    ) -> tuple[str | None, str | None]:
        if not value:
            return None, f'{label} is required'

        resource_match = resource_pattern.match(value)
        if resource_match:
            path_project = resource_match.group(1)
            if google_project_id and path_project != google_project_id:
                return None, (
                    f'{label} project "{path_project}" does not match '
                    f'GOOGLE_PROJECT_ID "{google_project_id}"'
                )
            return resource_match.group(2), None

        if _PUBSUB_ID_PATTERN.match(value):
            return value, None

        return None, (
            f'Invalid {label} '
            f'(use a short ID like keeper-chat-events, or {resource_hint})'
        )

    @classmethod
    def _normalize_subscription_id(
        cls, value: str, google_project_id: str = ''
    ) -> tuple[str | None, str | None]:
        return cls._normalize_pubsub_id(
            value,
            _SUBSCRIPTION_RESOURCE_PATTERN,
            'Pub/Sub Subscription ID',
            'projects/{project}/subscriptions/{id}',
            google_project_id,
        )

    @classmethod
    def _normalize_topic_id(
        cls, value: str, google_project_id: str = ''
    ) -> tuple[str | None, str | None]:
        return cls._normalize_pubsub_id(
            value,
            _TOPIC_RESOURCE_PATTERN,
            'Pub/Sub Topic ID',
            'projects/{project}/topics/{id}',
            google_project_id,
        )

