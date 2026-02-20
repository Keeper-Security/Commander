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
Slack App integration setup command.

Extends IntegrationSetupCommand with Slack-specific configuration
(App Token, Bot Token, Signing Secret, Channel ID).
"""

from .... import vault
from ....display import bcolors
from ...docker import SlackConfig
from .integration_setup_base import IntegrationSetupCommand


class SlackAppSetupCommand(IntegrationSetupCommand):
    """Slack App integration setup command."""

    def get_integration_name(self):
        return 'Slack'

    # ── Slack-specific configuration ──────────────────────────────

    def collect_integration_config(self):
        print(f"\n{bcolors.BOLD}SLACK_APP_TOKEN:{bcolors.ENDC}")
        print(f"  App-level token for Slack App")
        slack_app_token = self._prompt_with_validation(
            "Token (starts with xapp-):",
            lambda t: t and t.startswith('xapp-') and len(t) >= 90,
            "Invalid Slack App Token (must start with 'xapp-' and be at least 90 chars)"
        )

        print(f"\n{bcolors.BOLD}SLACK_BOT_TOKEN:{bcolors.ENDC}")
        print(f"  Bot token for Slack workspace")
        slack_bot_token = self._prompt_with_validation(
            "Token (starts with xoxb-):",
            lambda t: t and t.startswith('xoxb-') and len(t) >= 50,
            "Invalid Slack Bot Token (must start with 'xoxb-' and be at least 50 chars)"
        )

        print(f"\n{bcolors.BOLD}SLACK_SIGNING_SECRET:{bcolors.ENDC}")
        print(f"  Signing secret for verifying Slack requests")
        slack_signing_secret = self._prompt_with_validation(
            "Secret:",
            lambda s: s and len(s) == 32,
            "Invalid Slack Signing Secret (must be exactly 32 characters)"
        )

        print(f"\n{bcolors.BOLD}APPROVALS_CHANNEL_ID:{bcolors.ENDC}")
        print(f"  Slack channel ID for approval notifications")
        approvals_channel_id = self._prompt_with_validation(
            "Channel ID (starts with C):",
            lambda c: c and c.startswith('C'),
            "Invalid Approvals Channel ID (must start with 'C')"
        )

        pedm_enabled, pedm_interval = self._collect_pedm_config()
        da_enabled, da_interval = self._collect_device_approval_config()

        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Slack Configuration Complete!{bcolors.ENDC}")

        return SlackConfig(
            slack_app_token=slack_app_token,
            slack_bot_token=slack_bot_token,
            slack_signing_secret=slack_signing_secret,
            approvals_channel_id=approvals_channel_id,
            pedm_enabled=pedm_enabled,
            pedm_polling_interval=pedm_interval,
            device_approval_enabled=da_enabled,
            device_approval_polling_interval=da_interval
        )

    def build_record_custom_fields(self, config):
        return [
            vault.TypedField.new_field('secret', config.slack_app_token, 'slack_app_token'),
            vault.TypedField.new_field('secret', config.slack_bot_token, 'slack_bot_token'),
            vault.TypedField.new_field('secret', config.slack_signing_secret, 'slack_signing_secret'),
            vault.TypedField.new_field('text', config.approvals_channel_id, 'approvals_channel_id'),
            vault.TypedField.new_field('text', 'true' if config.pedm_enabled else 'false', 'pedm_enabled'),
            vault.TypedField.new_field('text', str(config.pedm_polling_interval), 'pedm_polling_interval'),
            vault.TypedField.new_field('text', 'true' if config.device_approval_enabled else 'false', 'device_approval_enabled'),
            vault.TypedField.new_field('text', str(config.device_approval_polling_interval), 'device_approval_polling_interval'),
        ]

    # ── Display ───────────────────────────────────────────────────

    def print_integration_specific_resources(self, config):
        print(f"    • Approvals Channel: {bcolors.OKBLUE}{config.approvals_channel_id}{bcolors.ENDC}")

    def print_integration_commands(self):
        print(f"\n{bcolors.BOLD}Slack Commands Available:{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}• /keeper-request-record{bcolors.ENDC} - Request access to a record")
        print(f"  {bcolors.OKGREEN}• /keeper-request-folder{bcolors.ENDC} - Request access to a folder")
        print(f"  {bcolors.OKGREEN}• /keeper-one-time-share{bcolors.ENDC} - Request a one-time share link\n")
