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

"""Teams App integration setup command."""

from .... import vault
from ....display import bcolors
from ...docker import TeamsConfig
from .integration_setup_base import IntegrationSetupCommand


class TeamsAppSetupCommand(IntegrationSetupCommand):
    """Teams App integration setup."""

    def get_integration_name(self):
        return 'Teams'

    # ── Teams-specific configuration ──────────────────────────────

    def collect_integration_config(self):
        print(f"\n{bcolors.BOLD}CLIENT_ID:{bcolors.ENDC}")
        print(f"  Azure AD App Registration Client ID")
        client_id = self._prompt_with_validation(
            "Client ID:",
            lambda v: self.is_valid_uuid(v),
            "Invalid Client ID (must be a valid UUID with 32 hex characters)"
        )

        print(f"\n{bcolors.BOLD}CLIENT_SECRET:{bcolors.ENDC}")
        print(f"  Azure AD App Registration Client Secret")
        client_secret = self._prompt_with_validation(
            "Client Secret:",
            lambda v: v and len(v) >= 30,
            "Invalid Client Secret (must be at least 30 characters)"
        )

        print(f"\n{bcolors.BOLD}TENANT_ID:{bcolors.ENDC}")
        print(f"  Azure AD Tenant ID")
        tenant_id = self._prompt_with_validation(
            "Tenant ID:",
            lambda v: self.is_valid_uuid(v),
            "Invalid Tenant ID (must be a valid UUID with 32 hex characters)"
        )

        print(f"\n{bcolors.BOLD}APPROVALS_CHANNEL_ID:{bcolors.ENDC}")
        print(f"  Teams channel ID for approval notifications")
        approvals_channel_id = self._prompt_with_validation(
            "Channel ID (starts with 19:):",
            lambda v: v and v.startswith('19:') and '@thread.tacv2' in v,
            "Invalid Channel ID (must start with '19:' and end with '@thread.tacv2')"
        )

        print(f"\n{bcolors.BOLD}APPROVALS_TEAM_ID:{bcolors.ENDC}")
        print(f"  Teams team ID containing the approvals channel")
        approvals_team_id = self._prompt_with_validation(
            "Team ID:",
            lambda v: self.is_valid_uuid(v),
            "Invalid Team ID (must be a valid UUID with 32 hex characters)"
        )

        pedm_enabled, pedm_interval = self._collect_pedm_config()
        da_enabled, da_interval = self._collect_device_approval_config()

        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Teams Configuration Complete!{bcolors.ENDC}")

        return TeamsConfig(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            approvals_channel_id=approvals_channel_id,
            approvals_team_id=approvals_team_id,
            pedm_enabled=pedm_enabled,
            pedm_polling_interval=pedm_interval,
            device_approval_enabled=da_enabled,
            device_approval_polling_interval=da_interval
        )

    def build_record_custom_fields(self, config):
        return [
            vault.TypedField.new_field('secret', config.client_id, 'client_id'),
            vault.TypedField.new_field('secret', config.client_secret, 'client_secret'),
            vault.TypedField.new_field('secret', config.tenant_id, 'tenant_id'),
            vault.TypedField.new_field('text', config.approvals_channel_id, 'approvals_channel_id'),
            vault.TypedField.new_field('text', config.approvals_team_id, 'approvals_team_id'),
            vault.TypedField.new_field('text', 'true' if config.pedm_enabled else 'false', 'pedm_enabled'),
            vault.TypedField.new_field('text', str(config.pedm_polling_interval), 'pedm_polling_interval'),
            vault.TypedField.new_field('text', 'true' if config.device_approval_enabled else 'false', 'device_approval_enabled'),
            vault.TypedField.new_field('text', str(config.device_approval_polling_interval), 'device_approval_polling_interval'),
        ]

    # ── Display ───────────────────────────────────────────────────

    def print_integration_specific_resources(self, config):
        print(f"    • Approvals Channel: {bcolors.OKBLUE}{config.approvals_channel_id}{bcolors.ENDC}")
        print(f"    • Approvals Team: {bcolors.OKBLUE}{config.approvals_team_id}{bcolors.ENDC}")

    def print_integration_commands(self):
        print(f"\n{bcolors.BOLD}Teams Bot Commands Available:{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}• @keeper request-record{bcolors.ENDC} - Request access to a record")
        print(f"  {bcolors.OKGREEN}• @keeper request-folder{bcolors.ENDC} - Request access to a folder")
        print(f"  {bcolors.OKGREEN}• @keeper one-time-share{bcolors.ENDC} - Request a one-time share link\n")
