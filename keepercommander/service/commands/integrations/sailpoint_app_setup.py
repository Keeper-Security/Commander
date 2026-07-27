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

"""SailPoint App integration setup command."""

import json
import os
from dataclasses import asdict

from .... import vault
from ....display import bcolors
from ....error import CommandError
from ...docker import DockerComposeBuilder, DockerSetupPrinter, SailPointConfig, SetupResult, ServiceConfig
from .integration_setup_base import IntegrationSetupCommand
from .sailpoint.command_policy import SailPointCommandPolicy
from .sailpoint.constants import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    DOCKER_RECORD_ENV,
    ENTITLEMENT_SCOPE_FIELD,
    PENDING_ENTITLEMENTS_FIELD,
    POLL_INTERVAL_FIELD,
    SAILPOINT_MARKER_FIELD,
    SAILPOINT_RECORD_ENV,
    SCOPE_BOTH,
    SCOPE_FOLDERS,
    SCOPE_RECORDS,
)
from .sailpoint.pending_store import SailPointPendingStore


class SailPointAppSetupCommand(IntegrationSetupCommand):

    def get_integration_name(self):
        return 'SailPoint'

    def get_integration_config_marker_field(self):
        return SAILPOINT_MARKER_FIELD

    def get_default_folder_name(self):
        return 'Commander Service Mode - SailPoint'

    def get_default_record_name(self):
        return 'Commander Service Mode SailPoint Config'

    def get_record_env_key(self) -> str:
        return SAILPOINT_RECORD_ENV

    def get_service_commands(self) -> str:
        return SailPointCommandPolicy.default_allowlist()

    def collect_integration_config(self, params):
        print(f"\n{bcolors.BOLD}ENTITLEMENT SCOPE:{bcolors.ENDC}")
        print(f"  Control which share entitlements SailPoint may manage via Service Mode")
        print(f"  Options: {SCOPE_FOLDERS}, {SCOPE_RECORDS}, {SCOPE_BOTH}")
        while True:
            scope = input(
                f"{bcolors.OKBLUE}Scope [Press Enter for {SCOPE_BOTH}]:{bcolors.ENDC} "
            ).strip().lower() or SCOPE_BOTH
            if scope in (SCOPE_FOLDERS, SCOPE_RECORDS, SCOPE_BOTH):
                break
            print(f"{bcolors.FAIL}Error: Enter folders, records, or both{bcolors.ENDC}")

        print(f"\n{bcolors.BOLD}POLL INTERVAL:{bcolors.ENDC}")
        print(f"  How often (seconds) to check whether invited users have become Active")
        while True:
            raw = input(
                f"{bcolors.OKBLUE}Interval seconds "
                f"[Press Enter for {DEFAULT_POLL_INTERVAL_SECONDS}]:{bcolors.ENDC} "
            ).strip()
            if not raw:
                interval = DEFAULT_POLL_INTERVAL_SECONDS
                break
            try:
                interval = max(15, int(raw))
                break
            except ValueError:
                print(f"{bcolors.FAIL}Error: Enter a whole number of seconds (>= 15){bcolors.ENDC}")

        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ SailPoint Configuration Complete!{bcolors.ENDC}")
        return SailPointConfig(
            entitlement_scope=scope,
            poll_interval_seconds=interval,
        )

    def build_record_custom_fields(self, config):
        return [
            vault.TypedField.new_field('text', 'true', SAILPOINT_MARKER_FIELD),
            vault.TypedField.new_field('text', config.entitlement_scope, ENTITLEMENT_SCOPE_FIELD),
            vault.TypedField.new_field('text', str(config.poll_interval_seconds), POLL_INTERVAL_FIELD),
            vault.TypedField.new_field('text', json.dumps({}), PENDING_ENTITLEMENTS_FIELD),
        ]

    def _run_integration_setup(self, params, setup_result: SetupResult,
                               service_config: ServiceConfig,
                               record_name: str):
        """Create/update dedicated SailPoint config record (not the Docker config record)."""
        DockerSetupPrinter.print_header('SailPoint Configuration')
        config = self.collect_integration_config(params)

        DockerSetupPrinter.print_step(1, 2, f"Creating SailPoint config record '{record_name}'...")
        custom_fields = self.build_record_custom_fields(config)
        record_uid = self._create_integration_record(
            params, record_name, setup_result.folder_uid, custom_fields
        )

        DockerSetupPrinter.print_step(2, 2, 'Updating docker-compose.yml (Commander service only)...')
        self._update_docker_compose(setup_result, service_config, record_uid, config)
        return record_uid, config

    def _update_record_custom_fields(self, params, record_uid: str, custom_fields) -> None:
        """Preserve existing pending_entitlements JSON when re-running setup."""
        existing_pending = SailPointPendingStore.load(params, record_uid)
        if existing_pending:
            payload = json.dumps(existing_pending, indent=2, sort_keys=True)
            custom_fields = [
                f for f in custom_fields if getattr(f, 'label', None) != PENDING_ENTITLEMENTS_FIELD
            ] + [vault.TypedField.new_field('text', payload, PENDING_ENTITLEMENTS_FIELD)]
        super()._update_record_custom_fields(params, record_uid, custom_fields)

    def _update_docker_compose(self, setup_result, service_config, record_uid, config=None):
        """Commander-only compose: COMMANDER_RECORD + SAILPOINT_RECORD (no SailPoint app container)."""
        compose_file = os.path.join(os.getcwd(), 'docker-compose.yml')
        compose_exists = os.path.exists(compose_file)
        if compose_exists:
            DockerSetupPrinter.print_warning(
                'Rewriting docker-compose.yml for SailPoint Commander service. Hand edits will be lost.'
            )

        try:
            cfg = asdict(service_config)
            cfg['commands'] = SailPointCommandPolicy.sanitize(cfg.get('commands') or '')
            builder = DockerComposeBuilder(
                setup_result,
                cfg,
                commander_service_name=self.get_commander_service_name(),
                commander_container_name=self.get_commander_container_name(),
                commander_environment={
                    DOCKER_RECORD_ENV: setup_result.record_uid,
                    self.get_record_env_key(): record_uid,
                },
            )
            with open(compose_file, 'w') as f:
                f.write(builder.build())
            DockerSetupPrinter.print_success(
                'docker-compose.yml regenerated successfully'
                if compose_exists else 'docker-compose.yml created successfully'
            )
        except Exception as e:
            raise CommandError(self.get_command_name(), f'Failed to update docker-compose.yml: {str(e)}')

    def print_integration_specific_resources(self, config):
        print(f"    • Entitlement Scope: {bcolors.OKBLUE}{config.entitlement_scope}{bcolors.ENDC}")
        print(f"    • Poll Interval: {bcolors.OKBLUE}{config.poll_interval_seconds}s{bcolors.ENDC}")
        print(f"    • Pending JSON field: {bcolors.OKBLUE}{PENDING_ENTITLEMENTS_FIELD}{bcolors.ENDC}")
        print(f"    • Env key: {bcolors.OKBLUE}{self.get_record_env_key()}{bcolors.ENDC}")

    def print_integration_commands(self):
        print(f"\n{bcolors.BOLD}SailPoint / Service Mode usage:{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}• enterprise-user user@co.com --invite --add-role Role --add-team Team{bcolors.ENDC}")
        print(f"    Invite now; role/team queued until the user is Active")
        print(f"  {bcolors.OKGREEN}• share-record -e user@co.com RECORD_UID{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}• share-folder -e user@co.com FOLDER_UID{bcolors.ENDC}")
        print(f"    Queued while invited; applied after activation\n")
