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

"""Container-start command-list enforcement for *-app-setup integrations."""

from __future__ import annotations

import os

from .... import vault
from ...util.exceptions import ValidationError
from ...docker import WorkflowApprovalConstants


def apply_runtime_command_policy(args, params=None) -> None:
    if getattr(args, 'commands', None) is None:
        return

    sanitizers = _integration_sanitizers(params)
    matched = [env_key for env_key in sanitizers if (os.environ.get(env_key) or '').strip()]
    if not matched:
        return
    if len(matched) > 1:
        raise ValidationError(
            f'Multiple integration env vars are set ({", ".join(matched)}); '
            f'remove all but one before starting the service.'
        )

    env_key = matched[0]
    cleaned = sanitizers[env_key](args.commands)
    if cleaned != args.commands:
        print(
            f'Service Mode ({env_key}): removed commands outside the integration '
            f'allowlist before service-create.\n  Was: {args.commands}\n  Now: {cleaned}'
        )
    args.commands = cleaned


def _read_workflow_approval_enabled(params, env_key: str) -> bool:
    """Read the optional PAM Workflow toggle from an integration config record.

    Missing config, missing field, or unreadable values are treated as disabled
    so a stale Compose command list cannot enable PAM accidentally.
    """
    if not params or not (record_uid := (os.environ.get(env_key) or '').strip()):
        return False
    try:
        record = vault.KeeperRecord.load(params, record_uid)
        if not record:
            return False
        for custom_field in getattr(record, 'custom', None) or []:
            if custom_field.label != WorkflowApprovalConstants.FIELD_ENABLED:
                continue
            value = custom_field.get_default_value()
            return str(value or '').strip().lower() in {'true', '1', 'yes', 'y', 'on'}
    except Exception:
        return False
    return False


def _integration_sanitizers(params=None):
    """Maps each integration's env var to its own sanitize_service_commands(); SailPoint is included too as a fallback in case SailPointService.maybe_enable() skipped sanitizing."""
    from ..terraform_app_setup import TerraformSetupConstants
    from .command_policy import sanitize_commands
    from .gchat_app_setup import GChatAppSetupCommand
    from .sailpoint_app_setup import SailPointAppSetupCommand
    from .slack_app_setup import SlackAppSetupCommand
    from .teams_app_setup import TeamsAppSetupCommand
    from ...decorators.min_commander_version import TERRAFORM_DOCKER_ENV, TERRAFORM_DOCKER_ENV_LEGACY

    slack = SlackAppSetupCommand()
    teams = TeamsAppSetupCommand()
    gchat = GChatAppSetupCommand()
    sailpoint = SailPointAppSetupCommand()
    terraform_sanitizer = lambda commands: sanitize_commands(
        commands, TerraformSetupConstants.SERVICE_COMMANDS_LIST
    )

    def integration_sanitizer(integration, env_key):
        return lambda commands: integration.sanitize_service_commands(
            commands,
            workflow_approval_enabled=(
                integration.supports_pam_workflow_approval()
                and _read_workflow_approval_enabled(params, env_key)
            ),
        )

    return {
        slack.get_record_env_key(): integration_sanitizer(slack, slack.get_record_env_key()),
        teams.get_record_env_key(): integration_sanitizer(teams, teams.get_record_env_key()),
        gchat.get_record_env_key(): integration_sanitizer(gchat, gchat.get_record_env_key()),
        sailpoint.get_record_env_key(): sailpoint.sanitize_service_commands,
        TERRAFORM_DOCKER_ENV: terraform_sanitizer,
        TERRAFORM_DOCKER_ENV_LEGACY: terraform_sanitizer,
    }
