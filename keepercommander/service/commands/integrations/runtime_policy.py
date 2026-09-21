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

from ...util.exceptions import ValidationError


def apply_runtime_command_policy(args) -> None:
    if getattr(args, 'commands', None) is None:
        return

    sanitizers = _integration_sanitizers()
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


def _integration_sanitizers():
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

    return {
        slack.get_record_env_key(): slack.sanitize_service_commands,
        teams.get_record_env_key(): teams.sanitize_service_commands,
        gchat.get_record_env_key(): gchat.sanitize_service_commands,
        sailpoint.get_record_env_key(): sailpoint.sanitize_service_commands,
        TERRAFORM_DOCKER_ENV: terraform_sanitizer,
        TERRAFORM_DOCKER_ENV_LEGACY: terraform_sanitizer,
    }
