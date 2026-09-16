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

"""Container-start command-list enforcement for *-app-setup integrations.

`service-create` runs every time the Commander container boots (it's the
container's `command:` in docker-compose.yml), so a hand-edited compose file
or a stale/rebuilt image can otherwise pass through a `commands` value that
no longer matches what the integration was actually set up to allow. This
re-sanitizes `args.commands` against the deploying integration's own
declared allowlist right before it's persisted.
"""

from __future__ import annotations

import os


def apply_runtime_command_policy(args) -> None:
    if not getattr(args, 'commands', None):
        return

    matched = [
        env_key for env_key in _integration_sanitizers()
        if (os.environ.get(env_key) or '').strip()
    ]
    if not matched:
        return
    if len(matched) > 1:
        print(
            f'Service Mode: multiple integration env vars are set ({", ".join(matched)}); '
            f'applying {matched[0]} allowlist. Remove the others from the container '
            f'environment to avoid ambiguous command policy.'
        )

    env_key = matched[0]
    sanitize = _integration_sanitizers()[env_key]
    cleaned = sanitize(args.commands)
    if cleaned != args.commands:
        print(
            f'Service Mode ({env_key}): removed commands outside the integration '
            f'allowlist before service-create.\n  Was: {args.commands}\n  Now: {cleaned}'
        )
    args.commands = cleaned


def _integration_sanitizers():
    """Map each integration's container-start env var to its own sanitize_service_commands()
    (or equivalent), reusing the exact allow/ban lists each *-app-setup command declares.

    SailPoint is included here too, even though SailPointService.maybe_enable() (called
    earlier in create_service.py) already sanitizes against the same allowlist: that call
    silently skips sanitizing if the vault marker-field check on SAILPOINT_RECORD fails or
    throws, so this acts as a fallback that applies regardless of that record's state.
    """
    from ..terraform_app_setup import TerraformSetupConstants
    from .command_policy import sanitize_commands
    from .gchat_app_setup import GChatAppSetupCommand
    from .sailpoint_app_setup import SailPointAppSetupCommand
    from .slack_app_setup import SlackAppSetupCommand
    from .teams_app_setup import TeamsAppSetupCommand
    from ...decorators.min_commander_version import TERRAFORM_DOCKER_ENV

    slack = SlackAppSetupCommand()
    teams = TeamsAppSetupCommand()
    gchat = GChatAppSetupCommand()
    sailpoint = SailPointAppSetupCommand()

    return {
        slack.get_record_env_key(): slack.sanitize_service_commands,
        teams.get_record_env_key(): teams.sanitize_service_commands,
        gchat.get_record_env_key(): gchat.sanitize_service_commands,
        sailpoint.get_record_env_key(): sailpoint.sanitize_service_commands,
        TERRAFORM_DOCKER_ENV: lambda commands: sanitize_commands(
            commands, TerraformSetupConstants.SERVICE_COMMANDS_LIST
        ),
    }
