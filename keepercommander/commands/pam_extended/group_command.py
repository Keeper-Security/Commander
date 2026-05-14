#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""``pam extended`` top-level group command.

Sub-groups:
  pam extended schedule list|set|delete
  pam extended rule     list|add|delete
"""
from __future__ import annotations

from ..base import GroupCommandNew
from .schedule_commands import (
    PamExtendedScheduleListCommand,
    PamExtendedScheduleSetCommand,
    PamExtendedScheduleDeleteCommand,
)
from .discovery_rule_commands import (
    PamExtendedRuleListCommand,
    PamExtendedRuleAddCommand,
    PamExtendedRuleDeleteCommand,
)


class PamExtendedScheduleGroup(GroupCommandNew):
    """``pam extended schedule`` sub-group."""

    def __init__(self) -> None:
        super().__init__("Manage PAM rotation schedules")
        self.register_command_new(PamExtendedScheduleListCommand(), "list")
        self.register_command_new(PamExtendedScheduleSetCommand(), "set")
        self.register_command_new(PamExtendedScheduleDeleteCommand(), "delete")


class PamExtendedRuleGroup(GroupCommandNew):
    """``pam extended rule`` sub-group."""

    def __init__(self) -> None:
        super().__init__("Manage PAM discovery rules")
        self.register_command_new(PamExtendedRuleListCommand(), "list")
        self.register_command_new(PamExtendedRuleAddCommand(), "add")
        self.register_command_new(PamExtendedRuleDeleteCommand(), "delete")


class PamExtendedCommand(GroupCommandNew):
    """``pam extended`` — advanced PAM schedule and discovery-rule management."""

    def __init__(self) -> None:
        super().__init__("Advanced PAM schedule and discovery-rule management")
        self.register_command_new(PamExtendedScheduleGroup(), "schedule")
        self.register_command_new(PamExtendedRuleGroup(), "rule")
