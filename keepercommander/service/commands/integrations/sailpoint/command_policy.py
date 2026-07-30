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

"""SailPoint Service Mode command allowlist policy."""

from __future__ import annotations

from typing import Optional

from .command_parse import SailPointCommandParser
from .constants import SAILPOINT_ALLOWED_COMMANDS, SAILPOINT_BANNED_COMMANDS

_ENTERPRISE_ROLE_CMDS = frozenset({'enterprise-role', 'er'})

# Role create / destroy / membership / rename / enforcement — not allowed in SailPoint.
_ER_BLOCKED_FLAGS = frozenset({
    '--add',
    '--copy',
    '--clone',
    '--delete',
    '--name',
    '--new-user',
    '--enforcement',
    '-au',
    '--add-user',
    '-ru',
    '--remove-user',
    '-at',
    '--add-team',
    '-rt',
    '--remove-team',
})

_ER_BLOCKED_PREFIXES = (
    '--name=',
    '--new-user=',
    '--enforcement=',
)

_ER_ALLOWED_HINT = (
    '--add-admin, --remove-admin, --add-privilege, --remove-privilege '
    '(plus --node, --cascade, -f)'
)


class SailPointCommandPolicy:
    """Sanitize / restrict commands allowed for SailPoint Service Mode."""

    @classmethod
    def sanitize(cls, commands: str) -> str:
        """
        Keep only SailPoint-allowed commands; always drop banned ones.

        Also ensures the full SailPoint allowlist is present so required
        commands (e.g. enterprise-role/er) are not dropped when the input
        list is a partial or older compose allowlist.
        """
        allowed = {c.strip().lower() for c in SAILPOINT_ALLOWED_COMMANDS}
        banned = {c.lower() for c in SAILPOINT_BANNED_COMMANDS}
        filtered = [
            cmd for raw in (commands or '').split(',')
            if (cmd := raw.strip())
            and (key := cmd.lower()) not in banned
            and key in allowed
        ]
        # Input order first, then any missing required allowlist entries.
        by_key = {cmd.lower(): cmd for cmd in filtered}
        for cmd in SAILPOINT_ALLOWED_COMMANDS:
            key = cmd.lower()
            if key not in banned and key not in by_key:
                by_key[key] = cmd
        return ','.join(by_key.values())

    @classmethod
    def default_allowlist(cls) -> str:
        return cls.sanitize(','.join(SAILPOINT_ALLOWED_COMMANDS))

    @classmethod
    def validate_enterprise_role(cls, command: str) -> Optional[str]:
        """
        Restrict enterprise-role to admin/privilege ops only.

        Returns an error message when blocked, or None when allowed
        (including read-only ``er <role>``).
        """
        tokens = SailPointCommandParser.tokenize(command)
        if not tokens or tokens[0].lower() not in _ENTERPRISE_ROLE_CMDS:
            return None

        for token in tokens[1:]:
            lower = token.lower()
            if lower in _ER_BLOCKED_FLAGS or any(lower.startswith(p) for p in _ER_BLOCKED_PREFIXES):
                flag = token.split('=', 1)[0]
                return (
                    f'SailPoint mode does not allow enterprise-role {flag}. '
                    f'Allowed: {_ER_ALLOWED_HINT}.'
                )
        return None
