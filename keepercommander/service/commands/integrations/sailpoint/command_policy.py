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

from typing import List

from .constants import SAILPOINT_ALLOWED_COMMANDS, SAILPOINT_BANNED_COMMANDS


class SailPointCommandPolicy:
    """Sanitize / restrict commands allowed for SailPoint Service Mode."""

    @classmethod
    def sanitize(cls, commands: str) -> str:
        """Keep only SailPoint-allowed commands; always drop banned secret-bearing ones."""
        allowed = {c.strip().lower() for c in SAILPOINT_ALLOWED_COMMANDS}
        banned = {c.lower() for c in SAILPOINT_BANNED_COMMANDS}
        parts: List[str] = []
        seen = set()
        for raw in (commands or '').split(','):
            cmd = raw.strip()
            if not cmd:
                continue
            key = cmd.lower()
            if key in banned or key not in allowed:
                continue
            if key in seen:
                continue
            seen.add(key)
            parts.append(cmd)
        if not parts:
            return ','.join(SAILPOINT_ALLOWED_COMMANDS)
        return ','.join(parts)

    @classmethod
    def default_allowlist(cls) -> str:
        return cls.sanitize(','.join(SAILPOINT_ALLOWED_COMMANDS))
