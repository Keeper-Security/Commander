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

"""Shared command-list sanitization for Service Mode *-app-setup commands."""

from __future__ import annotations

from typing import Iterable


def sanitize_commands(commands: str, allowed: Iterable[str], banned: Iterable[str] = ()) -> str:
    """Normalizes `commands` to exactly the allowed set minus banned; cannot narrow below the allowlist, only add missing/drop extra entries."""
    allowed = [c.strip() for c in allowed if c and c.strip()]
    allowed_set = {c.lower() for c in allowed}
    banned_set = {c.strip().lower() for c in banned}
    filtered = [
        cmd for raw in (commands or '').split(',')
        if (cmd := raw.strip())
        and (key := cmd.lower()) not in banned_set
        and key in allowed_set
    ]
    # Input order first, then any missing required allowlist entries.
    by_key = {cmd.lower(): cmd for cmd in filtered}
    for cmd in allowed:
        key = cmd.strip().lower()
        if key not in banned_set and key not in by_key:
            by_key[key] = cmd.strip()
    return ','.join(by_key.values())


def default_allowlist(allowed: Iterable[str], banned: Iterable[str] = ()) -> str:
    allowed = list(allowed)
    return sanitize_commands(','.join(allowed), allowed, banned)
