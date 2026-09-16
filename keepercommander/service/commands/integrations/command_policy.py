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

"""Shared command-list sanitization for Service Mode *-app-setup commands.

Each integration keeps its own allowed (and optional banned) command list;
this module only provides the generic filter/force-include mechanism so
every integration can restrict its docker-compose command list to what it
already declares as allowed.
"""

from __future__ import annotations

from typing import Iterable


def sanitize_commands(commands: str, allowed: Iterable[str], banned: Iterable[str] = ()) -> str:
    """
    Keep only allowed commands from ``commands``; always drop banned ones.

    Also ensures every allowed, non-banned command is present in the result,
    so required commands are not dropped when the input is a partial or
    stale command list (e.g. a hand-edited docker-compose.yml).
    """
    allowed = list(allowed)
    allowed_set = {c.strip().lower() for c in allowed}
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
