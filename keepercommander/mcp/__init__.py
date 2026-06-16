#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""Model Context Protocol (MCP) server integration for Keeper Commander.

This package exposes a curated set of Commander capabilities to AI assistants over
the Model Context Protocol. Access is governed by an approval/capability configuration
that is stored in a dedicated Keeper vault record (see ``config.py``). The MCP server
itself is forbidden from reading or modifying that record, so an agent cannot escalate
its own privileges.

The management surface (approve/revoke clients, toggle capabilities, set scope) is the
``mcp`` command (see ``commands.py``). The server itself runs over stdio via
``mcp start`` and is launched by the AI client.
"""

from .commands import register_commands, register_command_info

__all__ = ['register_commands', 'register_command_info']
