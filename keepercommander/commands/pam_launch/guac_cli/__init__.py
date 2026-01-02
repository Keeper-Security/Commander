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

"""
Guacamole CLI client module for Commander terminal mode.

This module provides Guacamole protocol handling for CLI sessions.

Components:
- instructions: Instruction handlers with routing to new guacamole module
- stdin_handler: Reads stdin and sends via pipe/blob/end pattern (for SSH/TTY)
- decoder: Parses Guacamole protocol instructions (legacy)
- renderer: Renders terminal output via ANSI/curses
- input: Maps stdin keystrokes to X11 keysyms (for graphical protocols)
"""

from .instructions import create_instruction_router, get_default_handlers
from .stdin_handler import StdinHandler
from .decoder import GuacamoleDecoder, GuacInstruction, GuacOp, X11Keysym
from .renderer import TerminalRenderer
from .input import InputHandler

__all__ = [
    'create_instruction_router',
    'get_default_handlers',
    'StdinHandler',
    'GuacamoleDecoder',
    'GuacInstruction',
    'GuacOp',
    'X11Keysym',
    'TerminalRenderer',
    'InputHandler',
]

