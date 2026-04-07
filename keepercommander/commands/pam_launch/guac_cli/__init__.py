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

Input modes
-----------
Key-event mode (default)
    InputHandler maps every keystroke to a Guacamole ``key`` instruction
    (press + release), matching Web Vault behaviour (Guacamole.Keyboard →
    sendKeyEvent).  This is the default for ``pam launch``.

Pipe / stdin mode (--stdin)
    StdinHandler reads raw stdin bytes and sends them via the pipe/blob/end
    STDIN stream, matching kcm-cli behaviour.  Selected with ``--stdin``.

Shared behaviour (both modes)
    Paste chords (Ctrl+V, Shift+Insert; Windows: also Ctrl+Shift+V) read the
    OS clipboard via pyperclip and send it using the Vault-equivalent Guacamole
    clipboard stream protocol (``clipboard`` + ``blob`` + ``end``).

    Ctrl+C double-tap: first press forwards the interrupt to the remote;
    a second press within 400 ms tears down the local session.

Components
----------
- input:         InputHandler — key-event mode stdin reader
- stdin_handler: StdinHandler — pipe/byte mode stdin reader
- session_input: CtrlCCoordinator, PasteOrchestrator — shared helpers
- instructions:  Instruction handlers with routing to the guacamole module
- decoder:       Guacamole protocol parser (legacy)
- renderer:      Terminal output renderer via ANSI/curses
"""

from .instructions import create_instruction_router, get_default_handlers
from .stdin_handler import StdinHandler
from .decoder import GuacamoleDecoder, GuacInstruction, GuacOp, X11Keysym
from .renderer import TerminalRenderer
from .input import InputHandler
from .session_input import CtrlCCoordinator, PasteOrchestrator

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
    'CtrlCCoordinator',
    'PasteOrchestrator',
]

