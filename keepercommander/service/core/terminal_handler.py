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

import os
import sys
from typing import Optional
from ..decorators.logging import debug_decorator

class TerminalHandler:
    @staticmethod
    @debug_decorator
    def get_terminal_info() -> Optional[str]:
        """Get terminal information based on platform."""
        try:
            if sys.platform.startswith('win'):
                return os.environ.get('COMSPEC')
            return os.ttyname(sys.stdout.fileno()) if sys.stdout.isatty() else None
        except Exception as e:
            return None

    @staticmethod
    def notify_other_terminal(terminal: str) -> None:
        """Notify other terminal about service stop."""
        if not sys.platform.startswith('win'):
            try:
                with open(terminal, 'w') as term:
                    term.write("Commander Service stopped by another terminal\n")
            except Exception as e:
                pass