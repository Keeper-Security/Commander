#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import re
from html import escape as _html_escape

def _esc(text) -> str:
    """Escape HTML-significant characters and strip control/ANSI sequences
    for safe use in prompt_toolkit HTML()."""
    s = re.sub(r'[\x00-\x1f\x7f]', '', str(text))  # strip control chars + ANSI
    return _html_escape(s, quote=False)
