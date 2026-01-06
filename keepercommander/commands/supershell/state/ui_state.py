"""
UIState - UI presentation state

Contains all state related to the UI presentation, not the underlying data.
"""

from dataclasses import dataclass, field
from typing import Optional, Set, List, Tuple


@dataclass
class UIState:
    """UI presentation state for SuperShell.

    This class holds all UI-related state that affects how
    data is displayed, but not the data itself.
    """

    # View settings
    view_mode: str = 'detail'
    """Current view mode: 'detail' or 'json'"""

    unmask_secrets: bool = False
    """When True, show secret/password/passphrase field values"""

    # Search state
    search_query: str = ""
    """Current search query"""

    search_input_text: str = ""
    """Text being typed in search box"""

    search_input_active: bool = False
    """True when typing in search, False when navigating results"""

    filtered_record_uids: Optional[Set[str]] = None
    """None = show all, Set = filtered UIDs from search"""

    # Command mode (vim :command)
    command_mode: bool = False
    """True when in : command mode"""

    command_buffer: str = ""
    """Accumulated command input"""

    # Shell pane state
    shell_pane_visible: bool = False
    """True when shell pane is shown"""

    shell_input_text: str = ""
    """Current text in shell input"""

    shell_history: List[Tuple[str, str]] = field(default_factory=list)
    """List of (command, output) tuples"""

    shell_input_active: bool = False
    """True when shell input has focus"""

    shell_command_history: List[str] = field(default_factory=list)
    """Command history for up/down arrow navigation"""

    shell_history_index: int = -1
    """Current position in command history (-1 = new command)"""

    def is_searching(self) -> bool:
        """Check if a search is active."""
        return self.filtered_record_uids is not None

    def clear_search(self) -> 'UIState':
        """Return a new UIState with search cleared."""
        return UIState(
            view_mode=self.view_mode,
            unmask_secrets=self.unmask_secrets,
            search_query="",
            search_input_text="",
            search_input_active=False,
            filtered_record_uids=None,
            command_mode=self.command_mode,
            command_buffer=self.command_buffer,
            shell_pane_visible=self.shell_pane_visible,
            shell_input_text=self.shell_input_text,
            shell_history=self.shell_history,
            shell_input_active=self.shell_input_active,
            shell_command_history=self.shell_command_history,
            shell_history_index=self.shell_history_index,
        )


@dataclass
class ThemeState:
    """Theme/color state for SuperShell."""

    color_theme: str = 'green'
    """Current theme name"""

    theme_colors: dict = field(default_factory=dict)
    """Color values for current theme"""
