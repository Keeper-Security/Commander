"""
Keyboard handling for SuperShell

Implements a dispatcher pattern to handle keyboard events based on
the current application state (search mode, shell mode, command mode, etc.)
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, List

from rich.markup import escape as rich_escape

if TYPE_CHECKING:
    from textual.events import Key
    from textual.widgets import Tree
    from .._supershell_impl import SuperShellApp


class KeyHandler(ABC):
    """Base class for keyboard event handlers.

    Each handler is responsible for a specific context (e.g., command mode,
    search input, shell input). The dispatcher checks each handler in order
    until one handles the event.
    """

    @abstractmethod
    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        """Check if this handler can handle the given event.

        Args:
            event: The keyboard event
            app: The SuperShell app instance

        Returns:
            True if this handler should handle the event
        """
        pass

    @abstractmethod
    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        """Handle the keyboard event.

        Args:
            event: The keyboard event
            app: The SuperShell app instance

        Returns:
            True if the event was handled and should not propagate
        """
        pass

    def _stop_event(self, event: 'Key') -> None:
        """Helper to stop event propagation."""
        event.prevent_default()
        event.stop()


class GlobalExitHandler(KeyHandler):
    """Handles ! key to exit to Keeper shell."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        return (
            event.character == "!" and
            not app.search_input_active and
            not app.shell_input_active
        )

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        app.exit("Exited to Keeper shell. Type 'supershell' or 'ss' to return.")
        self._stop_event(event)
        return True


class ShellPaneToggleHandler(KeyHandler):
    """Handles Ctrl+\\ to toggle shell pane."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        return event.key == "ctrl+backslash"

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        if app.shell_pane_visible:
            app._close_shell_pane()
        else:
            app._open_shell_pane()
        self._stop_event(event)
        return True


class CommandModeHandler(KeyHandler):
    """Handles vim-style :command mode."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        # Handle when in command mode OR when entering command mode with :
        if app.search_input_active or app.shell_input_active:
            return False
        return app.command_mode or event.character == ":"

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        # Enter command mode with :
        if event.character == ":" and not app.command_mode:
            app.command_mode = True
            app.command_buffer = ""
            app._update_status(":")
            self._stop_event(event)
            return True

        # Already in command mode
        if app.command_mode:
            if event.key == "escape":
                app.command_mode = False
                app.command_buffer = ""
                app._update_status("Command cancelled")
                self._stop_event(event)
                return True

            elif event.key == "enter":
                app._execute_command(app.command_buffer)
                app.command_mode = False
                app.command_buffer = ""
                self._stop_event(event)
                return True

            elif event.key == "backspace":
                if app.command_buffer:
                    app.command_buffer = app.command_buffer[:-1]
                    app._update_status(f":{app.command_buffer}")
                else:
                    app.command_mode = False
                    app._update_status("Navigate with j/k | / to search | ? for help")
                self._stop_event(event)
                return True

            elif event.character and event.character.isprintable():
                app.command_buffer += event.character
                app._update_status(f":{app.command_buffer}")
                self._stop_event(event)
                return True

        return False


class ShellInputHandler(KeyHandler):
    """Handles input when shell pane is visible and active."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        return app.shell_pane_visible and app.shell_input_active

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        tree = app.query_one("#folder_tree")

        if event.key == "ctrl+d":
            app._close_shell_pane()
            self._stop_event(event)
            return True

        if event.key == "enter":
            app._execute_shell_command(app.shell_input_text)
            app.shell_input_text = ""
            app._update_shell_input_display()
            self._stop_event(event)
            return True

        if event.key == "backspace":
            if app.shell_input_text:
                app.shell_input_text = app.shell_input_text[:-1]
                app._update_shell_input_display()
            self._stop_event(event)
            return True

        if event.key == "escape":
            app.shell_input_active = False
            tree.focus()
            app._update_shell_input_display()
            app._update_status("Shell open | Tab to cycle | press Enter in shell to run commands")
            self._stop_event(event)
            return True

        if event.key == "up":
            if app.shell_command_history:
                if app.shell_history_index < len(app.shell_command_history) - 1:
                    app.shell_history_index += 1
                    app.shell_input_text = app.shell_command_history[-(app.shell_history_index + 1)]
                    app._update_shell_input_display()
            self._stop_event(event)
            return True

        if event.key == "down":
            if app.shell_history_index > 0:
                app.shell_history_index -= 1
                app.shell_input_text = app.shell_command_history[-(app.shell_history_index + 1)]
            elif app.shell_history_index == 0:
                app.shell_history_index = -1
                app.shell_input_text = ""
            app._update_shell_input_display()
            self._stop_event(event)
            return True

        if event.character and event.character.isprintable():
            app.shell_input_text += event.character
            app._update_shell_input_display()
            self._stop_event(event)
            return True

        return False


class ShellPaneCloseHandler(KeyHandler):
    """Handles Ctrl+D to close shell even when not focused on input."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        return app.shell_pane_visible and event.key == "ctrl+d"

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        app._close_shell_pane()
        self._stop_event(event)
        return True


class SearchInputTabHandler(KeyHandler):
    """Handles Tab/Shift+Tab when in search input mode."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        return app.search_input_active and event.key in ("tab", "shift+tab")

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        from textual.widgets import Tree
        from textual.containers import VerticalScroll

        tree = app.query_one("#folder_tree", Tree)
        detail_scroll = app.query_one("#record_detail", VerticalScroll)
        search_display = app.query_one("#search_display")

        app.search_input_active = False
        tree.remove_class("search-input-active")

        if app.search_input_text:
            search_display.update(rich_escape(app.search_input_text))
        else:
            search_display.update("[dim]Search...[/dim]")

        if event.key == "tab":
            # Search input → Tree
            tree.focus()
            app._update_status("Navigate with j/k | Tab to detail | ? for help")
        else:
            # Shift+Tab: Search input → Shell (if visible) or Detail pane
            if app.shell_pane_visible:
                app.shell_input_active = True
                app._update_shell_input_display()
                app._update_status("Shell | Shift+Tab to detail | Tab to search")
            else:
                detail_scroll.focus()
                app._update_status("Detail pane | Tab to search | Shift+Tab to tree")

        self._stop_event(event)
        return True


class DetailPaneHandler(KeyHandler):
    """Handles keyboard events when detail pane has focus."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        from textual.containers import VerticalScroll
        detail_scroll = app.query_one("#record_detail", VerticalScroll)
        return detail_scroll.has_focus

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        from textual.widgets import Tree
        from textual.containers import VerticalScroll

        tree = app.query_one("#folder_tree", Tree)
        detail_scroll = app.query_one("#record_detail", VerticalScroll)

        if event.key == "tab":
            # Detail pane → Shell (if visible) or Search input
            if app.shell_pane_visible:
                app.shell_input_active = True
                app._update_shell_input_display()
                app._update_status("Shell | Tab to search | Shift+Tab to detail")
            else:
                app.search_input_active = True
                tree.add_class("search-input-active")
                app._update_search_display(perform_search=False)
                app._update_status("Type to search | Tab to tree | Ctrl+U to clear")
            self._stop_event(event)
            return True

        if event.key == "shift+tab":
            # Detail pane → Tree
            tree.focus()
            app._update_status("Navigate with j/k | Tab to detail | ? for help")
            self._stop_event(event)
            return True

        if event.key == "escape":
            tree.focus()
            self._stop_event(event)
            return True

        if event.key == "ctrl+y":
            # Ctrl+Y scrolls viewport up (like vim)
            detail_scroll.scroll_relative(y=-1)
            self._stop_event(event)
            return True

        if event.key == "ctrl+e":
            # Ctrl+E scrolls viewport down (like vim)
            detail_scroll.scroll_relative(y=1)
            self._stop_event(event)
            return True

        return False


class SearchBarTreeNavigationHandler(KeyHandler):
    """Handles tree navigation when search bar is visible but not typing."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        search_bar = app.query_one("#search_bar")
        from textual.widgets import Tree
        tree = app.query_one("#folder_tree", Tree)
        return (
            search_bar.styles.display != "none" and
            not app.search_input_active and
            tree.has_focus
        )

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        from textual.widgets import Tree
        from textual.containers import VerticalScroll

        tree = app.query_one("#folder_tree", Tree)
        detail_scroll = app.query_one("#record_detail", VerticalScroll)

        # Handle arrow keys for expand/collapse
        if event.key == "left":
            if tree.cursor_node and tree.cursor_node.allow_expand:
                tree.cursor_node.collapse()
            self._stop_event(event)
            return True

        if event.key == "right":
            if tree.cursor_node and tree.cursor_node.allow_expand:
                tree.cursor_node.expand()
            self._stop_event(event)
            return True

        # Navigation keys - let tree handle them
        if event.key in ("j", "k", "h", "l", "up", "down", "enter", "space"):
            return False

        # Action keys - let them pass through
        if event.key in ("t", "c", "u", "w", "i", "y", "d", "g", "p", "question_mark"):
            return False

        # Shift+G for go to bottom
        if event.character == "G":
            return False

        # Tab switches to detail pane
        if event.key == "tab":
            detail_scroll.focus()
            app._update_status("Detail pane | Tab to search | Shift+Tab to tree")
            self._stop_event(event)
            return True

        # Shift+Tab switches to search input
        if event.key == "shift+tab":
            app.search_input_active = True
            tree.add_class("search-input-active")
            app._update_search_display(perform_search=False)
            app._update_status("Type to search | Tab to tree | Ctrl+U to clear")
            self._stop_event(event)
            return True

        # / switches back to search input mode
        if event.key == "slash":
            app.search_input_active = True
            tree.add_class("search-input-active")
            app._update_search_display(perform_search=False)
            self._stop_event(event)
            return True

        return False


class SearchInputHandler(KeyHandler):
    """Handles keyboard input in search mode."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        search_bar = app.query_one("#search_bar")
        return search_bar.styles.display != "none"

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        from textual.widgets import Tree

        tree = app.query_one("#folder_tree", Tree)

        # Ctrl+U clears the search input
        if event.key == "ctrl+u" and app.search_input_active:
            app.search_input_text = ""
            app._update_search_display(perform_search=False)
            app._perform_live_search("")
            self._stop_event(event)
            return True

        # / to switch to search input mode
        if event.key == "slash" and not app.search_input_active:
            app.search_input_active = True
            tree.add_class("search-input-active")
            app._update_search_display(perform_search=False)
            self._stop_event(event)
            return True

        if event.key == "escape":
            # Clear search and move focus to tree
            app.search_input_text = ""
            app.search_input_active = False
            tree.remove_class("search-input-active")
            app._perform_live_search("")

            search_display = app.query_one("#search_display")
            search_display.update("[dim]Search... (Tab or /)[/dim]")
            results_label = app.query_one("#search_results_label")
            results_label.update("")

            # Restore previous selection
            app.selected_record = app.pre_search_selected_record
            app.selected_folder = app.pre_search_selected_folder
            app._restore_tree_selection(tree)

            tree.focus()
            app._update_status("Navigate with j/k | Tab to detail | ? for help")
            self._stop_event(event)
            return True

        if event.key in ("enter", "down") and app.search_input_active:
            # Move focus to tree to navigate results (only when typing in search)
            app.search_input_active = False
            tree.remove_class("search-input-active")

            search_display = app.query_one("#search_display")
            if app.search_input_text:
                search_display.update(rich_escape(app.search_input_text))
            else:
                search_display.update("[dim]Search...[/dim]")

            app.set_focus(tree)
            tree.focus()

            app._update_status("Navigate results with j/k | / to edit search | ESC to close")
            self._stop_event(event)
            return True

        if event.key == "backspace":
            if app.search_input_text:
                app.search_input_text = app.search_input_text[:-1]
                app._update_search_display()
            self._stop_event(event)
            return True

        if app.search_input_active and event.character and event.character.isprintable():
            app.search_input_text += event.character
            app._update_search_display()
            self._stop_event(event)
            return True

        return False


class TreeArrowHandler(KeyHandler):
    """Handles arrow keys for tree expand/collapse when search is not active."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        search_bar = app.query_one("#search_bar")
        from textual.widgets import Tree
        tree = app.query_one("#folder_tree", Tree)
        return (
            search_bar.styles.display == "none" and
            tree.has_focus and
            event.key in ("left", "right")
        )

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        from textual.widgets import Tree
        tree = app.query_one("#folder_tree", Tree)

        if event.key == "left":
            if tree.cursor_node and tree.cursor_node.allow_expand:
                tree.cursor_node.collapse()
            self._stop_event(event)
            return True

        if event.key == "right":
            if tree.cursor_node and tree.cursor_node.allow_expand:
                tree.cursor_node.expand()
            self._stop_event(event)
            return True

        return False


class TreeEscapeHandler(KeyHandler):
    """Handles Escape to collapse current or go to parent when search not active."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        search_bar = app.query_one("#search_bar")
        return search_bar.styles.display == "none" and event.key == "escape"

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        from textual.widgets import Tree
        tree = app.query_one("#folder_tree", Tree)
        app._collapse_current_or_parent(tree)
        self._stop_event(event)
        return True


class KeyboardDispatcher:
    """Dispatches keyboard events to appropriate handlers.

    Handlers are checked in order until one handles the event.
    The order matters - more specific handlers should come before
    more general ones.
    """

    def __init__(self):
        """Initialize with the handler chain."""
        self.handlers: List[KeyHandler] = [
            # Global handlers (highest priority)
            GlobalExitHandler(),
            ShellPaneToggleHandler(),

            # Mode-specific handlers
            CommandModeHandler(),
            ShellInputHandler(),
            ShellPaneCloseHandler(),

            # Tab cycling handlers
            SearchInputTabHandler(),
            DetailPaneHandler(),

            # Search handlers
            SearchBarTreeNavigationHandler(),
            SearchInputHandler(),

            # Tree handlers (lowest priority)
            TreeArrowHandler(),
            TreeEscapeHandler(),
        ]

    def dispatch(self, event: 'Key', app: 'SuperShellApp') -> bool:
        """Dispatch a keyboard event to the appropriate handler.

        Args:
            event: The keyboard event
            app: The SuperShell app instance

        Returns:
            True if the event was handled
        """
        for handler in self.handlers:
            if handler.can_handle(event, app):
                if handler.handle(event, app):
                    return True
        return False


# Module-level dispatcher instance for use by the app
keyboard_dispatcher = KeyboardDispatcher()
