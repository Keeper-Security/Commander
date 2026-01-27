"""
Keyboard handling for SuperShell

Implements a dispatcher pattern to handle keyboard events based on
the current application state (search mode, shell mode, command mode, etc.)
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, List

from rich.markup import escape as rich_escape

# Debug logging - writes to /tmp/supershell_debug.log when enabled
DEBUG_EVENTS = False
_debug_log_file = None

def _debug_log(msg: str):
    """Log debug message to /tmp/supershell_debug.log if DEBUG_EVENTS is True."""
    if not DEBUG_EVENTS:
        return
    global _debug_log_file
    try:
        if _debug_log_file is None:
            _debug_log_file = open('/tmp/supershell_debug.log', 'a')
        import datetime
        timestamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
        _debug_log_file.write(f"[{timestamp}] {msg}\n")
        _debug_log_file.flush()
    except Exception:
        pass

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
    """Placeholder for shell input key handling.

    Note: All key handling is now done by ShellInputTextArea itself,
    including Tab/Shift+Tab focus cycling. This handler is kept for
    potential future use but currently does not handle any keys.
    """

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        # ShellInputTextArea handles all keys directly
        return False

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        return False


class ShellPaneCloseHandler(KeyHandler):
    """Handles Ctrl+D to close shell when not focused on shell output (which uses Ctrl+D for page down)."""

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        if not (app.shell_pane_visible and event.key == "ctrl+d"):
            return False
        # Don't intercept Ctrl+D when shell output has focus (it's used for page down there)
        try:
            from textual.widgets import TextArea
            shell_output = app.query_one("#shell_output_content", TextArea)
            if shell_output.has_focus:
                return False
        except Exception:
            pass
        return True

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        app._close_shell_pane()
        self._stop_event(event)
        return True


class ShellCopyHandler(KeyHandler):
    """Handles Ctrl+C/Cmd+C to copy selected text, Ctrl+Shift+C/Cmd+Shift+C to copy all shell output."""

    # Keys that trigger copy selected text
    COPY_KEYS = ("ctrl+c", "cmd+c")
    # Keys that trigger copy all output
    COPY_ALL_KEYS = ("ctrl+shift+c", "cmd+shift+c")

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        all_copy_keys = self.COPY_KEYS + self.COPY_ALL_KEYS
        result = app.shell_pane_visible and event.key in all_copy_keys
        _debug_log(f"ShellCopyHandler.can_handle: shell_visible={app.shell_pane_visible} "
                   f"key={event.key!r} result={result}")
        return result

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        _debug_log(f"ShellCopyHandler.handle: key={event.key!r}")
        import pyperclip

        # Ctrl+C or Cmd+C: Copy selected text from TextArea
        if event.key in self.COPY_KEYS:
            try:
                from textual.widgets import TextArea
                shell_output = app.query_one("#shell_output_content", TextArea)
                selected = shell_output.selected_text
                _debug_log(f"ShellCopyHandler.handle: selected_text={selected!r}")

                if selected and selected.strip():
                    pyperclip.copy(selected)
                    preview = selected[:40] + ('...' if len(selected) > 40 else '')
                    preview = preview.replace('\n', ' ')
                    app.notify(f"Copied: {preview}", severity="information")
                    _debug_log(f"ShellCopyHandler.handle: Copied selected text")
                    self._stop_event(event)
                    return True
                else:
                    _debug_log(f"ShellCopyHandler.handle: No text selected, not handling")
                    return False  # Let event propagate if nothing selected
            except Exception as e:
                _debug_log(f"ShellCopyHandler.handle: Error getting selection: {e}")
                return False

        # Ctrl+Shift+C or Cmd+Shift+C: Copy all shell output
        if event.key in self.COPY_ALL_KEYS:
            import re
            lines = []
            _debug_log(f"ShellCopyHandler.handle: shell_history has {len(app.shell_history)} entries")
            for cmd, output in app.shell_history:
                lines.append(f"> {cmd}")
                if output.strip():
                    lines.append(output)
                    lines.append("")

            raw_text = '\n'.join(lines)
            clean_text = re.sub(r'\x1b\[[0-9;]*m', '', raw_text)
            clean_text = re.sub(r'\[[^\]]*\]', '', clean_text)

            if clean_text.strip():
                try:
                    pyperclip.copy(clean_text.strip())
                    app.notify("All shell output copied", severity="information")
                    _debug_log(f"ShellCopyHandler.handle: Copied all output")
                except Exception as e:
                    _debug_log(f"ShellCopyHandler.handle: Copy failed: {e}")
                    app.notify("Copy failed", severity="warning")
            else:
                app.notify("No output to copy", severity="information")

            self._stop_event(event)
            return True

        return False


class ShellOutputHandler(KeyHandler):
    """Handles keyboard events when shell output pane has focus.

    Provides vim-style scrolling (j/k, Ctrl+d/u) and Tab cycling
    when the terminal output pane is focused.
    """

    def can_handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        if not app.shell_pane_visible:
            return False
        try:
            from textual.widgets import TextArea
            shell_output = app.query_one("#shell_output_content", TextArea)
            return shell_output.has_focus
        except Exception:
            return False

    def handle(self, event: 'Key', app: 'SuperShellApp') -> bool:
        from textual.widgets import Tree, TextArea
        from textual.containers import VerticalScroll

        try:
            shell_output = app.query_one("#shell_output_content", TextArea)
        except Exception:
            return False

        # Tab cycles to Shell Input
        if event.key == "tab":
            app.shell_input_active = True
            try:
                shell_input = app.query_one("#shell_input_area")
                shell_input.focus()
            except Exception:
                pass
            app._update_status("Shell input | Tab to search | Shift+Tab to output")
            self._stop_event(event)
            return True

        # Shift+Tab cycles to Detail pane
        if event.key == "shift+tab":
            detail_scroll = app.query_one("#record_detail", VerticalScroll)
            detail_scroll.focus()
            app._update_status("Detail pane | Tab to shell output | Shift+Tab to tree")
            self._stop_event(event)
            return True

        # Escape goes back to tree
        if event.key == "escape":
            tree = app.query_one("#folder_tree", Tree)
            tree.focus()
            app._update_status("Navigate with j/k | Tab to detail | ? for help")
            self._stop_event(event)
            return True

        # Vim-style scrolling: j = down, k = up
        if event.key == "j" or event.key == "down":
            shell_output.scroll_relative(y=1)
            self._stop_event(event)
            return True

        if event.key == "k" or event.key == "up":
            shell_output.scroll_relative(y=-1)
            self._stop_event(event)
            return True

        # Ctrl+D = half page down
        if event.key == "ctrl+d":
            shell_output.scroll_relative(y=10)
            self._stop_event(event)
            return True

        # Ctrl+U = half page up
        if event.key == "ctrl+u":
            shell_output.scroll_relative(y=-10)
            self._stop_event(event)
            return True

        # Ctrl+F = full page down (vim)
        if event.key == "ctrl+f":
            shell_output.scroll_relative(y=20)
            self._stop_event(event)
            return True

        # Ctrl+B = full page up (vim)
        if event.key == "ctrl+b":
            shell_output.scroll_relative(y=-20)
            self._stop_event(event)
            return True

        # Ctrl+E = scroll down one line (vim)
        if event.key == "ctrl+e":
            shell_output.scroll_relative(y=1)
            self._stop_event(event)
            return True

        # Ctrl+Y = scroll up one line (vim)
        if event.key == "ctrl+y":
            shell_output.scroll_relative(y=-1)
            self._stop_event(event)
            return True

        # g = go to top, G = go to bottom
        if event.key == "g":
            shell_output.scroll_home()
            self._stop_event(event)
            return True

        if event.character == "G":
            shell_output.scroll_end()
            self._stop_event(event)
            return True

        return False


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
        search_bar = app.query_one("#search_bar")
        search_bar.remove_class("search-active")

        if app.search_input_text:
            search_display.update(rich_escape(app.search_input_text))
        else:
            search_display.update("[dim]Search...[/dim]")

        if event.key == "tab":
            # Search input → Tree
            tree.focus()
            app._update_status("Navigate with j/k | Tab to detail | ? for help")
        else:
            # Shift+Tab: Search input → Shell Input (if visible) or Detail pane
            if app.shell_pane_visible:
                app.shell_input_active = True
                try:
                    shell_input = app.query_one("#shell_input_area")
                    shell_input.focus()
                except Exception:
                    pass
                app._update_status("Shell input | Tab to search | Shift+Tab to output")
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
            # Detail pane → Shell Output (if visible) or Search input
            if app.shell_pane_visible:
                try:
                    from textual.widgets import TextArea
                    shell_output = app.query_one("#shell_output_content", TextArea)
                    shell_output.focus()
                except Exception:
                    pass
                app._update_status("Shell output | j/k to scroll | Tab to input | Shift+Tab to detail")
            else:
                app.search_input_active = True
                tree.add_class("search-input-active")
                search_bar = app.query_one("#search_bar")
                search_bar.add_class("search-active")
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
            # Ctrl+Y scrolls viewport up one line (like vim)
            detail_scroll.scroll_relative(y=-1)
            self._stop_event(event)
            return True

        if event.key == "ctrl+e":
            # Ctrl+E scrolls viewport down one line (like vim)
            detail_scroll.scroll_relative(y=1)
            self._stop_event(event)
            return True

        if event.key == "ctrl+u":
            # Ctrl+U scrolls viewport up half page (like vim)
            detail_scroll.scroll_relative(y=-10)
            self._stop_event(event)
            return True

        if event.key == "ctrl+d":
            # Ctrl+D scrolls viewport down half page (like vim)
            detail_scroll.scroll_relative(y=10)
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
            if app.shell_pane_visible:
                app._update_status("Detail pane | Tab to shell | Shift+Tab to tree")
            else:
                app._update_status("Detail pane | Tab to search | Shift+Tab to tree")
            self._stop_event(event)
            return True

        # Shift+Tab switches to search input
        if event.key == "shift+tab":
            app.search_input_active = True
            tree.add_class("search-input-active")
            search_bar = app.query_one("#search_bar")
            search_bar.add_class("search-active")
            app._update_search_display(perform_search=False)
            app._update_status("Type to search | Tab to tree | Ctrl+U to clear")
            self._stop_event(event)
            return True

        # / switches back to search input mode
        if event.key == "slash":
            app.search_input_active = True
            tree.add_class("search-input-active")
            search_bar = app.query_one("#search_bar")
            search_bar.add_class("search-active")
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

        # Ctrl+U clears the search input ONLY when actively typing in search
        # Otherwise, let it pass through for page-up navigation
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
            search_bar = app.query_one("#search_bar")
            search_bar.add_class("search-active")
            app._update_search_display(perform_search=False)
            self._stop_event(event)
            return True

        if event.key == "escape":
            # Clear search and move focus to tree
            app.search_input_text = ""
            app.search_input_active = False
            tree.remove_class("search-input-active")
            search_bar = app.query_one("#search_bar")
            search_bar.remove_class("search-active")
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
            search_bar = app.query_one("#search_bar")
            search_bar.remove_class("search-active")

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

        if event.key == "backspace" and app.search_input_active:
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
            ShellCopyHandler(),
            ShellOutputHandler(),

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
            can_handle = handler.can_handle(event, app)
            if can_handle:
                _debug_log(f"DISPATCH: {handler.__class__.__name__} can_handle=True for key={event.key!r}")
                result = handler.handle(event, app)
                _debug_log(f"DISPATCH: {handler.__class__.__name__} handle returned {result}")
                if result:
                    return True
        _debug_log(f"DISPATCH: No handler for key={event.key!r}")
        return False


# Module-level dispatcher instance for use by the app
keyboard_dispatcher = KeyboardDispatcher()
