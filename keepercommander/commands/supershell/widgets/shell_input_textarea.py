"""
Shell input TextArea widget for SuperShell

A TextArea specialized for shell command input with Enter-to-execute behavior
and shell history navigation.
"""

from typing import TYPE_CHECKING

from textual.widgets import TextArea, Tree

if TYPE_CHECKING:
    from ..app import SuperShellApp


class ShellInputTextArea(TextArea):
    """TextArea for shell command input with Enter-to-execute behavior.

    Features:
    - Enter executes command instead of inserting newline
    - Soft wrapping for long commands
    - Multi-line display
    - Integrates with shell history navigation
    """

    def __init__(self, app_ref: 'SuperShellApp', *args, **kwargs):
        # Set defaults for shell input behavior
        kwargs.setdefault('soft_wrap', True)
        kwargs.setdefault('show_line_numbers', False)
        kwargs.setdefault('tab_behavior', 'focus')  # Tab cycles focus, not inserts tab
        super().__init__(*args, **kwargs)
        self._app_ref = app_ref

    async def _on_key(self, event) -> None:
        """Intercept keys for shell-specific behavior."""
        # Enter executes command instead of inserting newline
        if event.key == "enter":
            command = self.text.strip()
            self.clear()  # Clear immediately for responsiveness
            if command:
                # Execute asynchronously with loading indicator
                self._app_ref._execute_shell_command_async(command)
            event.prevent_default()
            event.stop()
            return

        # Up arrow navigates history
        if event.key == "up":
            if self._app_ref.shell_command_history:
                if self._app_ref.shell_history_index < len(self._app_ref.shell_command_history) - 1:
                    self._app_ref.shell_history_index += 1
                    history_cmd = self._app_ref.shell_command_history[-(self._app_ref.shell_history_index + 1)]
                    self.clear()
                    self.insert(history_cmd)
            event.prevent_default()
            event.stop()
            return

        # Down arrow navigates history
        if event.key == "down":
            if self._app_ref.shell_history_index > 0:
                self._app_ref.shell_history_index -= 1
                history_cmd = self._app_ref.shell_command_history[-(self._app_ref.shell_history_index + 1)]
                self.clear()
                self.insert(history_cmd)
            elif self._app_ref.shell_history_index == 0:
                self._app_ref.shell_history_index = -1
                self.clear()
            event.prevent_default()
            event.stop()
            return

        # Ctrl+U clears the input (bash-like)
        if event.key == "ctrl+u":
            self.clear()
            self._app_ref.shell_history_index = -1
            event.prevent_default()
            event.stop()
            return

        # Ctrl+D closes shell pane
        if event.key == "ctrl+d":
            self._app_ref._close_shell_pane()
            event.prevent_default()
            event.stop()
            return

        # Escape unfocuses the input
        if event.key == "escape":
            self._app_ref.shell_input_active = False
            tree = self._app_ref.query_one("#folder_tree")
            tree.focus()
            self._app_ref._update_status("Shell open | Tab to cycle | press Enter in shell to run commands")
            event.prevent_default()
            event.stop()
            return

        # Tab cycles to search mode
        if event.key == "tab":
            self._app_ref.shell_input_active = False
            self._app_ref.search_input_active = True
            tree = self._app_ref.query_one("#folder_tree", Tree)
            tree.add_class("search-input-active")
            search_bar = self._app_ref.query_one("#search_bar")
            search_bar.add_class("search-active")
            tree.focus()  # Search mode works with tree focused
            self._app_ref._update_search_display(perform_search=False)
            self._app_ref._update_status("Type to search | Tab to tree | Ctrl+U to clear")
            event.prevent_default()
            event.stop()
            return

        # Shift+Tab cycles to shell output pane
        if event.key == "shift+tab":
            self._app_ref.shell_input_active = False
            try:
                shell_output = self._app_ref.query_one("#shell_output_content", TextArea)
                shell_output.focus()
            except Exception:
                pass
            self._app_ref._update_status("Shell output | j/k to scroll | Tab to input | Shift+Tab to detail")
            event.prevent_default()
            event.stop()
            return

        # Let parent TextArea handle all other keys (typing, backspace, cursor movement, etc.)
        await super()._on_key(event)
