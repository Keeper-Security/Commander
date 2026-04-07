"""
Auto-copy TextArea widget for SuperShell

A TextArea that automatically copies selected text to clipboard on mouse release,
similar to Linux terminal behavior.
"""

from typing import TYPE_CHECKING

from textual.widgets import TextArea
from textual.events import Click, MouseDown, MouseUp, MouseMove

from ..debug import debug_log as _debug_log

if TYPE_CHECKING:
    from textual.widgets.text_area import Selection


def safe_copy_to_clipboard(text: str) -> tuple[bool, str]:
    """Safely copy text to clipboard, handling missing clipboard on remote/headless systems.

    Returns:
        (True, "") on success
        (False, error_message) on failure
    """
    try:
        import pyperclip
        from pyperclip import PyperclipException
        pyperclip.copy(text)
        return True, ""
    except Exception as e:
        if 'PyperclipException' in str(type(e)):
            return False, "Clipboard not available (no X11/Wayland)"
        return False, str(e)


class AutoCopyTextArea(TextArea):
    """TextArea that auto-copies selected text to clipboard on mouse release.

    Behavior matches standard Linux terminal:
    - Click and drag to select text
    - Double-click to select word, drag to extend from word boundaries
    - On mouse up, automatically copy selection to clipboard
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import time
        self._last_click_time = 0.0
        self._last_click_pos = (0, 0)
        self._word_select_mode = False
        self._word_anchor_start = None  # (row, col)
        self._word_anchor_end = None    # (row, col)

    async def _on_mouse_down(self, event: MouseDown) -> None:
        """Handle mouse down - detect double-click for word selection."""
        import time
        current_time = time.time()
        current_pos = (event.x, event.y)

        # Check for double-click (within 500ms and reasonably close position)
        time_ok = (current_time - self._last_click_time) < 0.5
        pos_ok = (abs(current_pos[0] - self._last_click_pos[0]) <= 10 and
                  abs(current_pos[1] - self._last_click_pos[1]) <= 5)
        is_double_click = time_ok and pos_ok

        # Update click tracking
        self._last_click_time = current_time
        self._last_click_pos = current_pos

        if is_double_click:
            # Double-click: select word and prepare for drag
            self._select_word_at_position(event)
        else:
            # Single click: reset word mode and do normal selection
            self._word_select_mode = False
            self._word_anchor_start = None
            self._word_anchor_end = None
            await super()._on_mouse_down(event)

    def _select_word_at_position(self, event: MouseDown) -> None:
        """Select the word at the mouse position."""
        try:
            location = self.get_target_document_location(event)
            row, col = location

            lines = self.text.split('\n')
            if row >= len(lines):
                return
            line = lines[row]
            if col > len(line):
                col = len(line)

            # Find word boundaries (whitespace-delimited)
            start = col
            while start > 0 and not line[start - 1].isspace():
                start -= 1

            end = col
            while end < len(line) and not line[end].isspace():
                end += 1

            if start == end:
                # No word at this position
                return

            # Store anchors for potential drag extension
            self._word_anchor_start = (row, start)
            self._word_anchor_end = (row, end)
            self._word_select_mode = True

            # Select the word
            from textual.widgets.text_area import Selection
            self.selection = Selection((row, start), (row, end))

            # Set up for potential drag (like parent's _on_mouse_down)
            self._selecting = True
            self.capture_mouse()
            self._pause_blink(visible=False)
            self.history.checkpoint()

        except Exception as e:
            _debug_log(f"AutoCopyTextArea._select_word_at_position error: {e}")
            # On error, fall back to normal behavior
            self._word_select_mode = False

    async def _on_mouse_move(self, event: MouseMove) -> None:
        """Handle mouse move - extend selection if dragging."""
        if not self._selecting:
            return

        try:
            target = self.get_target_document_location(event)
            from textual.widgets.text_area import Selection

            if self._word_select_mode and self._word_anchor_start:
                # Word-select mode: anchor to original word boundaries
                anchor_start = self._word_anchor_start
                anchor_end = self._word_anchor_end

                if target < anchor_start:
                    self.selection = Selection(target, anchor_end)
                elif target > anchor_end:
                    self.selection = Selection(anchor_start, target)
                else:
                    self.selection = Selection(anchor_start, anchor_end)
            else:
                # Normal drag: extend from original click position
                selection_start, _ = self.selection
                self.selection = Selection(selection_start, target)
        except Exception:
            pass

    async def _on_mouse_up(self, event: MouseUp) -> None:
        """Handle mouse up - finalize selection and copy."""
        # Clean up word select state
        self._word_select_mode = False

        # Let parent finalize selection mode
        self._end_mouse_selection()

        # Always try to copy - _auto_copy_if_selected checks if there's actual selection
        self._auto_copy_if_selected()

    def _on_click(self, event: Click) -> None:
        """Handle click events - double-click selects and copies word."""
        # Double-click: select word and copy (backup for mouse_down detection)
        if event.chain >= 2:
            try:
                location = self.get_target_document_location(event)
                row, col = location

                lines = self.text.split('\n')
                if row < len(lines):
                    line = lines[row]
                    if col > len(line):
                        col = len(line)

                    # Find word boundaries
                    start = col
                    while start > 0 and not line[start - 1].isspace():
                        start -= 1
                    end = col
                    while end < len(line) and not line[end].isspace():
                        end += 1

                    if start < end:
                        word = line[start:end]
                        # Select and copy the word
                        from textual.widgets.text_area import Selection
                        self.selection = Selection((row, start), (row, end))
                        # Copy immediately
                        success, err = safe_copy_to_clipboard(word)
                        if success:
                            preview = word[:40] + ('...' if len(word) > 40 else '')
                            self.app.notify(f"Copied: {preview}", severity="information")
                        else:
                            self.app.notify(f"  {err}", severity="warning")
            except Exception:
                pass
            event.stop()
            return
        # Let parent handle single clicks
        super()._on_click(event)

    def _auto_copy_if_selected(self) -> None:
        """Copy selected text to clipboard if any."""
        try:
            selected = self.selected_text
            _debug_log(f"AutoCopyTextArea: selected_text={selected!r}")
            if selected and selected.strip():
                success, err = safe_copy_to_clipboard(selected)
                if success:
                    preview = selected[:40] + ('...' if len(selected) > 40 else '')
                    preview = preview.replace('\n', ' ')
                    # Use app.notify() instead of widget's notify()
                    self.app.notify(f"Copied: {preview}", severity="information")
                    _debug_log(f"AutoCopyTextArea: Copied to clipboard")
                else:
                    self.app.notify(f"  {err}", severity="warning")
        except Exception as e:
            _debug_log(f"AutoCopyTextArea: Error: {e}")
