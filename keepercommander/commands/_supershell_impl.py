"""
Keeper SuperShell - A full-screen terminal UI for Keeper vault

This is the implementation file during refactoring. Code is being
gradually migrated to the supershell/ package.
"""

import logging
import asyncio
import random
import sys
import io
import json
import re
import time
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
import pyperclip
from pyperclip import PyperclipException
from rich.markup import escape as rich_escape


def safe_copy_to_clipboard(text: str) -> tuple[bool, str]:
    """Safely copy text to clipboard, handling missing clipboard on remote/headless systems.

    Returns:
        (True, "") on success
        (False, error_message) on failure
    """
    try:
        pyperclip.copy(text)
        return True, ""
    except PyperclipException:
        return False, "Clipboard not available (no X11/Wayland)"
    except Exception as e:
        return False, str(e)

# Import from refactored modules
from .supershell.themes import COLOR_THEMES
from .supershell.utils import load_preferences, save_preferences, strip_ansi_codes
from .supershell.widgets import ClickableDetailLine, ClickableField, ClickableRecordUID
from .supershell.state import VaultData, UIState, ThemeState, SelectionState
from .supershell.data import load_vault_data, search_records
from .supershell.renderers import (
    is_sensitive_field as is_sensitive_field_name,
    mask_passwords_in_json,
    strip_field_type_prefix,
    is_section_header as is_record_section_header,
    RECORD_SECTION_HEADERS,
    FIELD_TYPE_PREFIXES,
    TYPE_FRIENDLY_NAMES,
)
from .supershell.handlers import keyboard_dispatcher
from .supershell.screens import PreferencesScreen, HelpScreen

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, Center, Middle
from textual.widgets import Tree, DataTable, Footer, Header, Static, Input, Label, Button, TextArea
from textual.binding import Binding
from textual.screen import Screen, ModalScreen
from textual.reactive import reactive
from textual import on, work
from textual.message import Message
from textual.timer import Timer
from rich.text import Text
from textual.events import Click, MouseDown, MouseUp, MouseMove, Paste

# === DEBUG EVENT LOGGING ===
# Set to True to log all mouse/keyboard events to /tmp/supershell_debug.log
# tail -f /tmp/supershell_debug.log to watch events in real-time
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
    except Exception as e:
        pass  # Silently fail if logging fails
# === END DEBUG EVENT LOGGING ===


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
                            self.app.notify(f"⚠️  {err}", severity="warning")
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
                    self.app.notify(f"⚠️  {err}", severity="warning")
        except Exception as e:
            _debug_log(f"AutoCopyTextArea: Error: {e}")


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
            from textual.widgets import Tree
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
            from textual.widgets import TextArea
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


from ..commands.base import Command

# Widget classes are now imported from .supershell.widgets at the top of this file

from ..commands.record import RecordGetUidCommand, ClipboardCommand
from ..display import bcolors
from .. import vault
from .. import utils


# Screen classes imported from .supershell.screens

class SuperShellApp(App):
    """The Keeper SuperShell TUI application"""
    
    # Constants for thresholds and limits
    AUTO_EXPAND_THRESHOLD = 100  # Auto-expand tree when search results < this number
    DEVICE_DISPLAY_LIMIT = 5     # Max devices to show before truncating
    SHARE_DISPLAY_LIMIT = 10     # Max shares to show before truncating
    PAGE_DOWN_NODES = 10         # Number of nodes to move for half-page down
    PAGE_DOWN_FULL_NODES = 20    # Number of nodes to move for full-page down

    # _strip_ansi_codes is now imported from .supershell.utils

    CSS = """
    Screen {
        background: #000000;
    }

    Input {
        background: #111111;
        color: #ffffff;
    }

    Input > .input--content {
        color: #ffffff;
    }

    Input > .input--placeholder {
        color: #666666;
    }

    Input > .input--cursor {
        color: #ffffff;
        text-style: reverse;
    }

    Input:focus {
        border: solid #888888;
    }

    Input:focus > .input--content {
        color: #ffffff;
    }

    #search_bar {
        dock: top;
        height: 3;
        width: 100%;
        background: #222222;
        border: solid #666666;
    }

    #search_display {
        width: 35%;
        background: #222222;
        color: #ffffff;
        padding: 0 2;
        height: 3;
    }

    #search_results_label {
        width: 15%;
        color: #aaaaaa;
        text-align: right;
        padding: 0 2;
        height: 3;
        background: #222222;
    }

    #user_info {
        width: auto;
        height: 3;
        background: #222222;
        color: #888888;
        padding: 0 1;
    }

    #device_status_info {
        width: auto;
        height: 3;
        background: #222222;
        color: #888888;
        padding: 0 2;
        text-align: right;
    }

    .clickable-info:hover {
        background: #333333;
    }

    #main_container {
        height: 100%;
        background: #000000;
    }

    #folder_panel {
        width: 50%;
        border-right: thick #666666;
        padding: 1;
        background: #000000;
    }

    #folder_tree {
        height: 100%;
        background: #000000;
    }

    #record_panel {
        width: 50%;
        padding: 1;
        background: #000000;
    }

    #record_detail {
        height: 100%;
        overflow-y: auto;
        padding: 1;
        background: #000000;
    }

    #detail_content {
        background: #000000;
        color: #ffffff;
    }

    Tree {
        background: #000000;
        color: #ffffff;
    }

    Tree > .tree--guides {
        color: #444444;
    }

    Tree > .tree--toggle {
        /* Hide expand/collapse icons - nodes still expand/collapse on click */
        width: 0;
    }

    Tree > .tree--cursor {
        /* Selected row - neutral background that works with all color themes */
        background: #333333;
        text-style: bold;
    }

    Tree > .tree--highlight {
        /* Hover row - subtle background, different from selection */
        background: #1a1a1a;
    }

    Tree > .tree--highlight-line {
        background: #1a1a1a;
    }

    /* Hide tree selection when search input is active */
    Tree.search-input-active > .tree--cursor {
        background: transparent;
        text-style: none;
    }

    Tree.search-input-active > .tree--highlight {
        background: transparent;
    }

    DataTable {
        background: #000000;
        color: #ffffff;
    }

    DataTable > .datatable--cursor {
        background: #444444;
        color: #ffffff;
        text-style: bold;
    }

    DataTable > .datatable--header {
        background: #222222;
        color: #ffffff;
        text-style: bold;
    }

    Static {
        background: #000000;
        color: #ffffff;
    }

    VerticalScroll {
        background: #000000;
    }

    #record_detail:focus {
        background: #0a0a0a;
    }

    #record_detail:focus-within {
        background: #0a0a0a;
    }

    /* Focus indicators - green left border shows which pane is active */
    #folder_panel:focus-within {
        border-left: solid #00cc00;
    }

    #record_panel:focus-within {
        border-left: solid #00cc00;
    }

    #shell_output_content:focus {
        border-left: solid #00cc00;
    }

    #shell_input_container:focus-within {
        border-left: solid #00cc00;
    }

    #search_bar.search-active {
        border-left: solid #00cc00;
    }

    #status_bar {
        dock: bottom;
        height: 1;
        background: #000000;
        color: #aaaaaa;
        padding: 0 2;
    }

    #shortcuts_bar {
        dock: bottom;
        height: 2;
        background: #111111;
        color: #888888;
        padding: 0 1;
        border-top: solid #333333;
    }

    /* Content area wrapper for shell pane visibility control */
    #content_area {
        height: 100%;
        width: 100%;
    }

    /* When shell is visible, compress main container to top half */
    #content_area.shell-visible #main_container {
        height: 50%;
    }

    /* Shell pane - hidden by default */
    #shell_pane {
        display: none;
        height: 50%;
        width: 100%;
        border-top: thick #666666;
        background: #000000;
    }

    /* Show shell pane when class is added */
    #content_area.shell-visible #shell_pane {
        display: block;
    }

    #shell_header {
        height: 1;
        background: #222222;
        color: #00ff00;
        padding: 0 1;
        border-bottom: solid #333333;
    }

    #shell_output_content {
        height: 1fr;
        background: #000000;
        color: #ffffff;
        border: none;
        padding: 0 1;
    }

    /* Theme-specific selection colors for shell output */
    #shell_output_content.theme-green .text-area--selection {
        background: #004400;
    }
    #shell_output_content.theme-blue .text-area--selection {
        background: #002244;
    }
    #shell_output_content.theme-magenta .text-area--selection {
        background: #330033;
    }
    #shell_output_content.theme-yellow .text-area--selection {
        background: #333300;
    }
    #shell_output_content.theme-white .text-area--selection {
        background: #444444;
    }
    /* Default fallback */
    #shell_output_content .text-area--selection {
        background: #004400;
    }

    /* Shell input container with prompt and TextArea */
    #shell_input_container {
        height: auto;
        min-height: 3;
        max-height: 6;
        background: #000000;
        border-top: solid #333333;
        border-bottom: solid #333333;
        padding: 0 1;
    }

    #shell_prompt {
        width: 2;
        height: 100%;
        background: #000000;
        color: #00ff00;
        padding: 0;
    }

    /* Shell input area - multi-line TextArea for command entry */
    #shell_input_area {
        width: 1fr;
        height: auto;
        min-height: 1;
        max-height: 5;
        background: #000000;
        color: #00ff00;
        border: none;
        padding: 0;
    }

    #shell_input_area:focus {
        background: #000000;
    }

    #shell_input_area .text-area--cursor {
        color: #00ff00;
        background: #00ff00;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=False),
        Binding("d", "sync_vault", "Sync", show=False),
        Binding("/", "search", "Search", show=False),
        Binding("P", "show_preferences", "Preferences", show=False),
        Binding("p", "copy_password", "Copy Password", show=False),
        Binding("u", "copy_username", "Copy Username", show=False),
        Binding("w", "copy_url", "Copy URL", show=False),
        Binding("i", "copy_uid", "Copy UID", show=False),
        Binding("c", "copy_record", "Copy All", show=False),
        Binding("t", "toggle_view_mode", "Toggle JSON", show=False),
        Binding("m", "toggle_unmask", "Toggle Unmask", show=False),
        Binding("W", "show_user_info", "User Info", show=False),
        Binding("D", "show_device_info", "Device Info", show=False),
        Binding("?", "show_help", "Help", show=False),
        # Vim-style navigation
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("h", "cursor_left", "Left", show=False),
        Binding("l", "cursor_right", "Right", show=False),
        Binding("g", "goto_top", "Go to Top", show=False),
        Binding("G", "goto_bottom", "Go to Bottom", show=False),
        # Vim page navigation
        Binding("ctrl+d", "page_down", "Page Down", show=False),
        Binding("ctrl+u", "page_up", "Page Up", show=False),
        Binding("ctrl+f", "page_down_full", "Page Down (Full)", show=False),
        Binding("ctrl+b", "page_up_full", "Page Up (Full)", show=False),
        # Vim line scrolling
        Binding("ctrl+e", "scroll_down", "Scroll Down", show=False),
        Binding("ctrl+y", "scroll_up", "Scroll Up", show=False),
    ]

    def __init__(self, params):
        super().__init__()
        self.params = params
        self.records = {}
        self.record_to_folder = {}
        self.records_in_subfolders = set()  # Records in actual subfolders (not root)
        self.file_attachment_to_parent = {}  # Maps attachment_uid -> parent_record_uid
        self.record_file_attachments = {}  # Maps record_uid -> list of attachment_uids
        self.linked_record_to_parent = {}  # Maps linked_record_uid -> parent_record_uid (for addressRef, cardRef, etc.)
        self.record_linked_records = {}  # Maps record_uid -> list of linked_record_uids
        self.app_record_uids = set()  # Set of Secrets Manager app record UIDs
        self.current_folder = None
        self.selected_record = None
        self.selected_folder = None
        self.view_mode = 'detail'  # 'detail' or 'json'
        self.unmask_secrets = False  # When True, show secret/password/passphrase field values
        self.search_query = ""  # Current search query
        self.search_input_text = ""  # Text being typed in search
        self.search_input_active = False  # True when typing in search, False when navigating results
        self.filtered_record_uids = None  # None = show all, Set = filtered UIDs
        # Save selection before search to restore on ESC
        self.pre_search_selected_record = None
        self.pre_search_selected_folder = None
        self.title = ""
        self.sub_title = ""
        # Vim-style command mode (e.g., :20 to go to line 20)
        self.command_mode = False
        self.command_buffer = ""
        # Shell pane state
        self.shell_pane_visible = False
        self.shell_input_text = ""
        self.shell_history = []  # List of (command, output) tuples
        self.shell_input_active = False
        self.shell_command_history = []  # For up/down arrow navigation
        self.shell_history_index = -1
        # Shell output uses TextArea widget with built-in selection support
        # Load color theme from preferences
        prefs = load_preferences()
        self.color_theme = prefs.get('color_theme', 'green')
        self.theme_colors = COLOR_THEMES.get(self.color_theme, COLOR_THEMES['green'])

    def set_color_theme(self, theme_name: str):
        """Set the color theme and refresh the display"""
        if theme_name in COLOR_THEMES:
            self.color_theme = theme_name
            self.theme_colors = COLOR_THEMES[theme_name]
            
            # Save the current tree expansion state before rebuilding
            tree = self.query_one("#folder_tree", Tree)
            expanded_nodes = set()
            
            def collect_expanded(node):
                """Recursively collect UIDs of expanded nodes"""
                if node.is_expanded and hasattr(node, 'data') and node.data:
                    node_uid = node.data.get('uid') if isinstance(node.data, dict) else None
                    node_type = node.data.get('type') if isinstance(node.data, dict) else None
                    if node_uid:
                        expanded_nodes.add(node_uid)
                    elif node_type == 'root':
                        expanded_nodes.add('__root__')
                    elif node_type == 'virtual_folder':
                        expanded_nodes.add('__secrets_manager_apps__')
                for child in node.children:
                    collect_expanded(child)
            
            collect_expanded(tree.root)
            
            # Refresh the tree to apply new colors
            self._setup_folder_tree()
            
            # Restore expansion state
            def restore_expanded(node):
                """Recursively restore expanded state"""
                if hasattr(node, 'data') and node.data:
                    node_uid = node.data.get('uid') if isinstance(node.data, dict) else None
                    node_type = node.data.get('type') if isinstance(node.data, dict) else None
                    
                    should_expand = False
                    if node_uid and node_uid in expanded_nodes:
                        should_expand = True
                    elif node_type == 'root' and '__root__' in expanded_nodes:
                        should_expand = True
                    elif node_type == 'virtual_folder' and node_uid == '__secrets_manager_apps__' and '__secrets_manager_apps__' in expanded_nodes:
                        should_expand = True
                    
                    if should_expand and node.allow_expand:
                        node.expand()
                
                for child in node.children:
                    restore_expanded(child)
            
            restore_expanded(tree.root)
            
            # Update header info (email/username colors)
            self._update_header_info_display()

            # Update CSS dynamically for tree selection/hover
            self._apply_theme_css()

            # Update shell output selection color theme
            try:
                shell_output = self.query_one("#shell_output_content")
                # Remove old theme classes and add new one
                for old_theme in COLOR_THEMES.keys():
                    shell_output.remove_class(f"theme-{old_theme}")
                shell_output.add_class(f"theme-{theme_name}")
            except Exception:
                pass  # Shell pane might not exist yet

    def notify(self, message, *, title="", severity="information", timeout=1.5):
        """Override notify to use faster timeout (default 1.5s instead of 5s)"""
        super().notify(message, title=title, severity=severity, timeout=timeout)

    def _get_welcome_screen_content(self) -> str:
        """Generate the My Vault welcome screen content with current theme colors"""
        t = self.theme_colors
        return f"""[bold {t['primary']}]● Keeper SuperShell[/bold {t['primary']}]

[{t['secondary']}]A CLI-based vault viewer with keyboard and mouse navigation.[/{t['secondary']}]

[bold {t['primary_bright']}]Getting Started[/bold {t['primary_bright']}]
  [{t['text_dim']}]•[/{t['text_dim']}] Use [{t['primary']}]j/k[/{t['primary']}] or [{t['primary']}]↑/↓[/{t['primary']}] to navigate up/down
  [{t['text_dim']}]•[/{t['text_dim']}] Use [{t['primary']}]l[/{t['primary']}] or [{t['primary']}]→[/{t['primary']}] to expand folders
  [{t['text_dim']}]•[/{t['text_dim']}] Use [{t['primary']}]h[/{t['primary']}] or [{t['primary']}]←[/{t['primary']}] to collapse folders
  [{t['text_dim']}]•[/{t['text_dim']}] Press [{t['primary']}]/[/{t['primary']}] to search for records
  [{t['text_dim']}]•[/{t['text_dim']}] Press [{t['primary']}]Esc[/{t['primary']}] to collapse and navigate back

[bold {t['primary_bright']}]Vim-Style Navigation[/bold {t['primary_bright']}]
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]g[/{t['primary']}] - Go to top
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]G[/{t['primary']}] (Shift+G) - Go to bottom
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]Ctrl+d/u[/{t['primary']}] - Half page down/up
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]Ctrl+e/y[/{t['primary']}] - Scroll down/up one line

[bold {t['primary_bright']}]Quick Actions[/bold {t['primary_bright']}]
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]c[/{t['primary']}] - Copy password
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]u[/{t['primary']}] - Copy username
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]w[/{t['primary']}] - Copy URL
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]t[/{t['primary']}] - Toggle Detail/JSON view
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]d[/{t['primary']}] - Sync & refresh vault
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]![/{t['primary']}] - Exit to Keeper shell
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]Ctrl+q[/{t['primary']}] - Quit SuperShell

[{t['text_dim']}]Press [/{t['text_dim']}][{t['primary']}]?[/{t['primary']}][{t['text_dim']}] for full keyboard shortcuts[/{t['text_dim']}]"""

    def _apply_theme_css(self):
        """Apply dynamic CSS based on current theme"""
        t = self.theme_colors

        try:
            # Update detail content - will be refreshed when record is selected
            if self.selected_record:
                # Check if it's a Secrets Manager app record
                if self.selected_record in self.app_record_uids:
                    self._display_secrets_manager_app(self.selected_record)
                else:
                    self._display_record_detail(self.selected_record)
            elif self.selected_folder:
                self._display_folder_with_clickable_fields(self.selected_folder)
            else:
                # No record/folder selected - update the "My Vault" welcome screen
                detail_widget = self.query_one("#detail_content", Static)
                detail_widget.update(self._get_welcome_screen_content())

        except Exception as e:
            logging.debug(f"Error applying theme CSS: {e}")

    def action_show_preferences(self):
        """Show preferences screen"""
        self.push_screen(PreferencesScreen(self))

    def compose(self) -> ComposeResult:
        """Create the application layout"""
        # Search bar at top (initially hidden)
        with Horizontal(id="search_bar"):
            yield Static("", id="search_display")
            yield Static("", id="search_results_label")
            yield Static("", id="user_info", classes="clickable-info")
            yield Static("", id="device_status_info", classes="clickable-info")

        # Content area wrapper - allows shell pane visibility control
        with Vertical(id="content_area"):
            with Horizontal(id="main_container"):
                with Vertical(id="folder_panel"):
                    yield Tree("[#00ff00]● My Vault[/#00ff00]", id="folder_tree")
                with Vertical(id="record_panel"):
                    with VerticalScroll(id="record_detail"):
                        yield Static("", id="detail_content")
                    # Fixed footer for shortcuts
                    yield Static("", id="shortcuts_bar")

            # Shell pane - hidden by default, shown when :command or Ctrl+\ pressed
            with Vertical(id="shell_pane"):
                yield Static("", id="shell_header")
                # AutoCopyTextArea auto-copies selected text on mouse release
                yield AutoCopyTextArea("", id="shell_output_content", read_only=True, classes=f"theme-{self.color_theme}")
                # Shell input line with prompt and TextArea
                with Horizontal(id="shell_input_container"):
                    yield Static("❯ ", id="shell_prompt")
                    yield ShellInputTextArea(self, "", id="shell_input_area")

        # Status bar at very bottom
        yield Static("", id="status_bar")

    async def on_mount(self):
        """Initialize the application when mounted"""
        logging.debug("SuperShell on_mount called")

        # Initialize clickable fields list for detail panel
        self.clickable_fields = []

        # Cache for record output to avoid repeated get command calls
        self._record_output_cache = {}

        # TOTP auto-refresh timer
        self._totp_timer = None
        self._totp_record_uid = None  # Record currently showing TOTP

        # Sync vault data if needed
        if not hasattr(self.params, 'record_cache') or not self.params.record_cache:
            from .utils import SyncDownCommand
            try:
                logging.debug("Syncing vault data...")
                SyncDownCommand().execute(self.params)
            except Exception as e:
                logging.error(f"Sync failed: {e}", exc_info=True)
                self.exit(message=f"Sync failed: {str(e)}")
                return

        try:
            # Load vault data
            logging.debug("Loading vault data...")
            self._load_vault_data()

            # Load device and user info for header display
            logging.debug("Loading device and user info...")
            self.device_info = self._load_device_info()
            self.whoami_info = self._load_whoami_info()

            # Setup folder tree with records
            logging.debug("Setting up folder tree...")
            self._setup_folder_tree()

            # Apply theme CSS after components are mounted
            self._apply_theme_css()

            # Update initial content with welcome/help and shortcuts bar
            t = self.theme_colors
            detail_widget = self.query_one("#detail_content", Static)
            help_content = f"""[bold {t['primary']}]● Keeper SuperShell[/bold {t['primary']}]

[{t['secondary']}]A CLI-based vault with vi-style keyboard and mouse navigation.[/{t['secondary']}]

[bold {t['primary_bright']}]Getting Started[/bold {t['primary_bright']}]
  [{t['text_dim']}]•[/{t['text_dim']}] Use [{t['primary']}]j/k[/{t['primary']}] or [{t['primary']}]↑/↓[/{t['primary']}] to navigate up/down
  [{t['text_dim']}]•[/{t['text_dim']}] Use [{t['primary']}]l[/{t['primary']}] or [{t['primary']}]→[/{t['primary']}] to expand folders
  [{t['text_dim']}]•[/{t['text_dim']}] Use [{t['primary']}]h[/{t['primary']}] or [{t['primary']}]←[/{t['primary']}] to collapse folders
  [{t['text_dim']}]•[/{t['text_dim']}] Press [{t['primary']}]/[/{t['primary']}] to search for records
  [{t['text_dim']}]•[/{t['text_dim']}] Press [{t['primary']}]Esc[/{t['primary']}] to collapse and navigate back

[bold {t['primary_bright']}]Vim-Style Navigation[/bold {t['primary_bright']}]
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]g[/{t['primary']}] - Go to top
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]G[/{t['primary']}] (Shift+G) - Go to bottom
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]Ctrl+d/u[/{t['primary']}] - Half page down/up
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]Ctrl+e/y[/{t['primary']}] - Scroll down/up one line

[bold {t['primary_bright']}]Quick Actions[/bold {t['primary_bright']}]
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]p[/{t['primary']}] - Copy password
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]u[/{t['primary']}] - Copy username
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]c[/{t['primary']}] - Copy all
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]t[/{t['primary']}] - Toggle Detail/JSON view
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]m[/{t['primary']}] - Mask/Unmask secrets
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]d[/{t['primary']}] - Sync & refresh vault
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]![/{t['primary']}] - Exit to Keeper shell
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]Ctrl+q[/{t['primary']}] - Quit SuperShell

[{t['text_dim']}]Press [/{t['text_dim']}][{t['primary']}]?[/{t['primary']}][{t['text_dim']}] for full keyboard shortcuts[/{t['text_dim']}]"""
            detail_widget.update(help_content)

            # Initialize shortcuts bar
            self._update_shortcuts_bar()

            # Initialize search bar with placeholder
            search_display = self.query_one("#search_display", Static)
            search_display.update("[dim]Search... (Tab or /)[/dim]")

            # Initialize header info display (user and device)
            self._update_header_info_display()

            # Focus the folder tree so vim keys work immediately
            self.query_one("#folder_tree", Tree).focus()

            logging.debug("SuperShell ready!")
            self._update_status("Navigate: j/k  Tab: detail  Help: ?")
        except Exception as e:
            logging.error(f"Error initializing SuperShell: {e}", exc_info=True)
            self.exit(message=f"Error: {str(e)}")

    def on_resize(self, event) -> None:
        """Handle window resize - update header to show/hide sections based on available width"""
        self._update_header_info_display()

    def _load_vault_data(self):
        """Load vault data from params"""
        # Build record to folder mapping using subfolder_record_cache
        # Records in root folder have folder_uid = '' (empty string)
        self.record_to_folder = {}  # Maps record_uid -> folder_uid
        self.records_in_subfolders = set()  # Track records that are in actual subfolders (not root)
        if hasattr(self.params, 'subfolder_record_cache'):
            for folder_uid, record_uids in self.params.subfolder_record_cache.items():
                for record_uid in record_uids:
                    self.record_to_folder[record_uid] = folder_uid
                    # Track records in non-root folders
                    if folder_uid and folder_uid != '':
                        self.records_in_subfolders.add(record_uid)

        # Track file attachments and their parent records
        self.file_attachment_to_parent = {}  # Maps attachment_uid -> parent_record_uid
        self.record_file_attachments = {}  # Maps record_uid -> list of attachment_uids
        self.linked_record_to_parent = {}  # Maps linked_record_uid -> parent_record_uid (for addressRef, cardRef, etc.)
        self.record_linked_records = {}  # Maps record_uid -> list of linked_record_uids

        # Secrets Manager app UIDs - identified by record type 'app' in the vault cache
        # NOTE: SuperShell should not make direct API calls during initialization.
        # Apps are identified by their record type instead of calling vault/get_applications_summary.
        self.app_record_uids = set()

        # Build record dictionary
        if hasattr(self.params, 'record_cache'):
            for record_uid, record_data in self.params.record_cache.items():
                try:
                    # Try to load and decrypt the record
                    record = vault.KeeperRecord.load(self.params, record_uid)

                    if record:
                        # Get record type - try multiple approaches
                        record_type = 'login'  # Default

                        # First, try get_record_type() method (most reliable)
                        if hasattr(record, 'get_record_type'):
                            try:
                                rt = record.get_record_type()
                                if rt:
                                    record_type = rt
                            except:
                                pass

                        # If still default, try record_type property
                        if record_type == 'login' and hasattr(record, 'record_type'):
                            try:
                                rt = record.record_type
                                if rt:
                                    record_type = rt
                            except:
                                pass

                        # Fallback: try to get from cached data
                        if record_type == 'login':
                            cached_rec = self.params.record_cache.get(record_uid, {})
                            version = cached_rec.get('version', 2)
                            if version == 3:
                                try:
                                    rec_data = cached_rec.get('data_unencrypted')
                                    if rec_data:
                                        if isinstance(rec_data, bytes):
                                            rec_data = rec_data.decode('utf-8')
                                        data_obj = json.loads(rec_data)
                                        rt = data_obj.get('type')
                                        if rt:
                                            record_type = rt
                                except:
                                    pass
                            elif version == 2:
                                record_type = 'legacy'

                        record_dict = {
                            'uid': record_uid,
                            'title': record.title if hasattr(record, 'title') else 'Untitled',
                            'folder_uid': self.record_to_folder.get(record_uid),
                            'record_type': record_type,
                        }

                        # Identify Secrets Manager apps by record type
                        if record_type == 'app':
                            self.app_record_uids.add(record_uid)

                        # Extract fileRef fields to build parent-child relationship
                        # Handles both 'fileRef' type fields and 'script' type fields (rotation scripts)
                        file_refs = []
                        if hasattr(record, 'fields'):
                            for field in record.fields:
                                field_type = getattr(field, 'type', None)
                                field_value = getattr(field, 'value', None)

                                if field_type == 'fileRef':
                                    # Direct fileRef field - value is list of UIDs
                                    if field_value and isinstance(field_value, list):
                                        for ref_uid in field_value:
                                            if isinstance(ref_uid, str) and ref_uid:
                                                file_refs.append(ref_uid)
                                                self.file_attachment_to_parent[ref_uid] = record_uid

                                elif field_type == 'script':
                                    # Script field - value is list of objects with 'fileRef' property
                                    if field_value and isinstance(field_value, list):
                                        for script_item in field_value:
                                            if isinstance(script_item, dict):
                                                ref_uid = script_item.get('fileRef')
                                                if ref_uid and isinstance(ref_uid, str):
                                                    file_refs.append(ref_uid)
                                                    self.file_attachment_to_parent[ref_uid] = record_uid

                        if file_refs:
                            self.record_file_attachments[record_uid] = file_refs

                        # Extract linked record references (addressRef, cardRef, etc.)
                        # These are records that are embedded/linked into this record
                        linked_refs = []
                        if hasattr(record, 'fields'):
                            for field in record.fields:
                                field_type = getattr(field, 'type', None)
                                field_value = getattr(field, 'value', None)

                                # addressRef, cardRef, etc. - records linked by reference
                                if field_type in ('addressRef', 'cardRef'):
                                    if field_value and isinstance(field_value, list):
                                        for ref_uid in field_value:
                                            if isinstance(ref_uid, str) and ref_uid:
                                                linked_refs.append(ref_uid)
                                                self.linked_record_to_parent[ref_uid] = record_uid

                        if linked_refs:
                            self.record_linked_records[record_uid] = linked_refs

                        # Extract fields based on record type
                        if hasattr(record, 'login'):
                            record_dict['login'] = record.login
                        if hasattr(record, 'password'):
                            record_dict['password'] = record.password
                        if hasattr(record, 'login_url'):
                            record_dict['login_url'] = record.login_url
                        if hasattr(record, 'notes'):
                            record_dict['notes'] = record.notes
                        # Extract TOTP URL (v2 legacy records have it as 'totp' attribute)
                        if hasattr(record, 'totp') and record.totp:
                            record_dict['totp_url'] = record.totp

                        # For TypedRecords, extract fields from the fields array
                        if hasattr(record, 'fields'):
                            custom_fields = []
                            for field in record.fields:
                                field_type = getattr(field, 'type', None)
                                field_value = getattr(field, 'value', None)
                                field_label = getattr(field, 'label', None)

                                # Extract password from typed field if not already set
                                if field_type == 'password' and field_value and not record_dict.get('password'):
                                    if isinstance(field_value, list) and len(field_value) > 0:
                                        record_dict['password'] = field_value[0]
                                    elif isinstance(field_value, str):
                                        record_dict['password'] = field_value

                                # Extract login from typed field if not already set
                                if field_type == 'login' and field_value and not record_dict.get('login'):
                                    if isinstance(field_value, list) and len(field_value) > 0:
                                        record_dict['login'] = field_value[0]
                                    elif isinstance(field_value, str):
                                        record_dict['login'] = field_value

                                # Extract URL from typed field if not already set
                                if field_type == 'url' and field_value and not record_dict.get('login_url'):
                                    if isinstance(field_value, list) and len(field_value) > 0:
                                        record_dict['login_url'] = field_value[0]
                                    elif isinstance(field_value, str):
                                        record_dict['login_url'] = field_value

                                # Extract TOTP URL from oneTimeCode field
                                if field_type == 'oneTimeCode' and field_value and not record_dict.get('totp_url'):
                                    if isinstance(field_value, list) and len(field_value) > 0:
                                        record_dict['totp_url'] = field_value[0]
                                    elif isinstance(field_value, str):
                                        record_dict['totp_url'] = field_value

                                # Collect custom fields (those with labels)
                                if field_label and field_value:
                                    custom_fields.append({
                                        'name': field_label,
                                        'value': str(field_value) if field_value else ''
                                    })
                            if custom_fields:
                                record_dict['custom_fields'] = custom_fields

                        self.records[record_uid] = record_dict
                except Exception as e:
                    logging.debug(f"Error loading record {record_uid}: {e}")
                    continue

    def _load_device_info(self):
        """Load device info using the 'this-device' command"""
        try:
            from .utils import ThisDeviceCommand

            # Call get_device_info directly - returns dict without printing
            return ThisDeviceCommand.get_device_info(self.params)

        except Exception as e:
            logging.error(f"Error loading device info: {e}", exc_info=True)
            return None

    def _load_whoami_info(self):
        """Load whoami info using the 'whoami' command"""
        try:
            from .utils import WhoamiCommand
            from .. import constants
            import datetime

            # Call get_whoami_info directly - returns dict without printing
            data = WhoamiCommand.get_whoami_info(self.params)

            # Add enterprise license info if available (similar to whoami --json)
            if self.params.enterprise:
                enterprise_licenses = []
                for x in self.params.enterprise.get('licenses', []):
                    license_info = {}
                    product_type_id = x.get('product_type_id', 0)
                    tier = x.get('tier', 0)
                    if product_type_id in (3, 5):
                        plan = 'Enterprise' if tier == 1 else 'Business'
                    elif product_type_id in (9, 10):
                        distributor = x.get('distributor', False)
                        plan = 'Distributor' if distributor else 'Managed MSP'
                    elif product_type_id in (11, 12):
                        plan = 'Keeper MSP'
                    elif product_type_id == 8:
                        plan = 'MC ' + ('Enterprise' if tier == 1 else 'Business')
                    else:
                        plan = 'Unknown'
                    if product_type_id in (5, 10, 12):
                        plan += ' Trial'
                    license_info['base_plan'] = plan

                    paid = x.get('paid') is True
                    if paid:
                        exp = x.get('expiration')
                        if exp and exp > 0:
                            dt = datetime.datetime.fromtimestamp(exp // 1000) + datetime.timedelta(days=1)
                            n = datetime.datetime.now()
                            td = (dt - n).days
                            expires = str(dt.date())
                            if td > 0:
                                expires += f' (in {td} days)'
                            else:
                                expires += ' (expired)'
                            license_info['license_expires'] = expires

                    license_info['user_licenses'] = {
                        'plan': x.get("number_of_seats", ""),
                        'active': x.get("seats_allocated", ""),
                        'invited': x.get("seats_pending", "")
                    }

                    file_plan = x.get('file_plan')
                    file_plan_lookup = {fp[0]: fp[2] for fp in constants.ENTERPRISE_FILE_PLANS}
                    license_info['secure_file_storage'] = file_plan_lookup.get(file_plan, '')

                    addons = []
                    addon_lookup = {a[0]: a[1] for a in constants.MSP_ADDONS}
                    for ao in x.get('add_ons', []):
                        if isinstance(ao, dict):
                            enabled = ao.get('enabled') is True
                            if enabled:
                                name = ao.get('name')
                                addon_name = addon_lookup.get(name) or name
                                if name == 'secrets_manager':
                                    api_count = ao.get('api_call_count')
                                    if isinstance(api_count, int) and api_count > 0:
                                        addon_name += f' ({api_count:,} API calls)'
                                elif name == 'connection_manager':
                                    seats = ao.get('seats')
                                    if isinstance(seats, int) and seats > 0:
                                        addon_name += f' ({seats} licenses)'
                                addons.append(addon_name)
                    if addons:
                        license_info['add_ons'] = addons

                    enterprise_licenses.append(license_info)

                if enterprise_licenses:
                    data['enterprise_licenses'] = enterprise_licenses

                # Add enterprise name if available
                if 'enterprise_name' in self.params.enterprise:
                    data['enterprise_name'] = self.params.enterprise['enterprise_name']

            return data

        except Exception as e:
            logging.error(f"Error loading whoami info: {e}", exc_info=True)
            return None

    def _update_header_info_display(self):
        """Update the user and device info displays in the search bar area"""
        try:
            user_info_widget = self.query_one("#user_info", Static)
            device_status_widget = self.query_one("#device_status_info", Static)
            t = self.theme_colors

            # Get available width for the header info area (roughly half the screen minus search)
            try:
                available_width = self.size.width // 2 - 10  # Approximate space for header info
            except:
                available_width = 80  # Default fallback

            separator = " │ "
            sep_len = 3

            # === User info widget: email | DC (click shows whoami) ===
            user_parts = []
            user_len = 0

            if hasattr(self, 'whoami_info') and self.whoami_info:
                user = self.whoami_info.get('user', '')
                if user:
                    # Truncate email if longer than 30 chars
                    max_email_len = 30
                    if len(user) > max_email_len:
                        user_display = user[:max_email_len-3] + '...'
                    else:
                        user_display = user
                    user_parts.append(f"[{t['primary']}]{user_display}[/{t['primary']}]")
                    user_len = len(user_display)

                # Data center
                data_center = self.whoami_info.get('data_center', '')
                if data_center and user_len + sep_len + len(data_center) < available_width // 2:
                    user_parts.append(f"[{t['primary']}]{data_center}[/{t['primary']}]")
                    user_len += sep_len + len(data_center)

            if user_parts:
                user_info_widget.update(separator.join(user_parts))
            else:
                user_info_widget.update("")

            # === Device status widget: Stay Logged In | Logout (click shows device info) ===
            device_parts = []
            device_len = 0
            remaining_width = available_width - user_len - sep_len

            if hasattr(self, 'device_info') and self.device_info:
                di = self.device_info

                # Stay Logged In status
                stay_logged_in_len = 19  # "Stay Logged In: OFF"
                if stay_logged_in_len < remaining_width:
                    if di.get('persistent_login'):
                        device_parts.append(f"[{t['text_dim']}]Stay Logged In:[/{t['text_dim']}] [green]ON[/green]")
                    else:
                        device_parts.append(f"[{t['text_dim']}]Stay Logged In:[/{t['text_dim']}] [red]OFF[/red]")
                    device_len = stay_logged_in_len

                # Logout timeout
                timeout = di.get('effective_logout_timeout') or di.get('device_logout_timeout') or ''
                if timeout:
                    timeout_str = str(timeout)
                    timeout_str = timeout_str.replace(' days', 'd').replace(' day', 'd')
                    timeout_str = timeout_str.replace(' hours', 'h').replace(' hour', 'h')
                    timeout_str = timeout_str.replace(' minutes', 'm').replace(' minute', 'm')
                    logout_text = f"Logout: {timeout_str}"
                    if device_len + sep_len + len(logout_text) < remaining_width:
                        device_parts.append(f"[{t['text_dim']}]Logout:[/{t['text_dim']}] [{t['primary_dim']}]{timeout_str}[/{t['primary_dim']}]")

            if device_parts:
                device_status_widget.update(separator.join(device_parts))
            else:
                device_status_widget.update("")

        except Exception as e:
            logging.debug(f"Error updating header info display: {e}")

    def _display_whoami_info(self):
        """Display whoami info in the detail panel"""
        try:
            # Clear any clickable fields from previous record display
            self._clear_clickable_fields()

            t = self.theme_colors
            detail_widget = self.query_one("#detail_content", Static)

            if not hasattr(self, 'whoami_info') or not self.whoami_info:
                detail_widget.update("[dim]Whoami info unavailable[/dim]")
                return

            wi = self.whoami_info

            lines = [f"[bold {t['primary']}]● User Information[/bold {t['primary']}]", ""]

            # Format basic fields
            fields = [
                ('User', wi.get('user')),
                ('Server', wi.get('server')),
                ('Data Center', wi.get('data_center')),
                ('Environment', wi.get('environment')),
                ('Account Type', wi.get('account_type')),
                ('Admin', 'Yes' if wi.get('admin') else 'No' if 'admin' in wi else None),
                ('Enterprise', wi.get('enterprise_name')),
                ('Renewal Date', wi.get('renewal_date')),
                ('Storage Capacity', wi.get('storage_capacity')),
                ('Storage Usage', wi.get('storage_usage')),
                ('Storage Renewal', wi.get('storage_renewal_date')),
                ('BreachWatch', 'Yes' if wi.get('breachwatch') else 'No'),
                ('Reporting & Alerts', 'Yes' if wi.get('reporting_and_alerts') else 'No' if 'reporting_and_alerts' in wi else None),
            ]

            for label, value in fields:
                if value is not None:
                    lines.append(f"  [{t['text_dim']}]{label}:[/{t['text_dim']}] [{t['primary']}]{value}[/{t['primary']}]")

            # Add enterprise license info if available
            enterprise_licenses = wi.get('enterprise_licenses', [])
            for lic in enterprise_licenses:
                lines.append("")
                lines.append(f"[bold {t['primary']}]● Enterprise License[/bold {t['primary']}]")
                lines.append("")

                lic_fields = [
                    ('Base Plan', lic.get('base_plan')),
                    ('License Expires', lic.get('license_expires')),
                    ('Secure File Storage', lic.get('secure_file_storage')),
                ]
                for label, value in lic_fields:
                    if value:
                        lines.append(f"  [{t['text_dim']}]{label}:[/{t['text_dim']}] [{t['primary']}]{value}[/{t['primary']}]")

                # User licenses
                user_lic = lic.get('user_licenses', {})
                if user_lic:
                    plan_seats = user_lic.get('plan', '')
                    active = user_lic.get('active', '')
                    invited = user_lic.get('invited', '')
                    if plan_seats:
                        lines.append(f"  [{t['text_dim']}]User Licenses:[/{t['text_dim']}] [{t['primary']}]{plan_seats}[/{t['primary']}] [{t['text_dim']}](Active: {active}, Invited: {invited})[/{t['text_dim']}]")

                # Add-ons
                addons = lic.get('add_ons', [])
                if addons:
                    lines.append("")
                    lines.append(f"  [{t['text_dim']}]Add-ons:[/{t['text_dim']}]")
                    for addon in addons:
                        lines.append(f"    [{t['primary']}]• {addon}[/{t['primary']}]")

            detail_widget.update("\n".join(lines))
            self._update_status("User information | Press Esc to return")
            self._update_shortcuts_bar(clear=True)

        except Exception as e:
            logging.debug(f"Error displaying whoami info: {e}")

    def _display_device_info(self):
        """Display this-device info in the detail panel"""
        try:
            # Clear any clickable fields from previous record display
            self._clear_clickable_fields()

            t = self.theme_colors
            detail_widget = self.query_one("#detail_content", Static)

            if not hasattr(self, 'device_info') or not self.device_info:
                detail_widget.update("[dim]Device info unavailable[/dim]")
                return

            di = self.device_info

            lines = [f"[bold {t['primary']}]● Device Information[/bold {t['primary']}]", ""]

            # Helper for ON/OFF display
            def on_off(val):
                return "[green]ON[/green]" if val else "[red]OFF[/red]"

            fields = [
                ('Device Name', di.get('device_name')),
                ('Data Key Present', 'Yes' if di.get('data_key_present') else 'No'),
                ('IP Auto Approve', on_off(di.get('ip_auto_approve'))),
                ('Persistent Login', on_off(di.get('persistent_login'))),
                ('Security Key No PIN', on_off(di.get('security_key_no_pin'))),
                ('Device Logout Timeout', di.get('device_logout_timeout')),
                ('Enterprise Logout Timeout', di.get('enterprise_logout_timeout')),
                ('Effective Logout Timeout', di.get('effective_logout_timeout')),
                ('Is SSO User', 'Yes' if di.get('is_sso_user') else 'No'),
                ('Config File', di.get('config_file')),
            ]

            for label, value in fields:
                if value is not None:
                    lines.append(f"  [{t['text_dim']}]{label}:[/{t['text_dim']}] [{t['primary']}]{value}[/{t['primary']}]")

            detail_widget.update("\n".join(lines))
            self._update_status("Device information | Press Esc to return")
            self._update_shortcuts_bar(clear=True)

        except Exception as e:
            logging.debug(f"Error displaying device info: {e}")

    def _is_displayable_record(self, record: dict) -> bool:
        """Check if a record should be displayed in normal folder structure.
        Excludes file attachments, linked records, and Secrets Manager app records."""
        record_uid = record.get('uid')

        # Exclude file attachments - they'll be shown under their parent
        if record_uid in self.file_attachment_to_parent:
            return False

        # Exclude linked records (addressRef, cardRef) - they'll be shown under their parent
        if record_uid in self.linked_record_to_parent:
            return False

        # Exclude Secrets Manager app records - they go in virtual folder
        if record_uid in self.app_record_uids:
            return False

        return True

    def _add_record_with_attachments(self, parent_node, record: dict, idx: int, auto_expand: bool = False, total_count: int = 0):
        """Add a record to the tree. Records with attachments show 📎 indicator."""
        record_uid = record.get('uid')
        record_title = record.get('title', 'Untitled')
        t = self.theme_colors  # Theme colors

        # Calculate width for right-aligned numbers based on total count
        width = len(str(total_count)) if total_count > 0 else len(str(idx))
        idx_str = str(idx).rjust(width)

        # Check if this record has file attachments or linked records
        attachments = self.record_file_attachments.get(record_uid, [])
        linked_records = self.record_linked_records.get(record_uid, [])

        # Add [+] indicator if record has attachments
        attachment_indicator = f" [{t['text_dim']}]\\[+][/{t['text_dim']}]" if (attachments or linked_records) else ""

        record_label = f"[{t['record_num']}]{idx_str}.[/{t['record_num']}] [{t['record']}]{rich_escape(str(record_title))}[/{t['record']}]{attachment_indicator}"

        # All records are leaf nodes for consistent alignment
        parent_node.add_leaf(
            record_label,
            data={'type': 'record', 'uid': record_uid, 'has_attachments': bool(attachments or linked_records)}
        )

    def _setup_folder_tree(self):
        """Setup the folder tree structure with records as children"""
        tree = self.query_one("#folder_tree", Tree)
        tree.clear()
        t = self.theme_colors  # Theme colors

        # Root node represents "My Vault"
        root = tree.root
        root_folder = self.params.root_folder
        if root_folder:
            root.label = f"[{t['root']}]● {root_folder.name}[/{t['root']}]"
            root.data = {'type': 'root', 'uid': None}
        else:
            root.label = f"[{t['root']}]● My Vault[/{t['root']}]"
            root.data = {'type': 'root', 'uid': None}

        # Determine if we should auto-expand (when filtering with < AUTO_EXPAND_THRESHOLD results)
        auto_expand = False
        if self.filtered_record_uids is not None and len(self.filtered_record_uids) < self.AUTO_EXPAND_THRESHOLD:
            auto_expand = True

        # Build tree recursively from root using proper folder structure
        def add_folder_node(parent_tree_node, folder_node, folder_uid):
            """Recursively add folder and its children to tree"""
            if not folder_node:
                return None

            # Get records in this folder (filtered if search is active)
            # Exclude file attachments and 'app' type records
            folder_records = []
            for r in self.records.values():
                if r.get('folder_uid') == folder_uid and self._is_displayable_record(r):
                    # Apply filter if active
                    if self.filtered_record_uids is None or r['uid'] in self.filtered_record_uids:
                        folder_records.append(r)

            # Get subfolders that have matching records (recursively)
            subfolders_with_records = []
            if hasattr(folder_node, 'subfolders') and folder_node.subfolders:
                for subfolder_uid in folder_node.subfolders:
                    if subfolder_uid in self.params.folder_cache:
                        subfolder = self.params.folder_cache[subfolder_uid]
                        # Check if this subfolder has any matching records
                        if self._folder_has_matching_records(subfolder_uid):
                            subfolders_with_records.append((subfolder.name.lower() if subfolder.name else '', subfolder_uid, subfolder))
                subfolders_with_records.sort(key=lambda x: x[0])

            # Skip this folder only when SEARCHING and it has no matching records/subfolders
            # When not searching (filtered_record_uids is None), show all folders including empty ones
            if self.filtered_record_uids is not None and not folder_records and not subfolders_with_records:
                return None

            # Determine label and color based on folder type
            color = t['folder']
            if folder_node.type == 'shared_folder':
                # Shared folder: bold green name with share icon after
                label = f"[bold {color}]{folder_node.name}[/bold {color}] 👥"
            else:
                # Regular folder: bold green name
                label = f"[bold {color}]{folder_node.name}[/bold {color}]"

            # Add this folder to the tree with color
            tree_node = parent_tree_node.add(
                label,
                data={'type': 'folder', 'uid': folder_uid}
            )

            # Add subfolders
            for _, subfolder_uid, subfolder in subfolders_with_records:
                add_folder_node(tree_node, subfolder, subfolder_uid)

            # Sort and add records (with their file attachments as children)
            folder_records.sort(key=lambda r: r.get('title', '').lower())
            total_records = len(folder_records)

            for idx, record in enumerate(folder_records, start=1):
                self._add_record_with_attachments(tree_node, record, idx, auto_expand, total_records)

            # Auto-expand if we're in search mode with < 100 results
            if auto_expand:
                tree_node.expand()

            return tree_node

        # Get and sort root-level folders that have matching records
        root_folders = []
        if root_folder and hasattr(root_folder, 'subfolders'):
            for folder_uid in root_folder.subfolders:
                if folder_uid in self.params.folder_cache:
                    folder = self.params.folder_cache[folder_uid]
                    # Only include folders with matching records
                    if self._folder_has_matching_records(folder_uid):
                        root_folders.append((folder.name.lower() if folder.name else '', folder_uid, folder))
            root_folders.sort(key=lambda x: x[0])

        # Add root folders
        for _, folder_uid, folder in root_folders:
            add_folder_node(root, folder, folder_uid)

        # Add root-level records (records not in any subfolder)
        # A record is at root if it's NOT in any actual subfolder (not in records_in_subfolders)
        # Exclude file attachments and Secrets Manager app records
        root_records = []
        for r in self.records.values():
            record_uid = r.get('uid')
            # Record is at root if it's not in any subfolder
            is_root_record = record_uid not in self.records_in_subfolders
            if is_root_record and self._is_displayable_record(r):
                # Apply filter if active
                if self.filtered_record_uids is None or record_uid in self.filtered_record_uids:
                    root_records.append(r)
        root_records.sort(key=lambda r: r.get('title', '').lower())
        total_root_records = len(root_records)

        for idx, record in enumerate(root_records, start=1):
            self._add_record_with_attachments(root, record, idx, auto_expand, total_root_records)

        # Add virtual "Secrets Manager Apps" folder at the bottom for app records
        app_records = []
        for r in self.records.values():
            if r.get('uid') in self.app_record_uids:
                # Apply filter if active
                if self.filtered_record_uids is None or r['uid'] in self.filtered_record_uids:
                    app_records.append(r)

        if app_records:
            app_records.sort(key=lambda r: r.get('title', '').lower())
            total_app_records = len(app_records)
            # Create virtual folder with distinct styling
            apps_folder = root.add(
                f"[{t['virtual_folder']}]★ Secrets Manager Apps[/{t['virtual_folder']}]",
                data={'type': 'virtual_folder', 'uid': '__secrets_manager_apps__'}
            )

            for idx, record in enumerate(app_records, start=1):
                self._add_record_with_attachments(apps_folder, record, idx, auto_expand, total_app_records)

            if auto_expand:
                apps_folder.expand()

        # Expand root
        root.expand()

    def _folder_has_matching_records(self, folder_uid: str) -> bool:
        """Check if a folder should be displayed.
        When no search filter is active, all folders are shown (including empty ones).
        When searching, only folders with matching records are shown."""
        # If no search filter, show all folders including empty ones
        if self.filtered_record_uids is None:
            return True

        # When searching, check if this folder has any matching displayable records
        for r in self.records.values():
            if r.get('folder_uid') == folder_uid and self._is_displayable_record(r):
                if r['uid'] in self.filtered_record_uids:
                    return True

        # Check subfolders recursively
        if folder_uid in self.params.folder_cache:
            folder = self.params.folder_cache[folder_uid]
            if hasattr(folder, 'subfolders') and folder.subfolders:
                for subfolder_uid in folder.subfolders:
                    if self._folder_has_matching_records(subfolder_uid):
                        return True

        return False

    def _restore_tree_selection(self, tree: Tree):
        """Restore tree selection to previously selected record or folder"""
        try:
            target_uid = self.selected_record or self.selected_folder
            if not target_uid:
                return

            # Find and select the node in the tree
            def find_and_select(node):
                if hasattr(node, 'data') and node.data:
                    data = node.data
                    node_uid = data.get('uid') if isinstance(data, dict) else None
                    if node_uid == target_uid:
                        # Found the node - select it
                        tree.select_node(node)
                        node.expand()
                        # Also expand parent nodes
                        parent = node.parent
                        while parent:
                            parent.expand()
                            parent = parent.parent
                        return True
                # Check children
                for child in node.children:
                    if find_and_select(child):
                        return True
                return False

            find_and_select(tree.root)

            # Update the detail pane if a record was selected
            if self.selected_record:
                self._display_record_detail(self.selected_record)
            elif self.selected_folder:
                folder = self.params.folder_cache.get(self.selected_folder)
                folder_name = folder.name if folder else "Unknown"
                detail = self.query_one("#detail_content", Static)
                t = self.theme_colors
                detail.update(f"[bold {t['primary']}]📁 {rich_escape(str(folder_name))}[/bold {t['primary']}]")

        except Exception as e:
            logging.error(f"Error restoring tree selection: {e}", exc_info=True)

    def _select_record_in_tree(self, tree: Tree, record_uid: str):
        """Select a specific record in the tree by its UID"""
        try:
            def find_and_select(node):
                if hasattr(node, 'data') and node.data:
                    data = node.data
                    node_uid = data.get('uid') if isinstance(data, dict) else None
                    if node_uid == record_uid:
                        # Found the node - select it
                        tree.select_node(node)
                        # Expand parent nodes to make visible
                        parent = node.parent
                        while parent:
                            parent.expand()
                            parent = parent.parent
                        return True
                # Check children
                for child in node.children:
                    if find_and_select(child):
                        return True
                return False

            find_and_select(tree.root)
        except Exception as e:
            logging.debug(f"Error selecting record in tree: {e}")

    def _search_records(self, query: str) -> set:
        """
        Search records with smart partial matching.
        Returns set of matching record UIDs.

        Search logic:
        - Tokenizes query by whitespace
        - Each token must match (partial) at least one field OR folder name
        - Order doesn't matter: "aws prod us" matches "us production aws"
        - Searches: title, url, custom field values, notes, AND folder name
        - If folder name matches, all records in that folder are candidates
          (but other tokens must still match the record)
        """
        if not query or not query.strip():
            return None  # None means show all

        # Tokenize query - split by whitespace and lowercase
        query_tokens = [token.lower().strip() for token in query.split() if token.strip()]
        if not query_tokens:
            return None

        matching_uids = set()

        # Build folder name cache for quick lookup
        folder_names = {}  # folder_uid -> folder_name (lowercase)
        if hasattr(self.params, 'folder_cache'):
            for folder_uid, folder in self.params.folder_cache.items():
                if hasattr(folder, 'name') and folder.name:
                    folder_names[folder_uid] = folder.name.lower()

        for record_uid, record in self.records.items():
            # Build searchable text from all record fields
            record_parts = []

            # Record UID - important for searching by UID
            record_parts.append(record_uid)

            # Title
            if record.get('title'):
                record_parts.append(str(record['title']))

            # URL
            if record.get('login_url'):
                record_parts.append(str(record['login_url']))

            # Username/Login
            if record.get('login'):
                record_parts.append(str(record['login']))

            # Custom fields
            if record.get('custom_fields'):
                for field in record['custom_fields']:
                    name = field.get('name', '')
                    value = field.get('value', '')
                    if name:
                        record_parts.append(str(name))
                    if value:
                        record_parts.append(str(value))

            # Notes
            if record.get('notes'):
                record_parts.append(str(record['notes']))

            # Combine record text
            record_text = ' '.join(record_parts).lower()

            # Get folder UID and name for this record
            folder_uid = self.record_to_folder.get(record_uid)
            folder_name = folder_names.get(folder_uid, '') if folder_uid else ''

            # Combined text includes record fields, folder UID, AND folder name
            combined_text = record_text + ' ' + (folder_uid.lower() if folder_uid else '') + ' ' + folder_name

            # Check if ALL query tokens match somewhere (record OR folder)
            # This allows "customer 123 google" to match record "google" in folder "Customer 123"
            all_tokens_match = all(
                token in combined_text
                for token in query_tokens
            )

            if all_tokens_match:
                matching_uids.add(record_uid)

        return matching_uids

    def _perform_live_search(self, query: str) -> int:
        """
        Perform live search and update tree.
        Returns count of matching records.
        """
        self.search_query = query

        # Get matching record UIDs
        self.filtered_record_uids = self._search_records(query)

        # Rebuild tree with filtered results
        self._setup_folder_tree()

        # Return count
        if self.filtered_record_uids is None:
            return len(self.records)
        else:
            return len(self.filtered_record_uids)

    def _format_record_for_tui(self, record_uid: str) -> str:
        """Format record details for TUI display using the 'get' command output"""
        t = self.theme_colors  # Get theme colors

        try:
            # Use the get command (same as shell) to fetch record details
            output = self._get_record_output(record_uid, format_type='detail')
            # Strip ANSI codes from command output
            output = strip_ansi_codes(output)

            if not output or output.strip() == '':
                return "[red]Failed to get record details[/red]"

            # Escape any Rich markup characters in the output
            output = output.replace('[', '\\[').replace(']', '\\]')

            # Parse and format the output more cleanly
            lines = []
            current_section = None
            prev_was_blank = False
            seen_first_user = False  # Track if we've seen first user in permissions section
            in_totp_section = False
            # Section headers - only when value is empty
            section_headers = {'Custom Fields', 'Attachments', 'User Permissions',
                               'Shared Folder Permissions', 'Share Admins', 'One-Time Share URL'}

            def is_section_header(key, value):
                """Check if key is a section header (only when value is empty)"""
                if value:
                    return False
                if key in section_headers:
                    return True
                for header in section_headers:
                    if key.startswith(header):
                        return True
                return False

            for line in output.split('\n'):
                stripped = line.strip()

                # Skip multiple consecutive blank lines
                if not stripped:
                    if not prev_was_blank and lines:
                        prev_was_blank = True
                    continue
                prev_was_blank = False

                # Check if line contains a colon (key: value format)
                if ':' in stripped:
                    parts = stripped.split(':', 1)
                    key = parts[0].strip()
                    value = parts[1].strip() if len(parts) > 1 else ''

                    # UID - use theme primary color
                    if key in ['UID', 'Record UID']:
                        lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]")
                    # Title - bold primary with label
                    elif key in ['Title', 'Name'] and not current_section:
                        lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [bold {t['primary']}]{rich_escape(str(value))}[/bold {t['primary']}]")
                    # Type field
                    elif key == 'Type':
                        display_type = value if value else 'app' if record_uid in self.app_record_uids else ''
                        lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary_dim']}]{rich_escape(str(display_type))}[/{t['primary_dim']}]")
                    # Notes - always a section
                    elif key == 'Notes':
                        lines.append("")
                        lines.append(f"[bold {t['secondary']}]Notes:[/bold {t['secondary']}]")
                        current_section = 'Notes'
                        if value:
                            lines.append(f"  [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]")
                    # TOTP fields - skip, will be calculated from stored URL
                    elif key == 'TOTP URL':
                        pass
                    elif key == 'Two Factor Code':
                        pass
                    # Section headers
                    elif is_section_header(key, value):
                        current_section = key
                        seen_first_user = False
                        in_totp_section = False
                        if lines:
                            lines.append("")
                        lines.append(f"[bold {t['secondary']}]{key}:[/bold {t['secondary']}]")
                    # Regular key-value pairs
                    elif value:
                        if key == 'User' and current_section == 'User Permissions':
                            if seen_first_user:
                                lines.append("")
                            seen_first_user = True
                        if current_section:
                            lines.append(f"  [{t['text_dim']}]{rich_escape(str(key))}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]")
                        else:
                            lines.append(f"[{t['text_dim']}]{rich_escape(str(key))}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]")
                    elif key:
                        lines.append(f"  [{t['primary_dim']}]{rich_escape(str(key))}[/{t['primary_dim']}]")
                else:
                    # Lines without colons - continuation of notes or other content
                    if current_section == 'Notes':
                        lines.append(f"  [{t['primary']}]{rich_escape(str(stripped))}[/{t['primary']}]")
                    elif stripped:
                        lines.append(f"  [{t['primary_dim']}]{rich_escape(str(stripped))}[/{t['primary_dim']}]")

            return "\n".join(lines)

        except Exception as e:
            logging.error(f"Error formatting record for TUI: {e}", exc_info=True)
            error_msg = str(e).replace('[', '\\[').replace(']', '\\]')
            return f"[red]Error formatting record:[/red]\n{error_msg}"

    def _format_folder_for_tui(self, folder_uid: str) -> str:
        """Format folder/shared folder details for TUI display"""
        t = self.theme_colors  # Get theme colors

        try:
            # Create a StringIO buffer to capture stdout from get command
            stdout_buffer = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_buffer

            # Execute the get command for folder
            get_cmd = RecordGetUidCommand()
            get_cmd.execute(self.params, uid=folder_uid, format='detail')

            # Restore stdout
            sys.stdout = old_stdout

            # Get the captured output
            output = stdout_buffer.getvalue()
            # Strip ANSI codes
            output = strip_ansi_codes(output)

            if not output or output.strip() == '':
                # Fallback to basic folder info if get command didn't work
                folder = self.params.folder_cache.get(folder_uid)
                if folder:
                    folder_type = folder.get_folder_type() if hasattr(folder, 'get_folder_type') else folder.type
                    folder_type_str = str(folder_type) if folder_type else 'Folder'
                    folder_icon = "👥" if 'shared' in folder_type_str.lower() else "📁"
                    return (
                        f"[bold {t['secondary']}]{folder_icon} {rich_escape(str(folder.name))}[/bold {t['secondary']}]\n\n"
                        f"[{t['text_dim']}]Folder:[/{t['text_dim']}] [bold {t['primary']}]{rich_escape(str(folder.name))}[/bold {t['primary']}]\n"
                        f"[{t['text_dim']}]UID:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(folder_uid))}[/{t['primary']}]\n\n"
                        f"[{t['primary_dim']}]Expand folder (press 'l' or →) to view records[/{t['primary_dim']}]"
                    )
                return "[red]Folder not found[/red]"

            # Format the output with proper alignment and theme colors
            lines = []

            # Determine folder header with icon and name
            folder = self.params.folder_cache.get(folder_uid)
            folder_name = folder.name if folder else "Folder"
            is_shared = 'Shared Folder UID' in output
            folder_icon = "👥" if is_shared else "📁"
            lines.append(f"[bold {t['secondary']}]{folder_icon} {rich_escape(str(folder_name))}[/bold {t['secondary']}]")
            lines.append("")

            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    lines.append("")
                    continue

                # Check if line contains a colon (key: value format)
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()

                        # Special formatting for headers
                        if key in ['Shared Folder UID', 'Folder UID', 'Team UID']:
                            lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]")
                        elif key == 'Name':
                            lines.append(f"[{t['text_dim']}]Folder:[/{t['text_dim']}] [bold {t['primary']}]{rich_escape(str(value))}[/bold {t['primary']}]")
                        # Section headers (no value or short value)
                        elif key in ['Record Permissions', 'User Permissions', 'Team Permissions', 'Share Administrators']:
                            lines.append("")
                            lines.append(f"[bold {t['primary_bright']}]{key}:[/bold {t['primary_bright']}]")
                        # Boolean values
                        elif value.lower() in ['true', 'false']:
                            color = t['primary'] if value.lower() == 'true' else t['primary_dim']
                            lines.append(f"[{t['secondary']}]{rich_escape(str(key)):>25}:[/{t['secondary']}]  [{color}]{rich_escape(str(value))}[/{color}]")
                        # Regular key-value pairs
                        else:
                            # Add indentation for permission entries
                            if key and not key[0].isspace():
                                lines.append(f"[{t['secondary']}]  • {rich_escape(str(key))}:[/{t['secondary']}]  [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]")
                            else:
                                lines.append(f"[{t['secondary']}]{rich_escape(str(key)):>25}:[/{t['secondary']}]  [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]")
                    else:
                        lines.append(f"[{t['primary']}]{rich_escape(str(line))}[/{t['primary']}]")
                else:
                    # Lines without colons (section content)
                    if line:
                        lines.append(f"[{t['primary']}]  {rich_escape(str(line))}[/{t['primary']}]")

            return "\n".join(lines)

        except Exception as e:
            sys.stdout = old_stdout
            logging.error(f"Error formatting folder for TUI: {e}", exc_info=True)
            return f"[red]Error displaying folder:[/red]\n{str(e)}"

    def _get_record_output(self, record_uid: str, format_type: str = 'detail', include_dag: bool = False) -> str:
        """Get record output using Commander's get command (cached for performance)"""
        # Check cache first
        cache_key = f"{record_uid}:{format_type}:{include_dag}"
        if hasattr(self, '_record_output_cache') and cache_key in self._record_output_cache:
            return self._record_output_cache[cache_key]

        try:
            # Create a StringIO buffer to capture stdout
            stdout_buffer = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_buffer

            try:
                # Execute the get command
                get_cmd = RecordGetUidCommand()
                get_cmd.execute(self.params, uid=record_uid, format=format_type, include_dag=include_dag)
            finally:
                # Always restore stdout
                sys.stdout = old_stdout

            # Get the captured output and cache it
            output = stdout_buffer.getvalue()
            
            # If output is empty or error, don't cache it
            if output and not output.startswith("Error"):
                if not hasattr(self, '_record_output_cache'):
                    self._record_output_cache = {}
                self._record_output_cache[cache_key] = output
            
            return output if output else "Record data not available"

        except Exception as e:
            if sys.stdout != old_stdout:
                sys.stdout = old_stdout
            logging.error(f"Error getting record output for {record_uid}: {e}", exc_info=True)
            return f"Error displaying record: {str(e)}"

    def _get_rotation_info(self, record_uid: str) -> Optional[Dict[str, Any]]:
        """Get rotation info for pamUser records from DAG and rotation cache.

        NOTE: This method fetches DAG data which makes API calls. This is acceptable
        because it only runs when a user explicitly views a pamUser record in SuperShell,
        not during initialization or sync operations.
        """
        try:
            record_data = self.records.get(record_uid, {})
            record_type = record_data.get('record_type', '')

            # Check if this is a PAM User record (or has rotation data configured)
            has_rotation_data = record_uid in self.params.record_rotation_cache
            is_pam_user = record_type == 'pamUser'

            if not is_pam_user and not has_rotation_data:
                return None

            from .. import vault

            rotation_info = {}
            rotation_profile = None
            config_uid = None
            resource_uid = None

            # Get rotation data from cache
            rotation_data = self.params.record_rotation_cache.get(record_uid)

            # Only fetch DAG data for pamUser records (requires PAM infrastructure)
            if is_pam_user:
                try:
                    from .tunnel.port_forward.tunnel_helpers import get_keeper_tokens
                    from .tunnel.port_forward.TunnelGraph import TunnelDAG
                    from keeper_dag.edge import EdgeType

                    encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(self.params)
                    tdag = TunnelDAG(self.params, encrypted_session_token, encrypted_transmission_key, record_uid,
                                     transmission_key=transmission_key)

                    if tdag.linking_dag.has_graph:
                        record_vertex = tdag.linking_dag.get_vertex(record_uid)
                        if record_vertex:
                            for parent_vertex in record_vertex.belongs_to_vertices():
                                acl_edge = record_vertex.get_edge(parent_vertex, EdgeType.ACL)
                                if acl_edge:
                                    edge_content = acl_edge.content_as_dict or {}
                                    belongs_to = edge_content.get('belongs_to', False)
                                    is_iam_user = edge_content.get('is_iam_user', False)
                                    rotation_settings = edge_content.get('rotation_settings', {})
                                    is_noop = rotation_settings.get('noop', False) if isinstance(rotation_settings, dict) else False

                                    if is_noop:
                                        rotation_profile = 'Scripts Only'
                                        config_uid = parent_vertex.uid
                                    elif is_iam_user:
                                        rotation_profile = 'IAM User'
                                        config_uid = parent_vertex.uid
                                    elif belongs_to:
                                        rotation_profile = 'General'
                                        resource_uid = parent_vertex.uid
                except Exception:
                    pass  # DAG fetch failed, continue with cached data only

            # Get config UID from rotation cache if not from DAG
            if not config_uid and rotation_data:
                config_uid = rotation_data.get('configuration_uid')
            if not resource_uid and rotation_data:
                resource_uid = rotation_data.get('resource_uid')
                # If resource_uid equals config_uid, it's an IAM/NOOP user, not General
                if resource_uid and resource_uid == config_uid:
                    resource_uid = None

            # Get configuration name
            config_name = None
            if config_uid:
                config_record = vault.KeeperRecord.load(self.params, config_uid)
                if config_record:
                    config_name = config_record.title

            # Get resource name
            resource_name = None
            if resource_uid:
                resource_record = vault.KeeperRecord.load(self.params, resource_uid)
                if resource_record:
                    resource_name = resource_record.title

            # Determine rotation status
            if not rotation_data and not rotation_profile:
                rotation_info['status'] = 'Not configured'
                return rotation_info

            # Rotation status
            if rotation_data:
                disabled = rotation_data.get('disabled', False)
                rotation_info['status'] = 'Disabled' if disabled else 'Enabled'
            else:
                rotation_info['status'] = 'Enabled'

            # Rotation profile
            if rotation_profile:
                rotation_info['profile'] = rotation_profile

            # PAM Configuration
            if config_name:
                rotation_info['config_name'] = config_name
            elif config_uid:
                rotation_info['config_uid'] = config_uid

            # Resource (for General profile)
            if resource_name:
                rotation_info['resource_name'] = resource_name
            elif resource_uid:
                rotation_info['resource_uid'] = resource_uid

            # Schedule
            if rotation_data and rotation_data.get('schedule'):
                try:
                    schedule_json = json.loads(rotation_data['schedule'])
                    if isinstance(schedule_json, list) and len(schedule_json) > 0:
                        schedule = schedule_json[0]
                        schedule_type = schedule.get('type', 'ON_DEMAND')
                        if schedule_type == 'ON_DEMAND':
                            rotation_info['schedule'] = 'On Demand'
                        else:
                            # Format schedule description
                            time_str = schedule.get('utcTime', schedule.get('time', ''))
                            tz = schedule.get('tz', 'UTC')
                            if schedule_type == 'DAILY':
                                interval = schedule.get('intervalCount', 1)
                                rotation_info['schedule'] = f"Every {interval} day(s) at {time_str} {tz}"
                            elif schedule_type == 'WEEKLY':
                                weekday = schedule.get('weekday', '')
                                rotation_info['schedule'] = f"Weekly on {weekday} at {time_str} {tz}"
                            elif schedule_type == 'MONTHLY_BY_DAY':
                                day = schedule.get('monthDay', 1)
                                rotation_info['schedule'] = f"Monthly on day {day} at {time_str} {tz}"
                            elif schedule_type == 'MONTHLY_BY_WEEKDAY':
                                week = schedule.get('occurrence', 'FIRST')
                                weekday = schedule.get('weekday', '')
                                rotation_info['schedule'] = f"{week.title()} {weekday} of month at {time_str} {tz}"
                            else:
                                rotation_info['schedule'] = f"{schedule_type} at {time_str} {tz}"
                    else:
                        rotation_info['schedule'] = 'On Demand'
                except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
                    logging.debug(f"Error parsing schedule: {e}")
                    rotation_info['schedule'] = 'On Demand'

            # Last rotation
            if rotation_data and rotation_data.get('last_rotation'):
                last_rotation_ts = rotation_data['last_rotation']
                if last_rotation_ts > 0:
                    import datetime
                    last_rotation_dt = datetime.datetime.fromtimestamp(last_rotation_ts / 1000)
                    rotation_info['last_rotated'] = last_rotation_dt.strftime("%b %d, %Y at %I:%M %p")

                    # Show rotation status if available
                    last_status = rotation_data.get('last_rotation_status')
                    # RecordRotationStatus enum: 0=NOT_ROTATED, 1=IN_PROGRESS, 2=SUCCESS, 3=FAILURE
                    if last_status is not None:
                        status_map = {0: 'Not Rotated', 1: 'In Progress', 2: 'Success', 3: 'Failure'}
                        rotation_info['last_status'] = status_map.get(last_status, f'Unknown ({last_status})')

            return rotation_info if rotation_info else None

        except (KeyError, AttributeError, ValueError, TypeError) as e:
            logging.debug(f"Error getting rotation info: {e}")
            return None

    def _clear_clickable_fields(self):
        """Remove any dynamically mounted clickable field widgets"""
        try:
            detail_scroll = self.query_one("#record_detail", VerticalScroll)
            # Collect all widgets to remove first, then batch remove
            widgets_to_remove = []
            widgets_to_remove.extend(detail_scroll.query(ClickableDetailLine))
            widgets_to_remove.extend(detail_scroll.query(ClickableField))
            widgets_to_remove.extend(detail_scroll.query(ClickableRecordUID))
            # Also remove any dynamically added Static widgets (but keep #detail_content)
            for widget in detail_scroll.query(Static):
                if widget.id != "detail_content" and widget.id != "shortcuts_bar":
                    widgets_to_remove.append(widget)
            # Batch remove all at once
            for widget in widgets_to_remove:
                widget.remove()
            self.clickable_fields.clear()
        except Exception as e:
            logging.debug(f"Error clearing clickable fields: {e}")

    def _display_record_with_clickable_fields(self, record_uid: str):
        """Display record details with clickable fields for copy-on-click"""
        t = self.theme_colors
        detail_scroll = self.query_one("#record_detail", VerticalScroll)
        detail_widget = self.query_one("#detail_content", Static)

        # Clear previous clickable fields
        self._clear_clickable_fields()

        # Get and parse record output
        output = self._get_record_output(record_uid, format_type='detail')
        output = strip_ansi_codes(output)

        if not output or output.strip() == '':
            detail_widget.update("[red]Failed to get record details[/red]")
            return

        # Hide the static placeholder
        detail_widget.update("")

        # Collect all widgets first, then mount in batch for performance
        widgets_to_mount = []

        # Helper to collect clickable lines (batched for performance)
        def mount_line(content: str, copy_value: str = None, is_password: bool = False):
            line = ClickableDetailLine(content, copy_value, record_uid=record_uid, is_password=is_password)
            widgets_to_mount.append(line)

        # Get the actual record data for password lookup
        record_data = self.records.get(record_uid, {})
        actual_password = record_data.get('password', '')

        # Determine header with icon and title
        record_title = record_data.get('title', 'Untitled')
        if record_uid in self.app_record_uids:
            type_header = f"🔐 {rich_escape(record_title)}"
        else:
            type_header = f"🔒 {rich_escape(record_title)}"

        # Type header with icon and title
        mount_line(f"[bold {t['secondary']}]{type_header}[/bold {t['secondary']}]", None)
        mount_line("", None)

        # Parse and create clickable lines
        current_section = None
        seen_first_user = False  # Track if we've seen first user in permissions section
        totp_displayed = False  # Track if TOTP has been displayed
        totp_url = record_data.get('totp_url')  # Get TOTP URL once for use in display
        # Section headers are only headers when they have NO value on the same line
        section_headers = {'Custom Fields', 'Attachments', 'User Permissions',
                          'Shared Folder Permissions', 'Share Admins', 'One-Time Share URL'}

        def display_totp():
            """Helper to display TOTP section"""
            nonlocal totp_displayed
            if totp_url and not totp_displayed:
                from ..record import get_totp_code
                try:
                    result = get_totp_code(totp_url)
                    if result:
                        code, seconds_remaining, period = result
                        mount_line("", None)  # Blank line before TOTP
                        mount_line(f"[bold {t['secondary']}]Two-Factor Authentication:[/bold {t['secondary']}]", None)
                        mount_line(f"  [{t['text_dim']}]Code:[/{t['text_dim']}] [bold {t['primary']}]{code}[/bold {t['primary']}]    [{t['text_dim']}]valid for[/{t['text_dim']}] [bold {t['secondary']}]{seconds_remaining} sec[/bold {t['secondary']}]", code)
                        mount_line("", None)  # Blank line after TOTP
                        totp_displayed = True
                except Exception as e:
                    logging.debug(f"Error calculating TOTP: {e}")

        def is_section_header(key, value):
            """Check if key is a section header (only when value is empty)"""
            if value:  # If there's a value on same line, it's not a section header
                return False
            if key in section_headers:
                return True
            # Handle cases like "Share Admins (64, showing first 10)"
            for header in section_headers:
                if key.startswith(header):
                    return True
            return False

        # Get attachments for this record
        file_attachment_uids = self.record_file_attachments.get(record_uid, [])
        linked_record_uids = self.record_linked_records.get(record_uid, [])
        attachments_displayed = False

        def display_attachments():
            """Helper to display file attachments section"""
            nonlocal attachments_displayed
            if attachments_displayed:
                return
            if not file_attachment_uids and not linked_record_uids:
                return

            mount_line("", None)  # Blank line before attachments
            mount_line(f"[bold {t['secondary']}]File Attachments:[/bold {t['secondary']}]", None)

            # Display file attachments (use + symbol instead of emoji)
            for att_uid in file_attachment_uids:
                att_record = self.records.get(att_uid, {})
                att_title = att_record.get('title', att_uid)
                mount_line(f"  [{t['text_dim']}]+[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(att_title))}[/{t['primary']}]", att_uid)

            # Display linked records (addressRef, cardRef, etc.)
            for link_uid in linked_record_uids:
                link_record = self.records.get(link_uid, {})
                link_title = link_record.get('title', link_uid)
                link_type = link_record.get('record_type', '')
                type_label = f" ({rich_escape(str(link_type))})" if link_type else ""
                mount_line(f"  [{t['text_dim']}]→[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(link_title))}[/{t['primary']}][{t['text_dim']}]{type_label}[/{t['text_dim']}]", link_uid)

            attachments_displayed = True

        # Rotation info for pamUser records
        rotation_info = self._get_rotation_info(record_uid)
        rotation_displayed = False

        def display_rotation():
            """Helper to display rotation info section"""
            nonlocal rotation_displayed
            if rotation_displayed or not rotation_info:
                return

            mount_line("", None)  # Blank line before rotation section
            mount_line(f"[bold {t['secondary']}]Rotation:[/bold {t['secondary']}]", None)

            status = rotation_info.get('status', 'Unknown')
            status_color = '#00ff00' if status == 'Enabled' else '#ff6600' if status == 'Disabled' else t['text_dim']
            mount_line(f"  [{t['text_dim']}]Status:[/{t['text_dim']}] [{status_color}]{status}[/{status_color}]", status)

            if rotation_info.get('profile'):
                mount_line(f"  [{t['text_dim']}]Profile:[/{t['text_dim']}] [{t['primary']}]{rotation_info['profile']}[/{t['primary']}]", rotation_info['profile'])

            if rotation_info.get('config_name'):
                mount_line(f"  [{t['text_dim']}]Configuration:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(rotation_info['config_name']))}[/{t['primary']}]", rotation_info['config_name'])
            elif rotation_info.get('config_uid'):
                mount_line(f"  [{t['text_dim']}]Configuration UID:[/{t['text_dim']}] [{t['primary']}]{rotation_info['config_uid']}[/{t['primary']}]", rotation_info['config_uid'])

            if rotation_info.get('resource_name'):
                mount_line(f"  [{t['text_dim']}]Resource:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(rotation_info['resource_name']))}[/{t['primary']}]", rotation_info['resource_name'])
            elif rotation_info.get('resource_uid'):
                mount_line(f"  [{t['text_dim']}]Resource UID:[/{t['text_dim']}] [{t['primary']}]{rotation_info['resource_uid']}[/{t['primary']}]", rotation_info['resource_uid'])

            if rotation_info.get('schedule'):
                mount_line(f"  [{t['text_dim']}]Schedule:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(rotation_info['schedule']))}[/{t['primary']}]", rotation_info['schedule'])

            if rotation_info.get('last_rotated'):
                mount_line(f"  [{t['text_dim']}]Last Rotated:[/{t['text_dim']}] [{t['primary']}]{rotation_info['last_rotated']}[/{t['primary']}]", rotation_info['last_rotated'])

            if rotation_info.get('last_status'):
                last_status = rotation_info['last_status']
                last_status_color = '#00ff00' if last_status == 'Success' else '#ff0000' if last_status == 'Failure' else '#ffff00'
                mount_line(f"  [{t['text_dim']}]Last Status:[/{t['text_dim']}] [{last_status_color}]{last_status}[/{last_status_color}]", last_status)

            rotation_displayed = True

        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            if ':' in stripped:
                parts = stripped.split(':', 1)
                key = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else ''

                if key in ['UID', 'Record UID']:
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                elif key in ['Title', 'Name'] and not current_section:
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [bold {t['primary']}]{rich_escape(str(value))}[/bold {t['primary']}]", value)
                elif key == 'Type':
                    # Show 'app' for app records if type is blank
                    display_type = value if value else 'app' if record_uid in self.app_record_uids else ''
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary_dim']}]{rich_escape(str(display_type))}[/{t['primary_dim']}]", display_type)
                elif key == 'Password':
                    # Show masked password but use ClipboardCommand to copy (generates audit event)
                    # Respect unmask_secrets toggle
                    if self.unmask_secrets:
                        display_value = actual_password if actual_password else value
                    else:
                        display_value = '******' if actual_password else value
                    copy_value = actual_password if actual_password else None
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(display_value))}[/{t['primary']}]", copy_value, is_password=True)
                elif key == 'URL':
                    # Display URL, then TOTP if present
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                    display_totp()  # Add TOTP section right after URL (before Notes)
                elif key == 'Notes':
                    # Display TOTP before Notes if not already shown (for records without URL)
                    display_totp()
                    # Notes section - check if it has content on same line or is multi-line
                    mount_line("", None)  # Blank line before Notes
                    mount_line(f"[bold {t['secondary']}]Notes:[/bold {t['secondary']}]", None)
                    current_section = 'Notes'
                    if value:
                        # Notes content is on the same line
                        mount_line(f"  [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                elif key == 'TOTP URL':
                    # Skip TOTP URL - we'll show the code calculated from stored URL
                    pass
                elif key == 'Two Factor Code':
                    # Skip - we'll calculate and show TOTP from stored URL below
                    pass
                elif key == 'Passkey':
                    # Passkey section header
                    mount_line("", None)  # Blank line before
                    mount_line(f"[bold {t['secondary']}]Passkey:[/bold {t['secondary']}]", None)
                    current_section = 'Passkey'
                elif current_section == 'Passkey' and key in ('Created', 'Username', 'Relying Party'):
                    # Passkey detail fields
                    mount_line(f"  [{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                elif is_section_header(key, value):
                    # Display rotation BEFORE User Permissions section
                    if key == 'User Permissions' and not rotation_displayed:
                        display_rotation()
                    # Display attachments BEFORE Share Admins section
                    if key.startswith('Share Admins') and not attachments_displayed:
                        display_attachments()
                    current_section = key
                    seen_first_user = False  # Reset for new section
                    mount_line("", None)  # Blank line
                    mount_line(f"[bold {t['secondary']}]{key}:[/bold {t['secondary']}]", None)
                elif key.rstrip(':') in ('fileRef', 'addressRef', 'cardRef'):
                    # Skip reference fields - we handle attachments/linked records separately
                    pass
                elif value:
                    # Strip type prefixes from field names (e.g., "text:Sign-In Address" -> "Sign-In Address")
                    display_key = key
                    field_type_prefixes = ('text:', 'multiline:', 'url:', 'phone:', 'email:', 'secret:', 'date:', 'name:', 'host:', 'address:')
                    for prefix in field_type_prefixes:
                        if key.lower().startswith(prefix):
                            display_key = key[len(prefix):]
                            # If label was empty, use a friendly name based on type
                            if not display_key:
                                type_friendly_names = {
                                    'text:': 'Text',
                                    'multiline:': 'Note',
                                    'url:': 'URL',
                                    'phone:': 'Phone',
                                    'email:': 'Email',
                                    'secret:': 'Secret',
                                    'date:': 'Date',
                                    'name:': 'Name',
                                    'host:': 'Host',
                                    'address:': 'Address',
                                }
                                display_key = type_friendly_names.get(prefix, prefix.rstrip(':').title())
                            break

                    # Add blank line before each User entry in User Permissions section (except first)
                    if display_key == 'User' and current_section == 'User Permissions':
                        if seen_first_user:
                            mount_line("", None)  # Blank line between users
                        seen_first_user = True
                    indent = "  " if current_section else ""

                    # Check if this is a sensitive field that should be masked
                    is_sensitive = self._is_sensitive_field(display_key) or self._is_sensitive_field(key)
                    if is_sensitive and not self.unmask_secrets:
                        display_value = '******'
                        # Use is_password=False so it uses pyperclip.copy(value) instead of ClipboardCommand
                        # ClipboardCommand only copies the record's Password field, not arbitrary secret fields
                        mount_line(f"{indent}[{t['text_dim']}]{rich_escape(str(display_key))}:[/{t['text_dim']}] [{t['primary']}]{display_value}[/{t['primary']}]", value)
                    else:
                        mount_line(f"{indent}[{t['text_dim']}]{rich_escape(str(display_key))}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                elif key:
                    mount_line(f"  [{t['primary_dim']}]{rich_escape(str(key))}[/{t['primary_dim']}]", key)
            else:
                # Lines without colons - continuation of notes or other multi-line content
                if current_section == 'Notes':
                    mount_line(f"  [{t['primary']}]{rich_escape(str(stripped))}[/{t['primary']}]", stripped)
                elif stripped:
                    mount_line(f"  [{t['primary_dim']}]{rich_escape(str(stripped))}[/{t['primary_dim']}]", stripped)

        # Display attachments at end if not already shown (records without Share Admins section)
        display_attachments()

        # Display rotation at end if not already shown (records without User Permissions section)
        display_rotation()

        # Batch mount all widgets at once for better performance
        if widgets_to_mount:
            detail_scroll.mount(*widgets_to_mount, before=detail_widget)

        # Start TOTP auto-refresh timer if this record has TOTP
        # Skip timer management if we're in a refresh callback
        if not getattr(self, '_totp_refreshing', False):
            self._stop_totp_timer()  # Stop any existing timer
            if totp_url:
                self._totp_record_uid = record_uid
                self._totp_timer = self.set_interval(1.0, self._refresh_totp_display)

    def _stop_totp_timer(self):
        """Stop the TOTP auto-refresh timer"""
        if hasattr(self, '_totp_timer') and self._totp_timer:
            self._totp_timer.stop()
            self._totp_timer = None
        self._totp_record_uid = None

    def _refresh_totp_display(self):
        """Refresh the TOTP display (called by timer every second)"""
        if not hasattr(self, '_totp_record_uid') or not self._totp_record_uid:
            self._stop_totp_timer()
            return

        if self._totp_record_uid != self.selected_record:
            self._stop_totp_timer()
            return

        # Don't refresh if in JSON view mode
        if self.view_mode == 'json':
            return

        # Re-display the record (TOTP is calculated fresh each time)
        record_uid = self._totp_record_uid
        self._totp_refreshing = True  # Flag to prevent timer restart
        try:
            self._display_record_with_clickable_fields(record_uid)
        finally:
            self._totp_refreshing = False
            # Restore the record UID since display clears it
            self._totp_record_uid = record_uid

    def _display_json_with_clickable_fields(self, record_uid: str):
        """Display JSON view with clickable string values, syntax highlighting, masking passwords"""
        # Stop TOTP timer when in JSON view (no live countdown)
        self._stop_totp_timer()

        t = self.theme_colors
        container = self.query_one("#record_detail", VerticalScroll)
        detail_widget = self.query_one("#detail_content", Static)

        # Clear previous clickable fields
        self._clear_clickable_fields()

        # Get JSON output (include DAG data for PAM records)
        output = self._get_record_output(record_uid, format_type='json', include_dag=True)
        output = strip_ansi_codes(output)

        try:
            json_obj = json.loads(output)
        except:
            # If JSON parsing fails, show raw output
            detail_widget.update(f"[{t['primary']}]JSON View:\n\n{rich_escape(str(output))}[/{t['primary']}]")
            return

        # Keep unmasked JSON for copying actual values
        unmasked_obj = json_obj

        # Create masked version for display
        display_obj = self._mask_passwords_in_json(json_obj)

        # Clear detail widget content
        detail_widget.update("")

        # Collect all widgets first for batch mounting
        widgets_to_mount = []

        # Helper to collect widgets (batched for performance)
        def mount_line(content: str, copy_value: str = None, is_password: bool = False):
            """Collect a clickable line for batch mounting"""
            line = ClickableDetailLine(
                content,
                copy_value=copy_value,
                record_uid=record_uid if is_password else None,
                is_password=is_password
            )
            widgets_to_mount.append(line)
            self.clickable_fields.append(line)

        # Render header with icon and title
        record_data = self.records.get(record_uid, {})
        record_title = record_data.get('title', 'Untitled')
        if record_uid in self.app_record_uids:
            type_header = f"🔐 {rich_escape(record_title)}"
        else:
            type_header = f"🔒 {rich_escape(record_title)}"
        mount_line(f"[bold {t['secondary']}]{type_header}[/bold {t['secondary']}] [{t['text_dim']}](JSON)[/{t['text_dim']}]")
        mount_line("")

        # Render JSON with syntax highlighting
        self._render_json_lines(display_obj, unmasked_obj, mount_line, t, record_uid)

        # Batch mount all widgets at once for better performance
        if widgets_to_mount:
            container.mount(*widgets_to_mount, before=detail_widget)

    def _render_json_lines(self, display_obj, unmasked_obj, mount_line, t, record_uid, indent=0):
        """Recursively render JSON object as clickable lines with syntax highlighting"""
        indent_str = "  " * indent
        key_color = "#88ccff"      # Light blue for keys
        string_color = t['primary']  # Theme color for strings
        number_color = "#ffcc66"   # Orange for numbers
        bool_color = "#ff99cc"     # Pink for booleans
        null_color = "#999999"     # Gray for null
        bracket_color = t['text_dim']

        if isinstance(display_obj, dict):
            # Make the root opening brace copyable with the entire object
            mount_line(f"{indent_str}[{bracket_color}]{{[/{bracket_color}]",
                       copy_value=json.dumps(unmasked_obj, indent=2))
            items = list(display_obj.items())
            for i, (key, value) in enumerate(items):
                comma = "," if i < len(items) - 1 else ""
                # Get unmasked value for copying
                unmasked_value = unmasked_obj.get(key, value) if isinstance(unmasked_obj, dict) else value

                if isinstance(value, str):
                    # Escape brackets for Rich markup
                    display_val = value.replace("[", "\\[")
                    is_password = (value == "************")
                    copy_val = unmasked_value if isinstance(unmasked_value, str) else str(unmasked_value)
                    mount_line(
                        f"{indent_str}  [{key_color}]\"{key}\"[/{key_color}]: [{string_color}]\"{display_val}\"[/{string_color}]{comma}",
                        copy_value=copy_val,
                        is_password=is_password
                    )
                elif isinstance(value, bool):
                    bool_str = "true" if value else "false"
                    mount_line(
                        f"{indent_str}  [{key_color}]\"{key}\"[/{key_color}]: [{bool_color}]{bool_str}[/{bool_color}]{comma}",
                        copy_value=str(value)
                    )
                elif isinstance(value, (int, float)):
                    mount_line(
                        f"{indent_str}  [{key_color}]\"{key}\"[/{key_color}]: [{number_color}]{value}[/{number_color}]{comma}",
                        copy_value=str(value)
                    )
                elif value is None:
                    mount_line(
                        f"{indent_str}  [{key_color}]\"{key}\"[/{key_color}]: [{null_color}]null[/{null_color}]{comma}"
                    )
                elif isinstance(value, list):
                    unmasked_list = unmasked_value if isinstance(unmasked_value, list) else value
                    # Make the opening line copyable with the entire array
                    mount_line(f"{indent_str}  [{key_color}]\"{key}\"[/{key_color}]: [{bracket_color}]\\[[/{bracket_color}]",
                               copy_value=json.dumps(unmasked_list, indent=2))
                    self._render_json_list_items(value, unmasked_list, mount_line, t, record_uid, indent + 2)
                    mount_line(f"{indent_str}  [{bracket_color}]][/{bracket_color}]{comma}")
                elif isinstance(value, dict):
                    unmasked_dict = unmasked_value if isinstance(unmasked_value, dict) else value
                    # Make the opening line copyable with the entire object
                    mount_line(f"{indent_str}  [{key_color}]\"{key}\"[/{key_color}]: [{bracket_color}]{{[/{bracket_color}]",
                               copy_value=json.dumps(unmasked_dict, indent=2))
                    self._render_json_dict_items(value, unmasked_dict, mount_line, t, record_uid, indent + 2)
                    mount_line(f"{indent_str}  [{bracket_color}]}}[/{bracket_color}]{comma}")
            mount_line(f"{indent_str}[{bracket_color}]}}[/{bracket_color}]")
        elif isinstance(display_obj, list):
            # Make the root opening bracket copyable with the entire array
            mount_line(f"{indent_str}[{bracket_color}]\\[[/{bracket_color}]",
                       copy_value=json.dumps(unmasked_obj, indent=2))
            self._render_json_list_items(display_obj, unmasked_obj, mount_line, t, record_uid, indent + 1)
            mount_line(f"{indent_str}[{bracket_color}]][/{bracket_color}]")

    def _render_json_dict_items(self, display_dict, unmasked_dict, mount_line, t, record_uid, indent):
        """Render dict items for nested objects"""
        indent_str = "  " * indent
        key_color = "#88ccff"
        string_color = t['primary']
        number_color = "#ffcc66"
        bool_color = "#ff99cc"
        null_color = "#999999"
        bracket_color = t['text_dim']

        items = list(display_dict.items())
        for i, (key, value) in enumerate(items):
            comma = "," if i < len(items) - 1 else ""
            unmasked_value = unmasked_dict.get(key, value) if isinstance(unmasked_dict, dict) else value

            if isinstance(value, str):
                display_val = rich_escape(value)
                is_password = (value == "************")
                copy_val = unmasked_value if isinstance(unmasked_value, str) else str(unmasked_value)
                mount_line(
                    f"{indent_str}[{key_color}]\"{rich_escape(str(key))}\"[/{key_color}]: [{string_color}]\"{display_val}\"[/{string_color}]{comma}",
                    copy_value=copy_val,
                    is_password=is_password
                )
            elif isinstance(value, bool):
                bool_str = "true" if value else "false"
                mount_line(
                    f"{indent_str}[{key_color}]\"{rich_escape(str(key))}\"[/{key_color}]: [{bool_color}]{bool_str}[/{bool_color}]{comma}",
                    copy_value=str(value)
                )
            elif isinstance(value, (int, float)):
                mount_line(
                    f"{indent_str}[{key_color}]\"{rich_escape(str(key))}\"[/{key_color}]: [{number_color}]{value}[/{number_color}]{comma}",
                    copy_value=str(value)
                )
            elif value is None:
                mount_line(f"{indent_str}[{key_color}]\"{rich_escape(str(key))}\"[/{key_color}]: [{null_color}]null[/{null_color}]{comma}")
            elif isinstance(value, list):
                unmasked_list = unmasked_value if isinstance(unmasked_value, list) else value
                # Make the opening line copyable with the entire array
                mount_line(f"{indent_str}[{key_color}]\"{rich_escape(str(key))}\"[/{key_color}]: [{bracket_color}]\\[[/{bracket_color}]",
                           copy_value=json.dumps(unmasked_list, indent=2))
                self._render_json_list_items(value, unmasked_list, mount_line, t, record_uid, indent + 1)
                mount_line(f"{indent_str}[{bracket_color}]][/{bracket_color}]{comma}")
            elif isinstance(value, dict):
                unmasked_inner = unmasked_value if isinstance(unmasked_value, dict) else value
                # Make the opening line copyable with the entire object
                mount_line(f"{indent_str}[{key_color}]\"{rich_escape(str(key))}\"[/{key_color}]: [{bracket_color}]{{[/{bracket_color}]",
                           copy_value=json.dumps(unmasked_inner, indent=2))
                self._render_json_dict_items(value, unmasked_inner, mount_line, t, record_uid, indent + 1)
                mount_line(f"{indent_str}[{bracket_color}]}}[/{bracket_color}]{comma}")

    def _render_json_list_items(self, display_list, unmasked_list, mount_line, t, record_uid, indent):
        """Render list items for arrays"""
        indent_str = "  " * indent
        string_color = t['primary']
        number_color = "#ffcc66"
        bool_color = "#ff99cc"
        null_color = "#999999"
        bracket_color = t['text_dim']

        for i, value in enumerate(display_list):
            comma = "," if i < len(display_list) - 1 else ""
            unmasked_value = unmasked_list[i] if isinstance(unmasked_list, list) and i < len(unmasked_list) else value

            if isinstance(value, str):
                display_val = rich_escape(value)
                is_password = (value == "************")
                copy_val = unmasked_value if isinstance(unmasked_value, str) else str(unmasked_value)
                mount_line(
                    f"{indent_str}[{string_color}]\"{display_val}\"[/{string_color}]{comma}",
                    copy_value=copy_val,
                    is_password=is_password
                )
            elif isinstance(value, bool):
                bool_str = "true" if value else "false"
                mount_line(f"{indent_str}[{bool_color}]{bool_str}[/{bool_color}]{comma}", copy_value=str(value))
            elif isinstance(value, (int, float)):
                mount_line(f"{indent_str}[{number_color}]{value}[/{number_color}]{comma}", copy_value=str(value))
            elif value is None:
                mount_line(f"{indent_str}[{null_color}]null[/{null_color}]{comma}")
            elif isinstance(value, dict):
                unmasked_inner = unmasked_value if isinstance(unmasked_value, dict) else value
                # Make the opening brace copyable with the entire object
                mount_line(f"{indent_str}[{bracket_color}]{{[/{bracket_color}]",
                           copy_value=json.dumps(unmasked_inner, indent=2))
                self._render_json_dict_items(value, unmasked_inner, mount_line, t, record_uid, indent + 1)
                mount_line(f"{indent_str}[{bracket_color}]}}[/{bracket_color}]{comma}")
            elif isinstance(value, list):
                unmasked_inner = unmasked_value if isinstance(unmasked_value, list) else value
                # Make the opening bracket copyable with the entire array
                mount_line(f"{indent_str}[{bracket_color}]\\[[/{bracket_color}]",
                           copy_value=json.dumps(unmasked_inner, indent=2))
                self._render_json_list_items(value, unmasked_inner, mount_line, t, record_uid, indent + 1)
                mount_line(f"{indent_str}[{bracket_color}]][/{bracket_color}]{comma}")

    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field name indicates it contains sensitive data"""
        if not field_name:
            return False
        name_lower = field_name.lower()
        return any(term in name_lower for term in ('secret', 'password', 'passphrase'))

    def _mask_passwords_in_json(self, obj, parent_key: str = None):
        """Recursively mask password/secret/passphrase values in JSON object for display"""
        if self.unmask_secrets:
            return obj  # Don't mask if unmask mode is enabled

        if isinstance(obj, dict):
            # Check if this dict is a password field (has type: "password")
            if obj.get('type') == 'password':
                masked = dict(obj)
                if 'value' in masked and isinstance(masked['value'], list) and len(masked['value']) > 0:
                    masked['value'] = ['************']
                return masked
            # Check if this dict has a label that indicates sensitive data
            label = obj.get('label', '')
            if self._is_sensitive_field(label):
                masked = dict(obj)
                if 'value' in masked and isinstance(masked['value'], list) and len(masked['value']) > 0:
                    masked['value'] = ['************']
                return masked
            # Otherwise recurse into dict values
            result = {}
            for key, value in obj.items():
                # Check if key itself indicates sensitive data
                if self._is_sensitive_field(key) and isinstance(value, str) and value:
                    result[key] = '************'
                else:
                    result[key] = self._mask_passwords_in_json(value, parent_key=key)
            return result
        elif isinstance(obj, list):
            return [self._mask_passwords_in_json(item, parent_key=parent_key) for item in obj]
        else:
            return obj

    def _display_folder_with_clickable_fields(self, folder_uid: str):
        """Display folder details with clickable fields for copy-on-click"""
        # Stop TOTP timer when viewing folders
        self._stop_totp_timer()

        # Check if JSON view is requested
        if self.view_mode == 'json':
            self._display_folder_json(folder_uid)
            return

        t = self.theme_colors
        detail_scroll = self.query_one("#record_detail", VerticalScroll)
        detail_widget = self.query_one("#detail_content", Static)

        # Clear previous clickable fields
        self._clear_clickable_fields()

        # Get folder from cache for type info
        folder = self.params.folder_cache.get(folder_uid)
        folder_type = ""
        if folder:
            folder_type = folder.get_folder_type() if hasattr(folder, 'get_folder_type') else str(folder.type)

        # Get folder output from get command
        try:
            stdout_buffer = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_buffer
            get_cmd = RecordGetUidCommand()
            get_cmd.execute(self.params, uid=folder_uid, format='detail')
            sys.stdout = old_stdout
            output = stdout_buffer.getvalue()
            output = strip_ansi_codes(output)
        except Exception as e:
            sys.stdout = old_stdout
            logging.error(f"Error getting folder output: {e}")
            output = ""

        # Hide the static placeholder
        detail_widget.update("")

        # Helper to mount clickable lines
        def mount_line(content: str, copy_value: str = None):
            line = ClickableDetailLine(content, copy_value)
            detail_scroll.mount(line, before=detail_widget)

        # Determine folder header with icon and name
        folder_name = folder.name if folder else "Folder"
        if folder:
            ft = folder.get_folder_type() if hasattr(folder, 'get_folder_type') else str(folder.type)
            if 'shared' in ft.lower():
                folder_icon = "👥"
            else:
                folder_icon = "📁"
        else:
            folder_icon = "📁"

        # Type header with icon and folder name
        mount_line(f"[bold {t['secondary']}]{folder_icon} {rich_escape(str(folder_name))}[/bold {t['secondary']}]", None)
        mount_line("", None)

        if not output or output.strip() == '':
            # Fallback to basic folder info
            if folder:
                mount_line(f"[{t['text_dim']}]Folder:[/{t['text_dim']}] [bold {t['primary']}]{rich_escape(str(folder.name))}[/bold {t['primary']}]", folder.name)
                mount_line(f"[{t['text_dim']}]UID:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(folder_uid))}[/{t['primary']}]", folder_uid)
            return

        # Parse the output and format with clickable lines
        current_section = None
        section_headers = {'Record Permissions', 'User Permissions', 'Team Permissions', 'Share Administrators'}
        share_admins_count = 0

        # First pass: count share admins
        in_share_admins = False
        for line in output.split('\n'):
            stripped = line.strip()
            if ':' in stripped:
                key = stripped.split(':', 1)[0].strip()
                if key == 'Share Administrators':
                    in_share_admins = True
                elif key in section_headers and key != 'Share Administrators':
                    in_share_admins = False
                elif in_share_admins and key == 'User':
                    share_admins_count += 1

        # Second pass: build clickable lines
        in_share_admins = False
        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            if ':' in stripped:
                parts = stripped.split(':', 1)
                key = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else ''

                # UID fields
                if key in ['Shared Folder UID', 'Folder UID', 'Team UID']:
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                # Folder Type
                elif key == 'Folder Type':
                    display_type = value if value else folder_type
                    mount_line(f"[{t['text_dim']}]Type:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(display_type))}[/{t['primary']}]", display_type)
                # Name - show with "Folder:" label for consistency
                elif key == 'Name':
                    mount_line(f"[{t['text_dim']}]Folder:[/{t['text_dim']}] [bold {t['primary']}]{rich_escape(str(value))}[/bold {t['primary']}]", value)
                # Section headers
                elif key in section_headers:
                    current_section = key
                    in_share_admins = (key == 'Share Administrators')
                    mount_line("", None)
                    if key == 'Share Administrators' and share_admins_count > 0:
                        mount_line(f"[bold {t['primary_bright']}]{key}:[/bold {t['primary_bright']}] [{t['text_dim']}]({share_admins_count} users)[/{t['text_dim']}]", None)
                    else:
                        mount_line(f"[bold {t['primary_bright']}]{key}:[/bold {t['primary_bright']}]", None)
                # Record UID in Record Permissions - show title
                elif key == 'Record UID' and current_section == 'Record Permissions':
                    if value in self.records:
                        record_title = self.records[value].get('title', 'Untitled')
                        mount_line(f"  [{t['text_dim']}]Record:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(record_title))}[/{t['primary']}]", record_title)
                        mount_line(f"    [{t['text_dim']}]UID:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                    else:
                        mount_line(f"  [{t['text_dim']}]Record UID:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                # Boolean values
                elif value.lower() in ['true', 'false']:
                    color = t['primary'] if value.lower() == 'true' else t['primary_dim']
                    indent = "  " if current_section else ""
                    mount_line(f"{indent}[{t['secondary']}]{rich_escape(str(key))}:[/{t['secondary']}] [{color}]{rich_escape(str(value))}[/{color}]", value)
                # Regular key-value pairs
                elif value:
                    indent = "  " if current_section else ""
                    # Skip Share Admins details (collapsed)
                    if in_share_admins and key in ['User', 'Email']:
                        continue
                    mount_line(f"{indent}[{t['secondary']}]{rich_escape(str(key))}:[/{t['secondary']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]", value)
                elif key:
                    indent = "  " if current_section else ""
                    if in_share_admins:
                        continue
                    mount_line(f"{indent}[{t['primary_dim']}]{rich_escape(str(key))}[/{t['primary_dim']}]", key)
            else:
                if stripped:
                    indent = "  " if current_section else ""
                    if in_share_admins:
                        continue
                    mount_line(f"{indent}[{t['primary']}]{rich_escape(str(stripped))}[/{t['primary']}]", stripped)

    def _display_folder_json(self, folder_uid: str):
        """Display folder/shared folder as JSON with clickable values"""
        t = self.theme_colors
        container = self.query_one("#record_detail", VerticalScroll)
        detail_widget = self.query_one("#detail_content", Static)

        # Clear previous clickable fields
        self._clear_clickable_fields()

        # Get JSON output from get command
        try:
            stdout_buffer = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_buffer
            get_cmd = RecordGetUidCommand()
            get_cmd.execute(self.params, uid=folder_uid, format='json')
            sys.stdout = old_stdout
            output = stdout_buffer.getvalue()
            output = strip_ansi_codes(output)
        except Exception as e:
            sys.stdout = old_stdout
            logging.error(f"Error getting folder JSON output: {e}")
            detail_widget.update(f"[red]Error getting folder JSON: {str(e)}[/red]")
            return

        try:
            json_obj = json.loads(output)
        except:
            # If JSON parsing fails, show raw output
            detail_widget.update(f"[{t['primary']}]JSON View:\n\n{rich_escape(str(output))}[/{t['primary']}]")
            return

        # Clear detail widget content
        detail_widget.update("")

        # Helper to mount clickable JSON lines
        def mount_json_line(content: str, copy_value: str = None, indent: int = 0):
            line = ClickableDetailLine(content, copy_value)
            container.mount(line, before=detail_widget)

        # Determine folder header with icon and name
        folder = self.params.folder_cache.get(folder_uid)
        folder_name = folder.name if folder else "Folder"
        if folder:
            ft = folder.get_folder_type() if hasattr(folder, 'get_folder_type') else str(folder.type)
            if 'shared' in ft.lower():
                folder_icon = "👥"
            else:
                folder_icon = "📁"
        else:
            folder_icon = "📁"

        # Build formatted JSON output with clickable values
        mount_json_line(f"[bold {t['secondary']}]{folder_icon} {rich_escape(str(folder_name))}[/bold {t['secondary']}] [{t['text_dim']}](JSON)[/{t['text_dim']}]", None)
        mount_json_line("", None)

        def render_json(obj, indent=0):
            """Recursively render JSON with clickable string values"""
            prefix = "  " * indent
            if isinstance(obj, dict):
                # Make the opening brace copyable with the entire object
                mount_json_line(f"{prefix}{{", json.dumps(obj, indent=2))
                items = list(obj.items())
                for i, (key, value) in enumerate(items):
                    comma = "," if i < len(items) - 1 else ""
                    if isinstance(value, str):
                        escaped_value = rich_escape(value)
                        mount_json_line(
                            f"{prefix}  [{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [{t['primary']}]\"{escaped_value}\"[/{t['primary']}]{comma}",
                            value
                        )
                    elif isinstance(value, bool):
                        bool_str = "true" if value else "false"
                        mount_json_line(
                            f"{prefix}  [{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [{t['primary_bright']}]{bool_str}[/{t['primary_bright']}]{comma}",
                            str(value)
                        )
                    elif isinstance(value, (int, float)):
                        mount_json_line(
                            f"{prefix}  [{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [{t['primary_bright']}]{value}[/{t['primary_bright']}]{comma}",
                            str(value)
                        )
                    elif value is None:
                        mount_json_line(
                            f"{prefix}  [{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [{t['text_dim']}]null[/{t['text_dim']}]{comma}",
                            None
                        )
                    elif isinstance(value, dict):
                        # Make the key line copyable with the entire object
                        mount_json_line(f"{prefix}  [{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: {{",
                                        json.dumps(value, indent=2))
                        render_json_items(value, indent + 2)
                        mount_json_line(f"{prefix}  }}{comma}", None)
                    elif isinstance(value, list):
                        # Make the key line copyable with the entire array
                        mount_json_line(f"{prefix}  [{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [",
                                        json.dumps(value, indent=2))
                        render_json_list_items(value, indent + 2)
                        mount_json_line(f"{prefix}  ]{comma}", None)
                mount_json_line(f"{prefix}}}", None)
            elif isinstance(obj, list):
                mount_json_line(f"{prefix}[", json.dumps(obj, indent=2))
                render_json_list_items(obj, indent + 1)
                mount_json_line(f"{prefix}]", None)

        def render_json_items(obj, indent):
            """Render dict items without outer braces"""
            prefix = "  " * indent
            items = list(obj.items())
            for i, (key, value) in enumerate(items):
                comma = "," if i < len(items) - 1 else ""
                if isinstance(value, str):
                    escaped_value = rich_escape(value)
                    mount_json_line(
                        f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [{t['primary']}]\"{escaped_value}\"[/{t['primary']}]{comma}",
                        value
                    )
                elif isinstance(value, bool):
                    bool_str = "true" if value else "false"
                    mount_json_line(
                        f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [{t['primary_bright']}]{bool_str}[/{t['primary_bright']}]{comma}",
                        str(value)
                    )
                elif isinstance(value, (int, float)):
                    mount_json_line(
                        f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [{t['primary_bright']}]{value}[/{t['primary_bright']}]{comma}",
                        str(value)
                    )
                elif value is None:
                    mount_json_line(
                        f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [{t['text_dim']}]null[/{t['text_dim']}]{comma}",
                        None
                    )
                elif isinstance(value, dict):
                    mount_json_line(f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: {{",
                                    json.dumps(value, indent=2))
                    render_json_items(value, indent + 1)
                    mount_json_line(f"{prefix}}}{comma}", None)
                elif isinstance(value, list):
                    mount_json_line(f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [",
                                    json.dumps(value, indent=2))
                    render_json_list_items(value, indent + 1)
                    mount_json_line(f"{prefix}]{comma}", None)

        def render_json_list_items(obj, indent):
            """Render list items without outer brackets"""
            prefix = "  " * indent
            for i, item in enumerate(obj):
                comma = "," if i < len(obj) - 1 else ""
                if isinstance(item, str):
                    escaped_item = rich_escape(item)
                    mount_json_line(f"{prefix}[{t['primary']}]\"{escaped_item}\"[/{t['primary']}]{comma}", item)
                elif isinstance(item, dict):
                    mount_json_line(f"{prefix}{{", json.dumps(item, indent=2))
                    render_json_items(item, indent + 1)
                    mount_json_line(f"{prefix}}}{comma}", None)
                elif isinstance(item, list):
                    mount_json_line(f"{prefix}[", json.dumps(item, indent=2))
                    render_json_list_items(item, indent + 1)
                    mount_json_line(f"{prefix}]{comma}", None)
                else:
                    mount_json_line(f"{prefix}[{t['primary_bright']}]{item}[/{t['primary_bright']}]{comma}", str(item))

        render_json(json_obj)

        # Add copy full JSON option
        full_json = json.dumps(json_obj, indent=2)
        mount_json_line(f"\n[{t['text_dim']}]Click to copy full JSON:[/{t['text_dim']}]", full_json)

    def _display_secrets_manager_app(self, app_uid: str):
        """Display Secrets Manager application details"""
        # Clear any previous content
        self._clear_clickable_fields()
        
        detail_widget = self.query_one("#detail_content", Static)
        t = self.theme_colors
        
        try:
            from ..proto import APIRequest_pb2, enterprise_pb2
            from .. import api, utils
            import json
            
            record = self.records[app_uid]
            app_title = record.get('title', 'Untitled')
            
            # Fetch app info from API
            app_data = {
                "app_name": app_title,
                "app_uid": app_uid,
                "client_devices": [],
                "shares": []
            }
            
            try:
                rq = APIRequest_pb2.GetAppInfoRequest()
                rq.appRecordUid.append(utils.base64_url_decode(app_uid))
                rs = api.communicate_rest(self.params, rq, 'vault/get_app_info', rs_type=APIRequest_pb2.GetAppInfoResponse)
                
                if rs.appInfo:
                    app_info = rs.appInfo[0]
                    
                    # Collect client devices
                    client_devices = [x for x in app_info.clients if x.appClientType == enterprise_pb2.GENERAL]
                    for client in client_devices:
                        app_data["client_devices"].append({
                            "device_name": client.id
                        })
                    
                    # Collect application access (shares)
                    for share in app_info.shares:
                        uid_str = utils.base64_url_encode(share.secretUid)
                        share_type = APIRequest_pb2.ApplicationShareType.Name(share.shareType)
                        
                        # Get title from cache
                        title = "Unknown"
                        if share_type == 'SHARE_TYPE_RECORD':
                            if uid_str in self.params.record_cache:
                                rec = self.params.record_cache[uid_str]
                                if 'data_unencrypted' in rec:
                                    data = json.loads(rec['data_unencrypted'])
                                    title = data.get('title', 'Untitled')
                            share_type_display = "RECORD"
                        elif share_type == 'SHARE_TYPE_FOLDER':
                            if hasattr(self.params, 'folder_cache'):
                                folder = self.params.folder_cache.get(uid_str)
                                if folder:
                                    title = folder.name
                            share_type_display = "FOLDER"
                        else:
                            share_type_display = share_type
                        
                        app_data["shares"].append({
                            "share_type": share_type,
                            "uid": uid_str,
                            "editable": share.editable,
                            "title": title,
                            "type": share_type_display
                        })
                    
            except (KeyError, AttributeError, json.JSONDecodeError, ValueError) as e:
                logging.debug(f"Error fetching app info: {e}", exc_info=True)
            
            # Display based on view mode
            if self.view_mode == 'json':
                # JSON view with syntax highlighting
                # Clear previous clickable fields
                self._clear_clickable_fields()
                detail_widget.update("")
                
                # Collect widgets for batch mounting
                container = self.query_one("#record_detail", VerticalScroll)
                widgets_to_mount = []
                
                def mount_line(content: str, copy_value: str = None, is_password: bool = False):
                    """Collect a clickable line for batch mounting"""
                    line = ClickableDetailLine(
                        content,
                        copy_value=copy_value,
                        record_uid=app_uid if is_password else None,
                        is_password=is_password
                    )
                    widgets_to_mount.append(line)
                    self.clickable_fields.append(line)
                
                # Render JSON header
                mount_line(f"[bold {t['primary']}]JSON View:[/bold {t['primary']}]")
                mount_line("")
                
                # Render JSON with syntax highlighting
                self._render_json_lines(app_data, app_data, mount_line, t, app_uid)
                
                # Batch mount all widgets
                if widgets_to_mount:
                    container.mount(*widgets_to_mount, before=detail_widget)
            else:
                # Detail view
                lines = []
                lines.append(f"[bold {t['primary']}]Secrets Manager Application[/bold {t['primary']}]")
                lines.append(f"[{t['text_dim']}]App Name:[/{t['text_dim']}] [{t['primary']}]{app_title}[/{t['primary']}]")
                lines.append(f"[{t['text_dim']}]App UID:[/{t['text_dim']}] [{t['primary']}]{app_uid}[/{t['primary']}]")
                lines.append("")
                
                # Show client devices
                if app_data["client_devices"]:
                    lines.append(f"[bold {t['secondary']}]Client Devices ({len(app_data['client_devices'])}):[/bold {t['secondary']}]")
                    for idx, device in enumerate(app_data["client_devices"][:self.DEVICE_DISPLAY_LIMIT], 1):
                        lines.append(f"  [{t['text_dim']}]{idx}.[/{t['text_dim']}] [{t['primary']}]{device['device_name']}[/{t['primary']}]")
                    if len(app_data["client_devices"]) > self.DEVICE_DISPLAY_LIMIT:
                        lines.append(f"  [{t['text_dim']}]... and {len(app_data['client_devices']) - self.DEVICE_DISPLAY_LIMIT} more[/{t['text_dim']}]")
                    lines.append("")
                else:
                    lines.append(f"[{t['text_dim']}]No client devices registered for this Application[/{t['text_dim']}]")
                    lines.append("")
                
                # Show application access
                if app_data["shares"]:
                    lines.append(f"[bold {t['secondary']}]Application Access:[/bold {t['secondary']}]")
                    lines.append("")
                    for idx, share in enumerate(app_data["shares"][:self.SHARE_DISPLAY_LIMIT], 1):
                        lines.append(f"  [{t['text_dim']}]{share['type']}:[/{t['text_dim']}] [{t['primary']}]{share['title']}[/{t['primary']}]")
                        lines.append(f"    [{t['text_dim']}]UID:[/{t['text_dim']}] [{t['text']}]{share['uid']}[/{t['text']}]")
                        permissions = "Editable" if share['editable'] else "Read-Only"
                        lines.append(f"    [{t['text_dim']}]Permissions:[/{t['text_dim']}] [{t['primary_dim']}]{permissions}[/{t['primary_dim']}]")
                        lines.append("")
                    if len(app_data["shares"]) > self.SHARE_DISPLAY_LIMIT:
                        lines.append(f"  [{t['text_dim']}]... and {len(app_data['shares']) - self.SHARE_DISPLAY_LIMIT} more shares[/{t['text_dim']}]")
                        lines.append("")
                else:
                    lines.append(f"[bold {t['secondary']}]Application Access:[/bold {t['secondary']}]")
                    lines.append(f"[{t['text_dim']}]No shared folders or records[/{t['text_dim']}]")
                    lines.append("")
                
                detail_widget.update("\n".join(lines))
            
            self._update_shortcuts_bar(record_selected=True)
            
        except Exception as e:
            logging.error(f"Error displaying Secrets Manager app: {e}", exc_info=True)
            detail_widget.update(f"[red]Error displaying app:[/red]\n{str(e)}")

    def _display_record_detail(self, record_uid: str):
        """Display record details in the right panel using Commander's get command"""
        detail_widget = self.query_one("#detail_content", Static)
        t = self.theme_colors  # Get theme colors

        try:
            if record_uid not in self.records:
                self._clear_clickable_fields()
                detail_widget.update("[red]Record not found[/red]")
                return

            # Use clickable fields for both views
            if self.view_mode == 'json':
                self._display_json_with_clickable_fields(record_uid)
            else:
                self._display_record_with_clickable_fields(record_uid)

            # Update shortcuts bar to show record-specific shortcuts
            self._update_shortcuts_bar(record_selected=True)

        except Exception as e:
            logging.error(f"Error displaying record detail: {e}", exc_info=True)
            self._clear_clickable_fields()
            # Fallback to simple static display
            try:
                content = self._format_record_for_tui(record_uid)
                detail_widget.update(content)
            except:
                error_msg = str(e).replace('[', '\\[').replace(']', '\\]')
                detail_widget.update(f"[red]Error displaying record:[/red]\n{error_msg}\n\n[dim]Press 't' to toggle view mode[/dim]")

    def _update_status(self, message: str):
        """Update the status bar"""
        status_bar = self.query_one("#status_bar", Static)
        status_bar.update(f"⚡ {message}")

    def _update_shortcuts_bar(self, record_selected: bool = False, folder_selected: bool = False, clear: bool = False):
        """Update the shortcuts bar at bottom of detail panel"""
        try:
            shortcuts_bar = self.query_one("#shortcuts_bar", Static)
            t = self.theme_colors

            if clear:
                # Clear the shortcuts bar (for info displays like device/user info)
                shortcuts_bar.update("")
            elif record_selected:
                mode = "JSON" if self.view_mode == 'json' else "Detail"
                mask_label = "Mask" if self.unmask_secrets else "Unmask"
                shortcuts_bar.update(
                    f"[{t['secondary']}]Mode: {mode}[/{t['secondary']}]  "
                    f"[{t['text_dim']}]t[/{t['text_dim']}]=Toggle  "
                    f"[{t['text_dim']}]p[/{t['text_dim']}]=Password  "
                    f"[{t['text_dim']}]u[/{t['text_dim']}]=Username  "
                    f"[{t['text_dim']}]c[/{t['text_dim']}]=Copy All  "
                    f"[{t['text_dim']}]m[/{t['text_dim']}]={mask_label}"
                )
            elif folder_selected:
                mode = "JSON" if self.view_mode == 'json' else "Detail"
                mask_label = "Mask" if self.unmask_secrets else "Unmask"
                shortcuts_bar.update(
                    f"[{t['secondary']}]Mode: {mode}[/{t['secondary']}]  "
                    f"[{t['text_dim']}]t[/{t['text_dim']}]=Toggle  "
                    f"[{t['text_dim']}]c[/{t['text_dim']}]=Copy All  "
                    f"[{t['text_dim']}]m[/{t['text_dim']}]={mask_label}"
                )
            else:
                # Root or other - hide navigation help
                shortcuts_bar.update("")
        except Exception as e:
            logging.debug(f"Error updating shortcuts bar: {e}")

    @on(Click, "#search_bar, #search_display")
    def on_search_bar_click(self, event: Click) -> None:
        """Activate search mode when search bar is clicked"""
        _debug_log(f"CLICK: search_bar x={event.x} y={event.y} button={event.button} "
                   f"shift={event.shift} ctrl={event.ctrl} meta={event.meta}")
        tree = self.query_one("#folder_tree", Tree)

        # Deactivate shell input if it was active
        if self.shell_input_active:
            self.shell_input_active = False
            try:
                shell_input = self.query_one("#shell_input_area", ShellInputTextArea)
                shell_input.blur()  # Remove focus from shell input
            except Exception:
                pass

        self.search_input_active = True
        tree.add_class("search-input-active")
        search_bar = self.query_one("#search_bar")
        search_bar.add_class("search-active")
        tree.focus()  # Focus tree so keyboard events go to search handler
        self._update_search_display(perform_search=False)  # Don't change tree when entering search
        self._update_status("Type to search | Tab to navigate | Ctrl+U to clear")
        event.stop()
        _debug_log(f"CLICK: search_bar -> stopped")

    @on(Click, "#user_info")
    def on_user_info_click(self, event: Click) -> None:
        """Show whoami info when user info is clicked"""
        _debug_log(f"CLICK: user_info x={event.x} y={event.y}")
        self._display_whoami_info()
        event.stop()
        _debug_log(f"CLICK: user_info -> stopped")

    @on(Click, "#device_status_info")
    def on_device_status_click(self, event: Click) -> None:
        """Show device info when Stay Logged In / Logout section is clicked"""
        _debug_log(f"CLICK: device_status_info x={event.x} y={event.y}")
        self._display_device_info()
        event.stop()
        _debug_log(f"CLICK: device_status_info -> stopped")

    @on(Click, "#shell_pane, #shell_input_area, #shell_header")
    def on_shell_pane_click(self, event: Click) -> None:
        """Handle clicks in shell pane (not output area) - activate shell input."""
        _debug_log(f"CLICK: shell_pane x={event.x} y={event.y} button={event.button}")

        # Normal click - activate and focus shell input
        if self.shell_pane_visible:
            self.shell_input_active = True
            try:
                shell_input = self.query_one("#shell_input_area", ShellInputTextArea)
                shell_input.focus()
            except Exception:
                pass
        event.stop()
        _debug_log(f"CLICK: shell_pane -> stopped")

    def on_paste(self, event: Paste) -> None:
        """Handle paste events (Cmd+V on Mac, Ctrl+V on Windows/Linux)"""
        _debug_log(f"PASTE: text={event.text!r} shell_input_active={self.shell_input_active}")
        # Shell input TextArea handles its own paste - don't interfere
        if self.search_input_active and event.text:
            # Append pasted text to search input (strip newlines)
            pasted_text = event.text.replace('\n', ' ').replace('\r', '')
            self.search_input_text += pasted_text
            self._update_search_display()
            event.stop()

    @on(Tree.NodeSelected)
    def on_tree_node_selected(self, event: Tree.NodeSelected):
        """Handle tree node selection (folder or record)"""
        # Deactivate search input mode when selecting a node (clicking or navigating)
        if self.search_input_active:
            self.search_input_active = False
            tree = self.query_one("#folder_tree", Tree)
            tree.remove_class("search-input-active")
            search_bar = self.query_one("#search_bar")
            search_bar.remove_class("search-active")
            # Update search display to remove cursor
            search_display = self.query_one("#search_display", Static)
            if self.search_input_text:
                search_display.update(rich_escape(self.search_input_text))
            else:
                search_display.update("[dim]Search... (Tab or /)[/dim]")

        node_data = event.node.data
        if not node_data:
            return

        node_type = node_data.get('type')
        node_uid = node_data.get('uid')

        if node_type == 'record':
            # Record selected - show details
            self.selected_record = node_uid
            self.selected_folder = None  # Clear folder selection
            
            # Verify record exists before displaying
            if node_uid in self.records:
                # Check if this is an app record (Secrets Manager)
                if node_uid in self.app_record_uids:
                    # Display Secrets Manager app info
                    self._display_secrets_manager_app(node_uid)
                    self._update_status(f"App record selected: {self.records[node_uid].get('title', 'Untitled')}")
                else:
                    self._display_record_detail(node_uid)
                    self._update_status(f"Record selected: {self.records[node_uid].get('title', 'Untitled')}")
            else:
                # Record not found - show error
                detail_widget = self.query_one("#detail_content", Static)
                detail_widget.update(f"[red]Error: Record not found[/red]\n\nUID: {node_uid}\n\nThis record may have been deleted or you may not have access to it.")
                self._update_status(f"Record not found: {node_uid}")
        elif node_type == 'folder':
            # Folder selected - show folder info with clickable fields
            self.selected_record = None  # Clear record selection
            self.selected_folder = node_uid  # Set folder selection
            folder = self.params.folder_cache.get(node_uid)
            if folder:
                # Use clickable fields for folder display
                self._display_folder_with_clickable_fields(node_uid)
                self._update_status(f"Folder: {folder.name}")
            else:
                self._clear_clickable_fields()
                detail_widget = self.query_one("#detail_content", Static)
                detail_widget.update("[red]Folder not found[/red]")
            self._update_shortcuts_bar(folder_selected=True)
        elif node_type == 'virtual_folder':
            # Virtual folder selected (e.g., Secrets Manager Apps)
            self.selected_record = None
            self.selected_folder = None
            self._clear_clickable_fields()
            detail_widget = self.query_one("#detail_content", Static)
            t = self.theme_colors
            if node_uid == '__secrets_manager_apps__':
                # Count app records
                app_count = len(self.app_record_uids)
                detail_widget.update(
                    f"[bold {t['virtual_folder']}]★ Secrets Manager Apps[/bold {t['virtual_folder']}]\n\n"
                    f"[{t['primary_dim']}]Contains {app_count} Secrets Manager application {'record' if app_count == 1 else 'records'}.\n"
                    f"Select a record to view details.[/{t['primary_dim']}]"
                )
                self._update_status("Secrets Manager Apps")
            else:
                detail_widget.update(f"[{t['primary_dim']}]Virtual folder[/{t['primary_dim']}]")
                self._update_status("Virtual folder")
            self._update_shortcuts_bar(folder_selected=True)
        elif node_type == 'root':
            # Root selected - show welcome/help content
            self.selected_record = None  # Clear record selection
            self.selected_folder = None  # Clear folder selection
            self._clear_clickable_fields()
            detail_widget = self.query_one("#detail_content", Static)
            detail_widget.update(self._get_welcome_screen_content())
            self._update_status("My Vault")
            self._update_shortcuts_bar(clear=True)  # Help content is already in the panel

    def _update_search_display(self, perform_search=True):
        """Update the search display and results with blinking cursor.

        Args:
            perform_search: If True, perform search when text changes. Set to False
                           when just entering search mode to avoid tree changes.
        """
        try:
            search_display = self.query_one("#search_display", Static)
            results_label = self.query_one("#search_results_label", Static)

            # Force visibility
            if search_display.styles.display == "none":
                search_display.styles.display = "block"

            # Update display with blinking cursor at end
            if self.search_input_text:
                # Show text with blinking cursor (escape special chars for Rich markup)
                escaped_text = rich_escape(self.search_input_text)
                # Double trailing backslash so it doesn't escape the [blink] tag
                if escaped_text.endswith('\\'):
                    escaped_text += '\\'
                display_text = f"> {escaped_text}[blink]▎[/blink]"
            else:
                # Show prompt with blinking cursor (ready to type)
                display_text = "> [blink]▎[/blink]"

            search_display.update(display_text)

            # Update status bar
            self._update_status("Type to search | Enter/Tab/↓ to navigate | ESC to close")

            # Only perform search when requested and there's text, or when clearing
            if perform_search:
                if self.search_input_text:
                    result_count = self._perform_live_search(self.search_input_text)
                    t = self.theme_colors

                    if result_count == 0:
                        results_label.update("[#ff0000]No matches[/#ff0000]")
                    elif result_count == 1:
                        results_label.update(f"[{t['secondary']}]1 match[/{t['secondary']}]")
                    else:
                        results_label.update(f"[{t['secondary']}]{result_count} matches[/{t['secondary']}]")
                else:
                    # Clear results label when no text
                    results_label.update("")
            else:
                # Just entering search mode - don't change results label
                pass

        except Exception as e:
            logging.error(f"Error in _update_search_display: {e}", exc_info=True)
            self._update_status(f"ERROR: {str(e)}")

    def on_key(self, event):
        """Handle keyboard events using the dispatcher pattern.

        Keyboard handling is delegated to specialized handlers in
        supershell/handlers/keyboard.py for better organization and testing.
        """
        _debug_log(f"KEY: key={event.key!r} char={event.character!r} "
                   f"shell_visible={self.shell_pane_visible} shell_input_active={self.shell_input_active} "
                   f"search_active={self.search_input_active}")

        # Dispatch to the keyboard handler chain
        handled = keyboard_dispatcher.dispatch(event, self)
        _debug_log(f"KEY: handled={handled}")
        if handled:
            return

        # Event was not handled by any handler - let it propagate
        pass

    # Old keyboard handling code has been moved to supershell/handlers/keyboard.py

    def _collapse_current_or_parent(self, tree: Tree):
        """Collapse current node if expanded, or go to parent. Stop at root."""
        cursor_node = tree.cursor_node
        if cursor_node is None:
            return

        # If we're at root, do nothing - this is as far as we go
        if cursor_node == tree.root:
            self._update_status("At root")
            return

        if cursor_node.is_expanded and cursor_node.children:
            # Current node is expanded - collapse it
            cursor_node.collapse()
            self._update_status("Collapsed")
        elif cursor_node.parent:
            # Go to parent
            tree.select_node(cursor_node.parent)
            self._update_status("Moved to parent")

    def _execute_command(self, command: str):
        """Execute vim-style command (e.g., :20 to go to line 20) or open shell with command"""
        command = command.strip()
        if not command:
            return

        # Handle quit commands (vim-style :q and :quit)
        if command.lower() in ('q', 'quit'):
            self.exit()
            return

        # Try to parse as line number first (vim navigation)
        try:
            line_num = int(command)
            self._goto_line(line_num)
            return
        except ValueError:
            pass

        # Not a number - open shell pane and run the command
        self._open_shell_pane(command)

    def _goto_line(self, line_num: int):
        """Go to specified line number in the tree (1-indexed like vim)"""
        tree = self.query_one("#folder_tree", Tree)

        # Build list of visible nodes
        visible_nodes = []

        def collect_visible_nodes(node, include_self=True):
            """Collect all visible nodes in order"""
            if include_self:
                visible_nodes.append(node)
            if node.is_expanded:
                for child in node.children:
                    collect_visible_nodes(child, include_self=True)

        # Start from root (line 1 = root)
        collect_visible_nodes(tree.root)

        # Convert 1-indexed to 0-indexed
        target_index = line_num - 1

        if target_index < 0:
            target_index = 0
        elif target_index >= len(visible_nodes):
            target_index = len(visible_nodes) - 1

        if visible_nodes:
            target_node = visible_nodes[target_index]
            tree.select_node(target_node)
            self._update_status(f"Line {target_index + 1} of {len(visible_nodes)}")
        else:
            self._update_status("No visible nodes")

    # ========== Shell Pane Methods ==========

    def _open_shell_pane(self, command: str = None):
        """Open the shell pane, optionally running a command immediately"""
        content_area = self.query_one("#content_area", Vertical)
        content_area.add_class("shell-visible")

        self.shell_pane_visible = True
        self.shell_input_active = True
        self.shell_input_text = ""  # Keep for compatibility
        self._shell_executing = False  # Track if command is executing

        # Update shell header with theme colors and prompt
        self._update_shell_header()

        # Initialize the prompt with green ❯
        try:
            prompt = self.query_one("#shell_prompt", Static)
            prompt.update("[green]❯[/green] ")
        except Exception:
            pass

        # Focus the input TextArea
        try:
            shell_input = self.query_one("#shell_input_area", ShellInputTextArea)
            shell_input.focus()
            shell_input.clear()
        except Exception:
            pass

        # If a command was provided, execute it immediately
        if command:
            self._execute_shell_command_async(command)

        self._update_status("Shell open | Enter to run | Up/Down for history | Ctrl+D to close")

    def _close_shell_pane(self):
        """Close the shell pane and return to normal view"""
        content_area = self.query_one("#content_area", Vertical)
        content_area.remove_class("shell-visible")

        self.shell_pane_visible = False
        self.shell_input_active = False
        self.shell_input_text = ""
        self.shell_history_index = -1

        # Clear the input TextArea
        try:
            shell_input = self.query_one("#shell_input_area", ShellInputTextArea)
            shell_input.clear()
        except Exception:
            pass

        # Focus tree
        tree = self.query_one("#folder_tree", Tree)
        tree.focus()

        self._update_status("Navigate with j/k | / to search | ? for help")

    def _execute_shell_command_async(self, command: str):
        """Execute a command asynchronously with loading indicator."""
        # Show spinner in prompt
        self._start_shell_spinner()

        # Run the command in a worker thread
        self.run_worker(
            lambda: self._execute_shell_command_worker(command),
            name="shell_command",
            exclusive=True,
            thread=True
        )

    def _start_shell_spinner(self):
        """Start the spinner animation in the shell prompt."""
        self._shell_spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self._shell_spinner_index = 0
        self._shell_executing = True

        # Update prompt to show first spinner frame
        try:
            prompt = self.query_one("#shell_prompt", Static)
            prompt.update(f"[yellow]{self._shell_spinner_frames[0]}[/yellow] ")
        except Exception:
            pass

        # Start timer for animation
        self._shell_spinner_timer = self.set_interval(0.1, self._animate_shell_spinner)

    def _animate_shell_spinner(self):
        """Animate the shell spinner."""
        if not self._shell_executing:
            return

        self._shell_spinner_index = (self._shell_spinner_index + 1) % len(self._shell_spinner_frames)
        try:
            prompt = self.query_one("#shell_prompt", Static)
            prompt.update(f"[yellow]{self._shell_spinner_frames[self._shell_spinner_index]}[/yellow] ")
        except Exception:
            pass

    def _stop_shell_spinner(self):
        """Stop the spinner and restore the prompt."""
        self._shell_executing = False
        if hasattr(self, '_shell_spinner_timer') and self._shell_spinner_timer:
            self._shell_spinner_timer.stop()
            self._shell_spinner_timer = None

        # Restore normal prompt
        try:
            prompt = self.query_one("#shell_prompt", Static)
            prompt.update("[green]❯[/green] ")
        except Exception:
            pass

    def _execute_shell_command_worker(self, command: str):
        """Worker function that executes the command and returns the result."""
        command = command.strip()

        # Handle quit commands
        if command.lower() in ('quit', 'q', 'exit'):
            self.call_from_thread(self._stop_shell_spinner)
            self.call_from_thread(self._close_shell_pane)
            return

        # Block supershell inside supershell
        cmd_name = command.split()[0].lower() if command.split() else ''
        if cmd_name in ('supershell', 'ss'):
            self.shell_history.append((command, "[yellow]Cannot run supershell inside supershell[/yellow]"))
            self.call_from_thread(self._stop_shell_spinner)
            self.call_from_thread(self._update_shell_output_display)
            self.call_from_thread(self._scroll_shell_to_bottom)
            return

        # Handle clear command
        if command.lower() == 'clear':
            self.shell_history = []
            self.call_from_thread(self._stop_shell_spinner)
            self.call_from_thread(self._update_shell_output_display)
            return

        # Add to command history for up/down navigation
        if command and (not self.shell_command_history or
                        self.shell_command_history[-1] != command):
            self.shell_command_history.append(command)
        self.shell_history_index = -1

        # Capture stdout/stderr for command execution
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        log_buffer = io.StringIO()
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        # Create a temporary logging handler to capture log output
        log_handler = logging.StreamHandler(log_buffer)
        log_handler.setLevel(logging.INFO)
        log_handler.setFormatter(logging.Formatter('%(message)s'))
        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)

        try:
            sys.stdout = stdout_buffer
            sys.stderr = stderr_buffer

            # Execute via cli.do_command
            from ..cli import do_command
            result = do_command(self.params, command)
            # Some commands return output (e.g., JSON format) instead of printing
            if result is not None:
                print(result)

        except Exception as e:
            stderr_buffer.write(f"Error: {str(e)}\n")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            root_logger.removeHandler(log_handler)

        # Get output
        output = stdout_buffer.getvalue()
        errors = stderr_buffer.getvalue()
        log_output = log_buffer.getvalue()

        # Strip ANSI codes
        output = strip_ansi_codes(output)
        errors = strip_ansi_codes(errors)
        log_output = strip_ansi_codes(log_output)

        # Combine output (stdout first, then log output, then errors)
        full_output = output.rstrip()
        if log_output.strip():
            if full_output:
                full_output += "\n"
            full_output += log_output.rstrip()
        if errors:
            if full_output:
                full_output += "\n"
            full_output += f"[red]{rich_escape(errors.rstrip())}[/red]"

        # Add to history
        self.shell_history.append((command, full_output))

        # Stop spinner and update display on the main thread
        self.call_from_thread(self._stop_shell_spinner)
        self.call_from_thread(self._update_shell_output_display)
        self.call_from_thread(self._scroll_shell_to_bottom)

    def _scroll_shell_to_bottom(self):
        """Scroll shell output to bottom."""
        try:
            shell_output = self.query_one("#shell_output_content", TextArea)
            shell_output.action_cursor_line_end()
            shell_output.scroll_end(animate=False)
        except Exception:
            pass

    def _execute_shell_command(self, command: str):
        """Execute a Keeper command in the shell pane and display output"""
        command = command.strip()
        if not command:
            # Empty command - do nothing
            return

        # Handle quit commands
        if command.lower() in ('quit', 'q', 'exit'):
            self._close_shell_pane()
            return

        # Handle clear command
        if command.lower() == 'clear':
            self.shell_history = []
            self._update_shell_output_display()
            return

        # Add to command history for up/down navigation
        if command and (not self.shell_command_history or
                        self.shell_command_history[-1] != command):
            self.shell_command_history.append(command)
        self.shell_history_index = -1

        # Capture stdout/stderr for command execution
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        log_buffer = io.StringIO()
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        # Create a temporary logging handler to capture log output
        log_handler = logging.StreamHandler(log_buffer)
        log_handler.setLevel(logging.INFO)
        log_handler.setFormatter(logging.Formatter('%(message)s'))
        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)

        try:
            sys.stdout = stdout_buffer
            sys.stderr = stderr_buffer

            # Execute via cli.do_command
            from ..cli import do_command
            result = do_command(self.params, command)
            # Some commands return output (e.g., JSON format) instead of printing
            if result is not None:
                print(result)

        except Exception as e:
            stderr_buffer.write(f"Error: {str(e)}\n")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            root_logger.removeHandler(log_handler)

        # Get output
        output = stdout_buffer.getvalue()
        errors = stderr_buffer.getvalue()
        log_output = log_buffer.getvalue()

        # Strip ANSI codes
        output = strip_ansi_codes(output)
        errors = strip_ansi_codes(errors)
        log_output = strip_ansi_codes(log_output)

        # Combine output (stdout first, then log output, then errors)
        full_output = output.rstrip()
        if log_output.strip():
            if full_output:
                full_output += "\n"
            full_output += log_output.rstrip()
        if errors:
            if full_output:
                full_output += "\n"
            full_output += f"[red]{rich_escape(errors.rstrip())}[/red]"

        # Add to history
        self.shell_history.append((command, full_output))

        # Update shell output display
        self._update_shell_output_display()

        # Scroll to bottom (defer to ensure content is rendered)
        def scroll_to_bottom():
            try:
                shell_output = self.query_one("#shell_output_content", TextArea)
                # Move cursor to end to scroll to bottom
                shell_output.action_cursor_line_end()
                shell_output.scroll_end(animate=False)
            except Exception:
                pass
        self.call_after_refresh(scroll_to_bottom)

    def _update_shell_output_display(self):
        """Update the shell output area with command history (using TextArea for selection support)"""
        try:
            shell_output_content = self.query_one("#shell_output_content", TextArea)
        except Exception:
            return

        lines = []

        for cmd, output in self.shell_history:
            # Show prompt and command (plain text - TextArea doesn't support Rich markup)
            prompt = self._get_shell_prompt()
            lines.append(f"{prompt}{cmd}")
            # Show output (with blank line separator only if there's output)
            if output.strip():
                # Strip Rich markup tags from output, but preserve JSON arrays
                # Rich tags look like [red], [/bold], [#ffffff], [bold red] - start with letter, /, or #
                # JSON arrays contain quotes, braces, colons, etc.
                plain_output = re.sub(r'\[/?[a-zA-Z#][a-zA-Z0-9_ #]*\]', '', output)
                lines.append(plain_output)
                lines.append("")  # Blank line after output

        # TextArea uses .text property, not .update()
        shell_output_content.text = "\n".join(lines)
        _debug_log(f"_update_shell_output_display: updated TextArea with {len(lines)} lines")

    def _update_shell_input_display(self):
        """Legacy method - now a no-op since ShellInputTextArea handles its own display.

        Kept for compatibility with any code that might still call it.
        The prompt is now shown in the shell header via _update_shell_header().
        """
        pass

    def _get_shell_prompt(self) -> str:
        """Get the shell prompt based on current folder context"""
        # Use the currently selected folder in the tree as context
        if self.selected_folder and self.params.folder_cache:
            folder = self.params.folder_cache.get(self.selected_folder)
            if folder and hasattr(folder, 'name'):
                name = folder.name
                if len(name) > 30:
                    name = "..." + name[-27:]
                return f"{name}> "

        # Default to "My Vault" if at root
        return "My Vault> "

    def _update_shell_header(self):
        """Update shell header bar with theme colors and current prompt context"""
        try:
            shell_header = self.query_one("#shell_header", Static)
        except Exception:
            return

        t = self.theme_colors
        prompt = self._get_shell_prompt()
        shell_header.update(
            f"[bold {t['primary']}]{prompt}[/bold {t['primary']}]"
            f"[{t['text_dim']}]  (Enter to run | Up/Down for history | Ctrl+D to close)[/{t['text_dim']}]"
        )

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        """Control whether actions are enabled based on search state"""
        # When search input is active, disable all bindings except escape and search
        # This allows keys to be captured as text input instead of triggering actions
        if hasattr(self, 'search_input_active') and self.search_input_active:
            # Only allow escape and search actions when typing in search
            if action in ("quit", "search"):
                return True
            # Disable all other actions - keys will be captured as text
            return False
        # When not in search input mode, allow all actions
        return True

    def action_search(self):
        """Activate search input mode"""
        tree = self.query_one("#folder_tree", Tree)

        # Save current selection before activating search
        if not self.search_input_active:
            self.pre_search_selected_record = self.selected_record
            self.pre_search_selected_folder = self.selected_folder

        # Activate search input mode
        self.search_input_active = True
        tree.add_class("search-input-active")
        self._update_search_display(perform_search=False)  # Don't change tree when entering search
        self._update_status("Type to search | Tab to navigate | Ctrl+U to clear")

    def action_toggle_view_mode(self):
        """Toggle between detail and JSON view modes"""
        # Works for records, folders, and shared folders
        if not self.selected_record and not self.selected_folder:
            self.notify("⚠️  No record or folder selected", severity="warning")
            return

        if self.view_mode == 'detail':
            self.view_mode = 'json'
            self.notify("📋 Switched to JSON view", severity="information")
        else:
            self.view_mode = 'detail'
            self.notify("📋 Switched to Detail view", severity="information")

        # Refresh the current display
        try:
            if self.selected_record:
                # Check if it's a Secret Manager app
                if self.selected_record in self.app_record_uids:
                    self._display_secrets_manager_app(self.selected_record)
                else:
                    self._display_record_detail(self.selected_record)
            elif self.selected_folder:
                self._display_folder_with_clickable_fields(self.selected_folder)
        except Exception as e:
            logging.error(f"Error toggling view mode: {e}", exc_info=True)
            self.notify(f"⚠️  Error switching view: {str(e)}", severity="error")

    def action_toggle_unmask(self):
        """Toggle unmasking of secret/password/passphrase fields"""
        if not self.selected_record and not self.selected_folder:
            self.notify("No record or folder selected", severity="warning")
            return

        self.unmask_secrets = not self.unmask_secrets
        status = "unmasked" if self.unmask_secrets else "masked"
        self.notify(f"Secrets {status}", severity="information")

        # Refresh the current display and shortcuts bar
        try:
            if self.selected_record:
                self._display_record_detail(self.selected_record)
                self._update_shortcuts_bar(record_selected=True)
            elif self.selected_folder:
                self._display_folder_with_clickable_fields(self.selected_folder)
                self._update_shortcuts_bar(folder_selected=True)
        except Exception as e:
            logging.error(f"Error toggling unmask: {e}", exc_info=True)

    def action_copy_password(self):
        """Copy password of selected record to clipboard using clipboard-copy command (generates audit event)"""
        if self.selected_record and self.selected_record in self.records:
            # First check if clipboard is available (to distinguish from "no password" errors)
            try:
                pyperclip.copy("")  # Test clipboard availability
            except PyperclipException:
                self.notify("⚠️  Clipboard not available (no X11/Wayland)", severity="warning")
                return
            except Exception as e:
                self.notify(f"⚠️  {e}", severity="warning")
                return

            try:
                # Use ClipboardCommand to copy password - this generates the audit event
                cc = ClipboardCommand()
                cc.execute(self.params, record=self.selected_record, output='clipboard',
                           username=None, copy_uid=False, login=False, totp=False, field=None, revision=None)
                self.notify("🔑 Password copied to clipboard!", severity="information")
            except Exception as e:
                logging.debug(f"ClipboardCommand error: {e}")
                self.notify("⚠️  No password found for this record", severity="warning")
        else:
            self.notify("⚠️  No record selected", severity="warning")

    def action_copy_username(self):
        """Copy username of selected record to clipboard"""
        if self.selected_record and self.selected_record in self.records:
            record = self.records[self.selected_record]
            if 'login' in record:
                success, err = safe_copy_to_clipboard(record['login'])
                if success:
                    self.notify("👤 Username copied to clipboard!", severity="information")
                else:
                    self.notify(f"⚠️  {err}", severity="warning")
            else:
                self.notify("⚠️  No username found for this record", severity="warning")
        else:
            self.notify("⚠️  No record selected", severity="warning")

    def action_copy_url(self):
        """Copy URL of selected record to clipboard"""
        if self.selected_record and self.selected_record in self.records:
            record = self.records[self.selected_record]
            if 'login_url' in record:
                success, err = safe_copy_to_clipboard(record['login_url'])
                if success:
                    self.notify("🔗 URL copied to clipboard!", severity="information")
                else:
                    self.notify(f"⚠️  {err}", severity="warning")
            else:
                self.notify("⚠️  No URL found for this record", severity="warning")
        else:
            self.notify("⚠️  No record selected", severity="warning")

    def action_copy_uid(self):
        """Copy UID of selected record or folder to clipboard"""
        if self.selected_record:
            success, err = safe_copy_to_clipboard(self.selected_record)
            if success:
                self.notify("📋 Record UID copied to clipboard!", severity="information")
            else:
                self.notify(f"⚠️  {err}", severity="warning")
        elif self.selected_folder:
            success, err = safe_copy_to_clipboard(self.selected_folder)
            if success:
                self.notify("📋 Folder UID copied to clipboard!", severity="information")
            else:
                self.notify(f"⚠️  {err}", severity="warning")
        else:
            self.notify("⚠️  No record or folder selected", severity="warning")

    def action_copy_record(self):
        """Copy entire record contents to clipboard (formatted or JSON based on view mode)"""
        if self.selected_record:
            try:
                import json  # Import json at the top of the method for both app and regular records
                
                # Check if it's a Secrets Manager app record
                if self.selected_record in self.app_record_uids:
                    # For Secrets Manager apps, copy the app data in JSON format
                    from ..proto import APIRequest_pb2, enterprise_pb2
                    from .. import api, utils
                    
                    record = self.records[self.selected_record]
                    app_title = record.get('title', 'Untitled')
                    
                    app_data = {
                        "app_name": app_title,
                        "app_uid": self.selected_record,
                        "client_devices": [],
                        "shares": []
                    }
                    
                    try:
                        rq = APIRequest_pb2.GetAppInfoRequest()
                        rq.appRecordUid.append(utils.base64_url_decode(self.selected_record))
                        rs = api.communicate_rest(self.params, rq, 'vault/get_app_info', rs_type=APIRequest_pb2.GetAppInfoResponse)
                        
                        if rs.appInfo:
                            app_info = rs.appInfo[0]
                            
                            # Collect client devices
                            client_devices = [x for x in app_info.clients if x.appClientType == enterprise_pb2.GENERAL]
                            for client in client_devices:
                                app_data["client_devices"].append({"device_name": client.id})
                            
                            # Collect application access (shares)
                            for share in app_info.shares:
                                uid_str = utils.base64_url_encode(share.secretUid)
                                share_type = APIRequest_pb2.ApplicationShareType.Name(share.shareType)
                                
                                title = "Unknown"
                                if share_type == 'SHARE_TYPE_RECORD':
                                    if uid_str in self.params.record_cache:
                                        rec = self.params.record_cache[uid_str]
                                        if 'data_unencrypted' in rec:
                                            data = json.loads(rec['data_unencrypted'])
                                            title = data.get('title', 'Untitled')
                                    share_type_display = "RECORD"
                                elif share_type == 'SHARE_TYPE_FOLDER':
                                    if hasattr(self.params, 'folder_cache'):
                                        folder = self.params.folder_cache.get(uid_str)
                                        if folder:
                                            title = folder.name
                                    share_type_display = "FOLDER"
                                else:
                                    share_type_display = share_type
                                
                                app_data["shares"].append({
                                    "share_type": share_type,
                                    "uid": uid_str,
                                    "editable": share.editable,
                                    "title": title,
                                    "type": share_type_display
                                })
                    except Exception as e:
                        logging.debug(f"Error fetching app info for copy: {e}")
                    
                    # Format based on view mode
                    if self.view_mode == 'json':
                        # Copy as JSON
                        formatted = json.dumps(app_data, indent=2)
                        success, err = safe_copy_to_clipboard(formatted)
                        if success:
                            self.notify("📋 Secrets Manager app JSON copied to clipboard!", severity="information")
                        else:
                            self.notify(f"⚠️  {err}", severity="warning")
                    else:
                        # Copy as formatted text (detail view)
                        lines = []
                        lines.append("Secrets Manager Application")
                        lines.append(f"App Name: {app_title}")
                        lines.append(f"App UID: {self.selected_record}")
                        lines.append("")
                        
                        # Client devices
                        if app_data["client_devices"]:
                            lines.append(f"Client Devices ({len(app_data['client_devices'])}):")
                            for idx, device in enumerate(app_data["client_devices"], 1):
                                lines.append(f"  {idx}. {device['device_name']}")
                            lines.append("")
                        else:
                            lines.append("No client devices registered for this Application")
                            lines.append("")
                        
                        # Application access
                        if app_data["shares"]:
                            lines.append("Application Access:")
                            lines.append("")
                            for share in app_data["shares"]:
                                lines.append(f"  {share['type']}: {share['title']}")
                                lines.append(f"    UID: {share['uid']}")
                                permissions = "Editable" if share['editable'] else "Read-Only"
                                lines.append(f"    Permissions: {permissions}")
                                lines.append("")
                        else:
                            lines.append("Application Access:")
                            lines.append("No shared folders or records")
                            lines.append("")
                        
                        formatted = "\n".join(lines)
                        success, err = safe_copy_to_clipboard(formatted)
                        if success:
                            self.notify("📋 Secrets Manager app details copied to clipboard!", severity="information")
                        else:
                            self.notify(f"⚠️  {err}", severity="warning")
                else:
                    # Regular record handling
                    record_data = self.records.get(self.selected_record, {})
                    has_password = bool(record_data.get('password'))

                    if self.view_mode == 'json':
                        # Copy JSON format (with actual password, not masked)
                        output = self._get_record_output(self.selected_record, format_type='json')
                        output = strip_ansi_codes(output)
                        json_obj = json.loads(output)
                        formatted = json.dumps(json_obj, indent=2)
                        success, err = safe_copy_to_clipboard(formatted)
                        if success:
                            # Generate audit event since JSON contains the password
                            if has_password:
                                self.params.queue_audit_event('copy_password', record_uid=self.selected_record)
                            self.notify("📋 JSON copied to clipboard!", severity="information")
                        else:
                            self.notify(f"⚠️  {err}", severity="warning")
                    else:
                        # Copy formatted text (without Rich markup)
                        content = self._format_record_for_tui(self.selected_record)
                        # Strip Rich markup for plain text clipboard
                        import re
                        plain = re.sub(r'\[/?[^\]]+\]', '', content)
                        success, err = safe_copy_to_clipboard(plain)
                        if success:
                            # Generate audit event if record has password (detail view includes password)
                            if has_password:
                                self.params.queue_audit_event('copy_password', record_uid=self.selected_record)
                            self.notify("📋 Record contents copied to clipboard!", severity="information")
                        else:
                            self.notify(f"⚠️  {err}", severity="warning")
            except Exception as e:
                logging.error(f"Error copying record: {e}", exc_info=True)
                self.notify("⚠️  Failed to copy record contents", severity="error")
        else:
            self.notify("⚠️  No record selected", severity="warning")

    def action_show_help(self):
        """Show help modal"""
        self.push_screen(HelpScreen())

    def action_show_user_info(self):
        """Show user/whoami information in detail panel"""
        self._display_whoami_info()

    def action_show_device_info(self):
        """Show device information in detail panel"""
        self._display_device_info()

    def action_sync_vault(self):
        """Sync vault data from server (sync-down + enterprise-down) and refresh UI"""
        self._update_status("Syncing vault data from server...")

        try:
            # Run sync-down command
            from .utils import SyncDownCommand
            SyncDownCommand().execute(self.params)

            # Run enterprise-down if available (enterprise users)
            try:
                from .enterprise import EnterpriseDownCommand
                EnterpriseDownCommand().execute(self.params)
            except Exception:
                pass  # Not an enterprise user or command not available

            # Reload vault data and refresh UI
            self.records = {}
            self.record_to_folder = {}
            self.records_in_subfolders = set()
            self.file_attachment_to_parent = {}
            self.record_file_attachments = {}
            self.linked_record_to_parent = {}
            self.record_linked_records = {}
            self.app_record_uids = set()
            self._record_output_cache = {}  # Clear record output cache
            self._load_vault_data()
            self.device_info = self._load_device_info()  # Refresh device info
            self.whoami_info = self._load_whoami_info()  # Refresh whoami info
            self._setup_folder_tree()
            self._update_header_info_display()  # Update header info display

            self._update_status("Vault synced & refreshed")
            self.notify("Vault synced & refreshed", severity="information")
        except Exception as e:
            logging.error(f"Error syncing vault: {e}", exc_info=True)
            self._update_status(f"Sync failed: {str(e)}")
            self.notify(f"Sync failed: {str(e)}", severity="error")

    # Vim-style navigation actions
    def action_cursor_down(self):
        """Move cursor down (Vim j)"""
        focused = self.focused
        if isinstance(focused, (Tree, DataTable)):
            focused.action_cursor_down()
        elif isinstance(focused, VerticalScroll):
            # Scroll down in the detail view
            focused.scroll_down(animate=False)

    def action_cursor_up(self):
        """Move cursor up (Vim k)"""
        focused = self.focused
        if isinstance(focused, (Tree, DataTable)):
            focused.action_cursor_up()
        elif isinstance(focused, VerticalScroll):
            # Scroll up in the detail view
            focused.scroll_up(animate=False)

    def action_cursor_left(self):
        """Move cursor left (Vim h)"""
        focused = self.focused
        if isinstance(focused, Tree):
            # Collapse node in tree
            if focused.cursor_node and focused.cursor_node.allow_expand:
                focused.cursor_node.collapse()

    def action_cursor_right(self):
        """Move cursor right (Vim l)"""
        focused = self.focused
        if isinstance(focused, Tree):
            # Expand node in tree
            if focused.cursor_node and focused.cursor_node.allow_expand:
                focused.cursor_node.expand()

    def action_goto_top(self):
        """Go to top (Vim g)"""
        focused = self.focused
        if isinstance(focused, DataTable):
            focused.move_cursor(row=0)
        elif isinstance(focused, Tree):
            # Get first child of root instead of root itself to avoid collapsing
            if focused.root and focused.root.children:
                first_child = focused.root.children[0]
                focused.select_node(first_child)
            else:
                focused.select_node(focused.root)
        elif isinstance(focused, VerticalScroll):
            focused.scroll_home(animate=False)

    def action_goto_bottom(self):
        """Go to bottom (Vim G)"""
        focused = self.focused
        if isinstance(focused, DataTable):
            focused.move_cursor(row=focused.row_count - 1)
        elif isinstance(focused, Tree):
            # Find the last visible node in the tree
            def get_last_visible_node(node):
                """Recursively find the last visible (expanded) node"""
                if node.is_expanded and node.children:
                    return get_last_visible_node(node.children[-1])
                return node
            last_node = get_last_visible_node(focused.root)
            focused.select_node(last_node)
        elif isinstance(focused, VerticalScroll):
            focused.scroll_end(animate=False)

    def action_page_down(self):
        """Page down (Vim CTRL+d) - half page"""
        focused = self.focused
        if isinstance(focused, DataTable):
            # Move down by half the visible height
            current_row = focused.cursor_row
            page_size = max(1, self.size.height // 4)  # Half page
            new_row = min(current_row + page_size, focused.row_count - 1)
            focused.move_cursor(row=new_row)
        elif isinstance(focused, Tree):
            # Move down through tree nodes
            for _ in range(self.PAGE_DOWN_NODES):  # Move down half page
                focused.action_cursor_down()
        elif isinstance(focused, VerticalScroll):
            # Scroll down by page in detail view
            focused.scroll_page_down(animate=False)

    def action_page_up(self):
        """Page up (Vim CTRL+u) - half page"""
        focused = self.focused
        if isinstance(focused, DataTable):
            # Move up by half the visible height
            current_row = focused.cursor_row
            page_size = max(1, self.size.height // 4)  # Half page
            new_row = max(current_row - page_size, 0)
            focused.move_cursor(row=new_row)
        elif isinstance(focused, Tree):
            # Move up through tree nodes
            for _ in range(self.PAGE_DOWN_NODES):  # Move up half page
                focused.action_cursor_up()
        elif isinstance(focused, VerticalScroll):
            # Scroll up by page in detail view
            focused.scroll_page_up(animate=False)

    def action_page_down_full(self):
        """Page down (Vim CTRL+f) - full page"""
        focused = self.focused
        if isinstance(focused, DataTable):
            # Move down by full visible height
            current_row = focused.cursor_row
            page_size = max(1, self.size.height // 2)  # Full page
            new_row = min(current_row + page_size, focused.row_count - 1)
            focused.move_cursor(row=new_row)
        elif isinstance(focused, Tree):
            # Move down through tree nodes
            for _ in range(self.PAGE_DOWN_FULL_NODES):  # Move down full page
                focused.action_cursor_down()
        elif isinstance(focused, VerticalScroll):
            # Scroll down by full page in detail view
            focused.scroll_page_down(animate=False)

    def action_page_up_full(self):
        """Page up (Vim CTRL+b) - full page"""
        focused = self.focused
        if isinstance(focused, DataTable):
            # Move up by full visible height
            current_row = focused.cursor_row
            page_size = max(1, self.size.height // 2)  # Full page
            new_row = max(current_row - page_size, 0)
            focused.move_cursor(row=new_row)
        elif isinstance(focused, Tree):
            # Move up through tree nodes
            for _ in range(self.PAGE_DOWN_FULL_NODES):  # Move up full page
                focused.action_cursor_up()
        elif isinstance(focused, VerticalScroll):
            # Scroll up by full page in detail view
            focused.scroll_page_up(animate=False)

    def action_scroll_up(self):
        """Scroll up one line (Vim CTRL+y)"""
        focused = self.focused
        if not self.search_input_active:
            if isinstance(focused, Tree):
                focused.scroll_relative(y=-1)
            elif isinstance(focused, VerticalScroll):
                focused.scroll_relative(y=-1)

    def action_scroll_down(self):
        """Scroll down one line (Vim CTRL+e)"""
        focused = self.focused
        if not self.search_input_active:
            if isinstance(focused, Tree):
                focused.scroll_relative(y=1)
            elif isinstance(focused, VerticalScroll):
                focused.scroll_relative(y=1)

    def action_quit(self):
        """Quit the application"""
        self._stop_totp_timer()
        self.exit()


class SuperShellCommand(Command):
    """Command to launch the SuperShell TUI"""

    def get_parser(self):
        from argparse import ArgumentParser
        parser = ArgumentParser(prog='supershell', description='Launch full terminal vault UI with vim navigation')
        # -h/--help is automatically added by ArgumentParser
        return parser

    def is_authorised(self):
        """Don't require pre-authentication - TUI handles all auth"""
        return False

    def execute(self, params, **kwargs):
        """Launch the SuperShell TUI - handles login if needed"""
        from .. import display
        from ..cli import debug_manager

        # Show government warning for GOV environments when entering SuperShell
        if params.server and 'govcloud' in params.server.lower():
            display.show_government_warning()

        # Disable debug mode for SuperShell to prevent log output from messing up the TUI
        saved_debug = getattr(params, 'debug', False)
        saved_log_level = logging.getLogger().level
        if saved_debug or logging.getLogger().level == logging.DEBUG:
            params.debug = False
            debug_manager.set_console_debug(False, params.batch_mode)
            # Also set root logger level to suppress all debug output
            logging.getLogger().setLevel(logging.WARNING)

        try:
            self._execute_supershell(params, **kwargs)
        finally:
            # Restore debug state when SuperShell exits
            if saved_debug:
                params.debug = saved_debug
                debug_manager.set_console_debug(True, params.batch_mode)
                logging.getLogger().setLevel(saved_log_level)

    def _execute_supershell(self, params, **kwargs):
        """Internal method to run SuperShell"""
        import threading
        import time
        import sys

        class Spinner:
            """Animated spinner that runs in a background thread"""
            def __init__(self, message="Loading..."):
                self.message = message
                self.running = False
                self.thread = None
                self.chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
                self.colors = ['\033[36m', '\033[32m', '\033[33m', '\033[35m']

            def _spin(self):
                i = 0
                while self.running:
                    color = self.colors[i % len(self.colors)]
                    char = self.chars[i % len(self.chars)]
                    # Check running again before writing to avoid race condition
                    if not self.running:
                        break
                    sys.stdout.write(f"\r  {color}{char}\033[0m {self.message}")
                    sys.stdout.flush()
                    time.sleep(0.1)
                    i += 1

            def start(self):
                self.running = True
                self.thread = threading.Thread(target=self._spin, daemon=True)
                self.thread.start()

            def stop(self, success_message=None):
                self.running = False
                if self.thread:
                    self.thread.join(timeout=0.5)
                # Small delay to ensure thread has stopped writing
                time.sleep(0.15)
                # Clear spinner line (do it twice to handle any race condition)
                sys.stdout.write("\r\033[K")
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
                if success_message:
                    print(f"  \033[32m✓\033[0m {success_message}")

            def update(self, message):
                self.message = message

        # Check if authentication is needed
        if not params.session_token:
            from .utils import LoginCommand
            try:
                # Run login (no spinner - login may prompt for 2FA, password, etc.)
                # show_help=False to suppress the batch mode help text
                LoginCommand().execute(params, email=params.user, password=params.password, new_login=False, show_help=False)

                if not params.session_token:
                    logging.error("\nLogin failed or was cancelled.")
                    return

                # Sync vault data with spinner (no success message - TUI will load immediately)
                sync_spinner = Spinner("Syncing vault data...")
                sync_spinner.start()
                try:
                    from .utils import SyncDownCommand
                    SyncDownCommand().execute(params)
                    sync_spinner.stop()  # No success message - TUI loads immediately
                except Exception as e:
                    sync_spinner.stop()
                    raise

            except KeyboardInterrupt:
                print("\n\nLogin cancelled.")
                return
            except Exception as e:
                logging.error(f"\nLogin failed: {e}")
                return

        # Launch the TUI app
        try:
            app = SuperShellApp(params)
            result = app.run()

            # If user pressed '!' to exit to shell, start the Keeper shell
            if result and "Exited to Keeper shell" in str(result):
                print(result)  # Show the exit message
                # Check if we were in batch mode BEFORE modifying it
                was_batch_mode = params.batch_mode
                # Clear batch mode and pending commands so the shell runs interactively
                params.batch_mode = False
                params.commands = [c for c in params.commands if c.lower() not in ('q', 'quit')]
                # Only start a new shell if we were in batch mode (ran 'keeper supershell' directly)
                # Otherwise, just return to the existing interactive shell
                if was_batch_mode:
                    from ..cli import loop as shell_loop
                    shell_loop(params, skip_init=True, suppress_goodbye=True)
                    # When the inner shell exits, queue 'q' so the outer batch-mode loop also exits
                    params.commands.append('q')
        except KeyboardInterrupt:
            logging.debug("SuperShell interrupted")
        except Exception as e:
            logging.error(f"Error running SuperShell: {e}")
            raise
