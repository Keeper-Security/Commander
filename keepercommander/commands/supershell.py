"""
Keeper SuperShell - A full-screen terminal UI for Keeper vault
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
from rich.markup import escape as rich_escape


# Color themes - each theme uses variations of a primary color
COLOR_THEMES = {
    'green': {
        'primary': '#00ff00',        # Bright green
        'primary_dim': '#00aa00',    # Dim green
        'primary_bright': '#44ff44', # Light green
        'secondary': '#88ff88',      # Light green accent
        'selection_bg': '#004400',   # Selection background
        'hover_bg': '#002200',       # Hover background (dimmer than selection)
        'text': '#ffffff',           # White text
        'text_dim': '#aaaaaa',       # Dim text
        'folder': '#44ff44',         # Folder color (light green)
        'folder_shared': '#00dd00',  # Shared folder (slightly different green)
        'record': '#00aa00',         # Record color (dimmer than folders)
        'record_num': '#888888',     # Record number
        'attachment': '#00cc00',     # Attachment color
        'virtual_folder': '#00ff88', # Virtual folder
        'status': '#00ff00',         # Status bar
        'border': '#00aa00',         # Borders
        'root': '#00ff00',           # Root node
        'header_user': '#00bbff',    # Header username (blue contrast)
    },
    'blue': {
        'primary': '#0099ff',
        'primary_dim': '#0066cc',
        'primary_bright': '#66bbff',
        'secondary': '#00ccff',
        'selection_bg': '#002244',
        'hover_bg': '#001122',
        'text': '#ffffff',
        'text_dim': '#aaaaaa',
        'folder': '#66bbff',
        'folder_shared': '#0099ff',
        'record': '#0077cc',         # Record color (dimmer than folders)
        'record_num': '#888888',
        'attachment': '#0077cc',
        'virtual_folder': '#00aaff',
        'status': '#0099ff',
        'border': '#0066cc',
        'root': '#0099ff',
        'header_user': '#ff9900',    # Header username (orange contrast)
    },
    'magenta': {
        'primary': '#ff66ff',
        'primary_dim': '#cc44cc',
        'primary_bright': '#ff99ff',
        'secondary': '#ffaaff',
        'selection_bg': '#330033',
        'hover_bg': '#220022',
        'text': '#ffffff',
        'text_dim': '#aaaaaa',
        'folder': '#ff99ff',
        'folder_shared': '#ff66ff',
        'record': '#cc44cc',         # Record color (dimmer than folders)
        'record_num': '#888888',
        'attachment': '#cc44cc',
        'virtual_folder': '#ffaaff',
        'status': '#ff66ff',
        'border': '#cc44cc',
        'root': '#ff66ff',
        'header_user': '#66ff66',    # Header username (green contrast)
    },
    'yellow': {
        'primary': '#ffff00',
        'primary_dim': '#cccc00',
        'primary_bright': '#ffff66',
        'secondary': '#ffcc00',
        'selection_bg': '#333300',
        'hover_bg': '#222200',
        'text': '#ffffff',
        'text_dim': '#aaaaaa',
        'folder': '#ffff66',
        'folder_shared': '#ffcc00',
        'record': '#cccc00',         # Record color (dimmer than folders)
        'record_num': '#888888',
        'attachment': '#cccc00',
        'virtual_folder': '#ffff88',
        'status': '#ffff00',
        'border': '#cccc00',
        'root': '#ffff00',
        'header_user': '#66ccff',    # Header username (blue contrast)
    },
    'white': {
        'primary': '#ffffff',
        'primary_dim': '#cccccc',
        'primary_bright': '#ffffff',
        'secondary': '#dddddd',
        'selection_bg': '#444444',
        'hover_bg': '#333333',
        'text': '#ffffff',
        'text_dim': '#999999',
        'folder': '#eeeeee',
        'folder_shared': '#dddddd',
        'record': '#bbbbbb',         # Record color (dimmer than folders)
        'record_num': '#888888',
        'attachment': '#cccccc',
        'virtual_folder': '#ffffff',
        'status': '#ffffff',
        'border': '#888888',
        'root': '#ffffff',
        'header_user': '#66ccff',    # Header username (blue contrast)
    },
}

# Preferences file path
PREFS_FILE = Path.home() / '.keeper' / 'supershell_prefs.json'


def load_preferences() -> dict:
    """Load preferences from file, return defaults if not found"""
    defaults = {'color_theme': 'green'}
    try:
        if PREFS_FILE.exists():
            with open(PREFS_FILE, 'r') as f:
                prefs = json.load(f)
                # Merge with defaults
                return {**defaults, **prefs}
    except Exception as e:
        logging.debug(f"Error loading preferences: {e}")
    return defaults


def save_preferences(prefs: dict):
    """Save preferences to file"""
    try:
        PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PREFS_FILE, 'w') as f:
            json.dump(prefs, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving preferences: {e}")

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, Center, Middle
from textual.widgets import Tree, DataTable, Footer, Header, Static, Input, Label, Button
from textual.binding import Binding
from textual.screen import Screen, ModalScreen
from textual.reactive import reactive
from textual import on, work
from textual.message import Message
from textual.timer import Timer
from rich.text import Text
from textual.events import Click, MouseDown, Paste

from ..commands.base import Command


class ClickableDetailLine(Static):
    """A single line in the detail view that highlights on hover and copies on click"""

    DEFAULT_CSS = """
    ClickableDetailLine {
        width: 100%;
        height: auto;
        padding: 0 1;
    }

    ClickableDetailLine:hover {
        background: #1a1a2e;
    }

    ClickableDetailLine.has-value {
        /* Clickable lines get a subtle left border indicator */
    }

    ClickableDetailLine.has-value:hover {
        background: #16213e;
        text-style: bold;
        border-left: thick #00ff00;
    }
    """

    def __init__(self, content: str, copy_value: str = None, record_uid: str = None, is_password: bool = False, *args, **kwargs):
        """
        Create a clickable detail line.

        Args:
            content: Rich markup content to display
            copy_value: Value to copy on click (None = not copyable)
            record_uid: Record UID for password audit events
            is_password: If True, use ClipboardCommand for audit event
        """
        self.copy_value = copy_value
        self.record_uid = record_uid
        self.is_password = is_password
        classes = "has-value" if copy_value else ""
        super().__init__(content, classes=classes, *args, **kwargs)

    def on_mouse_down(self, event: MouseDown) -> None:
        """Handle mouse down to copy value - fires immediately without waiting for focus"""
        if self.copy_value:
            try:
                if self.is_password and self.record_uid:
                    # Use ClipboardCommand to generate audit event for password copy
                    cc = ClipboardCommand()
                    cc.execute(self.app.params, record=self.record_uid, output='clipboard',
                               username=None, copy_uid=False, login=False, totp=False, field=None, revision=None)
                    self.app.notify("🔑 Password copied to clipboard!", severity="information")
                else:
                    # Regular copy for non-password fields
                    pyperclip.copy(self.copy_value)
                    self.app.notify(f"Copied: {self.copy_value[:50]}{'...' if len(self.copy_value) > 50 else ''}", severity="information")
            except Exception as e:
                self.app.notify(f"Copy failed: {e}", severity="error")


class ClickableField(Static):
    """A clickable field that copies value to clipboard on click"""

    DEFAULT_CSS = """
    ClickableField {
        width: 100%;
        height: auto;
        padding: 0 1;
    }

    ClickableField:hover {
        background: #333333;
    }

    ClickableField.clickable-value:hover {
        background: #444444;
        text-style: bold;
    }
    """

    def __init__(self, label: str, value: str, copy_value: str = None,
                 label_color: str = "#aaaaaa", value_color: str = "#00ff00",
                 is_header: bool = False, indent: int = 0, *args, **kwargs):
        """
        Create a clickable field.

        Args:
            label: The field label (e.g., "Username:")
            value: The display value
            copy_value: The value to copy (defaults to value)
            label_color: Color for label
            value_color: Color for value
            is_header: If True, style as section header
            indent: Indentation level (spaces)
        """
        self.copy_value = copy_value if copy_value is not None else value

        # Build content before calling super().__init__
        indent_str = "  " * indent
        # Escape brackets for Rich markup
        safe_value = value.replace('[', '\\[').replace(']', '\\]') if value else ''
        safe_label = label.replace('[', '\\[').replace(']', '\\]') if label else ''

        if is_header:
            content = f"[bold {value_color}]{indent_str}{safe_label}[/bold {value_color}]"
        elif label:
            content = f"{indent_str}[{label_color}]{safe_label}[/{label_color}] [{value_color}]{safe_value}[/{value_color}]"
        else:
            content = f"{indent_str}[{value_color}]{safe_value}[/{value_color}]"

        # Set classes for hover effect
        classes = "clickable-value" if self.copy_value else ""

        super().__init__(content, classes=classes, *args, **kwargs)

    def on_mouse_down(self, event: MouseDown) -> None:
        """Handle mouse down to copy value - fires immediately without waiting for focus"""
        if self.copy_value:
            try:
                pyperclip.copy(self.copy_value)
                self.app.notify(f"Copied to clipboard", severity="information")
            except Exception as e:
                self.app.notify(f"Copy failed: {e}", severity="error")


class ClickableRecordUID(Static):
    """A clickable record UID that navigates to the record when clicked"""

    DEFAULT_CSS = """
    ClickableRecordUID {
        width: 100%;
        height: auto;
        padding: 0 1;
    }

    ClickableRecordUID:hover {
        background: #333344;
        text-style: bold underline;
    }
    """

    def __init__(self, label: str, record_uid: str, record_title: str = None,
                 label_color: str = "#aaaaaa", value_color: str = "#ffff00",
                 indent: int = 0, *args, **kwargs):
        """
        Create a clickable record UID that navigates to the record.

        Args:
            label: The field label (e.g., "Record UID:")
            record_uid: The UID of the record to navigate to
            record_title: Optional title to display instead of UID
            label_color: Color for label
            value_color: Color for value
            indent: Indentation level
        """
        self.record_uid = record_uid

        # Build content before calling super().__init__
        indent_str = "  " * indent
        display_value = record_title or record_uid
        safe_value = display_value.replace('[', '\\[').replace(']', '\\]')
        safe_label = label.replace('[', '\\[').replace(']', '\\]') if label else ''

        if label:
            content = f"{indent_str}[{label_color}]{safe_label}[/{label_color}] [{value_color}]{safe_value} ↗[/{value_color}]"
        else:
            content = f"{indent_str}[{value_color}]{safe_value} ↗[/{value_color}]"

        super().__init__(content, *args, **kwargs)

    def on_mouse_down(self, event: MouseDown) -> None:
        """Handle mouse down to navigate to record - fires immediately without waiting for focus"""
        # Find the app and trigger record selection
        app = self.app
        if hasattr(app, 'records') and self.record_uid in app.records:
            # Navigate to the record in the tree
            app.selected_record = self.record_uid
            app.selected_folder = None
            app._display_record_detail(self.record_uid)

            # Try to select the node in the tree
            tree = app.query_one("#folder_tree", Tree)
            app._select_record_in_tree(tree, self.record_uid)

            app.notify(f"Navigated to record", severity="information")
        else:
            # Just copy the UID if record not found
            pyperclip.copy(self.record_uid)
            app.notify(f"Record not in vault. UID copied.", severity="warning")


from ..commands.record import RecordGetUidCommand, ClipboardCommand
from ..display import bcolors
from .. import vault
from .. import utils


class PreferencesScreen(ModalScreen):
    """Modal screen for user preferences"""

    DEFAULT_CSS = """
    PreferencesScreen {
        align: center middle;
    }

    #prefs_container {
        width: 40;
        height: auto;
        max-height: 90%;
        background: #111111;
        border: solid #444444;
        padding: 1 2;
    }

    #prefs_title {
        text-align: center;
        text-style: bold;
        padding-bottom: 1;
    }

    #prefs_content {
        height: auto;
        padding: 0 1;
    }

    #prefs_footer {
        text-align: center;
        padding-top: 1;
        color: #666666;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
        Binding("q", "dismiss", "Close", show=False),
        Binding("1", "select_green", "Green", show=False),
        Binding("2", "select_blue", "Blue", show=False),
        Binding("3", "select_magenta", "Magenta", show=False),
        Binding("4", "select_yellow", "Yellow", show=False),
        Binding("5", "select_white", "White", show=False),
    ]

    def __init__(self, app_instance):
        super().__init__()
        self.app_instance = app_instance

    def compose(self) -> ComposeResult:
        current = self.app_instance.color_theme
        with Vertical(id="prefs_container"):
            yield Static("[bold cyan]⚙ Preferences[/bold cyan]", id="prefs_title")
            yield Static(f"""[green]Color Theme:[/green]
  [#00ff00]1[/#00ff00]  {'●' if current == 'green' else '○'} Green
  [#0099ff]2[/#0099ff]  {'●' if current == 'blue' else '○'} Blue
  [#ff66ff]3[/#ff66ff]  {'●' if current == 'magenta' else '○'} Magenta
  [#ffff00]4[/#ffff00]  {'●' if current == 'yellow' else '○'} Yellow
  [#ffffff]5[/#ffffff]  {'●' if current == 'white' else '○'} White""", id="prefs_content")
            yield Static("[dim]Press 1-5 to select, Esc or q to close[/dim]", id="prefs_footer")

    def action_dismiss(self):
        """Close the preferences screen"""
        self.dismiss()

    def key_escape(self):
        """Handle escape key directly"""
        self.dismiss()

    def key_q(self):
        """Handle q key directly"""
        self.dismiss()

    def action_select_green(self):
        self._apply_theme('green')

    def action_select_blue(self):
        self._apply_theme('blue')

    def action_select_magenta(self):
        self._apply_theme('magenta')

    def action_select_yellow(self):
        self._apply_theme('yellow')

    def action_select_white(self):
        self._apply_theme('white')

    def _apply_theme(self, theme_name: str):
        """Apply the selected theme and save preferences"""
        self.app_instance.set_color_theme(theme_name)
        # Save to preferences file
        prefs = load_preferences()
        prefs['color_theme'] = theme_name
        save_preferences(prefs)
        self.app_instance.notify(f"Theme changed to {theme_name}")
        self.dismiss()


class HelpScreen(ModalScreen):
    """Modal screen for help/keyboard shortcuts"""

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }

    #help_container {
        width: 90;
        height: auto;
        max-height: 90%;
        background: #111111;
        border: solid #444444;
        padding: 1 2;
    }

    #help_title {
        text-align: center;
        text-style: bold;
        padding-bottom: 1;
    }

    #help_columns {
        height: auto;
    }

    .help_column {
        width: 1fr;
        height: auto;
        padding: 0 1;
    }

    #help_footer {
        text-align: center;
        padding-top: 1;
        color: #666666;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
        Binding("q", "dismiss", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help_container"):
            yield Static("[bold cyan]⌨ Keyboard Shortcuts[/bold cyan]", id="help_title")
            with Horizontal(id="help_columns"):
                yield Static("""[green]Navigation:[/green]
  j/k ↑/↓       Move up/down
  h/l ←/→       Collapse/expand
  g / G         Top / bottom
  Ctrl+d/u      Half page
  Ctrl+e/y      Scroll line
  Esc           Clear/collapse

[green]Focus Cycling:[/green]
  Tab           Tree→Detail→Search
  Shift+Tab     Cycle backwards
  /             Focus search
  Ctrl+U        Clear search
  Esc           Focus tree

[green]General:[/green]
  ?             Help
  !             Keeper shell
  Ctrl+q        Quit""", classes="help_column")
                yield Static("""[green]Copy to Clipboard:[/green]
  p             Password
  u             Username
  c             Copy all
  w             URL
  i             Record UID

[green]Actions:[/green]
  t             Toggle JSON view
  m             Mask/Unmask
  d             Sync vault
  W             User info
  D             Device info
  P             Preferences""", classes="help_column")
            yield Static("[dim]Press Esc or q to close[/dim]", id="help_footer")

    def action_dismiss(self):
        """Close the help screen"""
        self.dismiss()

    def key_escape(self):
        """Handle escape key directly"""
        self.dismiss()

    def key_q(self):
        """Handle q key directly"""
        self.dismiss()


class SuperShellApp(App):
    """The Keeper SuperShell TUI application"""
    
    # Constants for thresholds and limits
    AUTO_EXPAND_THRESHOLD = 100  # Auto-expand tree when search results < this number
    DEVICE_DISPLAY_LIMIT = 5     # Max devices to show before truncating
    SHARE_DISPLAY_LIMIT = 10     # Max shares to show before truncating
    PAGE_DOWN_NODES = 10         # Number of nodes to move for half-page down
    PAGE_DOWN_FULL_NODES = 20    # Number of nodes to move for full-page down

    @staticmethod
    def _strip_ansi_codes(text: str) -> str:
        """Remove ANSI color codes from text"""
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)

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
        border: solid #333333;
    }

    #record_detail:focus-within {
        background: #0a0a0a;
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
            
            # Update CSS dynamically for tree selection/hover
            self._apply_theme_css()

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

        with Horizontal(id="main_container"):
            with Vertical(id="folder_panel"):
                yield Tree("[#00ff00]● My Vault[/#00ff00]", id="folder_tree")
            with Vertical(id="record_panel"):
                with VerticalScroll(id="record_detail"):
                    yield Static("", id="detail_content")
                # Fixed footer for shortcuts
                yield Static("", id="shortcuts_bar")
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
            output = self._strip_ansi_codes(output)

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
            output = self._strip_ansi_codes(output)

            if not output or output.strip() == '':
                # Fallback to basic folder info if get command didn't work
                folder = self.params.folder_cache.get(folder_uid)
                if folder:
                    folder_type = folder.get_folder_type() if hasattr(folder, 'get_folder_type') else folder.type
                    return (
                        f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]\n"
                        f"[bold {t['primary']}]{rich_escape(str(folder.name))}[/bold {t['primary']}]\n"
                        f"[{t['text_dim']}]UID:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(folder_uid))}[/{t['primary']}]\n"
                        f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]\n\n"
                        f"[{t['secondary']}]{'Type':>20}:[/{t['secondary']}]  [{t['primary']}]{rich_escape(str(folder_type))}[/{t['primary']}]\n\n"
                        f"[{t['primary_dim']}]Expand folder (press 'l' or →) to view records[/{t['primary_dim']}]"
                    )
                return "[red]Folder not found[/red]"

            # Format the output with proper alignment and theme colors
            lines = []
            lines.append(f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]")

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
                            lines.append(f"[bold {t['primary']}]{rich_escape(str(value))}[/bold {t['primary']}]")
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

            lines.append(f"\n[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]")
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
        output = self._strip_ansi_codes(output)

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
        output = self._strip_ansi_codes(output)

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

        # Render JSON header
        mount_line(f"[bold {t['primary']}]JSON View:[/bold {t['primary']}]")
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
            output = self._strip_ansi_codes(output)
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

        # Header line
        mount_line(f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]", None)

        if not output or output.strip() == '':
            # Fallback to basic folder info
            if folder:
                mount_line(f"[bold {t['primary']}]{rich_escape(str(folder.name))}[/bold {t['primary']}]", folder.name)
                mount_line(f"[{t['text_dim']}]UID:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(folder_uid))}[/{t['primary']}]", folder_uid)
                mount_line(f"[{t['text_dim']}]Type:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(folder_type))}[/{t['primary']}]", folder_type)
            mount_line(f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]", None)
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
                # Name - title
                elif key == 'Name':
                    mount_line(f"[bold {t['primary']}]{rich_escape(str(value))}[/bold {t['primary']}]", value)
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

        # Footer line
        mount_line(f"\n[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]", None)

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
            output = self._strip_ansi_codes(output)
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

        # Build formatted JSON output with clickable values
        mount_json_line(f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]", None)
        mount_json_line(f"[bold {t['primary']}]JSON View[/bold {t['primary']}] [{t['text_dim']}](press 't' for detail view)[/{t['text_dim']}]", None)
        mount_json_line(f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]", None)
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

        mount_json_line("", None)
        mount_json_line(f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]", None)

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
        tree = self.query_one("#folder_tree", Tree)
        self.search_input_active = True
        tree.add_class("search-input-active")
        self._update_search_display(perform_search=False)  # Don't change tree when entering search
        self._update_status("Type to search | Tab to navigate | Ctrl+U to clear")
        event.stop()

    @on(Click, "#user_info")
    def on_user_info_click(self, event: Click) -> None:
        """Show whoami info when user info is clicked"""
        self._display_whoami_info()
        event.stop()

    @on(Click, "#device_status_info")
    def on_device_status_click(self, event: Click) -> None:
        """Show device info when Stay Logged In / Logout section is clicked"""
        self._display_device_info()
        event.stop()

    def on_paste(self, event: Paste) -> None:
        """Handle paste events (Cmd+V on Mac, Ctrl+V on Windows/Linux)"""
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
                display_text = f"> {rich_escape(self.search_input_text)}[blink]▎[/blink]"
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
        """Handle keyboard events"""
        search_bar = self.query_one("#search_bar")
        tree = self.query_one("#folder_tree", Tree)

        # Global key handlers that work regardless of focus
        # ! exits to regular shell (works from any widget)
        if event.character == "!" and not self.search_input_active:
            self.exit("Exited to Keeper shell. Type 'supershell' or 'ss' to return.")
            event.prevent_default()
            event.stop()
            return

        # Handle Tab/Shift+Tab cycling: Tree → Detail → Search (counterclockwise)
        detail_scroll = self.query_one("#record_detail", VerticalScroll)

        # Handle search input mode Tab/Shift+Tab first (search_input_active takes priority)
        if self.search_input_active:
            if event.key == "tab":
                # Search input → Tree (forward in cycle)
                self.search_input_active = False
                tree.remove_class("search-input-active")
                search_display = self.query_one("#search_display", Static)
                if self.search_input_text:
                    search_display.update(rich_escape(self.search_input_text))
                else:
                    search_display.update("[dim]Search...[/dim]")
                tree.focus()
                self._update_status("Navigate with j/k | Tab to detail | ? for help")
                event.prevent_default()
                event.stop()
                return
            elif event.key == "shift+tab":
                # Search input → Detail pane (backwards in cycle)
                self.search_input_active = False
                tree.remove_class("search-input-active")
                search_display = self.query_one("#search_display", Static)
                if self.search_input_text:
                    search_display.update(rich_escape(self.search_input_text))
                else:
                    search_display.update("[dim]Search...[/dim]")
                detail_scroll.focus()
                self._update_status("Detail pane | Tab to search | Shift+Tab to tree")
                event.prevent_default()
                event.stop()
                return

        if detail_scroll.has_focus:
            if event.key == "tab":
                # Detail pane → Search input
                self.search_input_active = True
                tree.add_class("search-input-active")
                self._update_search_display(perform_search=False)  # Don't change tree when entering search
                self._update_status("Type to search | Tab to tree | Ctrl+U to clear")
                event.prevent_default()
                event.stop()
                return
            elif event.key == "shift+tab":
                # Detail pane → Tree
                tree.focus()
                self._update_status("Navigate with j/k | Tab to detail | ? for help")
                event.prevent_default()
                event.stop()
                return
            elif event.key == "escape":
                tree.focus()
                event.prevent_default()
                event.stop()
                return
            elif event.key == "ctrl+y":
                # Ctrl+Y scrolls viewport up (like vim)
                detail_scroll.scroll_relative(y=-1)
                event.prevent_default()
                event.stop()
                return
            elif event.key == "ctrl+e":
                # Ctrl+E scrolls viewport down (like vim)
                detail_scroll.scroll_relative(y=1)
                event.prevent_default()
                event.stop()
                return

        if search_bar.styles.display != "none":
            # Search bar is active

            # If we're navigating results (not typing), let tree/app handle its keys
            if not self.search_input_active and tree.has_focus:
                # Handle left/right arrow keys for expand/collapse
                if event.key == "left":
                    if tree.cursor_node and tree.cursor_node.allow_expand:
                        tree.cursor_node.collapse()
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "right":
                    if tree.cursor_node and tree.cursor_node.allow_expand:
                        tree.cursor_node.expand()
                    event.prevent_default()
                    event.stop()
                    return
                # Navigation keys for tree
                if event.key in ("j", "k", "h", "l", "up", "down", "enter", "space"):
                    return
                # Action keys (copy, toggle view, etc.) - let them pass through
                if event.key in ("t", "c", "u", "w", "i", "y", "d", "g", "p", "question_mark"):
                    return
                # Shift+G for go to bottom
                if event.character == "G":
                    return
                # Tab switches to detail pane
                if event.key == "tab":
                    detail_scroll.focus()
                    self._update_status("Detail pane | Tab to search | Shift+Tab to tree")
                    event.prevent_default()
                    event.stop()
                    return
                # Shift+Tab switches to search input
                elif event.key == "shift+tab":
                    self.search_input_active = True
                    tree.add_class("search-input-active")
                    self._update_search_display(perform_search=False)  # Don't change tree when entering search
                    self._update_status("Type to search | Tab to tree | Ctrl+U to clear")
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "slash":
                    # Switch back to search input mode
                    self.search_input_active = True
                    tree.add_class("search-input-active")
                    self._update_search_display(perform_search=False)  # Don't change tree when entering search
                    event.prevent_default()
                    event.stop()
                    return

            # Ctrl+U clears the search input (like bash)
            # Reset tree to show all items when clearing search
            if event.key == "ctrl+u" and self.search_input_active:
                self.search_input_text = ""
                self._update_search_display(perform_search=False)  # Just update display
                self._perform_live_search("")  # Reset tree to show all
                event.prevent_default()
                event.stop()
                return

            # "/" to switch to search input mode (works from anywhere when search bar visible)
            if event.key == "slash" and not self.search_input_active:
                self.search_input_active = True
                tree.add_class("search-input-active")
                self._update_search_display(perform_search=False)  # Don't change tree when entering search
                event.prevent_default()
                event.stop()
                return

            if event.key == "escape":
                # Clear search and move focus to tree (don't hide search bar)
                self.search_input_text = ""
                self.search_input_active = False
                tree.remove_class("search-input-active")
                self._perform_live_search("")  # Reset to show all

                # Update search display to show placeholder
                search_display = self.query_one("#search_display", Static)
                search_display.update("[dim]Search... (Tab or /)[/dim]")
                results_label = self.query_one("#search_results_label", Static)
                results_label.update("")

                # Restore previous selection
                self.selected_record = self.pre_search_selected_record
                self.selected_folder = self.pre_search_selected_folder
                self._restore_tree_selection(tree)

                tree.focus()
                self._update_status("Navigate with j/k | Tab to detail | ? for help")
                event.prevent_default()
                event.stop()
            elif event.key in ("enter", "down"):
                # Move focus to tree to navigate results
                # Switch to navigation mode
                self.search_input_active = False

                # Show tree selection - remove the class that hides it
                tree.remove_class("search-input-active")

                # Remove cursor from search display
                search_display = self.query_one("#search_display", Static)
                if self.search_input_text:
                    search_display.update(rich_escape(self.search_input_text))  # No cursor
                else:
                    search_display.update("[dim]Search...[/dim]")

                # Force focus to tree
                self.set_focus(tree)
                tree.focus()

                self._update_status("Navigate results with j/k | / to edit search | ESC to close")
                event.prevent_default()
                event.stop()
                return  # Return immediately to avoid further processing
            elif event.key == "backspace":
                # Delete last character
                if self.search_input_text:
                    self.search_input_text = self.search_input_text[:-1]
                    self._update_search_display()
                event.prevent_default()
                event.stop()
            elif self.search_input_active and event.character and event.character.isprintable():
                # Only add characters when search input is active (not when navigating results)
                self.search_input_text += event.character
                self._update_search_display()
                event.prevent_default()
                event.stop()
        else:
            # Search bar is NOT active - handle escape and command mode

            # Handle command mode (vim :N navigation)
            if self.command_mode:
                if event.key == "escape":
                    # Cancel command mode
                    self.command_mode = False
                    self.command_buffer = ""
                    self._update_status("Command cancelled")
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "enter":
                    # Execute command
                    self._execute_command(self.command_buffer)
                    self.command_mode = False
                    self.command_buffer = ""
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "backspace":
                    # Delete last character
                    if self.command_buffer:
                        self.command_buffer = self.command_buffer[:-1]
                        self._update_status(f":{self.command_buffer}")
                    else:
                        # Exit command mode if buffer is empty
                        self.command_mode = False
                        self._update_status("Navigate with j/k | / to search | ? for help")
                    event.prevent_default()
                    event.stop()
                    return
                elif event.character and event.character.isdigit():
                    # Accept digits for line number navigation
                    self.command_buffer += event.character
                    self._update_status(f":{self.command_buffer}")
                    event.prevent_default()
                    event.stop()
                    return
                else:
                    # Invalid character for command mode
                    event.prevent_default()
                    event.stop()
                    return

            # Enter command mode with :
            if event.character == ":":
                self.command_mode = True
                self.command_buffer = ""
                self._update_status(":")
                event.prevent_default()
                event.stop()
                return

            # Handle arrow keys for expand/collapse when search is not active
            if tree.has_focus:
                if event.key == "left":
                    if tree.cursor_node and tree.cursor_node.allow_expand:
                        tree.cursor_node.collapse()
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "right":
                    if tree.cursor_node and tree.cursor_node.allow_expand:
                        tree.cursor_node.expand()
                    event.prevent_default()
                    event.stop()
                    return

            if event.key == "escape":
                # Escape: collapse current folder or go to parent, stop at root
                self._collapse_current_or_parent(tree)
                event.prevent_default()
                event.stop()
                return

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
        """Execute vim-style command (e.g., :20 to go to line 20)"""
        command = command.strip()

        # Try to parse as line number
        try:
            line_num = int(command)
            self._goto_line(line_num)
        except ValueError:
            self._update_status(f"Unknown command: {command}")

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

    def check_action(self, action: str, parameters: tuple) -> bool | None:
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
                pyperclip.copy(record['login'])
                self.notify("👤 Username copied to clipboard!", severity="information")
            else:
                self.notify("⚠️  No username found for this record", severity="warning")
        else:
            self.notify("⚠️  No record selected", severity="warning")

    def action_copy_url(self):
        """Copy URL of selected record to clipboard"""
        if self.selected_record and self.selected_record in self.records:
            record = self.records[self.selected_record]
            if 'login_url' in record:
                pyperclip.copy(record['login_url'])
                self.notify("🔗 URL copied to clipboard!", severity="information")
            else:
                self.notify("⚠️  No URL found for this record", severity="warning")
        else:
            self.notify("⚠️  No record selected", severity="warning")

    def action_copy_uid(self):
        """Copy UID of selected record or folder to clipboard"""
        if self.selected_record:
            pyperclip.copy(self.selected_record)
            self.notify("📋 Record UID copied to clipboard!", severity="information")
        elif self.selected_folder:
            pyperclip.copy(self.selected_folder)
            self.notify("📋 Folder UID copied to clipboard!", severity="information")
        else:
            self.notify("⚠️  No record or folder selected", severity="warning")

    def action_copy_record(self):
        """Copy entire record contents to clipboard (formatted or JSON based on view mode)"""
        if self.selected_record:
            try:
                # Check if it's a Secrets Manager app record
                if self.selected_record in self.app_record_uids:
                    # For Secrets Manager apps, copy the app data in JSON format
                    from ..proto import APIRequest_pb2, enterprise_pb2
                    from .. import api, utils
                    import json
                    
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
                        pyperclip.copy(formatted)
                        self.notify("📋 Secrets Manager app JSON copied to clipboard!", severity="information")
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
                        pyperclip.copy(formatted)
                        self.notify("📋 Secrets Manager app details copied to clipboard!", severity="information")
                else:
                    # Regular record handling
                    record_data = self.records.get(self.selected_record, {})
                    has_password = bool(record_data.get('password'))

                    if self.view_mode == 'json':
                        # Copy JSON format (with actual password, not masked)
                        output = self._get_record_output(self.selected_record, format_type='json')
                        output = self._strip_ansi_codes(output)
                        json_obj = json.loads(output)
                        formatted = json.dumps(json_obj, indent=2)
                        pyperclip.copy(formatted)
                        # Generate audit event since JSON contains the password
                        if has_password:
                            self.params.queue_audit_event('copy_password', record_uid=self.selected_record)
                        self.notify("📋 JSON copied to clipboard!", severity="information")
                    else:
                        # Copy formatted text (without Rich markup)
                        content = self._format_record_for_tui(self.selected_record)
                        # Strip Rich markup for plain text clipboard
                        import re
                        plain = re.sub(r'\[/?[^\]]+\]', '', content)
                        pyperclip.copy(plain)
                        # Generate audit event if record has password (detail view includes password)
                        if has_password:
                            self.params.queue_audit_event('copy_password', record_uid=self.selected_record)
                        self.notify("📋 Record contents copied to clipboard!", severity="information")
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
                LoginCommand().execute(params, email=params.user, password=params.password, new_login=False)

                if not params.session_token:
                    logging.error("\nLogin failed or was cancelled.")
                    return

                # Sync vault data with spinner
                sync_spinner = Spinner("Syncing vault data...")
                sync_spinner.start()
                try:
                    from .utils import SyncDownCommand
                    SyncDownCommand().execute(params)
                    sync_spinner.stop("Vault synced!")
                except Exception as e:
                    sync_spinner.stop()
                    raise

                print()  # Blank line before TUI

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
