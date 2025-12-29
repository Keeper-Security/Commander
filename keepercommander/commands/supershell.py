"""
Keeper SuperShell - A Matrix-style full-screen terminal interface for Keeper vault
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
        'record': '#00ff00',         # Record color
        'record_num': '#888888',     # Record number
        'attachment': '#00cc00',     # Attachment color
        'virtual_folder': '#00ff88', # Virtual folder
        'status': '#00ff00',         # Status bar
        'border': '#00aa00',         # Borders
        'root': '#00ff00',           # Root node
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
        'record': '#0099ff',
        'record_num': '#888888',
        'attachment': '#0077cc',
        'virtual_folder': '#00aaff',
        'status': '#0099ff',
        'border': '#0066cc',
        'root': '#0099ff',
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
        'record': '#ff66ff',
        'record_num': '#888888',
        'attachment': '#cc44cc',
        'virtual_folder': '#ffaaff',
        'status': '#ff66ff',
        'border': '#cc44cc',
        'root': '#ff66ff',
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
        'record': '#ffff00',
        'record_num': '#888888',
        'attachment': '#cccc00',
        'virtual_folder': '#ffff88',
        'status': '#ffff00',
        'border': '#cccc00',
        'root': '#ffff00',
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
        'record': '#ffffff',
        'record_num': '#888888',
        'attachment': '#cccccc',
        'virtual_folder': '#ffffff',
        'status': '#ffffff',
        'border': '#888888',
        'root': '#ffffff',
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
from textual.events import Click

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

    def on_click(self, event: Click) -> None:
        """Handle click to copy value"""
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

    def on_click(self, event: Click) -> None:
        """Handle click to copy value"""
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

    def on_click(self, event: Click) -> None:
        """Handle click to navigate to record"""
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
from .. import api
from .. import vault
from .. import loginv3
from .. import utils
from ..proto import APIRequest_pb2


class MatrixRain(Static):
    """Matrix-style falling characters animation"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.columns = []
        self.timer = None

    def on_mount(self) -> None:
        """Start the animation when mounted"""
        self.timer = self.set_interval(0.1, self.update_rain)

    def update_rain(self) -> None:
        """Update the rain animation"""
        # Matrix characters
        chars = "ｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        width = self.size.width
        height = self.size.height

        if not self.columns or len(self.columns) != width:
            self.columns = [{'y': random.randint(-height, 0), 'speed': random.randint(1, 3)} for _ in range(width)]

        # Build the rain display
        lines = [[' ' for _ in range(width)] for _ in range(height)]

        for x, col in enumerate(self.columns):
            if 0 <= col['y'] < height:
                lines[col['y']][x] = random.choice(chars)

            # Move column down
            col['y'] += col['speed']
            if col['y'] >= height + 5:
                col['y'] = random.randint(-height, -1)
                col['speed'] = random.randint(1, 3)

        # Render as text
        display = '\n'.join([''.join(line) for line in lines])
        self.update(f"[green]{display}[/green]")


class LoginScreen(ModalScreen):
    """Modal screen for Matrix-style login with animation"""

    DEFAULT_CSS = """
    LoginScreen {
        align: center middle;
        background: $surface;
    }

    #matrix_bg {
        width: 100%;
        height: 100%;
        color: #003300;
    }

    #login_container {
        width: 70;
        height: auto;
        border: thick $success;
        background: $surface;
        padding: 2;
    }

    #matrix_title {
        text-align: center;
        padding: 1;
        color: $success;
        text-style: bold;
    }

    .login_label {
        color: $accent;
        text-style: bold;
        margin: 1 0 0 0;
    }

    .login_input {
        margin: 0 0 1 0;
        border: solid $success;
    }

    #login_button {
        margin: 1 0;
        width: 100%;
    }

    #login_status {
        text-align: center;
        color: $warning;
        height: auto;
        margin: 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel", show=False),
    ]

    def __init__(self, params):
        super().__init__()
        self.params = params
        self.login_in_progress = False

    def compose(self) -> ComposeResult:
        """Create the login screen"""
        yield MatrixRain(id="matrix_bg")
        with Center():
            with Middle():
                with Vertical(id="login_container"):
                    yield Static(self._get_ascii_title(), id="matrix_title")
                    yield Label("Email:", classes="login_label")
                    yield Input(placeholder="your.email@example.com", id="email_input", classes="login_input")
                    yield Label("Password:", classes="login_label")
                    yield Input(placeholder="Enter your password", password=True, id="password_input", classes="login_input")
                    yield Button("⚡ LOGIN TO THE MATRIX ⚡", variant="success", id="login_button")
                    yield Static("", id="login_status")

    def _get_ascii_title(self) -> str:
        """Get Matrix-style ASCII art title"""
        return """[bold green]
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██╗  ██╗███████╗███████╗██████╗ ███████╗██████╗        ║
║   ██║ ██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗       ║
║   █████╔╝ █████╗  █████╗  ██████╔╝█████╗  ██████╔╝       ║
║   ██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗       ║
║   ██║  ██╗███████╗███████╗██║     ███████╗██║  ██║       ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝       ║
║                                                           ║
║              ███████╗██╗   ██╗██████╗ ███████╗██████╗    ║
║              ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗   ║
║              ███████╗██║   ██║██████╔╝█████╗  ██████╔╝   ║
║              ╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗   ║
║              ███████║╚██████╔╝██║     ███████╗██║  ██║   ║
║              ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝   ║
║                                                           ║
║               ███████╗██╗  ██╗███████╗██╗     ██╗        ║
║               ██╔════╝██║  ██║██╔════╝██║     ██║        ║
║               ███████╗███████║█████╗  ██║     ██║        ║
║               ╚════██║██╔══██║██╔══╝  ██║     ██║        ║
║               ███████║██║  ██║███████╗███████╗███████╗   ║
║               ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ║
║                                                           ║
║             [cyan]Wake up, Neo... The Matrix has you...[/cyan]       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
[/bold green]"""

    def on_mount(self):
        """Focus email input when mounted"""
        self.query_one("#email_input", Input).focus()

    @on(Button.Pressed, "#login_button")
    async def handle_login(self):
        """Handle login button press"""
        if self.login_in_progress:
            return

        email_input = self.query_one("#email_input", Input)
        password_input = self.query_one("#password_input", Input)
        status = self.query_one("#login_status", Static)

        email = email_input.value.strip()
        password = password_input.value

        if not email:
            status.update("[red]⚠ Email is required[/red]")
            email_input.focus()
            return

        if not password:
            status.update("[red]⚠ Password is required[/red]")
            password_input.focus()
            return

        self.login_in_progress = True
        status.update("[yellow]⚡ Authenticating...[/yellow]")

        # Perform login
        try:
            self.params.user = email.lower()
            self.params.password = password

            # Run login in executor to avoid blocking
            await self.run_worker(self._do_login, exclusive=True)
        except Exception as e:
            status.update(f"[red]⚠ Login failed: {str(e)}[/red]")
            self.login_in_progress = False

    async def _do_login(self):
        """Perform the actual login (runs in thread)"""
        try:
            # Login using the API
            api.login(self.params, new_login=False)

            if self.params.session_token:
                # Login successful, dismiss with success
                self.dismiss(True)
            else:
                # Login failed
                status = self.query_one("#login_status", Static)
                status.update("[red]⚠ Login failed. Please check credentials.[/red]")
                self.login_in_progress = False
        except KeyboardInterrupt:
            status = self.query_one("#login_status", Static)
            status.update("[red]⚠ Login cancelled[/red]")
            self.login_in_progress = False
            raise
        except Exception as e:
            status = self.query_one("#login_status", Static)
            status.update(f"[red]⚠ Error: {str(e)}[/red]")
            self.login_in_progress = False

    @on(Input.Submitted)
    async def on_input_submitted(self, event: Input.Submitted):
        """Handle Enter key in inputs"""
        if event.input.id == "email_input":
            self.query_one("#password_input", Input).focus()
        elif event.input.id == "password_input":
            await self.handle_login()

    def action_dismiss(self):
        """Cancel login"""
        if not self.login_in_progress:
            self.dismiss(False)


class SyncScreen(ModalScreen):
    """Loading screen while syncing vault data"""

    DEFAULT_CSS = """
    SyncScreen {
        align: center middle;
        background: $surface;
    }

    #sync_matrix_bg {
        width: 100%;
        height: 100%;
        color: #003300;
    }

    #sync_container {
        width: 60;
        height: 20;
        border: thick $success;
        background: $surface;
        padding: 2;
    }

    #sync_title {
        text-align: center;
        color: $success;
        text-style: bold;
        padding: 1;
    }

    #sync_spinner {
        text-align: center;
        color: $accent;
        padding: 1;
    }

    #sync_status {
        text-align: center;
        color: $warning;
        padding: 1;
    }
    """

    def __init__(self, params):
        super().__init__()
        self.params = params
        self.spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_idx = 0

    def compose(self) -> ComposeResult:
        """Create the sync screen"""
        yield MatrixRain(id="sync_matrix_bg")
        with Center():
            with Middle():
                with Vertical(id="sync_container"):
                    yield Static("[bold green]⚡ SYNCING VAULT DATA ⚡[/bold green]", id="sync_title")
                    yield Static("", id="sync_spinner")
                    yield Static("[yellow]Downloading encrypted records...[/yellow]", id="sync_status")

    def on_mount(self):
        """Start sync and spinner animation"""
        self.set_interval(0.1, self.update_spinner)
        self.run_worker(self._do_sync, exclusive=True)

    def update_spinner(self):
        """Update the loading spinner"""
        spinner = self.query_one("#sync_spinner", Static)
        spinner.update(f"[cyan]{self.spinner_frames[self.spinner_idx]} Loading...[/cyan]")
        self.spinner_idx = (self.spinner_idx + 1) % len(self.spinner_frames)

    async def _do_sync(self):
        """Perform vault sync"""
        try:
            status = self.query_one("#sync_status", Static)

            # Sync vault data
            status.update("[yellow]⚡ Downloading vault structure...[/yellow]")
            await asyncio.sleep(0.3)

            from .utils import SyncDownCommand
            SyncDownCommand().execute(self.params)

            status.update("[green]✓ Vault data synchronized![/green]")
            await asyncio.sleep(0.5)

            # Success - dismiss and show main app
            self.dismiss(True)
        except Exception as e:
            status = self.query_one("#sync_status", Static)
            status.update(f"[red]⚠ Sync failed: {str(e)}[/red]")
            await asyncio.sleep(2)
            self.dismiss(False)


class RecordDetailScreen(ModalScreen):
    """Modal screen to display record details with Matrix styling"""

    @staticmethod
    def _strip_ansi_codes(text: str) -> str:
        """Remove ANSI color codes from text"""
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)

    DEFAULT_CSS = """
    RecordDetailScreen {
        align: center middle;
    }

    #detail_container {
        width: 80;
        height: auto;
        max-height: 80%;
        border: thick $success;
        background: $surface;
        padding: 1 2;
    }

    #detail_title {
        background: $success;
        color: $surface;
        text-align: center;
        padding: 1;
        text-style: bold;
    }

    #detail_content {
        height: auto;
        max-height: 60;
        padding: 1;
        color: $success;
    }

    .detail_field {
        margin: 1 0;
    }

    .detail_label {
        color: $accent;
        text-style: bold;
    }

    .detail_value {
        color: $success;
    }
    """

    BINDINGS = [
        Binding("escape,q", "dismiss", "Close", show=True),
        Binding("c", "copy_password", "Copy Password", show=True),
        Binding("u", "copy_username", "Copy Username", show=True),
        Binding("w", "copy_url", "Copy URL", show=True),
    ]

    def __init__(self, record_data: Dict[str, Any], params, record_uid: str):
        super().__init__()
        self.record_data = record_data
        self.params = params
        self.record_uid = record_uid

    def compose(self) -> ComposeResult:
        """Create the modal content"""
        with Vertical(id="detail_container"):
            yield Static(f"📋 {self.record_data.get('title', 'Record Details')}", id="detail_title")
            with VerticalScroll(id="detail_content"):
                yield self._build_record_details()

    def _get_record_output(self, format_type: str = 'detail') -> str:
        """Get record output using Commander's get command"""
        try:
            # Create a StringIO buffer to capture stdout
            stdout_buffer = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_buffer

            # Execute the get command with unmask=True for full view
            get_cmd = RecordGetUidCommand()
            get_cmd.execute(self.params, uid=self.record_uid, format=format_type, unmask=True)

            # Restore stdout
            sys.stdout = old_stdout

            # Get the captured output
            output = stdout_buffer.getvalue()
            return output

        except Exception as e:
            sys.stdout = old_stdout
            logging.error(f"Error getting record output: {e}", exc_info=True)
            return f"Error getting record: {str(e)}"

    def _build_record_details(self) -> Static:
        """Build the record details display using Commander's get command"""
        try:
            # Get the record output using Commander's get command (unmasked for full view)
            output = self._get_record_output(format_type='detail')
            # Strip ANSI codes
            output = self._strip_ansi_codes(output)
            # Escape brackets for Rich markup
            output = output.replace('[', '\\[').replace(']', '\\]')
            content = f"[green]{output}[/green]"
            return Static(content)
        except Exception as e:
            logging.error(f"Error building record details: {e}", exc_info=True)
            return Static(f"[red]Error displaying record:[/red]\n{str(e)}")

    def action_copy_password(self):
        """Copy password to clipboard using clipboard-copy command (generates audit event)"""
        try:
            # Use ClipboardCommand to copy password - this generates the audit event
            cc = ClipboardCommand()
            cc.execute(self.params, record=self.record_uid, output='clipboard',
                       username=None, copy_uid=False, login=False, totp=False, field=None, revision=None)
            self.app.notify("🔑 Password copied to clipboard!", severity="information")
        except Exception as e:
            logging.debug(f"ClipboardCommand error: {e}")
            self.app.notify("⚠️ No password found for this record", severity="warning")

    def action_copy_username(self):
        """Copy username to clipboard"""
        if 'login' in self.record_data:
            pyperclip.copy(self.record_data['login'])
            self.app.notify("👤 Username copied to clipboard!", severity="information")

    def action_copy_url(self):
        """Copy URL to clipboard"""
        if 'login_url' in self.record_data:
            pyperclip.copy(self.record_data['login_url'])
            self.app.notify("🔗 URL copied to clipboard!", severity="information")

    def action_dismiss(self):
        """Close the modal"""
        self.dismiss()


class SearchScreen(ModalScreen):
    """Modal screen for searching records with live filtering"""

    DEFAULT_CSS = """
    SearchScreen {
        align: left top;
        background: rgba(0, 0, 0, 0);
    }

    #search_container {
        width: 100%;
        height: 1;
        dock: top;
        background: rgba(0, 20, 0, 0.7);
        border: none;
        padding: 0;
    }

    #search_input {
        width: 70%;
        border: none;
        background: rgba(0, 0, 0, 0);
        color: #ffffff;
        padding: 0 1;
        height: 1;
    }

    #search_results_label {
        width: 30%;
        color: #aaaaaa;
        text-align: right;
        padding: 0 1;
        height: 1;
        background: rgba(0, 0, 0, 0);
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel", show=False),
        Binding("enter", "dismiss", "Done", show=False),
    ]

    def __init__(self, app_instance):
        super().__init__()
        self.app_instance = app_instance
        self.result_count = 0

    def compose(self) -> ComposeResult:
        with Horizontal(id="search_container"):
            yield Input(placeholder="🔍 Search...", id="search_input")
            yield Static("", id="search_results_label")

    def on_mount(self):
        """Focus the input when mounted"""
        self.query_one("#search_input", Input).focus()

    def on_input_changed(self, event: Input.Changed):
        """Handle search input changes in real-time"""
        search_query = event.value
        # Call parent app to filter results
        self.result_count = self.app_instance._perform_live_search(search_query)
        t = self.app_instance.theme_colors

        # Update results label with theme colors
        results_label = self.query_one("#search_results_label", Static)
        if search_query:
            if self.result_count == 0:
                results_label.update(f"[#ff0000]No matches found[/#ff0000]")
            elif self.result_count == 1:
                results_label.update(f"[{t['primary']}]1 match found[/{t['primary']}]")
            else:
                results_label.update(f"[{t['primary']}]{self.result_count} matches found[/{t['primary']}]")
        else:
            results_label.update(f"[{t['text_dim']}]Start typing to search...[/{t['text_dim']}]")

    def action_dismiss(self):
        """Close search and restore full view"""
        # Clear search when closing
        self.app_instance._perform_live_search("")
        self.dismiss()


class PreferencesScreen(ModalScreen):
    """Modal screen for user preferences"""

    DEFAULT_CSS = """
    PreferencesScreen {
        align: center middle;
    }

    #prefs_container {
        width: 50;
        height: auto;
        background: #111111;
        border: solid #444444;
        padding: 1 2;
    }

    #prefs_title {
        text-align: center;
        text-style: bold;
        padding-bottom: 1;
    }

    .theme_option {
        width: 100%;
        height: 3;
        margin: 0 0 1 0;
        content-align: center middle;
    }

    .theme_option:hover {
        background: #333333;
    }

    .theme_selected {
        border: solid;
    }

    #close_btn {
        margin-top: 1;
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
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
            yield Static("[bold]⚙ Preferences[/bold]", id="prefs_title")
            yield Static("[dim]Select color theme (1-5):[/dim]")
            yield Button(f"{'●' if current == 'green' else '○'} [#00ff00]1. Green[/#00ff00]", id="btn_green", classes="theme_option")
            yield Button(f"{'●' if current == 'blue' else '○'} [#0099ff]2. Blue[/#0099ff]", id="btn_blue", classes="theme_option")
            yield Button(f"{'●' if current == 'magenta' else '○'} [#ff66ff]3. Magenta[/#ff66ff]", id="btn_magenta", classes="theme_option")
            yield Button(f"{'●' if current == 'yellow' else '○'} [#ffff00]4. Yellow[/#ffff00]", id="btn_yellow", classes="theme_option")
            yield Button(f"{'●' if current == 'white' else '○'} [#ffffff]5. White[/#ffffff]", id="btn_white", classes="theme_option")
            yield Button("Close [ESC]", id="close_btn", variant="primary")

    @on(Button.Pressed, "#btn_green")
    def select_green_btn(self):
        self._apply_theme('green')

    @on(Button.Pressed, "#btn_blue")
    def select_blue_btn(self):
        self._apply_theme('blue')

    @on(Button.Pressed, "#btn_magenta")
    def select_magenta_btn(self):
        self._apply_theme('magenta')

    @on(Button.Pressed, "#btn_yellow")
    def select_yellow_btn(self):
        self._apply_theme('yellow')

    @on(Button.Pressed, "#btn_white")
    def select_white_btn(self):
        self._apply_theme('white')

    @on(Button.Pressed, "#close_btn")
    def close_prefs(self):
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
        width: 70;
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

    #help_content {
        height: auto;
        padding: 0 1;
    }

    #help_close_btn {
        margin-top: 1;
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
        Binding("q", "dismiss", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help_container"):
            yield Static("[bold cyan]⌨ Keyboard Shortcuts[/bold cyan]", id="help_title")
            yield Static("""[green]Navigation:[/green]
  j/k or ↑/↓    Move up/down
  h/l or ←/→    Collapse/expand folder
  g / G         Go to top / bottom
  Ctrl+d/u      Half page down/up
  :N            Go to line N (vim style)
  Esc           Collapse folder / go to parent

[green]Actions:[/green]
  /             Search records
  t             Toggle Detail/JSON view
  d             Sync vault data
  r             Refresh display
  p             Preferences (color theme)

[green]Copy to Clipboard:[/green]
  c             Password
  u             Username
  w             URL
  i             Record UID
  y             Copy entire record

[green]General:[/green]
  ?             Show this help
  q             Quit SuperShell""", id="help_content")
            yield Button("Close [ESC]", id="help_close_btn", variant="primary")

    @on(Button.Pressed, "#help_close_btn")
    def close_help(self):
        self.dismiss()

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
    """The Matrix-style Keeper SuperShell TUI application"""

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
        display: none;
    }

    #search_display {
        width: 70%;
        background: #222222;
        color: #ffffff;
        padding: 0 2;
        height: 3;
    }

    #search_results_label {
        width: 30%;
        color: #aaaaaa;
        text-align: right;
        padding: 0 2;
        height: 1;
        background: #222222;
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
        Binding("q", "quit", "Quit", show=False),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("d", "sync_vault", "Sync", show=False),
        Binding("/", "search", "Search", show=False),
        Binding("p", "show_preferences", "Preferences", show=False),
        Binding("c", "copy_password", "Copy Password", show=False),
        Binding("u", "copy_username", "Copy Username", show=False),
        Binding("w", "copy_url", "Copy URL", show=False),
        Binding("i", "copy_uid", "Copy UID", show=False),
        Binding("y", "copy_record", "Copy Record", show=False),
        Binding("t", "toggle_view_mode", "Toggle JSON", show=False),
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
    ]

    def __init__(self, params):
        super().__init__()
        self.params = params
        self.records = {}
        self.record_to_folder = {}
        self.records_in_subfolders = set()  # Records in actual subfolders (not root)
        self.file_attachment_to_parent = {}  # Maps attachment_uid -> parent_record_uid
        self.record_file_attachments = {}  # Maps record_uid -> list of attachment_uids
        self.app_record_uids = set()  # Set of Secrets Manager app record UIDs
        self.current_folder = None
        self.selected_record = None
        self.selected_folder = None
        self.view_mode = 'detail'  # 'detail' or 'json'
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
            # Refresh the tree to apply new colors
            self._setup_folder_tree()
            # Update CSS dynamically for tree selection/hover
            self._apply_theme_css()

    def _apply_theme_css(self):
        """Apply dynamic CSS based on current theme"""
        t = self.theme_colors

        try:
            # Update detail content - will be refreshed when record is selected
            if self.selected_record:
                self._display_record_detail(self.selected_record)
            elif self.selected_folder:
                self._display_folder_with_clickable_fields(self.selected_folder)

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
        logging.info("SuperShell on_mount called")

        # Sync vault data if needed
        if not hasattr(self.params, 'record_cache') or not self.params.record_cache:
            from .utils import SyncDownCommand
            try:
                logging.info("Syncing vault data...")
                SyncDownCommand().execute(self.params)
            except Exception as e:
                logging.error(f"Sync failed: {e}", exc_info=True)
                self.exit(message=f"Sync failed: {str(e)}")
                return

        try:
            # Load vault data
            logging.info("Loading vault data...")
            self._load_vault_data()

            # Setup folder tree with records
            logging.info("Setting up folder tree...")
            self._setup_folder_tree()

            # Apply theme CSS after components are mounted
            self._apply_theme_css()

            # Update initial content with welcome/help and shortcuts bar
            t = self.theme_colors
            detail_widget = self.query_one("#detail_content", Static)
            help_content = f"""[bold {t['primary']}]● Keeper SuperShell[/bold {t['primary']}]

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
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]:N[/{t['primary']}] - Go to line N (e.g., :20)
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]Ctrl+d/u[/{t['primary']}] - Half page down/up

[bold {t['primary_bright']}]Quick Actions[/bold {t['primary_bright']}]
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]c[/{t['primary']}] - Copy password
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]u[/{t['primary']}] - Copy username
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]w[/{t['primary']}] - Copy URL
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]t[/{t['primary']}] - Toggle Detail/JSON view
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]d[/{t['primary']}] - Sync vault from server

[{t['text_dim']}]Press [/{t['text_dim']}][{t['primary']}]?[/{t['primary']}][{t['text_dim']}] for full keyboard shortcuts[/{t['text_dim']}]"""
            detail_widget.update(help_content)

            # Initialize shortcuts bar
            self._update_shortcuts_bar()

            # Focus the folder tree so vim keys work immediately
            self.query_one("#folder_tree", Tree).focus()

            logging.info("SuperShell ready!")
            self._update_status("Navigate: j/k  Expand: l  Search: /  Help: ?")
        except Exception as e:
            logging.error(f"Error initializing SuperShell: {e}", exc_info=True)
            self.exit(message=f"Error: {str(e)}")

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

        # Fetch Secrets Manager app UIDs from API (definitive list)
        self.app_record_uids = set()
        try:
            rs = api.communicate_rest(self.params, None, 'vault/get_applications_summary',
                                      rs_type=APIRequest_pb2.GetApplicationsSummaryResponse)
            for app_summary in rs.applicationSummary:
                app_uid = utils.base64_url_encode(app_summary.appRecordUid)
                self.app_record_uids.add(app_uid)
            logging.info(f"Found {len(self.app_record_uids)} Secrets Manager apps")
        except Exception as e:
            logging.debug(f"Could not fetch app list: {e}")

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

                        # Extract fields based on record type
                        if hasattr(record, 'login'):
                            record_dict['login'] = record.login
                        if hasattr(record, 'password'):
                            record_dict['password'] = record.password
                        if hasattr(record, 'login_url'):
                            record_dict['login_url'] = record.login_url
                        if hasattr(record, 'notes'):
                            record_dict['notes'] = record.notes

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

    def _is_displayable_record(self, record: dict) -> bool:
        """Check if a record should be displayed in normal folder structure.
        Excludes file attachments (handled separately) and Secrets Manager app records (virtual folder)."""
        record_uid = record.get('uid')

        # Exclude file attachments - they'll be shown under their parent
        if record_uid in self.file_attachment_to_parent:
            return False

        # Exclude Secrets Manager app records - they go in virtual folder
        if record_uid in self.app_record_uids:
            return False

        return True

    def _add_record_with_attachments(self, parent_node, record: dict, idx: int, auto_expand: bool = False):
        """Add a record to the tree, including any file attachments as children."""
        record_uid = record.get('uid')
        record_title = record.get('title', 'Untitled')
        t = self.theme_colors  # Theme colors

        # Check if this record has file attachments
        attachments = self.record_file_attachments.get(record_uid, [])

        if attachments:
            # Record has attachments - make it expandable
            record_label = f"[{t['record_num']}]{idx}.[/{t['record_num']}] [{t['record']}]{record_title}[/{t['record']}]"
            record_node = parent_node.add(
                record_label,
                data={'type': 'record', 'uid': record_uid}
            )

            # Add file attachments as children
            for att_idx, att_uid in enumerate(attachments, start=1):
                if att_uid in self.records:
                    att_record = self.records[att_uid]
                    att_title = att_record.get('title', 'Attachment')
                    att_label = f"[{t['text_dim']}]{att_idx}.[/{t['text_dim']}] [{t['attachment']}]📎 {att_title}[/{t['attachment']}]"
                    record_node.add_leaf(
                        att_label,
                        data={'type': 'record', 'uid': att_uid}
                    )

            if auto_expand:
                record_node.expand()
        else:
            # No attachments - add as leaf
            record_label = f"[{t['record_num']}]{idx}.[/{t['record_num']}] [{t['record']}]{record_title}[/{t['record']}]"
            parent_node.add_leaf(
                record_label,
                data={'type': 'record', 'uid': record_uid}
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

        # Determine if we should auto-expand (when filtering with < 100 results)
        auto_expand = False
        if self.filtered_record_uids is not None and len(self.filtered_record_uids) < 100:
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

            # Skip this folder if it has no matching records and no subfolders with records
            if not folder_records and not subfolders_with_records:
                return None

            # Determine icon and color based on folder type
            if folder_node.type == 'shared_folder':
                icon = "◆"  # Diamond for shared folders
                color = t['folder_shared']
            else:
                icon = "▸"  # Triangle for regular folders
                color = t['folder']

            # Add this folder to the tree with color
            tree_node = parent_tree_node.add(
                f"[{color}]{icon} {folder_node.name}[/{color}]",
                data={'type': 'folder', 'uid': folder_uid}
            )

            # Add subfolders
            for _, subfolder_uid, subfolder in subfolders_with_records:
                add_folder_node(tree_node, subfolder, subfolder_uid)

            # Sort and add records (with their file attachments as children)
            folder_records.sort(key=lambda r: r.get('title', '').lower())

            for idx, record in enumerate(folder_records, start=1):
                self._add_record_with_attachments(tree_node, record, idx, auto_expand)

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

        for idx, record in enumerate(root_records, start=1):
            self._add_record_with_attachments(root, record, idx, auto_expand)

        # Add virtual "Secrets Manager Apps" folder at the bottom for app records
        app_records = []
        for r in self.records.values():
            if r.get('uid') in self.app_record_uids:
                # Apply filter if active
                if self.filtered_record_uids is None or r['uid'] in self.filtered_record_uids:
                    app_records.append(r)

        if app_records:
            app_records.sort(key=lambda r: r.get('title', '').lower())
            # Create virtual folder with distinct styling
            apps_folder = root.add(
                f"[{t['virtual_folder']}]★ Secrets Manager Apps[/{t['virtual_folder']}]",
                data={'type': 'virtual_folder', 'uid': '__secrets_manager_apps__'}
            )

            for idx, record in enumerate(app_records, start=1):
                self._add_record_with_attachments(apps_folder, record, idx, auto_expand)

            if auto_expand:
                apps_folder.expand()

        # Expand root
        root.expand()

    def _folder_has_matching_records(self, folder_uid: str) -> bool:
        """Check if a folder or any of its subfolders has matching records.
        Excludes file attachments and 'app' type records from consideration."""
        # Check if this folder has any matching displayable records
        for r in self.records.values():
            if r.get('folder_uid') == folder_uid and self._is_displayable_record(r):
                if self.filtered_record_uids is None or r['uid'] in self.filtered_record_uids:
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
                detail.update(f"[bold {t['primary']}]📁 {folder_name}[/bold {t['primary']}]")

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

            # Get folder name for this record
            folder_uid = self.record_to_folder.get(record_uid)
            folder_name = folder_names.get(folder_uid, '') if folder_uid else ''

            # Combined text includes both record fields AND folder name
            combined_text = record_text + ' ' + folder_name

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
            section_headers = {'Custom Fields', 'Notes', 'Attachments', 'User Permissions',
                               'Shared Folder Permissions', 'Share Admins', 'One-Time Share URL'}

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

                    # UID - yellow value
                    if key in ['UID', 'Record UID']:
                        lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [#ffff00]{value}[/#ffff00]")
                    # Title - bold primary with label
                    elif key in ['Title', 'Name'] and not current_section:
                        lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [bold {t['primary']}]{value}[/bold {t['primary']}]")
                    # Type field
                    elif key == 'Type':
                        lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary_dim']}]{value}[/{t['primary_dim']}]")
                    # Section headers
                    elif key in section_headers:
                        current_section = key
                        if lines:
                            lines.append("")  # Single blank line before section
                        lines.append(f"[bold {t['secondary']}]{key}:[/bold {t['secondary']}]")
                    # Regular key-value pairs
                    elif value:
                        if current_section:
                            lines.append(f"  [{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{value}[/{t['primary']}]")
                        else:
                            lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{value}[/{t['primary']}]")
                    elif key:
                        # Key with no value (like a sub-header)
                        lines.append(f"  [{t['primary_dim']}]{key}[/{t['primary_dim']}]")
                else:
                    # Lines without colons (list items, continuation text)
                    if stripped:
                        lines.append(f"  [{t['primary_dim']}]{stripped}[/{t['primary_dim']}]")

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
                        f"[bold {t['primary']}]{folder.name}[/bold {t['primary']}]\n"
                        f"[{t['text_dim']}]UID:[/{t['text_dim']}] [#ffff00]{folder_uid}[/#ffff00]\n"
                        f"[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]\n\n"
                        f"[{t['secondary']}]{'Type':>20}:[/{t['secondary']}]  [{t['primary']}]{folder_type}[/{t['primary']}]\n\n"
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
                            lines.append(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [#ffff00]{value}[/#ffff00]")
                        elif key == 'Name':
                            lines.append(f"[bold {t['primary']}]{value}[/bold {t['primary']}]")
                        # Section headers (no value or short value)
                        elif key in ['Record Permissions', 'User Permissions', 'Team Permissions', 'Share Administrators']:
                            lines.append("")
                            lines.append(f"[bold {t['primary_bright']}]{key}:[/bold {t['primary_bright']}]")
                        # Boolean values
                        elif value.lower() in ['true', 'false']:
                            color = t['primary'] if value.lower() == 'true' else t['primary_dim']
                            lines.append(f"[{t['secondary']}]{key:>25}:[/{t['secondary']}]  [{color}]{value}[/{color}]")
                        # Regular key-value pairs
                        else:
                            # Add indentation for permission entries
                            if key and not key[0].isspace():
                                lines.append(f"[{t['secondary']}]  • {key}:[/{t['secondary']}]  [{t['primary']}]{value}[/{t['primary']}]")
                            else:
                                lines.append(f"[{t['secondary']}]{key:>25}:[/{t['secondary']}]  [{t['primary']}]{value}[/{t['primary']}]")
                    else:
                        lines.append(f"[{t['primary']}]{line}[/{t['primary']}]")
                else:
                    # Lines without colons (section content)
                    if line:
                        lines.append(f"[{t['primary']}]  {line}[/{t['primary']}]")

            lines.append(f"\n[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]")
            return "\n".join(lines)

        except Exception as e:
            sys.stdout = old_stdout
            logging.error(f"Error formatting folder for TUI: {e}", exc_info=True)
            return f"[red]Error displaying folder:[/red]\n{str(e)}"

    def _get_record_output(self, record_uid: str, format_type: str = 'detail') -> str:
        """Get record output using Commander's get command"""
        try:
            # Create a StringIO buffer to capture stdout
            stdout_buffer = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_buffer

            # Execute the get command
            get_cmd = RecordGetUidCommand()
            get_cmd.execute(self.params, uid=record_uid, format=format_type)

            # Restore stdout
            sys.stdout = old_stdout

            # Get the captured output
            output = stdout_buffer.getvalue()
            return output

        except Exception as e:
            sys.stdout = old_stdout
            logging.error(f"Error getting record output: {e}", exc_info=True)
            return f"Error getting record: {str(e)}"

    def _clear_clickable_fields(self):
        """Remove any dynamically mounted clickable field widgets"""
        try:
            detail_scroll = self.query_one("#record_detail", VerticalScroll)
            # Remove all clickable widget types
            for widget in list(detail_scroll.query(ClickableDetailLine)):
                widget.remove()
            for widget in list(detail_scroll.query(ClickableField)):
                widget.remove()
            for widget in list(detail_scroll.query(ClickableRecordUID)):
                widget.remove()
            # Also remove any dynamically added Static widgets (but keep #detail_content)
            for widget in list(detail_scroll.query(Static)):
                if widget.id != "detail_content" and widget.id != "shortcuts_bar":
                    widget.remove()
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

        # Helper to mount clickable lines
        def mount_line(content: str, copy_value: str = None, is_password: bool = False):
            line = ClickableDetailLine(content, copy_value, record_uid=record_uid, is_password=is_password)
            detail_scroll.mount(line, before=detail_widget)

        # Get the actual record data for password lookup
        record_data = self.records.get(record_uid, {})
        actual_password = record_data.get('password', '')

        # Parse and create clickable lines
        current_section = None
        section_headers = {'Custom Fields', 'Notes', 'Attachments', 'User Permissions',
                          'Shared Folder Permissions', 'Share Admins', 'One-Time Share URL'}

        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            if ':' in stripped:
                parts = stripped.split(':', 1)
                key = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else ''

                if key in ['UID', 'Record UID']:
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [#ffff00]{value}[/#ffff00]", value)
                elif key in ['Title', 'Name'] and not current_section:
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [bold {t['primary']}]{value}[/bold {t['primary']}]", value)
                elif key == 'Type':
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary_dim']}]{value}[/{t['primary_dim']}]", value)
                elif key == 'Password':
                    # Show masked password but use ClipboardCommand to copy (generates audit event)
                    display_value = '******' if actual_password else value
                    copy_value = actual_password if actual_password else None
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{display_value}[/{t['primary']}]", copy_value, is_password=True)
                elif key in section_headers:
                    current_section = key
                    mount_line("", None)  # Blank line
                    mount_line(f"[bold {t['secondary']}]{key}:[/bold {t['secondary']}]", None)
                elif value:
                    indent = "  " if current_section else ""
                    mount_line(f"{indent}[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{value}[/{t['primary']}]", value)
                elif key:
                    mount_line(f"  [{t['primary_dim']}]{key}[/{t['primary_dim']}]", key)
            else:
                if stripped:
                    mount_line(f"  [{t['primary_dim']}]{stripped}[/{t['primary_dim']}]", stripped)


    def _display_json_with_clickable_fields(self, record_uid: str):
        """Display JSON view with clickable string values, masking passwords"""
        t = self.theme_colors
        detail_widget = self.query_one("#detail_content", Static)

        # Clear previous clickable fields
        self._clear_clickable_fields()

        # Get JSON output
        output = self._get_record_output(record_uid, format_type='json')
        output = self._strip_ansi_codes(output)

        try:
            json_obj = json.loads(output)
            # Mask password values in the display
            display_obj = self._mask_passwords_in_json(json_obj)
            output = json.dumps(display_obj, indent=2)
        except:
            pass

        # Use Rich Text object to mix styled header with plain JSON (no markup processing)
        text = Text()
        text.append("JSON View:\n\n", style=f"bold {t['primary']}")
        text.append(output, style=t['primary'])  # Plain text, no markup processing
        detail_widget.update(text)

    def _mask_passwords_in_json(self, obj):
        """Recursively mask password values in JSON object for display"""
        if isinstance(obj, dict):
            # Check if this dict is a password field (has type: "password")
            if obj.get('type') == 'password':
                masked = dict(obj)
                if 'value' in masked and isinstance(masked['value'], list) and len(masked['value']) > 0:
                    masked['value'] = ['************']
                return masked
            # Otherwise recurse into dict values
            result = {}
            for key, value in obj.items():
                result[key] = self._mask_passwords_in_json(value)
            return result
        elif isinstance(obj, list):
            return [self._mask_passwords_in_json(item) for item in obj]
        else:
            return obj

    def _render_json_clickable(self, container, detail_widget, obj, t, indent=0):
        """Recursively render JSON object with clickable string values"""
        indent_str = "  " * indent

        def mount_field(widget):
            container.mount(widget, before=detail_widget)

        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    # String value - make it clickable
                    field = ClickableField(
                        label=f"{indent_str}\"{key}\":",
                        value=f"\"{value}\"",
                        copy_value=value,
                        label_color=t['secondary'],
                        value_color=t['primary']
                    )
                    mount_field(field)
                elif isinstance(value, (int, float, bool)) or value is None:
                    # Primitive value
                    display_val = str(value).lower() if isinstance(value, bool) else str(value)
                    if value is None:
                        display_val = "null"
                    field = ClickableField(
                        label=f"{indent_str}\"{key}\":",
                        value=display_val,
                        copy_value=str(value) if value is not None else None,
                        label_color=t['secondary'],
                        value_color=t['primary_dim']
                    )
                    mount_field(field)
                elif isinstance(value, list):
                    # Array
                    mount_field(Static(f"{indent_str}[{t['secondary']}]\"{key}\":[/{t['secondary']}] ["))
                    for item in value:
                        self._render_json_clickable(container, detail_widget, item, t, indent + 1)
                    mount_field(Static(f"{indent_str}]"))
                elif isinstance(value, dict):
                    # Nested object
                    mount_field(Static(f"{indent_str}[{t['secondary']}]\"{key}\":[/{t['secondary']}] {{"))
                    self._render_json_clickable(container, detail_widget, value, t, indent + 1)
                    mount_field(Static(f"{indent_str}}}"))
        elif isinstance(obj, str):
            # Direct string value (in array)
            field = ClickableField(
                label="",
                value=f"{indent_str}\"{obj}\"",
                copy_value=obj,
                value_color=t['primary']
            )
            mount_field(field)

    def _display_folder_with_clickable_fields(self, folder_uid: str):
        """Display folder details with clickable fields for copy-on-click"""
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
                mount_line(f"[bold {t['primary']}]{folder.name}[/bold {t['primary']}]", folder.name)
                mount_line(f"[{t['text_dim']}]UID:[/{t['text_dim']}] [#ffff00]{folder_uid}[/#ffff00]", folder_uid)
                mount_line(f"[{t['text_dim']}]Type:[/{t['text_dim']}] [{t['primary']}]{folder_type}[/{t['primary']}]", folder_type)
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
                    mount_line(f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [#ffff00]{value}[/#ffff00]", value)
                # Folder Type
                elif key == 'Folder Type':
                    display_type = value if value else folder_type
                    mount_line(f"[{t['text_dim']}]Type:[/{t['text_dim']}] [{t['primary']}]{display_type}[/{t['primary']}]", display_type)
                # Name - title
                elif key == 'Name':
                    mount_line(f"[bold {t['primary']}]{value}[/bold {t['primary']}]", value)
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
                        mount_line(f"  [{t['text_dim']}]Record:[/{t['text_dim']}] [#ffff00]{record_title}[/#ffff00]", record_title)
                        mount_line(f"    [{t['text_dim']}]UID:[/{t['text_dim']}] [{t['primary_dim']}]{value}[/{t['primary_dim']}]", value)
                    else:
                        mount_line(f"  [{t['text_dim']}]Record UID:[/{t['text_dim']}] [#ffff00]{value}[/#ffff00]", value)
                # Boolean values
                elif value.lower() in ['true', 'false']:
                    color = t['primary'] if value.lower() == 'true' else t['primary_dim']
                    indent = "  " if current_section else ""
                    mount_line(f"{indent}[{t['secondary']}]{key}:[/{t['secondary']}] [{color}]{value}[/{color}]", value)
                # Regular key-value pairs
                elif value:
                    indent = "  " if current_section else ""
                    # Skip Share Admins details (collapsed)
                    if in_share_admins and key in ['User', 'Email']:
                        continue
                    mount_line(f"{indent}[{t['secondary']}]{key}:[/{t['secondary']}] [{t['primary']}]{value}[/{t['primary']}]", value)
                elif key:
                    indent = "  " if current_section else ""
                    if in_share_admins:
                        continue
                    mount_line(f"{indent}[{t['primary_dim']}]{key}[/{t['primary_dim']}]", key)
            else:
                if stripped:
                    indent = "  " if current_section else ""
                    if in_share_admins:
                        continue
                    mount_line(f"{indent}[{t['primary']}]{stripped}[/{t['primary']}]", stripped)

        # Footer line
        mount_line(f"\n[bold {t['secondary']}]{'━' * 60}[/bold {t['secondary']}]", None)

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

    def _update_shortcuts_bar(self, record_selected: bool = False):
        """Update the shortcuts bar at bottom of detail panel"""
        try:
            shortcuts_bar = self.query_one("#shortcuts_bar", Static)
            t = self.theme_colors

            if record_selected:
                mode = "JSON" if self.view_mode == 'json' else "Detail"
                shortcuts_bar.update(
                    f"[{t['secondary']}]Mode: {mode}[/{t['secondary']}]  "
                    f"[{t['text_dim']}]c[/{t['text_dim']}]=Password  "
                    f"[{t['text_dim']}]u[/{t['text_dim']}]=Username  "
                    f"[{t['text_dim']}]w[/{t['text_dim']}]=URL  "
                    f"[{t['text_dim']}]i[/{t['text_dim']}]=UID  "
                    f"[{t['text_dim']}]y[/{t['text_dim']}]=Copy  "
                    f"[{t['text_dim']}]t[/{t['text_dim']}]=Toggle"
                )
            else:
                shortcuts_bar.update(
                    f"[{t['text_dim']}]Navigate: j/k  Expand: l  Search: /  Sync: d  Help: ?[/{t['text_dim']}]"
                )
        except Exception as e:
            logging.debug(f"Error updating shortcuts bar: {e}")

    @on(Tree.NodeSelected)
    def on_tree_node_selected(self, event: Tree.NodeSelected):
        """Handle tree node selection (folder or record)"""
        node_data = event.node.data
        if not node_data:
            return

        node_type = node_data.get('type')
        node_uid = node_data.get('uid')

        if node_type == 'record':
            # Record selected - show details
            self.selected_record = node_uid
            self.selected_folder = None  # Clear folder selection
            self._display_record_detail(node_uid)
            self._update_status(f"Record selected: {self.records[node_uid].get('title', 'Untitled')}")
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
            self._update_shortcuts_bar(record_selected=False)
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
                    f"[{t['primary_dim']}]Contains {app_count} Secrets Manager application record(s).\n"
                    f"Select a record to view details.[/{t['primary_dim']}]"
                )
                self._update_status("Secrets Manager Apps")
            else:
                detail_widget.update(f"[{t['primary_dim']}]Virtual folder[/{t['primary_dim']}]")
                self._update_status("Virtual folder")
            self._update_shortcuts_bar(record_selected=False)
        elif node_type == 'root':
            # Root selected - show welcome/help content
            self.selected_record = None  # Clear record selection
            self.selected_folder = None  # Clear folder selection
            self._clear_clickable_fields()
            detail_widget = self.query_one("#detail_content", Static)
            t = self.theme_colors
            help_content = f"""[bold {t['primary']}]● Keeper SuperShell[/bold {t['primary']}]

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
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]:N[/{t['primary']}] - Go to line N (e.g., :20)
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]Ctrl+d/u[/{t['primary']}] - Half page down/up

[bold {t['primary_bright']}]Quick Actions[/bold {t['primary_bright']}]
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]c[/{t['primary']}] - Copy password
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]u[/{t['primary']}] - Copy username
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]w[/{t['primary']}] - Copy URL
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]t[/{t['primary']}] - Toggle Detail/JSON view
  [{t['text_dim']}]•[/{t['text_dim']}] [{t['primary']}]d[/{t['primary']}] - Sync vault from server

[{t['text_dim']}]Press [/{t['text_dim']}][{t['primary']}]?[/{t['primary']}][{t['text_dim']}] for full keyboard shortcuts[/{t['text_dim']}]"""
            detail_widget.update(help_content)
            self._update_status("My Vault")
            self._update_shortcuts_bar(record_selected=False)

    def _update_search_display(self):
        """Update the search display and results with blinking cursor"""
        try:
            search_display = self.query_one("#search_display", Static)
            results_label = self.query_one("#search_results_label", Static)

            # Force visibility
            if search_display.styles.display == "none":
                search_display.styles.display = "block"

            # Update display with blinking cursor at end
            if self.search_input_text:
                # Show text with blinking cursor
                display_text = f"{self.search_input_text}[blink]▎[/blink]"
            else:
                # Show placeholder with blinking cursor
                display_text = "[dim]Search...[/dim][blink]▎[/blink]"

            search_display.update(display_text)

            # Update status bar
            self._update_status("Type to search | Enter/Tab/↓ to navigate | ESC to close")

            # Perform search and update results
            result_count = self._perform_live_search(self.search_input_text)
            t = self.theme_colors

            if self.search_input_text:
                if result_count == 0:
                    results_label.update("[#ff0000]No matches[/#ff0000]")
                elif result_count == 1:
                    results_label.update(f"[{t['secondary']}]1 match[/{t['secondary']}]")
                else:
                    results_label.update(f"[{t['secondary']}]{result_count} matches[/{t['secondary']}]")
            else:
                results_label.update("")

        except Exception as e:
            logging.error(f"Error in _update_search_display: {e}", exc_info=True)
            self._update_status(f"ERROR: {str(e)}")

    def on_key(self, event):
        """Handle keyboard events"""
        search_bar = self.query_one("#search_bar")
        tree = self.query_one("#folder_tree", Tree)

        if search_bar.styles.display != "none":
            # Search bar is active

            # If we're navigating results (not typing), let tree handle its keys
            if not self.search_input_active and tree.has_focus:
                if event.key in ("j", "k", "h", "l", "up", "down", "left", "right", "enter", "space"):
                    return
                elif event.key == "slash":
                    # Switch back to search input mode
                    self.search_input_active = True
                    # Hide tree selection while typing
                    tree.add_class("search-input-active")
                    # Restore cursor in search display
                    self._update_search_display()
                    event.prevent_default()
                    event.stop()
                    return

            if event.key == "escape":
                # Close search and clear filter
                search_bar.styles.display = "none"
                self.search_input_text = ""
                self.search_input_active = False
                # Show tree selection again
                tree.remove_class("search-input-active")
                self._perform_live_search("")  # Reset to show all

                # Restore previous selection
                self.selected_record = self.pre_search_selected_record
                self.selected_folder = self.pre_search_selected_folder

                # Navigate tree to the previously selected item
                self._restore_tree_selection(tree)

                tree.focus()
                self._update_status("Navigate with j/k | / to search | ? for help")
                event.prevent_default()
                event.stop()
            elif event.key in ("enter", "down", "tab"):
                # Move focus to tree to navigate results
                # Switch to navigation mode
                self.search_input_active = False

                # Show tree selection - remove the class that hides it
                tree.remove_class("search-input-active")

                # Remove cursor from search display
                search_display = self.query_one("#search_display", Static)
                if self.search_input_text:
                    search_display.update(self.search_input_text)  # No cursor
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
                # event.key gives key names like "minus", "period" while event.character gives the actual char
                logging.info(f"Character pressed: '{event.character}' (key={event.key})")
                self.search_input_text += event.character
                logging.info(f"New search_input_text: '{self.search_input_text}'")
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
                elif event.character and (event.character.isdigit() or event.character in "qwW"):
                    # Accept digits and some commands (q=quit, w=write not applicable here)
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

            if event.key == "escape":
                # Escape: collapse current folder or go to parent, stop at root
                self._collapse_current_or_parent(tree)
                event.prevent_default()
                event.stop()

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
        """Execute vim-style command (e.g., :20 to go to line 20, :q to quit)"""
        command = command.strip()

        if command == "q":
            self.exit()
            return

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
        """Toggle search bar visibility"""
        search_bar = self.query_one("#search_bar")
        tree = self.query_one("#folder_tree", Tree)

        if search_bar.styles.display == "none":
            # Save current selection before opening search
            self.pre_search_selected_record = self.selected_record
            self.pre_search_selected_folder = self.selected_folder
            # Show search bar
            search_bar.styles.display = "block"
            self.search_input_text = ""
            self.search_input_active = True  # Start in input mode
            # Hide tree selection while typing in search
            tree.add_class("search-input-active")
            self._update_search_display()
        else:
            # Hide search bar and clear search
            search_bar.styles.display = "none"
            self.search_input_text = ""
            self.search_input_active = False
            # Show tree selection again
            tree.remove_class("search-input-active")
            self._perform_live_search("")  # Reset to show all

            # Restore previous selection
            self.selected_record = self.pre_search_selected_record
            self.selected_folder = self.pre_search_selected_folder
            self._restore_tree_selection(tree)

            # Focus back on tree
            tree.focus()
            self._update_status("Navigate with j/k | / to search | ? for help")

    def action_toggle_view_mode(self):
        """Toggle between detail and JSON view modes"""
        # Only works for records, not folders
        if not self.selected_record:
            self.notify("⚠️ View toggle only works for records, not folders", severity="warning")
            return

        if self.view_mode == 'detail':
            self.view_mode = 'json'
            self.notify("📋 Switched to JSON view", severity="information")
        else:
            self.view_mode = 'detail'
            self.notify("📋 Switched to Detail view", severity="information")

        # Refresh the current record display
        try:
            self._display_record_detail(self.selected_record)
        except Exception as e:
            logging.error(f"Error toggling view mode: {e}", exc_info=True)
            self.notify(f"⚠️ Error switching view: {str(e)}", severity="error")

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
                self.notify("⚠️ No password found for this record", severity="warning")
        else:
            self.notify("⚠️ No record selected", severity="warning")

    def action_refresh(self):
        """Refresh vault data"""
        self._update_status("🔄 Refreshing vault data...")

        # Reload vault data
        self.records = {}
        self.record_to_folder = {}
        self.records_in_subfolders = set()
        self.file_attachment_to_parent = {}
        self.record_file_attachments = {}
        self.app_record_uids = set()
        self._load_vault_data()
        self._setup_folder_tree()

        self._update_status("✅ Vault data refreshed")

    def action_copy_username(self):
        """Copy username of selected record to clipboard"""
        if self.selected_record and self.selected_record in self.records:
            record = self.records[self.selected_record]
            if 'login' in record:
                pyperclip.copy(record['login'])
                self.notify("👤 Username copied to clipboard!", severity="information")
            else:
                self.notify("⚠️ No username found for this record", severity="warning")
        else:
            self.notify("⚠️ No record selected", severity="warning")

    def action_copy_url(self):
        """Copy URL of selected record to clipboard"""
        if self.selected_record and self.selected_record in self.records:
            record = self.records[self.selected_record]
            if 'login_url' in record:
                pyperclip.copy(record['login_url'])
                self.notify("🔗 URL copied to clipboard!", severity="information")
            else:
                self.notify("⚠️ No URL found for this record", severity="warning")
        else:
            self.notify("⚠️ No record selected", severity="warning")

    def action_copy_uid(self):
        """Copy UID of selected record or folder to clipboard"""
        if self.selected_record:
            pyperclip.copy(self.selected_record)
            self.notify("📋 Record UID copied to clipboard!", severity="information")
        elif self.selected_folder:
            pyperclip.copy(self.selected_folder)
            self.notify("📋 Folder UID copied to clipboard!", severity="information")
        else:
            self.notify("⚠️ No record or folder selected", severity="warning")

    def action_copy_record(self):
        """Copy entire record contents to clipboard (formatted or JSON based on view mode)"""
        if self.selected_record:
            try:
                # Get record data to check if it has a password
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
                self.notify("⚠️ Failed to copy record contents", severity="error")
        else:
            self.notify("⚠️ No record selected", severity="warning")

    def action_show_help(self):
        """Show help modal"""
        self.push_screen(HelpScreen())

    def action_sync_vault(self):
        """Sync vault data from server (sync-down + enterprise-down)"""
        self._update_status("Syncing vault data...")

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
            self.app_record_uids = set()
            self._load_vault_data()
            self._setup_folder_tree()

            self._update_status("Vault synced successfully")
            self.notify("Vault data synced", severity="information")
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
            for _ in range(10):  # Move down 10 nodes
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
            for _ in range(10):  # Move up 10 nodes
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
            for _ in range(20):  # Move down 20 nodes
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
            for _ in range(20):  # Move up 20 nodes
                focused.action_cursor_up()
        elif isinstance(focused, VerticalScroll):
            # Scroll up by full page in detail view
            focused.scroll_page_up(animate=False)

    def action_quit(self):
        """Quit the application"""
        self.exit()


class SuperShellCommand(Command):
    """Command to launch the SuperShell TUI"""

    def get_parser(self):
        return None  # No arguments needed

    def is_authorised(self):
        """Don't require pre-authentication - TUI handles all auth"""
        return False

    def execute(self, params, **kwargs):
        """Launch the SuperShell TUI - handles login if needed"""

        # Disable debug mode for SuperShell to prevent log output from messing up the TUI
        saved_debug = getattr(params, 'debug', False)
        saved_log_level = logging.getLogger().level
        if saved_debug:
            params.debug = False
            logging.getLogger().setLevel(logging.WARNING)

        try:
            self._execute_supershell(params, **kwargs)
        finally:
            # Restore debug state when SuperShell exits
            if saved_debug:
                params.debug = saved_debug
                logging.getLogger().setLevel(saved_log_level)

    def _execute_supershell(self, params, **kwargs):
        """Internal method to run SuperShell"""

        # Check if authentication is needed
        if not params.session_token:
            # Simple animated loading message
            import time
            colors = ['\033[36m', '\033[32m', '\033[33m', '\033[35m']  # Cyan, Green, Yellow, Magenta
            spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

            print("\n")
            for i in range(10):
                color = colors[i % len(colors)]
                spin = spinner[i % len(spinner)]
                print(f"\r  {color}{spin} Loading...\033[0m", end='', flush=True)
                time.sleep(0.1)
            print("\r\033[K", end='', flush=True)  # Clear the line

            # Run the login flow
            from .utils import LoginCommand
            try:
                LoginCommand().execute(params, email=params.user, password=params.password, new_login=False)

                if not params.session_token:
                    logging.error("\nLogin failed or was cancelled.")
                    return

                print("\n✓ Login successful!")

                # Sync vault data after login
                print("✓ Syncing vault data...")
                from .utils import SyncDownCommand
                SyncDownCommand().execute(params)
                print("✓ Vault synced!\n")

            except KeyboardInterrupt:
                print("\n\nLogin cancelled.")
                return
            except Exception as e:
                logging.error(f"\nLogin failed: {e}")
                return

        # Launch the TUI app
        import time
        colors = ['\033[36m', '\033[32m', '\033[33m', '\033[35m']  # Cyan, Green, Yellow, Magenta
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

        print("")
        for i in range(8):
            color = colors[i % len(colors)]
            spin = spinner[i % len(spinner)]
            print(f"\r  {color}{spin} Loading...\033[0m", end='', flush=True)
            time.sleep(0.08)
        print("\r\033[K", end='', flush=True)  # Clear the line

        try:
            app = SuperShellApp(params)
            app.run()
        except KeyboardInterrupt:
            logging.info("SuperShell interrupted")
        except Exception as e:
            logging.error(f"Error running SuperShell: {e}")
            raise
