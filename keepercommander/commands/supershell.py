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
from typing import Optional, List, Dict, Any
import pyperclip

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, Center, Middle
from textual.widgets import Tree, DataTable, Footer, Header, Static, Input, Label, Button
from textual.binding import Binding
from textual.screen import Screen, ModalScreen
from textual.reactive import reactive
from textual import on, work
from textual.message import Message
from textual.timer import Timer

from ..commands.base import Command
from ..commands.record import RecordGetUidCommand
from ..display import bcolors
from .. import api
from .. import vault
from .. import loginv3


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
        """Copy password to clipboard"""
        if 'password' in self.record_data:
            pyperclip.copy(self.record_data['password'])
            self.app.notify("🔑 Password copied to clipboard!", severity="information")

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
        color: #00ff00;
        padding: 0 1;
        height: 1;
    }

    #search_results_label {
        width: 30%;
        color: #00ffff;
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

        # Update results label
        results_label = self.query_one("#search_results_label", Static)
        if search_query:
            if self.result_count == 0:
                results_label.update(f"[#ff0000]No matches found[/#ff0000]")
            elif self.result_count == 1:
                results_label.update(f"[#00ff00]1 match found[/#00ff00]")
            else:
                results_label.update(f"[#00ff00]{self.result_count} matches found[/#00ff00]")
        else:
            results_label.update(f"[#00aaaa]Start typing to search...[/#00aaaa]")

    def action_dismiss(self):
        """Close search and restore full view"""
        # Clear search when closing
        self.app_instance._perform_live_search("")
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
        border: solid #00ff00;
    }

    Input:focus > .input--content {
        color: #ffffff;
    }

    #search_bar {
        dock: top;
        height: 3;
        width: 100%;
        background: #222222;
        border: solid #00ff00;
        display: none;
    }

    #search_display {
        width: 70%;
        background: #222222;
        color: #00ff00;
        padding: 0 2;
        height: 3;
    }

    #search_results_label {
        width: 30%;
        color: #00ddff;
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
        border-right: thick #00aa00;
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
        color: #00aa00;
    }

    Tree > .tree--cursor {
        background: #00ff00;
        color: #000000;
        text-style: bold;
    }

    Tree > .tree--highlight {
        background: #00ff00;
        color: #000000;
    }

    DataTable {
        background: #000000;
        color: #00ff00;
    }

    DataTable > .datatable--cursor {
        background: #00ff00;
        color: #000000;
        text-style: bold;
    }

    DataTable > .datatable--header {
        background: #003300;
        color: #00ffff;
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
        color: #00aaff;
        padding: 0 2;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=False),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("/", "search", "Search", show=False),
        Binding("c", "copy_password", "Copy Password", show=False),
        Binding("u", "copy_username", "Copy Username", show=False),
        Binding("w", "copy_url", "Copy URL", show=False),
        Binding("i", "copy_uid", "Copy UID", show=False),
        Binding("y", "copy_record", "Copy Record", show=False),
        Binding("v", "view_record", "View Details", show=False),
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
        self.current_folder = None
        self.selected_record = None
        self.selected_folder = None
        self.view_mode = 'detail'  # 'detail' or 'json'
        self.search_query = ""  # Current search query
        self.search_input_text = ""  # Text being typed in search
        self.search_input_active = False  # True when typing in search, False when navigating results
        self.filtered_record_uids = None  # None = show all, Set = filtered UIDs
        self.title = ""
        self.sub_title = ""

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
                    yield Static("[#00aaff]Press ? for help | / to search | j/k to navigate[/#00aaff]", id="detail_content")
        yield Static("", id="status_bar")

    async def on_mount(self):
        """Initialize the application when mounted"""
        logging.info("SuperShell on_mount called")

        # Set Matrix theme colors
        self.theme = "dracula"  # Dark theme as base

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

            # Focus the folder tree so vim keys work immediately
            self.query_one("#folder_tree", Tree).focus()

            logging.info("SuperShell ready!")
            self._update_status("Ready. Navigate folders with j/k, expand with l, select record to view | Press ? for help")
        except Exception as e:
            logging.error(f"Error initializing SuperShell: {e}", exc_info=True)
            self.exit(message=f"Error: {str(e)}")

    def _load_vault_data(self):
        """Load vault data from params"""
        # Build record to folder mapping using subfolder_record_cache
        self.record_to_folder = {}  # Maps record_uid -> folder_uid
        if hasattr(self.params, 'subfolder_record_cache'):
            for folder_uid, record_uids in self.params.subfolder_record_cache.items():
                for record_uid in record_uids:
                    self.record_to_folder[record_uid] = folder_uid

        # Build record dictionary
        if hasattr(self.params, 'record_cache'):
            for record_uid, record_data in self.params.record_cache.items():
                try:
                    # Try to load and decrypt the record
                    record = vault.KeeperRecord.load(self.params, record_uid)

                    if record:
                        record_dict = {
                            'uid': record_uid,
                            'title': record.title if hasattr(record, 'title') else 'Untitled',
                            'folder_uid': self.record_to_folder.get(record_uid),
                        }

                        # Extract fields based on record type
                        if hasattr(record, 'login'):
                            record_dict['login'] = record.login
                        if hasattr(record, 'password'):
                            record_dict['password'] = record.password
                        if hasattr(record, 'login_url'):
                            record_dict['login_url'] = record.login_url
                        if hasattr(record, 'notes'):
                            record_dict['notes'] = record.notes

                        # For TypedRecords, extract fields
                        if hasattr(record, 'fields'):
                            custom_fields = []
                            for field in record.fields:
                                if hasattr(field, 'label') and hasattr(field, 'value'):
                                    custom_fields.append({
                                        'name': field.label,
                                        'value': str(field.value) if field.value else ''
                                    })
                            if custom_fields:
                                record_dict['custom_fields'] = custom_fields

                        self.records[record_uid] = record_dict
                except Exception as e:
                    logging.debug(f"Error loading record {record_uid}: {e}")
                    continue

    def _setup_folder_tree(self):
        """Setup the folder tree structure with records as children"""
        tree = self.query_one("#folder_tree", Tree)
        tree.clear()

        # Root node represents "My Vault"
        root = tree.root
        root_folder = self.params.root_folder
        if root_folder:
            root.label = f"[#00ff00]● {root_folder.name}[/#00ff00]"
            root.data = {'type': 'root', 'uid': None}
        else:
            root.label = "[#00ff00]● My Vault[/#00ff00]"
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
            folder_records = []
            for r in self.records.values():
                if r.get('folder_uid') == folder_uid:
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
                color = "#0099ff"  # Bright blue for shared folders
            elif folder_node.type == '/':
                icon = "▸"  # Triangle for regular folders
                color = "#00ffff"  # Bright cyan for folders
            else:
                icon = "▸"  # Triangle for regular folders
                color = "#00ffff"  # Bright cyan for folders

            # Add this folder to the tree with color
            tree_node = parent_tree_node.add(
                f"[{color}]{icon} {folder_node.name}[/{color}]",
                data={'type': 'folder', 'uid': folder_uid}
            )

            # Add subfolders
            for _, subfolder_uid, subfolder in subfolders_with_records:
                add_folder_node(tree_node, subfolder, subfolder_uid)

            # Sort and add records
            folder_records.sort(key=lambda r: r.get('title', '').lower())

            # Add records with numbering - yellow for record titles
            for idx, record in enumerate(folder_records, start=1):
                record_title = record.get('title', 'Untitled')
                record_label = f"[#ffffff]{idx}.[/#ffffff] [#ffff00]{record_title}[/#ffff00]"
                tree_node.add_leaf(
                    record_label,
                    data={'type': 'record', 'uid': record['uid']}
                )

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

        # Add root-level records (records not in any folder)
        root_records = []
        for r in self.records.values():
            if r.get('folder_uid') is None:
                # Apply filter if active
                if self.filtered_record_uids is None or r['uid'] in self.filtered_record_uids:
                    root_records.append(r)
        root_records.sort(key=lambda r: r.get('title', '').lower())

        for idx, record in enumerate(root_records, start=1):
            record_title = record.get('title', 'Untitled')
            record_label = f"[#ffffff]{idx}.[/#ffffff] [#ffff00]{record_title}[/#ffff00]"
            root.add_leaf(
                record_label,
                data={'type': 'record', 'uid': record['uid']}
            )

        # Expand root
        root.expand()

    def _folder_has_matching_records(self, folder_uid: str) -> bool:
        """Check if a folder or any of its subfolders has matching records"""
        # Check if this folder has any matching records
        for r in self.records.values():
            if r.get('folder_uid') == folder_uid:
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

    def _search_records(self, query: str) -> set:
        """
        Search records with smart partial matching.
        Returns set of matching record UIDs.

        Search logic:
        - Tokenizes query by whitespace
        - Each token must match (partial) at least one field
        - Order doesn't matter: "aws prod us" matches "us production aws"
        - Searches: title, url, custom field values, notes
        """
        if not query or not query.strip():
            return None  # None means show all

        # Tokenize query - split by whitespace and lowercase
        query_tokens = [token.lower().strip() for token in query.split() if token.strip()]
        if not query_tokens:
            return None

        matching_uids = set()

        for record_uid, record in self.records.items():
            # Build searchable text from all fields
            searchable_parts = []

            # Title
            if record.get('title'):
                searchable_parts.append(str(record['title']))

            # URL
            if record.get('login_url'):
                searchable_parts.append(str(record['login_url']))

            # Username/Login
            if record.get('login'):
                searchable_parts.append(str(record['login']))

            # Custom fields
            if record.get('custom_fields'):
                for field in record['custom_fields']:
                    name = field.get('name', '')
                    value = field.get('value', '')
                    if name:
                        searchable_parts.append(str(name))
                    if value:
                        searchable_parts.append(str(value))

            # Notes
            if record.get('notes'):
                searchable_parts.append(str(record['notes']))

            # Combine all searchable text
            combined_text = ' '.join(searchable_parts).lower()

            # Check if ALL query tokens match (partial match anywhere in the text)
            # This allows "prod" to match "production" and order doesn't matter
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
        """Format record details specifically for TUI display with clean layout"""
        def escape_markup(text):
            """Escape Rich markup characters in user-provided text"""
            if text is None:
                return ""
            return str(text).replace('[', '\\[').replace(']', '\\]')

        try:
            if record_uid not in self.params.record_cache:
                return "[red]Record not found in cache[/red]"

            cached_rec = self.params.record_cache[record_uid]
            version = cached_rec.get('version', 2)

            # Load the record
            r = api.get_record(self.params, record_uid)
            if not r:
                return "[red]Failed to load record[/red]"

            lines = []

            # Header with UID - using bright colors
            lines.append(f"[bold #00ffff]{'━' * 60}[/bold #00ffff]")
            lines.append(f"[bold #00ff00]{escape_markup(r.title)}[/bold #00ff00]")
            lines.append(f"[#00aaaa]UID:[/#00aaaa] [#ffff00]{record_uid}[/#ffff00]")
            lines.append(f"[bold #00ffff]{'━' * 60}[/bold #00ffff]")
            lines.append("")

            # Main fields with right-aligned labels - bright cyan labels, bright green values
            if r.login:
                lines.append(f"[bold #00ffff]{'Username':>20}:[/bold #00ffff]  [#00ff00]{escape_markup(r.login)}[/#00ff00]")

            if r.password:
                masked = '•' * min(len(r.password), 16)
                lines.append(f"[bold #00ffff]{'Password':>20}:[/bold #00ffff]  [#00ff00]{masked}[/#00ff00]")

            if r.login_url:
                lines.append(f"[bold #00ffff]{'URL':>20}:[/bold #00ffff]  [#00ff00]{escape_markup(r.login_url)}[/#00ff00]")

            # Custom fields - yellow header, cyan labels, bright green values
            if r.custom_fields:
                lines.append("")
                lines.append(f"[bold #ffff00]Custom Fields:[/bold #ffff00]")
                for field in r.custom_fields:
                    name = field.get('name', 'Field')
                    value = field.get('value', '')
                    if name:  # Skip empty names
                        # Truncate long values
                        if isinstance(value, str) and len(value) > 100:
                            value = value[:100] + '...'
                        lines.append(f"[#00ffff]{'  ' + escape_markup(name):>22}:[/#00ffff]  [#00ff00]{escape_markup(value)}[/#00ff00]")

            # Notes - yellow header, bright green text
            if r.notes:
                lines.append("")
                lines.append(f"[bold #ffff00]Notes:[/bold #ffff00]")
                note_lines = r.notes.split('\n')
                for line in note_lines[:10]:  # Limit to 10 lines
                    lines.append(f"[#00aa00]  {escape_markup(line)}[/#00aa00]")
                if len(note_lines) > 10:
                    lines.append(f"[#00aa00]  ... ({len(note_lines) - 10} more lines)[/#00aa00]")

            # Attachments - yellow header, cyan text
            if r.attachments:
                lines.append("")
                lines.append(f"[bold #ffff00]Attachments:[/bold #ffff00]")
                for atta in r.attachments:
                    name = atta.get('title') or atta.get('name', 'Unknown')
                    size = atta.get('size', 0)
                    size_str = self._format_size(size)
                    lines.append(f"[#00ffff]  • {escape_markup(name)}[/#00ffff] [#00aa00]({size_str})[/#00aa00]")

            # Permissions - only if they exist
            if cached_rec.get('shares'):
                shares = cached_rec['shares']

                # User permissions - yellow header, cyan names, dim green details
                if shares.get('user_permissions'):
                    lines.append("")
                    lines.append(f"[bold #ffff00]User Permissions:[/bold #ffff00]")
                    for user in shares['user_permissions']:
                        username = user.get('username', 'Unknown')
                        shareable = user.get('sharable', user.get('shareable', False))
                        lines.append(f"[#00ffff]  • {escape_markup(username)}[/#00ffff]")
                        lines.append(f"[#00aa00]    Shareable: {'Yes' if shareable else 'No'}[/#00aa00]")

                # Shared folder permissions
                if shares.get('shared_folder_permissions'):
                    lines.append("")
                    lines.append(f"[bold #ffff00]Shared Folder Permissions:[/bold #ffff00]")
                    for sf in shares['shared_folder_permissions']:
                        sf_uid = sf.get('shared_folder_uid', 'Unknown')
                        perms = []
                        if sf.get('manage_users'): perms.append('Manage Users')
                        if sf.get('manage_records'): perms.append('Manage Records')
                        if sf.get('can_edit'): perms.append('Can Edit')
                        if sf.get('can_share'): perms.append('Can Share')
                        lines.append(f"[#00ffff]  • Folder:[/#00ffff] [#00aa00]{escape_markup(sf_uid)}[/#00aa00]")
                        if perms:
                            lines.append(f"[#00aa00]    {', '.join(perms)}[/#00aa00]")

            return "\n".join(lines)

        except Exception as e:
            logging.error(f"Error formatting record for TUI: {e}", exc_info=True)
            error_msg = str(e).replace('[', '\\[').replace(']', '\\]')
            return f"[red]Error formatting record:[/red]\n{error_msg}"

    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format"""
        if size < 1024:
            return f"{size}B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f}KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f}MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f}GB"

    def _format_folder_for_tui(self, folder_uid: str) -> str:
        """Format folder/shared folder details for TUI display"""
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
                        f"[bold #00ffff]{'━' * 60}[/bold #00ffff]\n"
                        f"[bold #00ff00]{folder.name}[/bold #00ff00]\n"
                        f"[#00aaaa]UID:[/#00aaaa] [#ffff00]{folder_uid}[/#ffff00]\n"
                        f"[bold #00ffff]{'━' * 60}[/bold #00ffff]\n\n"
                        f"[#00ffff]{'Type':>20}:[/#00ffff]  [#00ff00]{folder_type}[/#00ff00]\n\n"
                        f"[#00aa00]Expand folder (press 'l' or →) to view records[/#00aa00]"
                    )
                return "[red]Folder not found[/red]"

            # Format the output with proper alignment and bright colors
            lines = []
            lines.append(f"[bold #00ffff]{'━' * 60}[/bold #00ffff]")

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
                            lines.append(f"[#00aaaa]{key}:[/#00aaaa] [#ffff00]{value}[/#ffff00]")
                        elif key == 'Name':
                            lines.append(f"[bold #00ff00]{value}[/bold #00ff00]")
                        # Section headers (no value or short value)
                        elif key in ['Record Permissions', 'User Permissions', 'Team Permissions', 'Share Administrators']:
                            lines.append("")
                            lines.append(f"[bold #ffff00]{key}:[/bold #ffff00]")
                        # Boolean values
                        elif value.lower() in ['true', 'false']:
                            color = '#00ff00' if value.lower() == 'true' else '#00aa00'
                            lines.append(f"[#00ffff]{key:>25}:[/#00ffff]  [{color}]{value}[/{color}]")
                        # Regular key-value pairs
                        else:
                            # Add indentation for permission entries
                            if key and not key[0].isspace():
                                lines.append(f"[#00ffff]  • {key}:[/#00ffff]  [#00ff00]{value}[/#00ff00]")
                            else:
                                lines.append(f"[#00ffff]{key:>25}:[/#00ffff]  [#00ff00]{value}[/#00ff00]")
                    else:
                        lines.append(f"[#00ff00]{line}[/#00ff00]")
                else:
                    # Lines without colons (section content)
                    if line:
                        lines.append(f"[#00ff00]  {line}[/#00ff00]")

            lines.append(f"\n[bold #00ffff]{'━' * 60}[/bold #00ffff]")
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

    def _display_record_detail(self, record_uid: str):
        """Display record details in the right panel using Commander's get command"""
        detail_widget = self.query_one("#detail_content", Static)

        try:
            if record_uid not in self.records:
                detail_widget.update("[red]Record not found[/red]")
                return

            # Get the record output
            if self.view_mode == 'json':
                output = self._get_record_output(record_uid, format_type='json')
                # Strip ANSI codes
                output = self._strip_ansi_codes(output)
                # Pretty print JSON
                try:
                    json_obj = json.loads(output)
                    output = json.dumps(json_obj, indent=2)
                    # Don't escape brackets - JSON needs them as-is
                    # Just show header in color, JSON in plain text
                    content = f"[bold #00ff00]JSON View:[/bold #00ff00]\n\n{output}"
                except:
                    # If JSON parsing fails, just show the raw output
                    content = f"[bold #00ff00]JSON View:[/bold #00ff00]\n\n{output}"
            else:
                # Detail view - use TUI formatter
                content = self._format_record_for_tui(record_uid)

            # Add keyboard shortcuts
            mode_indicator = "[bold #00ffff]Mode: JSON[/bold #00ffff]" if self.view_mode == 'json' else "[bold #00ffff]Mode: Detail[/bold #00ffff]"
            footer = f"\n\n[#00aa00]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/#00aa00]\n{mode_indicator}\n[#00aa00]c=Password  u=Username  w=URL  i=UID  y=Copy All  v=Full  t=JSON[/#00aa00]"
            content += footer

            detail_widget.update(content)

        except Exception as e:
            logging.error(f"Error displaying record detail: {e}", exc_info=True)
            # Escape the error message to prevent Rich markup errors
            error_msg = str(e).replace('[', '\\[').replace(']', '\\]')
            detail_widget.update(f"[red]Error displaying record:[/red]\n{error_msg}\n\n[dim]Press 't' to toggle view mode[/dim]")

    def _update_status(self, message: str):
        """Update the status bar"""
        status_bar = self.query_one("#status_bar", Static)
        status_bar.update(f"⚡ {message}")

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
            # Folder selected - show folder info using get command
            self.selected_record = None  # Clear record selection
            self.selected_folder = node_uid  # Set folder selection
            detail_widget = self.query_one("#detail_content", Static)
            folder = self.params.folder_cache.get(node_uid)
            if folder:
                # Use the TUI formatter which internally calls get command
                content = self._format_folder_for_tui(node_uid)
                detail_widget.update(content)
                self._update_status(f"Folder selected: {folder.name}")
            else:
                detail_widget.update("[red]Folder not found[/red]")
        elif node_type == 'root':
            # Root selected
            self.selected_record = None  # Clear record selection
            self.selected_folder = None  # Clear folder selection
            detail_widget = self.query_one("#detail_content", Static)
            detail_widget.update(
                "[bold #00ff00]● My Vault[/bold #00ff00]\n\n"
                "[#00aa00]Navigate: j/k (up/down) | h/l (collapse/expand)\n"
                "Search: / | Help: ? | Copy: c/u/w/i/y\n\n"
                "Select a folder or record to view details[/#00aa00]"
            )
            self._update_status("My Vault - Navigate to folders and records")

    def _update_search_display(self):
        """Update the search display and results"""
        try:
            search_display = self.query_one("#search_display", Static)
            results_label = self.query_one("#search_results_label", Static)

            # Debug: Log state
            logging.info(f"=== UPDATE SEARCH DISPLAY ===")
            logging.info(f"search_input_text: '{self.search_input_text}'")
            logging.info(f"search_display widget found: {search_display is not None}")

            # Force visibility
            if search_display.styles.display == "none":
                logging.info("WARNING: search_display is hidden! Forcing visible...")
                search_display.styles.display = "block"

            logging.info(f"search_display color: {search_display.styles.color}")
            logging.info(f"search_display background: {search_display.styles.background}")
            logging.info(f"search_display display: {search_display.styles.display}")
            logging.info(f"search_display visible: {search_display.visible}")
            logging.info(f"results_label widget found: {results_label is not None}")

            # Update display to show what's being typed
            if self.search_input_text:
                # Try PLAIN text first without markup
                display_text = self.search_input_text
                logging.info(f"Updating search_display with PLAIN text: {display_text}")
                search_display.update(display_text)
                search_display.refresh()  # Force refresh
                logging.info(f"After update - search_display visible: {search_display.styles.display}")
            else:
                display_text = "Type to search..."
                logging.info(f"Updating search_display with placeholder: {display_text}")
                search_display.update(display_text)
                search_display.refresh()  # Force refresh

            # Show in status bar as well for debugging
            self._update_status(f"SEARCH: '{self.search_input_text}' | Display updated: {display_text}")

            # Perform search and update results
            result_count = self._perform_live_search(self.search_input_text)

            if self.search_input_text:
                if result_count == 0:
                    results_label.update(f"[#ff0000]No matches[/#ff0000]")
                elif result_count == 1:
                    results_label.update(f"[#00ffff]1 match[/#00ffff]")
                else:
                    results_label.update(f"[#00ffff]{result_count} matches[/#00ffff]")
            else:
                results_label.update("")

            logging.info(f"=== END UPDATE ===")
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
                    self._update_status("Search mode - Type to search")
                    event.prevent_default()
                    event.stop()
                    return

            if event.key == "escape":
                # Close search and clear filter
                search_bar.styles.display = "none"
                self.search_input_text = ""
                self._perform_live_search("")
                tree.focus()
                event.prevent_default()
                event.stop()
            elif event.key == "enter" or event.key == "down":
                # Move focus to tree to navigate results
                logging.info("Enter/Down pressed - focusing tree")

                # Switch to navigation mode
                self.search_input_active = False

                # Force focus to tree
                self.set_focus(tree)
                tree.focus()

                # Ensure tree can receive focus
                if hasattr(tree, 'can_focus'):
                    tree.can_focus = True

                logging.info(f"Tree has focus after set: {tree.has_focus}")
                logging.info(f"Focused widget: {self.focused}")

                self._update_status("Navigate results with j/k, press / to search again, ESC to close")
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
            elif event.key == "space":
                # Add space
                self.search_input_text += " "
                self._update_search_display()
                event.prevent_default()
                event.stop()
            elif len(event.key) == 1 and event.key.isprintable():
                # Add typed character
                logging.info(f"Key pressed: '{event.key}'")
                self.search_input_text += event.key
                logging.info(f"New search_input_text: '{self.search_input_text}'")
                self._update_search_display()
                event.prevent_default()
                event.stop()

    def action_search(self):
        """Toggle search bar visibility"""
        search_bar = self.query_one("#search_bar")

        if search_bar.styles.display == "none":
            # Show search bar
            logging.info("=== OPENING SEARCH BAR ===")
            search_bar.styles.display = "block"
            self.search_input_text = ""
            self.search_input_active = True  # Start in input mode
            logging.info(f"Search bar display: {search_bar.styles.display}")
            self._update_search_display()
            self._update_status("Search active - Type to search, Enter to navigate, ESC to close")
        else:
            # Hide search bar and clear search
            logging.info("=== CLOSING SEARCH BAR ===")
            search_bar.styles.display = "none"
            self.search_input_text = ""
            self.search_input_active = False
            self._perform_live_search("")
            # Focus back on tree
            self.query_one("#folder_tree", Tree).focus()

    def action_view_record(self):
        """View selected record details"""
        if self.selected_record and self.selected_record in self.records:
            record_data = self.records[self.selected_record]
            self.push_screen(RecordDetailScreen(record_data, self.params, self.selected_record))
        else:
            self.notify("⚠️ No record selected", severity="warning")

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
        """Copy password of selected record to clipboard"""
        if self.selected_record and self.selected_record in self.records:
            record = self.records[self.selected_record]
            if 'password' in record:
                pyperclip.copy(record['password'])
                self.notify("🔑 Password copied to clipboard!", severity="information")
            else:
                self.notify("⚠️ No password found for this record", severity="warning")
        else:
            self.notify("⚠️ No record selected", severity="warning")

    def action_refresh(self):
        """Refresh vault data"""
        self._update_status("🔄 Refreshing vault data...")

        # Reload vault data
        self.records = {}
        self.record_to_folder = {}
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
                if self.view_mode == 'json':
                    # Copy JSON format
                    output = self._get_record_output(self.selected_record, format_type='json')
                    output = self._strip_ansi_codes(output)
                    json_obj = json.loads(output)
                    formatted = json.dumps(json_obj, indent=2)
                    pyperclip.copy(formatted)
                    self.notify("📋 JSON copied to clipboard!", severity="information")
                else:
                    # Copy formatted text (without Rich markup)
                    content = self._format_record_for_tui(self.selected_record)
                    # Strip Rich markup for plain text clipboard
                    import re
                    plain = re.sub(r'\[/?[^\]]+\]', '', content)
                    pyperclip.copy(plain)
                    self.notify("📋 Record contents copied to clipboard!", severity="information")
            except Exception as e:
                logging.error(f"Error copying record: {e}", exc_info=True)
                self.notify("⚠️ Failed to copy record contents", severity="error")
        else:
            self.notify("⚠️ No record selected", severity="warning")

    def action_show_help(self):
        """Show help information"""
        help_text = """[bold cyan]Keeper SuperShell - Keyboard Shortcuts[/bold cyan]

[green]Vim Navigation:[/green]
  j/k        Navigate up/down
  h/l        Navigate left/right (collapse/expand folders)
  g          Go to top
  G          Go to bottom
  CTRL+d     Page down (half page)
  CTRL+u     Page up (half page)
  CTRL+f     Page down (full page)
  CTRL+b     Page up (full page)

[green]Standard Navigation:[/green]
  ↑/↓        Navigate items
  ←/→        Collapse/expand folders
  Tab        Switch between panels
  Enter      Select item

[green]Actions:[/green]
  /          Live interactive search (results update as you type)
  v          View record details (full modal)
  t          Toggle between Detail/JSON view
  r          Refresh vault data

[green]Copy Actions:[/green]
  c          Copy password to clipboard
  u          Copy username to clipboard
  w          Copy URL to clipboard
  i          Copy record UID to clipboard
  y          Copy entire record (formatted/JSON based on mode)

[green]General:[/green]
  ?          Show this help
  q          Quit SuperShell
  Esc        Close modals

[yellow]Tip: Follow the white rabbit... 🔐[/yellow]
        """
        self.notify(help_text, severity="information", timeout=10)

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
