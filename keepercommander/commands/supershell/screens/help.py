"""
SuperShell Help Screen

Modal screen displaying keyboard shortcuts and help information.
"""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Static


class HelpScreen(ModalScreen):
    """Modal screen for help/keyboard shortcuts"""

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
        background: rgba(0, 0, 0, 0.8);
    }

    HelpScreen > Vertical {
        background: #000000;
    }

    HelpScreen > Vertical > Horizontal {
        background: #000000;
    }

    HelpScreen Static {
        background: #000000;
    }

    #help_container {
        width: 90;
        height: auto;
        max-height: 90%;
        background: #000000;
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
            yield Static("[bold cyan]Keyboard Shortcuts[/bold cyan]", id="help_title")
            with Horizontal(id="help_columns"):
                yield Static("""[green]Navigation:[/green]
  j/k           Move up/down
  h/l           Collapse/expand
  g / G         Top / bottom
  Ctrl+d/u      Half page
  Ctrl+e/y      Scroll line
  Esc           Clear/collapse

[green]Focus Cycling:[/green]
  Tab           Tree->Detail->Search
  Shift+Tab     Cycle backwards
  /             Focus search
  Ctrl+U        Clear search
  Esc           Focus tree

[green]Shell Pane:[/green]
  :cmd          Open shell + run cmd
  Ctrl+\\        Open/close shell
  Up/Down       Command history
  quit/q        Close shell pane
  Ctrl+D        Close shell pane
  Select text   Auto-copies to clipboard

[green]General:[/green]
  ?             Help
  !             Exit to Keeper shell
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
