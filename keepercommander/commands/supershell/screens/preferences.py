"""
SuperShell Preferences Screen

Modal screen for user preferences including theme selection.
"""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from ..utils import load_preferences, save_preferences


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
            yield Static("[bold cyan]Preferences[/bold cyan]", id="prefs_title")
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
