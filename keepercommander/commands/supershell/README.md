# SuperShell Package Architecture

SuperShell is a full-screen terminal UI (TUI) for browsing and managing Keeper vault records. It's built on [Textual](https://textual.textualize.io/), a modern Python TUI framework.

## Package Structure

```
supershell/
├── __init__.py              # Main exports and package interface
├── constants.py             # Configuration constants
├── utils.py                 # Utility functions (preferences, ANSI stripping)
│
├── themes/                  # Visual theming
│   ├── __init__.py
│   ├── colors.py            # COLOR_THEMES dict with 5 color schemes
│   └── css.py               # Textual CSS stylesheet
│
├── screens/                 # Modal screens
│   ├── __init__.py
│   ├── preferences.py       # Theme selection modal
│   └── help.py              # Keyboard shortcuts help modal
│
├── widgets/                 # Custom Textual widgets
│   ├── __init__.py
│   ├── clickable_line.py    # ClickableDetailLine - copy-on-click text
│   ├── clickable_field.py   # ClickableField - labeled copy-on-click
│   └── clickable_uid.py     # ClickableRecordUID - UID with navigation
│
├── state/                   # State management dataclasses
│   ├── __init__.py
│   ├── vault_data.py        # VaultData - records, folders, mappings
│   ├── ui_state.py          # UIState, ThemeState - UI presentation state
│   └── selection.py         # SelectionState - current selection tracking
│
├── data/                    # Data loading and search
│   ├── __init__.py
│   ├── vault_loader.py      # load_vault_data() - extracts data from params
│   └── search.py            # search_records() - tokenized search
│
├── renderers/               # Display formatting
│   ├── __init__.py
│   ├── json_syntax.py       # JSON syntax highlighting, password masking
│   ├── record.py            # Record field formatting, JsonRenderer class
│   └── folder.py            # Folder field formatting, FolderJsonRenderer
│
└── handlers/                # Input handling
    ├── __init__.py
    └── keyboard.py          # KeyboardDispatcher and handler classes
```

## Key Components

### Main Application (`_supershell_impl.py`)

The `SuperShellApp` class (in the parent directory) is the main Textual application. It:
- Composes the UI layout (tree, detail pane, search bar, shell pane)
- Manages application state
- Handles tree node selection events
- Coordinates between components

### Keyboard Handling (`handlers/keyboard.py`)

Uses a **dispatcher pattern** for clean keyboard event handling:

```python
class KeyboardDispatcher:
    handlers = [
        GlobalExitHandler(),      # ! to exit
        ShellPaneToggleHandler(), # Ctrl+\ to toggle shell
        CommandModeHandler(),     # :command vim-style
        ShellInputHandler(),      # Shell pane input
        SearchInputHandler(),     # Search typing
        # ... more handlers
    ]
```

Each handler has:
- `can_handle(event, app)` - Check if this handler applies
- `handle(event, app)` - Process the event, return True if handled

### State Management (`state/`)

Uses Python dataclasses for type-safe state:

```python
@dataclass
class VaultData:
    records: Dict[str, dict]           # record_uid -> record data
    record_to_folder: Dict[str, str]   # record_uid -> folder_uid
    records_in_subfolders: Set[str]    # records not in root
    # ... attachment and linked record mappings

@dataclass
class UIState:
    view_mode: str = 'detail'          # 'detail' or 'json'
    unmask_secrets: bool = False       # Show/hide passwords
    search_query: str = ""
    # ... more UI state
```

### Search (`data/search.py`)

Smart tokenized search:
- Splits query into tokens by whitespace
- Each token must match somewhere in record fields OR folder name
- Order doesn't matter: "aws prod" matches "Production AWS Server"
- Searches: title, URL, username, custom fields, notes, folder name

### Renderers (`renderers/`)

Format data for display with Rich markup:

```python
# JSON rendering with syntax highlighting
renderer = JsonRenderer(theme_colors, unmask_secrets=False)
renderer.render_lines(json_obj, on_line_callback)

# Field formatting helpers
format_password_line("Password", "******", theme_colors)
format_totp_display("123456", 25, theme_colors)
```

### Themes (`themes/`)

Five color themes available:
- **green** (default) - Matrix-style green
- **blue** - Cool blue tones
- **magenta** - Purple/pink
- **yellow** - Warm amber
- **white** - High contrast

Each theme defines 18 color properties used throughout the UI.

## Data Flow

```
1. User launches `keeper supershell`
   └── SuperShellCommand.execute() creates SuperShellApp

2. App initialization
   └── _load_vault_data() extracts records from params.record_cache
   └── _setup_folder_tree() builds the tree widget

3. User navigates tree
   └── on_tree_node_selected() fires
   └── _display_record_with_clickable_fields() renders detail

4. User presses key
   └── on_key() delegates to keyboard_dispatcher
   └── Appropriate handler processes event

5. User searches
   └── _update_search_display() captures input
   └── _perform_live_search() filters tree in real-time
```

## Key Bindings

| Key | Action |
|-----|--------|
| `j/k` | Navigate up/down |
| `h/l` | Collapse/expand folder |
| `Enter` | Select item |
| `/` | Focus search |
| `Esc` | Clear/back |
| `t` | Toggle JSON view |
| `m` | Mask/unmask secrets |
| `p` | Copy password |
| `u` | Copy username |
| `c` | Copy all fields |
| `:cmd` | Run Keeper command |
| `Ctrl+\` | Toggle shell pane |
| `?` | Show help |
| `!` | Exit to Keeper shell |

## Adding New Features

### Adding a New Keyboard Shortcut

1. Create a handler class in `handlers/keyboard.py`:
```python
class MyNewHandler(KeyHandler):
    def can_handle(self, event, app):
        return event.key == "my_key" and not app.search_input_active

    def handle(self, event, app):
        # Do something
        self._stop_event(event)
        return True
```

2. Add to `KeyboardDispatcher.handlers` list in appropriate priority position

### Adding a New Theme

1. Add color dict to `themes/colors.py`:
```python
COLOR_THEMES = {
    # ... existing themes
    'mytheme': {
        'primary': '#ff0000',
        'secondary': '#00ff00',
        # ... all 18 color properties
    }
}
```

2. Update `screens/preferences.py` to show the new option

### Adding a New Display Mode

1. Add rendering logic to `renderers/`
2. Add state tracking to `state/ui_state.py` if needed
3. Add toggle action in main app
4. Add keyboard binding via handler

## Testing

Run SuperShell with:
```bash
keeper supershell
```

Or with the alias:
```bash
keeper ss
```

## Dependencies

- **textual** - TUI framework
- **rich** - Terminal formatting (used by Textual)
- **pyperclip** - Clipboard operations
