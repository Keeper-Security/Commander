"""
SuperShell color themes

Each theme uses variations of a primary color with consistent structure.
"""

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

# Default theme
DEFAULT_THEME = 'green'

# Available theme names
THEME_NAMES = list(COLOR_THEMES.keys())
