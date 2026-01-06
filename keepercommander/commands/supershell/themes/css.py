"""
SuperShell CSS styling

Base CSS and dynamic theme-specific CSS generation.
"""

from .colors import COLOR_THEMES

# Base CSS - static styles that don't change with themes
BASE_CSS = """
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

#shell_output {
    height: 1fr;
    overflow-y: auto;
    padding: 0 1;
    background: #000000;
    align: left bottom;
}

#shell_output_content {
    background: #000000;
    color: #ffffff;
    width: 100%;
}

#shell_input_line {
    height: 2;
    background: #111111;
    color: #00ff00;
    padding: 1 1 0 1;
    border-top: solid #333333;
}

#shell_pane:focus-within #shell_input_line {
    background: #1a1a2e;
}
"""


def get_theme_css(theme_name: str) -> str:
    """Generate dynamic CSS for a specific theme.

    This can be used to override specific colors based on theme.
    Currently themes are applied via Rich markup rather than CSS,
    but this provides a hook for future theme-based CSS customization.
    """
    if theme_name not in COLOR_THEMES:
        theme_name = 'green'

    theme = COLOR_THEMES[theme_name]

    # Dynamic CSS based on theme colors
    return f"""
    #shell_header {{
        color: {theme['primary']};
    }}

    #shell_input_line {{
        color: {theme['primary']};
    }}
    """
