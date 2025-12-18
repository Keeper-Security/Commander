#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Terminal renderer for Guacamole CLI mode.

Renders Guacamole terminal output using ANSI escape codes or curses.
Supports basic text operations, cursor movement, and attributes for SSH/Telnet.
"""

from __future__ import annotations
import sys
import os
import logging
from typing import Optional, Tuple
from .decoder import GuacInstruction, GuacOp


class TerminalRenderer:
    """
    Renders Guacamole terminal output to stdout using ANSI escape codes.

    This is a minimal renderer focused on text operations for SSH/Telnet.
    It maintains a virtual screen buffer and handles cursor positioning,
    text output, and basic attributes.
    """

    def __init__(self, width: int = 80, height: int = 24):
        """
        Initialize the terminal renderer.

        Args:
            width: Terminal width in characters
            height: Terminal height in characters
        """
        self.width = width
        self.height = height
        self.cursor_x = 0
        self.cursor_y = 0

        # Virtual screen buffer (2D array of characters)
        self.screen = [[' ' for _ in range(width)] for _ in range(height)]

        # Attribute buffer (for colors, bold, etc.)
        self.attrs = [[0 for _ in range(width)] for _ in range(height)]

        # Current drawing attributes
        self.current_fg = 7  # White
        self.current_bg = 0  # Black
        self.current_bold = False
        self.current_underline = False

        # Track if we're in raw mode
        self.raw_mode = False

    def initialize(self):
        """Initialize the terminal for rendering"""
        # Clear screen and hide cursor
        sys.stdout.write('\033[2J')  # Clear screen
        sys.stdout.write('\033[?25l')  # Hide cursor
        sys.stdout.flush()
        self.raw_mode = True

    def cleanup(self):
        """Restore terminal to normal state"""
        # Show cursor and reset attributes
        sys.stdout.write('\033[?25h')  # Show cursor
        sys.stdout.write('\033[0m')    # Reset attributes
        sys.stdout.write('\n')
        sys.stdout.flush()
        self.raw_mode = False

    def handle_instruction(self, instruction: GuacInstruction):
        """
        Handle a Guacamole instruction and update the display.

        Args:
            instruction: Parsed Guacamole instruction
        """
        opcode = instruction.opcode
        args = instruction.args

        try:
            if opcode == GuacOp.CURSOR.value:
                self._handle_cursor(args)
            elif opcode == GuacOp.TEXT.value:
                self._handle_text(args)
            elif opcode == GuacOp.RECT.value:
                self._handle_rect(args)
            elif opcode == GuacOp.CFILL.value:
                self._handle_cfill(args)
            elif opcode == GuacOp.COPY.value:
                self._handle_copy(args)
            elif opcode == GuacOp.SIZE.value:
                self._handle_size(args)
            elif opcode == GuacOp.MOVE.value:
                self._handle_move(args)
            elif opcode == GuacOp.PNG.value or opcode == GuacOp.JPEG.value:
                # Image operations - log but don't render in text mode
                logging.debug(f"Ignoring image operation: {opcode}")
            elif opcode == GuacOp.SYNC.value:
                # Sync instruction - refresh display
                self._handle_sync(args)
            elif opcode == GuacOp.ERROR.value:
                self._handle_error(args)
            elif opcode == GuacOp.DISCONNECT.value:
                logging.debug("Guacamole disconnect instruction received")
            elif opcode in (GuacOp.ACK.value, GuacOp.NOP.value):
                # Acknowledgment or no-op - ignore
                pass
            else:
                logging.debug(f"Unhandled Guacamole instruction: {opcode}")

        except Exception as e:
            logging.error(f"Error handling instruction {opcode}: {e}")

    def _handle_cursor(self, args: list):
        """Handle cursor positioning"""
        if len(args) >= 2:
            try:
                x = int(args[0])
                y = int(args[1])
                self.cursor_x = min(max(0, x), self.width - 1)
                self.cursor_y = min(max(0, y), self.height - 1)
            except ValueError:
                pass

    def _handle_text(self, args: list):
        """
        Handle text drawing.

        Args format: [layer, x, y, text]
        """
        if len(args) >= 4:
            try:
                # layer = args[0]  # Ignore layer for now
                x = int(args[1])
                y = int(args[2])
                text = args[3]

                # Draw text at position
                self._draw_text(x, y, text)

            except (ValueError, IndexError) as e:
                logging.debug(f"Error in text instruction: {e}")

    def _draw_text(self, x: int, y: int, text: str):
        """Draw text at specified position in screen buffer"""
        if y < 0 or y >= self.height:
            return

        for i, ch in enumerate(text):
            col = x + i
            if col >= 0 and col < self.width:
                self.screen[y][col] = ch
                self.attrs[y][col] = self._encode_attrs()

    def _encode_attrs(self) -> int:
        """Encode current attributes to a single integer"""
        attr = 0
        if self.current_bold:
            attr |= 1
        if self.current_underline:
            attr |= 2
        attr |= (self.current_fg & 0xF) << 4
        attr |= (self.current_bg & 0xF) << 8
        return attr

    def _handle_rect(self, args: list):
        """Handle rectangle drawing (fill with color)"""
        if len(args) >= 5:
            try:
                # layer = args[0]
                x = int(args[1])
                y = int(args[2])
                w = int(args[3])
                h = int(args[4])

                # Fill rectangle with spaces
                for row in range(y, min(y + h, self.height)):
                    for col in range(x, min(x + w, self.width)):
                        if row >= 0 and col >= 0:
                            self.screen[row][col] = ' '
                            self.attrs[row][col] = self._encode_attrs()

            except (ValueError, IndexError):
                pass

    def _handle_cfill(self, args: list):
        """Handle color fill"""
        if len(args) >= 4:
            try:
                # Parse color (r, g, b, a)
                # For simplicity, map to nearest ANSI color
                r = int(args[0])
                g = int(args[1])
                b = int(args[2])
                # a = int(args[3])  # alpha

                # Map RGB to ANSI color (0-15)
                self.current_bg = self._rgb_to_ansi(r, g, b)

            except (ValueError, IndexError):
                pass

    def _rgb_to_ansi(self, r: int, g: int, b: int) -> int:
        """Map RGB (0-255) to ANSI color code (0-15)"""
        # Simple mapping to 8 basic colors
        if r < 128 and g < 128 and b < 128:
            return 0  # Black
        elif r > 200 and g > 200 and b > 200:
            return 7  # White
        elif r > 128:
            return 1  # Red
        elif g > 128:
            return 2  # Green
        elif b > 128:
            return 4  # Blue
        else:
            return 7  # Default white

    def _handle_copy(self, args: list):
        """Handle copy operation (copy screen region)"""
        if len(args) >= 7:
            try:
                # src_layer = args[0]
                src_x = int(args[1])
                src_y = int(args[2])
                w = int(args[3])
                h = int(args[4])
                # dst_layer = args[5]
                dst_x = int(args[6])
                dst_y = int(args[7])

                # Copy region
                for row in range(h):
                    for col in range(w):
                        src_row = src_y + row
                        src_col = src_x + col
                        dst_row = dst_y + row
                        dst_col = dst_x + col

                        if (0 <= src_row < self.height and 0 <= src_col < self.width and
                            0 <= dst_row < self.height and 0 <= dst_col < self.width):
                            self.screen[dst_row][dst_col] = self.screen[src_row][src_col]
                            self.attrs[dst_row][dst_col] = self.attrs[src_row][src_col]

            except (ValueError, IndexError):
                pass

    def _handle_size(self, args: list):
        """Handle terminal size change"""
        if len(args) >= 3:
            try:
                # layer = args[0]
                new_width = int(args[1])
                new_height = int(args[2])

                if new_width > 0 and new_height > 0:
                    self.resize(new_width, new_height)

            except (ValueError, IndexError):
                pass

    def _handle_move(self, args: list):
        """Handle layer move (not relevant for text terminal)"""
        pass

    def _handle_sync(self, args: list):
        """Handle sync instruction - refresh the display"""
        self.refresh()

    def _handle_error(self, args: list):
        """Handle error message from server"""
        if args:
            error_msg = args[0]
            logging.error(f"Guacamole server error: {error_msg}")
            sys.stderr.write(f"\nServer error: {error_msg}\n")
            sys.stderr.flush()

    def resize(self, new_width: int, new_height: int):
        """
        Resize the terminal buffer.

        Args:
            new_width: New width in characters
            new_height: New height in characters
        """
        # Create new buffers
        new_screen = [[' ' for _ in range(new_width)] for _ in range(new_height)]
        new_attrs = [[0 for _ in range(new_width)] for _ in range(new_height)]

        # Copy old content
        for y in range(min(self.height, new_height)):
            for x in range(min(self.width, new_width)):
                new_screen[y][x] = self.screen[y][x]
                new_attrs[y][x] = self.attrs[y][x]

        self.width = new_width
        self.height = new_height
        self.screen = new_screen
        self.attrs = new_attrs

        # Clamp cursor position
        self.cursor_x = min(self.cursor_x, new_width - 1)
        self.cursor_y = min(self.cursor_y, new_height - 1)

        # Clear and redraw
        sys.stdout.write('\033[2J')  # Clear screen
        self.refresh()

    def refresh(self):
        """Refresh the entire display from the screen buffer"""
        if not self.raw_mode:
            return

        # Move cursor to home
        sys.stdout.write('\033[H')

        # Render each line
        for y in range(self.height):
            line = ''.join(self.screen[y])
            sys.stdout.write(line)
            if y < self.height - 1:
                sys.stdout.write('\n')

        # Move cursor to current position
        sys.stdout.write(f'\033[{self.cursor_y + 1};{self.cursor_x + 1}H')
        sys.stdout.flush()

    def get_size(self) -> Tuple[int, int]:
        """
        Get current terminal size.

        Returns:
            Tuple of (width, height) in characters
        """
        try:
            # Try to get actual terminal size
            import shutil
            size = shutil.get_terminal_size(fallback=(80, 24))
            return (size.columns, size.lines)
        except:
            return (self.width, self.height)

    def clear(self):
        """Clear the screen"""
        self.screen = [[' ' for _ in range(self.width)] for _ in range(self.height)]
        self.attrs = [[0 for _ in range(self.width)] for _ in range(self.height)]
        if self.raw_mode:
            sys.stdout.write('\033[2J')
            sys.stdout.write('\033[H')
            sys.stdout.flush()

