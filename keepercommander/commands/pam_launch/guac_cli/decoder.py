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
Guacamole protocol decoder for Commander CLI terminal mode.

Parses Guacamole protocol instructions (text-based, comma-separated format)
and converts them to terminal operations for rendering.

Protocol format: opcode,arg1,arg2,...;
Example: "4.sync,8.12345678;"
         "3.key,3.100,1.1;" (key press, keycode 100)
"""

from __future__ import annotations
import logging
from typing import List, Tuple, Optional, Callable
from enum import Enum


class GuacInstruction:
    """Represents a parsed Guacamole instruction"""

    def __init__(self, opcode: str, args: List[str]):
        self.opcode = opcode
        self.args = args

    def __repr__(self):
        return f"GuacInstruction({self.opcode}, {self.args})"


class GuacOp(Enum):
    """Guacamole opcodes relevant to terminal sessions"""
    # Core protocol
    SYNC = "sync"           # Synchronization with timestamp
    ACK = "ack"             # Acknowledge received frames
    NOP = "nop"             # No operation / keepalive

    # Display operations
    SIZE = "size"           # Terminal size (layers, width, height)
    MOVE = "move"           # Move layer
    SHADE = "shade"         # Set layer opacity
    DISPOSE = "dispose"     # Dispose of layer

    # Drawing operations  
    RECT = "rect"           # Draw rectangle
    CFILL = "cfill"         # Color fill
    COPY = "copy"           # Copy region
    PNG = "png"             # PNG image data
    JPEG = "jpeg"           # JPEG image data

    # Text operations (primary for SSH/Telnet)
    CURSOR = "cursor"       # Set cursor position
    TEXT = "text"           # Draw text

    # Input operations
    KEY = "key"             # Keyboard event
    MOUSE = "mouse"         # Mouse event
    CLIPBOARD = "clipboard" # Clipboard data

    # Stream operations
    BLOB = "blob"           # Binary data blob
    END = "end"             # End stream

    # Audio (not used for terminal)
    AUDIO = "audio"         # Audio stream

    # File transfer
    FILE = "file"           # File metadata
    PIPE = "pipe"           # Pipe stream

    # Other
    ARGS = "args"           # Connection arguments
    ERROR = "error"         # Error message
    DISCONNECT = "disconnect"  # Connection closed


class GuacamoleDecoder:
    """
    Decoder for Guacamole protocol instructions.

    Parses the text-based Guacamole protocol and emits structured instructions
    for terminal rendering. Focuses on SSH/Telnet text operations.
    """

    def __init__(self):
        self.buffer = ""
        self.handlers = {}  # opcode -> callback mapping

    def register_handler(self, opcode: str, callback: Callable[[GuacInstruction], None]):
        """Register a handler for a specific opcode"""
        self.handlers[opcode] = callback

    def feed(self, data: bytes) -> List[GuacInstruction]:
        """
        Feed raw bytes from the data channel and parse instructions.

        Args:
            data: Raw bytes from Guacamole server

        Returns:
            List of parsed instructions
        """
        try:
            # Guacamole protocol is UTF-8 text
            text = data.decode('utf-8')
            self.buffer += text
        except UnicodeDecodeError as e:
            logging.warning(f"Failed to decode Guacamole data: {e}")
            return []

        instructions = []

        # Parse complete instructions (terminated by semicolon)
        while ';' in self.buffer:
            idx = self.buffer.index(';')
            instruction_text = self.buffer[:idx]
            self.buffer = self.buffer[idx + 1:]

            # Parse the instruction
            instruction = self._parse_instruction(instruction_text)
            if instruction:
                instructions.append(instruction)

                # Call registered handler if exists
                if instruction.opcode in self.handlers:
                    try:
                        self.handlers[instruction.opcode](instruction)
                    except Exception as e:
                        logging.error(f"Error in handler for {instruction.opcode}: {e}")

        return instructions

    def _parse_instruction(self, text: str) -> Optional[GuacInstruction]:
        """
        Parse a single instruction from text format.

        Format: length.value,length.value,...
        Example: "4.sync,8.12345678" -> sync instruction with timestamp

        Args:
            text: Raw instruction text (without semicolon)

        Returns:
            Parsed GuacInstruction or None if parsing fails
        """
        if not text:
            return None

        try:
            elements = []
            remaining = text

            while remaining:
                # Find the length prefix
                if '.' not in remaining:
                    break

                dot_idx = remaining.index('.')
                length_str = remaining[:dot_idx]

                try:
                    length = int(length_str)
                except ValueError:
                    logging.warning(f"Invalid length prefix in Guacamole instruction: {length_str}")
                    return None

                # Extract the value
                value_start = dot_idx + 1
                value_end = value_start + length

                if value_end > len(remaining):
                    logging.warning(f"Truncated Guacamole instruction: expected {length} bytes")
                    return None

                value = remaining[value_start:value_end]
                elements.append(value)

                # Move to next element
                remaining = remaining[value_end:]
                if remaining.startswith(','):
                    remaining = remaining[1:]

            if not elements:
                return None

            # First element is the opcode
            opcode = elements[0]
            args = elements[1:]

            return GuacInstruction(opcode, args)

        except Exception as e:
            logging.error(f"Error parsing Guacamole instruction '{text}': {e}")
            return None

    def encode_instruction(self, opcode: str, *args) -> bytes:
        """
        Encode a Guacamole instruction to send to the server.

        Args:
            opcode: Instruction opcode
            *args: Instruction arguments

        Returns:
            Encoded instruction as bytes
        """
        elements = [opcode] + list(args)
        encoded_parts = []

        for element in elements:
            element_str = str(element)
            encoded_parts.append(f"{len(element_str)}.{element_str}")

        instruction = ','.join(encoded_parts) + ';'
        return instruction.encode('utf-8')

    def encode_key(self, keycode: int, pressed: bool) -> bytes:
        """
        Encode a keyboard event.

        Args:
            keycode: X11 keysym value
            pressed: True for press, False for release

        Returns:
            Encoded key instruction
        """
        return self.encode_instruction('key', str(keycode), '1' if pressed else '0')

    def encode_mouse(self, x: int, y: int, button_mask: int) -> bytes:
        """
        Encode a mouse event.

        Args:
            x: X coordinate
            y: Y coordinate
            button_mask: Bitmask of pressed buttons

        Returns:
            Encoded mouse instruction
        """
        return self.encode_instruction('mouse', str(x), str(y), str(button_mask))

    def encode_size(self, width: int, height: int) -> bytes:
        """
        Encode a terminal size change.

        Args:
            width: Terminal width in characters
            height: Terminal height in characters

        Returns:
            Encoded size instruction
        """
        # Size instruction: size,layer,width,height
        # Layer 0 is the root layer
        return self.encode_instruction('size', '0', str(width), str(height))

    def encode_clipboard(self, mimetype: str, data: str) -> bytes:
        """
        Encode clipboard data.

        Args:
            mimetype: MIME type (typically "text/plain")
            data: Clipboard text

        Returns:
            Encoded clipboard instruction
        """
        return self.encode_instruction('clipboard', mimetype, data)

    def encode_sync(self, timestamp: str) -> bytes:
        """
        Encode a sync acknowledgment.

        Args:
            timestamp: Timestamp from server's sync instruction

        Returns:
            Encoded sync instruction
        """
        return self.encode_instruction('sync', timestamp)


# X11 keysym mappings for common keys
# Reference: https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html#keysym_encoding
class X11Keysym:
    """X11 keysym values for common keyboard keys"""

    # Control keys
    BACKSPACE = 0xFF08
    TAB = 0xFF09
    RETURN = 0xFF0D
    ESCAPE = 0xFF1B
    DELETE = 0xFFFF

    # Cursor movement
    HOME = 0xFF50
    LEFT = 0xFF51
    UP = 0xFF52
    RIGHT = 0xFF53
    DOWN = 0xFF54
    PAGE_UP = 0xFF55
    PAGE_DOWN = 0xFF56
    END = 0xFF57

    # Function keys
    F1 = 0xFFBE
    F2 = 0xFFBF
    F3 = 0xFFC0
    F4 = 0xFFC1
    F5 = 0xFFC2
    F6 = 0xFFC3
    F7 = 0xFFC4
    F8 = 0xFFC5
    F9 = 0xFFC6
    F10 = 0xFFC7
    F11 = 0xFFC8
    F12 = 0xFFC9

    # Modifiers
    SHIFT_L = 0xFFE1
    SHIFT_R = 0xFFE2
    CONTROL_L = 0xFFE3
    CONTROL_R = 0xFFE4
    CAPS_LOCK = 0xFFE5
    META_L = 0xFFE7
    META_R = 0xFFE8
    ALT_L = 0xFFE9
    ALT_R = 0xFFEA

    # ASCII printable range (0x20-0x7E) maps directly
    # For example: 'A' = 0x41, 'a' = 0x61, '0' = 0x30

    @staticmethod
    def from_char(ch: str) -> int:
        """Convert a single character to X11 keysym"""
        if len(ch) == 1:
            return ord(ch)
        return 0

