"""
Guacamole protocol parser.

This module provides the Parser class for parsing Guacamole protocol instructions
from incoming data streams. It handles the length-prefixed element format and
properly counts Unicode codepoints.

The Guacamole protocol uses instructions in the format:
    LENGTH.VALUE,LENGTH.VALUE,...,LENGTH.VALUE;

Where LENGTH is the number of Unicode codepoints in VALUE.
"""

import re
from typing import Any, Callable, List, Optional

from .exceptions import InvalidInstructionError


# Regex pattern for detecting UTF-16 surrogate pairs
# In Python strings (which are UTF-32 internally), surrogate pairs appear
# as two separate characters when the string came from UTF-16 encoding
_SURROGATE_PAIR_PATTERN = re.compile(r'[\uD800-\uDBFF][\uDC00-\uDFFF]')

# Minimum codepoint that requires a surrogate pair in UTF-16
_MIN_CODEPOINT_REQUIRES_SURROGATE = 0x10000

# Range checks for surrogates
_HIGH_SURROGATE_MIN = 0xD800
_HIGH_SURROGATE_MAX = 0xDBFF
_LOW_SURROGATE_MIN = 0xDC00
_LOW_SURROGATE_MAX = 0xDFFF


def _is_high_surrogate(char_code: int) -> bool:
    """Check if a character code is a high surrogate."""
    return _HIGH_SURROGATE_MIN <= char_code <= _HIGH_SURROGATE_MAX


def _is_low_surrogate(char_code: int) -> bool:
    """Check if a character code is a low surrogate."""
    return _LOW_SURROGATE_MIN <= char_code <= _LOW_SURROGATE_MAX


class Parser:
    """
    Simple Guacamole protocol parser that invokes an oninstruction callback when
    full instructions are available from data received via receive().

    The parser handles the Guacamole wire protocol format where each element
    is prefixed with its length in Unicode codepoints, followed by a period,
    then the element value, and finally a terminator (',' for more elements
    or ';' for end of instruction).

    Example:
        parser = Parser()
        parser.oninstruction = lambda opcode, args: print(f"{opcode}: {args}")
        parser.receive("4.sync,10.1234567890;")
        # Output: sync: ['1234567890']

    Attributes:
        oninstruction: Callback invoked when a complete instruction is parsed.
            Signature: (opcode: str, parameters: List[str]) -> None
    """

    # Number of parsed characters before truncating the buffer to conserve memory
    BUFFER_TRUNCATION_THRESHOLD = 4096

    def __init__(self):
        """Initialize a new Parser instance."""
        # Current buffer of received data
        self._buffer: str = ''

        # Buffer of all received, complete elements for current instruction
        self._element_buffer: List[str] = []

        # Character offset of current element's terminator (-1 if not yet known)
        self._element_end: int = -1

        # Character offset where parser should start looking for next element
        self._start_index: int = 0

        # Declared length of current element in Unicode codepoints
        self._element_codepoints: int = 0

        # Callback for completed instructions
        self.oninstruction: Optional[Callable[[str, List[str]], None]] = None

    def receive(self, packet: str, is_buffer: bool = False) -> None:
        """
        Append instruction data to the internal buffer and execute all
        completed instructions at the beginning of the buffer.

        Args:
            packet: The instruction data to receive.
            is_buffer: If True, the packet is treated as an external buffer
                that grows continuously. The packet MUST always start with
                the data provided to the previous call. If False (default),
                only new data should be provided and previously-received
                data will be buffered automatically.

        Raises:
            InvalidInstructionError: If a malformed instruction is encountered.
        """
        if is_buffer:
            self._buffer = packet
        else:
            # Truncate buffer as necessary to conserve memory
            if (self._start_index > self.BUFFER_TRUNCATION_THRESHOLD and
                    self._element_end >= self._start_index):
                self._buffer = self._buffer[self._start_index:]
                # Reset parse positions relative to truncation
                self._element_end -= self._start_index
                self._start_index = 0

            # Append data to buffer only if there is outstanding data.
            # Otherwise, parse the received buffer as-is for efficiency.
            if self._buffer:
                self._buffer += packet
            else:
                self._buffer = packet

        # Parse while search is within currently received data
        while self._element_end < len(self._buffer):

            # If we are waiting for element data
            if self._element_end >= self._start_index:

                # Count codepoints in the expected element substring
                codepoints = code_point_count(
                    self._buffer,
                    self._start_index,
                    self._element_end
                )

                # If we don't have enough codepoints yet, adjust element_end
                # This handles characters that are represented as surrogate pairs
                if codepoints < self._element_codepoints:
                    self._element_end += self._element_codepoints - codepoints
                    continue

                # If element_end points to a character that's part of a surrogate pair,
                # we need to adjust. Two cases:
                # 1. element_end-1 is HIGH surrogate and element_end is LOW surrogate
                #    (we're about to split a pair, need to include the LOW)
                # 2. element_end-1 is >= 0x10000 (combined supplementary char in Python,
                #    though this is rare since Python usually keeps surrogates separate)
                if (self._element_codepoints and
                        self._element_end > 0 and
                        self._element_end < len(self._buffer)):
                    last_char_index = self._element_end - 1
                    if last_char_index >= self._start_index:
                        last_char_code = ord(self._buffer[last_char_index])
                        term_char_code = ord(self._buffer[self._element_end])

                        # Case 1: Last char is HIGH surrogate, terminator pos is LOW surrogate
                        # This means we're about to cut a surrogate pair in half
                        if _is_high_surrogate(last_char_code) and _is_low_surrogate(term_char_code):
                            self._element_end += 1
                            continue

                        # Case 2: Character >= 0x10000 (combined supplementary char)
                        if last_char_code >= _MIN_CODEPOINT_REQUIRES_SURROGATE:
                            self._element_end += 1
                            continue

                # We now have enough data for the element - parse it
                element = self._buffer[self._start_index:self._element_end]

                # Get terminator character
                if self._element_end < len(self._buffer):
                    terminator = self._buffer[self._element_end]
                else:
                    # Need more data
                    break

                # Add element to array
                self._element_buffer.append(element)

                # If last element (semicolon terminator), handle instruction
                if terminator == ';':
                    # Get opcode (first element)
                    opcode = self._element_buffer.pop(0)

                    # Call instruction handler
                    if self.oninstruction is not None:
                        self.oninstruction(opcode, self._element_buffer)

                    # Clear elements for next instruction
                    self._element_buffer = []

                    # Immediately truncate buffer if fully parsed
                    if not is_buffer and self._element_end + 1 == len(self._buffer):
                        self._element_end = -1
                        self._buffer = ''

                elif terminator != ',':
                    raise InvalidInstructionError(
                        'Element terminator of instruction was not ";" nor ",".',
                        instruction=self._buffer[:self._element_end + 1]
                    )

                # Start searching for length at character after terminator
                self._start_index = self._element_end + 1

            # Search for end of length (the period)
            length_end = self._buffer.find('.', self._start_index)
            if length_end != -1:
                # Parse length
                length_str = self._buffer[self._element_end + 1:length_end]
                try:
                    self._element_codepoints = int(length_str)
                except ValueError:
                    raise InvalidInstructionError(
                        'Non-numeric character in element length.',
                        instruction=length_str
                    )

                # Calculate start of element value
                self._start_index = length_end + 1

                # Calculate location of element terminator
                self._element_end = self._start_index + self._element_codepoints

            else:
                # No period yet, continue search when more data is received
                self._start_index = len(self._buffer)
                break


def code_point_count(s: str, start: int = 0, end: Optional[int] = None) -> int:
    """
    Return the number of Unicode codepoints in the given string or substring.

    In Python, strings are stored as proper Unicode (UTF-32 internally), so
    len() already gives the codepoint count. However, this function also handles
    edge cases where surrogate characters might appear in strings that originated
    from UTF-16 encoding.

    Unlike JavaScript's string.length which counts UTF-16 code units (where
    surrogate pairs count as 2), this function counts actual Unicode codepoints.

    Args:
        s: The string to inspect.
        start: The starting index (default 0).
        end: The ending index (exclusive). If None, counts to end of string.

    Returns:
        The number of Unicode codepoints in the specified portion of the string.

    Example:
        >>> code_point_count("hello")
        5
        >>> code_point_count("test string", 0, 4)
        4
    """
    # Extract substring
    substring = s[start:end]

    # In Python, len() gives codepoint count for normal strings.
    # However, if the string contains unpaired surrogates (from malformed UTF-16),
    # we need to handle surrogate pairs that are stored as two characters.
    # Find proper surrogate pairs (high surrogate followed by low surrogate)
    surrogate_pairs = _SURROGATE_PAIR_PATTERN.findall(substring)

    # Each surrogate pair represents a single codepoint but is stored as
    # two characters in Python when originating from UTF-16 data.
    # Subtract the number of pairs to get the actual codepoint count.
    return len(substring) - len(surrogate_pairs)


def to_instruction(elements: List[Any]) -> str:
    """
    Convert a list of values into a properly formatted Guacamole instruction.

    Each element is converted to a string and prefixed with its length in
    Unicode codepoints, followed by a period. Elements are separated by
    commas, and the instruction ends with a semicolon.

    Args:
        elements: The values to encode as instruction elements. Must have at
            least one element (the opcode). Each element will be converted
            to a string.

    Returns:
        A complete Guacamole instruction string.

    Example:
        >>> to_instruction(["key", "65", "1"])
        '3.key,2.65,1.1;'
        >>> to_instruction(["sync", "1234567890"])
        '4.sync,10.1234567890;'
    """
    if not elements:
        raise ValueError("Instruction must have at least one element (opcode)")

    def to_element(value: Any) -> str:
        """Convert a value to a length-prefixed element string."""
        s = str(value)
        length = code_point_count(s)
        return f"{length}.{s}"

    # Build instruction: first element, then comma-separated remaining elements
    instruction = to_element(elements[0])
    for element in elements[1:]:
        instruction += ',' + to_element(element)

    return instruction + ';'


# Expose functions at module level for convenience
Parser.code_point_count = staticmethod(code_point_count)
Parser.to_instruction = staticmethod(to_instruction)
