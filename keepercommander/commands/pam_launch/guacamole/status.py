"""
Guacamole status codes and Status class.

This module provides the Status class and StatusCode enum for representing
Guacamole protocol status codes and associated messages.
"""

from enum import IntEnum
from typing import Optional


class StatusCode(IntEnum):
    """
    Enumeration of all Guacamole protocol status codes.

    Status codes are divided into ranges:
    - 0x0000-0x00FF: Success/informational
    - 0x0100-0x01FF: Unsupported operations
    - 0x0200-0x02FF: Server errors
    - 0x0300-0x03FF: Client errors
    """

    # Success
    SUCCESS = 0x0000

    # Unsupported
    UNSUPPORTED = 0x0100

    # Server errors
    SERVER_ERROR = 0x0200
    SERVER_BUSY = 0x0201
    UPSTREAM_TIMEOUT = 0x0202
    UPSTREAM_ERROR = 0x0203
    RESOURCE_NOT_FOUND = 0x0204
    RESOURCE_CONFLICT = 0x0205
    RESOURCE_CLOSED = 0x0206
    UPSTREAM_NOT_FOUND = 0x0207
    UPSTREAM_UNAVAILABLE = 0x0208
    SESSION_CONFLICT = 0x0209
    SESSION_TIMEOUT = 0x020A
    SESSION_CLOSED = 0x020B

    # Client errors
    CLIENT_BAD_REQUEST = 0x0300
    CLIENT_UNAUTHORIZED = 0x0301
    CLIENT_FORBIDDEN = 0x0303
    CLIENT_TIMEOUT = 0x0308
    CLIENT_OVERRUN = 0x030D
    CLIENT_BAD_TYPE = 0x030F
    CLIENT_TOO_MANY = 0x031D

    @classmethod
    def from_http_code(cls, http_status: int) -> 'StatusCode':
        """
        Return the Guacamole status code that most closely represents
        the given HTTP status code.

        Args:
            http_status: The HTTP status code to translate.

        Returns:
            The corresponding Guacamole status code.
        """
        http_to_guac = {
            400: cls.CLIENT_BAD_REQUEST,
            403: cls.CLIENT_FORBIDDEN,
            404: cls.RESOURCE_NOT_FOUND,
            429: cls.CLIENT_TOO_MANY,
            503: cls.SERVER_BUSY,
        }
        return http_to_guac.get(http_status, cls.SERVER_ERROR)

    @classmethod
    def from_websocket_code(cls, ws_code: int) -> 'StatusCode':
        """
        Return the Guacamole status code that most closely represents
        the given WebSocket close code.

        Args:
            ws_code: The WebSocket status code to translate.

        Returns:
            The corresponding Guacamole status code.
        """
        # Successful disconnect
        if ws_code == 1000:  # Normal Closure
            return cls.SUCCESS

        # Server not reachable
        if ws_code in (1006, 1015):  # Abnormal Closure, TLS Handshake
            return cls.UPSTREAM_NOT_FOUND

        # Server busy/unavailable
        if ws_code in (1001, 1012, 1013, 1014):  # Going Away, Service Restart, Try Again, Bad Gateway
            return cls.UPSTREAM_UNAVAILABLE

        return cls.SERVER_ERROR


class Status:
    """
    A Guacamole status consisting of a status code and optional message.

    The status code is defined by the protocol, while the message is an
    optional human-readable description, typically for debugging.

    Attributes:
        code: The Guacamole status code.
        message: Optional human-readable message.

    Example:
        status = Status(StatusCode.SUCCESS, "Connection established")
        if status.is_error():
            print(f"Error: {status.message}")
    """

    def __init__(self, code: int, message: Optional[str] = None):
        """
        Initialize a new Status.

        Args:
            code: The Guacamole status code (can be int or StatusCode).
            message: Optional human-readable message.
        """
        self.code: int = int(code)
        self.message: Optional[str] = message

    def is_error(self) -> bool:
        """
        Return whether this status represents an error.

        Returns:
            True if this is an error status, False otherwise.
        """
        return self.code < 0 or self.code > 0x00FF

    def __repr__(self) -> str:
        """Return a string representation of this status."""
        try:
            code_name = StatusCode(self.code).name
        except ValueError:
            code_name = f"UNKNOWN({self.code})"

        if self.message:
            return f"Status({code_name}, {self.message!r})"
        return f"Status({code_name})"

    def __str__(self) -> str:
        """Return a human-readable string for this status."""
        try:
            code_name = StatusCode(self.code).name
        except ValueError:
            code_name = f"Code {self.code}"

        if self.message:
            return f"{code_name}: {self.message}"
        return code_name
