"""
Custom exceptions for the Guacamole protocol library.

This module defines the exception hierarchy for all Guacamole-related errors.
"""

from typing import Optional


class GuacamoleError(Exception):
    """Base exception for all Guacamole-related errors."""

    def __init__(self, message: str, code: Optional[int] = None):
        """
        Initialize a GuacamoleError.

        Args:
            message: Human-readable error description.
            code: Optional Guacamole status code.
        """
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        if self.code is not None:
            return f"[{self.code}] {self.message}"
        return self.message


class InvalidInstructionError(GuacamoleError):
    """Raised when a malformed Guacamole instruction is encountered."""

    def __init__(self, message: str, instruction: Optional[str] = None):
        """
        Initialize an InvalidInstructionError.

        Args:
            message: Description of why the instruction is invalid.
            instruction: The malformed instruction data, if available.
        """
        super().__init__(message)
        self.instruction = instruction


class ProtocolError(GuacamoleError):
    """Raised when a protocol-level error occurs."""

    def __init__(self, message: str, code: Optional[int] = None):
        """
        Initialize a ProtocolError.

        Args:
            message: Description of the protocol error.
            code: Optional Guacamole status code.
        """
        super().__init__(message, code)


class TunnelError(GuacamoleError):
    """Raised when a tunnel-related error occurs."""

    def __init__(self, message: str, code: Optional[int] = None):
        """
        Initialize a TunnelError.

        Args:
            message: Description of the tunnel error.
            code: Optional Guacamole status code.
        """
        super().__init__(message, code)


class ClientError(GuacamoleError):
    """Raised when a client-related error occurs."""

    def __init__(self, message: str, code: Optional[int] = None):
        """
        Initialize a ClientError.

        Args:
            message: Description of the client error.
            code: Optional Guacamole status code.
        """
        super().__init__(message, code)
