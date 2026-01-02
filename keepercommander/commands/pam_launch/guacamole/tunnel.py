"""
Guacamole tunnel abstract base class.

This module provides the abstract Tunnel class that defines the interface
for Guacamole protocol communication channels. Concrete implementations
should handle the actual transport mechanism (WebSocket, HTTP, WebRTC, etc.).
"""

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Any, Callable, List, Optional

from .status import Status


class TunnelState(IntEnum):
    """
    All possible tunnel states.

    Attributes:
        CONNECTING: A connection is pending. It is not yet known whether
            connection was successful.
        OPEN: Connection was successful, and data is being received.
        CLOSED: The connection is closed. Connection may not have been
            successful, the tunnel may have been explicitly closed by
            either side, or an error may have occurred.
        UNSTABLE: The connection is open, but communication appears to be
            disrupted, and the connection may close as a result.
    """
    CONNECTING = 0
    OPEN = 1
    CLOSED = 2
    UNSTABLE = 3


class Tunnel(ABC):
    """
    Abstract base class for Guacamole protocol tunnels.

    This class defines the interface for sending and receiving Guacamole
    protocol instructions over a communication channel. Concrete implementations
    should handle the specific transport mechanism.

    Attributes:
        state: The current state of this tunnel.
        uuid: The UUID uniquely identifying this tunnel, or None if not yet known.
        receive_timeout: Maximum time (ms) to wait for data before closing.
        unstable_threshold: Time (ms) before connection is considered unstable.
        oninstruction: Callback for received instructions.
        onstatechange: Callback for state changes.
        onerror: Callback for errors.
        onuuid: Callback when UUID becomes known.

    Example:
        class MyTunnel(Tunnel):
            def connect(self, data=None):
                # Implementation
                pass

            def disconnect(self):
                # Implementation
                pass

            def send_message(self, *elements):
                # Implementation
                pass
    """

    # Internal data opcode used by tunnel implementations
    INTERNAL_DATA_OPCODE = ''

    def __init__(self):
        """Initialize a new Tunnel instance."""
        self._state: TunnelState = TunnelState.CLOSED
        self.uuid: Optional[str] = None
        self.receive_timeout: int = 15000
        self.unstable_threshold: int = 1500

        # Callbacks
        self.oninstruction: Optional[Callable[[str, List[str]], None]] = None
        self.onstatechange: Optional[Callable[[TunnelState], None]] = None
        self.onerror: Optional[Callable[[Status], None]] = None
        self.onuuid: Optional[Callable[[str], None]] = None

    @property
    def state(self) -> TunnelState:
        """Get the current tunnel state."""
        return self._state

    @state.setter
    def state(self, value: TunnelState) -> None:
        """Set the tunnel state (use set_state() for callback notification)."""
        self._state = value

    def set_state(self, state: TunnelState) -> None:
        """
        Change the tunnel state, firing onstatechange if the state changes.

        Args:
            state: The new state of this tunnel.
        """
        if state != self._state:
            self._state = state
            if self.onstatechange:
                self.onstatechange(state)

    def set_uuid(self, uuid: str) -> None:
        """
        Set the tunnel UUID, firing onuuid callback.

        Args:
            uuid: The unique identifier for this tunnel.
        """
        self.uuid = uuid
        if self.onuuid:
            self.onuuid(uuid)

    def is_connected(self) -> bool:
        """
        Return whether this tunnel is currently connected.

        Returns:
            True if the tunnel is in OPEN or UNSTABLE state, False otherwise.
        """
        return self._state in (TunnelState.OPEN, TunnelState.UNSTABLE)

    @abstractmethod
    def connect(self, data: Optional[str] = None) -> None:
        """
        Connect to the tunnel with the given optional data.

        The data is typically used for authentication. The format of data
        accepted is up to the tunnel implementation.

        Args:
            data: Optional data to send during connection (e.g., auth tokens).
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from the tunnel."""
        pass

    @abstractmethod
    def send_message(self, *elements: Any) -> None:
        """
        Send a message through the tunnel.

        All messages are guaranteed to be received in the order sent.

        Args:
            *elements: The elements of the message to send. These will be
                formatted as a Guacamole instruction.
        """
        pass
