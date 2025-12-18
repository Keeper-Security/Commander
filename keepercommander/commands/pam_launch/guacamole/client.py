"""
Guacamole protocol client.

This module provides the Client class for handling Guacamole protocol
communication. This is a terminal-focused implementation that handles
the instruction routing and state management needed for SSH/RDP/VNC
terminal sessions.

Note: GUI-related handlers (png, jpeg, img, rect, cfill, copy, move, cursor,
video, audio, etc.) are not implemented in this port as they require a
graphical display layer. This implementation focuses on:
- Connection state management
- Keep-alive/sync handling
- Keyboard and mouse input
- Clipboard support
- Stream management
- Error handling
"""

import time
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

from .integer_pool import IntegerPool
from .parser import Parser
from .status import Status, StatusCode
from .tunnel import Tunnel, TunnelState


class ClientState(IntEnum):
    """
    All possible Guacamole client states.

    Attributes:
        IDLE: The client is idle, with no active connection.
        CONNECTING: The client is in the process of establishing a connection.
        WAITING: The client is waiting on further information or a remote
            server to establish the connection.
        CONNECTED: The client is actively connected to a remote server.
        DISCONNECTING: The client is in the process of disconnecting.
        DISCONNECTED: The client has completed disconnection.
    """
    IDLE = 0
    CONNECTING = 1
    WAITING = 2
    CONNECTED = 3
    DISCONNECTING = 4
    DISCONNECTED = 5


class ClientMessage(IntEnum):
    """
    Possible messages that can be sent by the server.

    Attributes:
        USER_JOINED: A user has joined the connection.
        USER_LEFT: A user has left the connection.
    """
    USER_JOINED = 0x0001
    USER_LEFT = 0x0002


class InputStream:
    """
    Guacamole input stream for receiving data from the server.

    Attributes:
        client: The client that owns this stream.
        index: The index of this stream.
        onblob: Callback for received blob data.
        onend: Callback when stream ends.
    """

    def __init__(self, client: 'Client', index: int):
        """
        Initialize a new InputStream.

        Args:
            client: The client that owns this stream.
            index: The index of this stream.
        """
        self.client = client
        self.index = index
        self.onblob: Optional[Callable[[str], None]] = None
        self.onend: Optional[Callable[[], None]] = None


class OutputStream:
    """
    Guacamole output stream for sending data to the server.

    Attributes:
        client: The client that owns this stream.
        index: The index of this stream.
        onack: Callback for acknowledgement of sent data.
    """

    def __init__(self, client: 'Client', index: int):
        """
        Initialize a new OutputStream.

        Args:
            client: The client that owns this stream.
            index: The index of this stream.
        """
        self.client = client
        self.index = index
        self.onack: Optional[Callable[[Status], None]] = None


class Client:
    """
    Guacamole protocol client for terminal-focused applications.

    Given a Tunnel, automatically handles incoming and outgoing Guacamole
    instructions via the provided tunnel. This implementation focuses on
    terminal operations (keyboard, mouse, clipboard) rather than graphical
    display rendering.

    Attributes:
        tunnel: The tunnel used for communication.
        State: Alias for ClientState enum.
        Message: Alias for ClientMessage enum.

    Callbacks:
        onstatechange: Called when client state changes.
        onerror: Called when an error occurs.
        onname: Called when connection name is received.
        onsync: Called when sync instruction is received.
        onclipboard: Called when clipboard data is available.
        onfile: Called when a file transfer starts.
        onpipe: Called when a named pipe is created.
        onargv: Called when argument value is received.
        onrequired: Called when additional parameters are required.
        onjoin: Called when a user joins.
        onleave: Called when a user leaves.
        onmsg: Called for general messages.

    Example:
        client = Client(tunnel)
        client.onstatechange = lambda state: print(f"State: {state}")
        client.connect("hostname=example.com")
    """

    # Expose enums as class attributes
    State = ClientState
    Message = ClientMessage

    # Keep-alive ping frequency in milliseconds
    KEEP_ALIVE_FREQUENCY = 5000

    def __init__(self, tunnel: Tunnel):
        """
        Initialize a new Client.

        Args:
            tunnel: The tunnel to use for communication.
        """
        self.tunnel = tunnel
        self._state = ClientState.IDLE
        self._current_timestamp = 0
        self._last_sent_keepalive = 0
        self._keepalive_timeout: Optional[float] = None

        # Stream management
        self._stream_indices = IntegerPool()
        self._streams: Dict[int, InputStream] = {}
        self._output_streams: Dict[int, OutputStream] = {}

        # Callbacks
        self.onstatechange: Optional[Callable[[ClientState], None]] = None
        self.onerror: Optional[Callable[[Status], None]] = None
        self.onname: Optional[Callable[[str], None]] = None
        self.onsync: Optional[Callable[[int, int], None]] = None
        self.onclipboard: Optional[Callable[[InputStream, str], None]] = None
        self.onfile: Optional[Callable[[InputStream, str, str], None]] = None
        self.onpipe: Optional[Callable[[InputStream, str, str], None]] = None
        self.onargv: Optional[Callable[[InputStream, str, str], None]] = None
        self.onrequired: Optional[Callable[[List[str]], None]] = None
        self.onjoin: Optional[Callable[[str, str], None]] = None
        self.onleave: Optional[Callable[[str, str], None]] = None
        self.onmsg: Optional[Callable[[int, List[str]], Optional[bool]]] = None

        # Set up instruction handlers
        self._instruction_handlers: Dict[str, Callable[[List[str]], None]] = {
            'ack': self._handle_ack,
            'argv': self._handle_argv,
            'blob': self._handle_blob,
            'clipboard': self._handle_clipboard,
            'disconnect': self._handle_disconnect,
            'end': self._handle_end,
            'error': self._handle_error,
            'file': self._handle_file,
            'msg': self._handle_msg,
            'name': self._handle_name,
            'nop': self._handle_nop,
            'pipe': self._handle_pipe,
            'required': self._handle_required,
            'sync': self._handle_sync,
        }

        # Wire up tunnel instruction handler
        tunnel.oninstruction = self._on_instruction

    @property
    def state(self) -> ClientState:
        """Get the current client state."""
        return self._state

    def _set_state(self, state: ClientState) -> None:
        """
        Set the client state, firing onstatechange if changed.

        Args:
            state: The new client state.
        """
        if state != self._state:
            self._state = state
            if self.onstatechange:
                self.onstatechange(state)

    def _is_connected(self) -> bool:
        """Return whether the client is connected or waiting."""
        return self._state in (ClientState.CONNECTED, ClientState.WAITING)

    def _on_instruction(self, opcode: str, parameters: List[str]) -> None:
        """
        Handle a received instruction.

        Args:
            opcode: The instruction opcode.
            parameters: The instruction parameters.
        """
        handler = self._instruction_handlers.get(opcode)
        if handler:
            handler(parameters)

        # Schedule next keep-alive on any network activity
        self._schedule_keepalive()

    # ==========================================================================
    # Instruction Handlers
    # ==========================================================================

    def _handle_ack(self, parameters: List[str]) -> None:
        """Handle ack instruction."""
        stream_index = int(parameters[0])
        reason = parameters[1]
        code = int(parameters[2])

        stream = self._output_streams.get(stream_index)
        if stream:
            if stream.onack:
                stream.onack(Status(code, reason))

            # If error code, invalidate stream
            if code >= 0x0100 and self._output_streams.get(stream_index) is stream:
                self._stream_indices.free(stream_index)
                del self._output_streams[stream_index]

    def _handle_argv(self, parameters: List[str]) -> None:
        """Handle argv instruction (argument value stream)."""
        stream_index = int(parameters[0])
        mimetype = parameters[1]
        name = parameters[2]

        if self.onargv:
            stream = InputStream(self, stream_index)
            self._streams[stream_index] = stream
            self.onargv(stream, mimetype, name)
        else:
            self.send_ack(stream_index, "Receiving argument values unsupported", 0x0100)

    def _handle_blob(self, parameters: List[str]) -> None:
        """Handle blob instruction (stream data)."""
        stream_index = int(parameters[0])
        data = parameters[1]

        stream = self._streams.get(stream_index)
        if stream and stream.onblob:
            stream.onblob(data)

    def _handle_clipboard(self, parameters: List[str]) -> None:
        """Handle clipboard instruction."""
        stream_index = int(parameters[0])
        mimetype = parameters[1]

        if self.onclipboard:
            stream = InputStream(self, stream_index)
            self._streams[stream_index] = stream
            self.onclipboard(stream, mimetype)
        else:
            self.send_ack(stream_index, "Clipboard unsupported", 0x0100)

    def _handle_disconnect(self, parameters: List[str]) -> None:
        """Handle disconnect instruction."""
        self.disconnect()

    def _handle_end(self, parameters: List[str]) -> None:
        """Handle end instruction (stream end)."""
        stream_index = int(parameters[0])

        stream = self._streams.get(stream_index)
        if stream:
            if stream.onend:
                stream.onend()
            del self._streams[stream_index]

    def _handle_error(self, parameters: List[str]) -> None:
        """Handle error instruction."""
        reason = parameters[0]
        code = int(parameters[1])

        if self.onerror:
            self.onerror(Status(code, reason))

        self.disconnect()

    def _handle_file(self, parameters: List[str]) -> None:
        """Handle file instruction (file transfer)."""
        stream_index = int(parameters[0])
        mimetype = parameters[1]
        filename = parameters[2]

        if self.onfile:
            stream = InputStream(self, stream_index)
            self._streams[stream_index] = stream
            self.onfile(stream, mimetype, filename)
        else:
            self.send_ack(stream_index, "File transfer unsupported", 0x0100)

    def _handle_msg(self, parameters: List[str]) -> None:
        """Handle msg instruction (general message)."""
        msgid = int(parameters[0])

        # Fire general message handler first
        allow_default = True
        if self.onmsg:
            result = self.onmsg(msgid, parameters[1:])
            if result is not None:
                allow_default = result

        # Fire specific convenience events if allowed
        if allow_default:
            if msgid == ClientMessage.USER_JOINED:
                user_id = parameters[1]
                username = parameters[2]
                if self.onjoin:
                    self.onjoin(user_id, username)
            elif msgid == ClientMessage.USER_LEFT:
                user_id = parameters[1]
                username = parameters[2]
                if self.onleave:
                    self.onleave(user_id, username)

    def _handle_name(self, parameters: List[str]) -> None:
        """Handle name instruction (connection name)."""
        if self.onname:
            self.onname(parameters[0])

    def _handle_nop(self, parameters: List[str]) -> None:
        """Handle nop instruction (no operation / keep-alive)."""
        # No operation needed - just confirms connection is alive
        pass

    def _handle_pipe(self, parameters: List[str]) -> None:
        """Handle pipe instruction (named pipe)."""
        stream_index = int(parameters[0])
        mimetype = parameters[1]
        name = parameters[2]

        if self.onpipe:
            stream = InputStream(self, stream_index)
            self._streams[stream_index] = stream
            self.onpipe(stream, mimetype, name)
        else:
            self.send_ack(stream_index, "Named pipes unsupported", 0x0100)

    def _handle_required(self, parameters: List[str]) -> None:
        """Handle required instruction (additional parameters needed)."""
        if self.onrequired:
            self.onrequired(parameters)

    def _handle_sync(self, parameters: List[str]) -> None:
        """Handle sync instruction."""
        timestamp = int(parameters[0])
        frames = int(parameters[1]) if len(parameters) > 1 else 0

        # Send sync response
        if timestamp != self._current_timestamp:
            self.tunnel.send_message("sync", timestamp)
            self._current_timestamp = timestamp

        # Transition from WAITING to CONNECTED on first sync
        if self._state == ClientState.WAITING:
            self._set_state(ClientState.CONNECTED)

        # Fire callback
        if self.onsync:
            self.onsync(timestamp, frames)

    # ==========================================================================
    # Keep-alive Management
    # ==========================================================================

    def _send_keepalive(self) -> None:
        """Send a keep-alive nop instruction."""
        self.tunnel.send_message('nop')
        self._last_sent_keepalive = time.time() * 1000

    def _schedule_keepalive(self) -> None:
        """Schedule the next keep-alive ping."""
        current_time = time.time() * 1000
        keepalive_delay = max(
            self._last_sent_keepalive + self.KEEP_ALIVE_FREQUENCY - current_time,
            0
        )

        if keepalive_delay <= 0:
            self._send_keepalive()
        else:
            # In async environments, this would schedule a timeout
            # For sync usage, keep-alive is sent on next network activity
            self._keepalive_timeout = current_time + keepalive_delay

    def _stop_keepalive(self) -> None:
        """Stop sending keep-alive pings."""
        self._keepalive_timeout = None

    # ==========================================================================
    # Public API - Sending
    # ==========================================================================

    def send_key_event(self, pressed: bool, keysym: int) -> None:
        """
        Send a key event to the server.

        Args:
            pressed: True if key is pressed, False if released.
            keysym: The X11 keysym of the key.
        """
        if not self._is_connected():
            return
        self.tunnel.send_message("key", keysym, 1 if pressed else 0)

    def send_mouse_state(self, x: int, y: int, button_mask: int) -> None:
        """
        Send a mouse state to the server.

        Args:
            x: X coordinate of the mouse.
            y: Y coordinate of the mouse.
            button_mask: Bitmask of pressed buttons (1=left, 2=middle, 4=right,
                8=scroll-up, 16=scroll-down).
        """
        if not self._is_connected():
            return
        self.tunnel.send_message("mouse", x, y, button_mask)

    def send_size(self, width: int, height: int) -> None:
        """
        Send the current screen size to the server.

        Args:
            width: Screen width in pixels.
            height: Screen height in pixels.
        """
        if not self._is_connected():
            return
        self.tunnel.send_message("size", width, height)

    def send_ack(self, stream_index: int, message: str, code: int) -> None:
        """
        Acknowledge receipt of data on a stream.

        Args:
            stream_index: The index of the stream.
            message: Human-readable status message.
            code: Status code (0 for success).
        """
        if not self._is_connected():
            return
        self.tunnel.send_message("ack", stream_index, message, code)

    def send_blob(self, stream_index: int, data: str) -> None:
        """
        Send blob data on a stream.

        Args:
            stream_index: The index of the stream.
            data: Base64-encoded data to send.
        """
        if not self._is_connected():
            return
        self.tunnel.send_message("blob", stream_index, data)

    def end_stream(self, stream_index: int) -> None:
        """
        Mark a stream as complete.

        Args:
            stream_index: The index of the stream to end.
        """
        if not self._is_connected():
            return

        self.tunnel.send_message("end", stream_index)

        # Free stream index
        if stream_index in self._output_streams:
            self._stream_indices.free(stream_index)
            del self._output_streams[stream_index]

    # ==========================================================================
    # Public API - Stream Management
    # ==========================================================================

    def create_output_stream(self) -> OutputStream:
        """
        Create a new output stream.

        Returns:
            A new OutputStream with an allocated index.
        """
        index = self._stream_indices.next()
        stream = OutputStream(self, index)
        self._output_streams[index] = stream
        return stream

    def create_clipboard_stream(self, mimetype: str) -> OutputStream:
        """
        Create a clipboard stream for sending clipboard data.

        Args:
            mimetype: The mimetype of the clipboard data.

        Returns:
            An output stream for sending clipboard data.
        """
        stream = self.create_output_stream()
        self.tunnel.send_message("clipboard", stream.index, mimetype)
        return stream

    def create_file_stream(self, mimetype: str, filename: str) -> OutputStream:
        """
        Create a file stream for sending a file.

        Args:
            mimetype: The mimetype of the file.
            filename: The name of the file.

        Returns:
            An output stream for sending file data.
        """
        stream = self.create_output_stream()
        self.tunnel.send_message("file", stream.index, mimetype, filename)
        return stream

    def create_pipe_stream(self, mimetype: str, name: str) -> OutputStream:
        """
        Create a named pipe stream.

        Args:
            mimetype: The mimetype of the data.
            name: The name of the pipe.

        Returns:
            An output stream for the pipe.
        """
        stream = self.create_output_stream()
        self.tunnel.send_message("pipe", stream.index, mimetype, name)
        return stream

    # ==========================================================================
    # Public API - Connection Management
    # ==========================================================================

    def connect(self, data: Optional[str] = None) -> None:
        """
        Connect to the Guacamole server.

        Args:
            data: Arbitrary connection data to send during handshake.

        Raises:
            Status: If an error occurs during connection.
        """
        self._set_state(ClientState.CONNECTING)

        try:
            self.tunnel.connect(data)
        except Exception as e:
            self._set_state(ClientState.IDLE)
            raise

        # Start keep-alive pings
        self._schedule_keepalive()

        self._set_state(ClientState.WAITING)

    def disconnect(self) -> None:
        """Disconnect from the Guacamole server."""
        if self._state in (ClientState.DISCONNECTED, ClientState.DISCONNECTING):
            return

        self._set_state(ClientState.DISCONNECTING)

        # Stop keep-alive
        self._stop_keepalive()

        # Send disconnect and close tunnel
        self.tunnel.send_message("disconnect")
        self.tunnel.disconnect()

        self._set_state(ClientState.DISCONNECTED)
