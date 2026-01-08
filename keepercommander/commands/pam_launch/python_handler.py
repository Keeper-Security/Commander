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
PythonHandler Protocol Mode for Guacamole CLI connections.

This module implements the Python callback handler for the PythonHandler protocol mode
in keeper_pam_webrtc_rs. It receives Guacamole protocol data from the Rust layer
(which handles all control frames like OpenConnection, Ping/Pong, etc.) and processes
the pure Guacamole instructions.

Architecture:
    Rust Layer (handles automatically):
        - OpenConnection/CloseConnection lifecycle
        - Ping/Pong heartbeat
        - Connection state management
        - Bounded channel with backpressure
        - Batching optimization (up to 10 messages per GIL acquisition)

    Python Layer (this module):
        - Receive Guacamole data via callback
        - Parse Guacamole instructions
        - Respond to 'args' with 'connect', 'size', 'audio', 'image' (handshake)
        - Send Guacamole responses back to Rust

Event Types from Rust:
    - connection_opened: Virtual connection established (conn_no)
    - data: Guacamole protocol data (conn_no, payload)
    - connection_closed: Connection terminated (conn_no, reason)

Guacamole Handshake Flow (PythonHandler mode):
    1. Gateway sends 'select' to guacd with protocol type (ssh, telnet, etc.)
    2. guacd responds with 'args' listing required parameters
    3. Gateway forwards 'args' to Python via WebRTC
    4. Python responds with 'connect', 'size', 'audio', 'image'
    5. guacd responds with 'ready' (optional, custom extension)
    6. guacd sends first 'sync' (TRUE readiness signal - matches JS client behavior)
    7. Terminal session begins

Connection Readiness:
    The JS Guacamole client (guacamole-common-js Client.js line 1679) considers
    the connection CONNECTED when the first 'sync' instruction is received, NOT
    when 'ready' is received. We follow the same pattern for reliability.

    wait_for_ready() returns True when EITHER:
    - First 'sync' instruction is received (protocol standard), OR
    - 'ready' instruction is received (custom extension)
"""

from __future__ import annotations
import base64
import logging
import sys
import threading
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Any

from .guacamole import Parser, to_instruction
from .guac_cli.instructions import create_instruction_router

if TYPE_CHECKING:
    pass


class GuacamoleHandler:
    """
    Handle Guacamole protocol data from Rust PythonHandler mode.

    Receives batched events from Rust, parses Guacamole instructions,
    and sends responses back via send_handler_data().

    The Rust layer handles:
        - Control frames (OpenConnection, CloseConnection, Ping/Pong)
        - Connection lifecycle management
        - Message batching for GIL efficiency

    This class handles:
        - Guacamole instruction parsing
        - Sync acknowledgments
        - Terminal rendering (via instruction handlers)
    """

    def __init__(
        self,
        tube_registry,
        conversation_id: str,
        conn_no: int = 1,
        connection_settings: Optional[Dict[str, Any]] = None,
        on_ready: Optional[Callable[[], None]] = None,
        on_disconnect: Optional[Callable[[str], None]] = None,
    ):
        """
        Initialize the Guacamole handler.

        Args:
            tube_registry: PyTubeRegistry instance for sending data back
            conversation_id: The conversation/channel ID for this connection
            conn_no: Connection number within the channel (default: 1)
            connection_settings: Connection parameters for Guacamole handshake:
                - protocol: Protocol type (ssh, telnet, mysql, etc.)
                - hostname: Target hostname
                - port: Target port
                - width: Terminal width in pixels
                - height: Terminal height in pixels
                - dpi: Display DPI (default 96)
                - audio_mimetypes: List of supported audio types (optional)
                - image_mimetypes: List of supported image types (optional)
                - guacd_params: Additional guacd parameters dict (optional)
            on_ready: Optional callback when Guacamole connection is ready
            on_disconnect: Optional callback when connection is closed (receives reason)
        """
        self.tube_registry = tube_registry
        self.conversation_id = conversation_id
        self.conn_no = conn_no
        self.on_ready = on_ready
        self.on_disconnect = on_disconnect

        # Connection settings for Guacamole handshake
        self.connection_settings = connection_settings or {}
        self.handshake_sent = False  # Track if we've responded to 'args'

        # Guacamole protocol parser (using new guacamole module)
        self.parser = Parser()

        # STDOUT stream tracking for pipe/blob/end pattern (plaintext SSH/TTY)
        # Server sends pipe with name "STDOUT", then blobs with base64 terminal output
        self.stdout_stream_index: int = -1

        # Feature detection for CLI pipe mode
        # STDOUT pipe: if the server supports plaintext SSH/TTY mode, it sends a STDOUT pipe
        # STDIN pipe: when we try to send input, the server should ack successfully
        self.stdout_pipe_opened = threading.Event()  # Set when STDOUT pipe is received
        self.stdin_pipe_failed = False  # Set if STDIN pipe ack fails
        self.stdin_stream_index: int = 0  # Stream index we use for STDIN
        self.pending_stdin_ack = False  # True when waiting for STDIN ack

        # Create instruction router with custom handlers for our needs
        # Pass self as stdout_stream_tracker so router can decode STDOUT blobs
        self.parser.oninstruction = create_instruction_router(
            custom_handlers={
                'args': self._on_args,
                'sync': self._on_sync,
                'ready': self._on_ready,
                'disconnect': self._on_guac_disconnect,
                'error': self._on_error,
                'ack': self._on_ack,  # Custom ack handler for STDIN failure detection
                'pipe': self._on_pipe,  # Custom pipe handler for STDOUT detection
            },
            send_ack_callback=self._send_ack,
            stdout_stream_tracker=self,
        )

        # State
        self.running = False
        self.last_sync_timestamp: Optional[str] = None

        # Connection readiness states (matching JS client behavior)
        # JS client transitions WAITING -> CONNECTED on first sync, NOT on 'ready'
        # We track both for compatibility:
        # - handshake_complete: Set when we receive 'ready' instruction (informational)
        # - data_flowing: Set when we receive first 'sync' instruction (TRUE readiness)
        self.handshake_complete = threading.Event()  # 'ready' received (custom extension)
        self.data_flowing = threading.Event()  # First 'sync' received (protocol standard)

        # For backwards compatibility, connection_ready = data_flowing
        # This matches JS client behavior where sync = ready
        self.connection_ready = self.data_flowing

        self.guac_connection_id: Optional[str] = None
        self.sync_count = 0  # Track number of syncs received

        # Statistics
        self.messages_received = 0
        self.bytes_received = 0
        self.messages_sent = 0
        self.bytes_sent = 0

    def start(self):
        """Start the handler."""
        if self.running:
            return
        self.running = True
        logging.debug(f"GuacamoleHandler started (conversation_id={self.conversation_id})")

    def stop(self, skip_disconnect: bool = False):
        """
        Stop the handler and optionally send disconnect to guacd.

        Args:
            skip_disconnect: If True, skip sending disconnect instruction.
                           Use this when connection is already closed to avoid deadlock.
        """
        if not self.running:
            return

        self.running = False

        # Send graceful disconnect to guacd (unless connection already closed)
        if not skip_disconnect:
            try:
                disconnect_instruction = self._format_instruction('disconnect')
                self._send_to_gateway(disconnect_instruction)
                logging.debug("Sent disconnect instruction to guacd")
            except Exception as e:
                # Don't warn if connection is already closed - this is expected
                if "closed" not in str(e).lower() and "disconnected" not in str(e).lower():
                    logging.warning(f"Failed to send disconnect instruction: {e}")

        logging.debug(
            f"GuacamoleHandler stopped (conversation_id={self.conversation_id}, "
            f"rx={self.messages_received}, tx={self.messages_sent})"
        )

    def handle_events(self, events: List[Dict[str, Any]]):
        """
        Handle a batch of events from Rust PythonHandler.

        This is called by the Rust handler task with a list of events.
        Events are batched for GIL efficiency (up to 10 messages per batch).

        Args:
            events: List of event dicts, each with:
                - type: "connection_opened" | "data" | "connection_closed"
                - conn_no: Connection number (int)
                - conversation_id: Conversation ID (str)
                - payload: Bytes data (for "data" events)
                - reason: Close reason code (for "connection_closed" events)
        """
        for event in events:
            try:
                self._handle_single_event(event)
            except Exception as e:
                logging.error(f"Error handling event: {e}", exc_info=True)

    def _handle_single_event(self, event: Dict[str, Any]):
        """Handle a single event from Rust."""
        event_type = event.get('type')
        conn_no = event.get('conn_no', 1)

        if event_type == 'connection_opened':
            self._on_connection_opened(conn_no)
        elif event_type == 'data':
            payload = event.get('payload', b'')
            self._on_data(conn_no, payload)
        elif event_type == 'connection_closed':
            reason = event.get('reason', 0)
            self._on_connection_closed(conn_no, reason)
        else:
            logging.warning(f"Unknown event type: {event_type}")

    def _on_connection_opened(self, conn_no: int):
        """
        Handle connection_opened event from Rust.

        This is sent when the Gateway has acknowledged the OpenConnection
        request and the virtual connection is now established.

        Flow:
        1. Python calls tube_registry.open_handler_connection(conversation_id, conn_no)
        2. Rust sends OpenConnection control frame to Gateway via WebRTC
        3. Gateway receives OpenConnection, starts guacd, connects to target
        4. Gateway sends ConnectionOpened back to Rust
        5. Rust notifies Python via this callback
        6. Gateway/guacd sends 'args' instruction (Guacamole handshake starts)
        """
        logging.debug(f"✓ Connection opened: conn_no={conn_no}")
        self.conn_no = conn_no

        # The connection is now ready for Guacamole protocol
        # Gateway will send guacd's 'args' instruction next

    def _on_data(self, conn_no: int, payload: bytes):
        """
        Handle data event from Rust.

        This contains pure Guacamole protocol data (no channel prefix).
        The Rust layer has already stripped the frame header.
        """
        if not payload:
            return

        self.messages_received += 1
        self.bytes_received += len(payload)

        try:
            # Decode Guacamole instructions
            instructions_str = payload.decode('utf-8')

            # Log received data for debugging
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                preview = instructions_str[:100]
                logging.debug(
                    f"<<< GUACD DATA: {len(payload)} bytes, preview: {preview}"
                    f"{'...' if len(instructions_str) > 100 else ''}"
                )

            # Parse and dispatch instructions
            self.parser.receive(instructions_str)

        except UnicodeDecodeError:
            logging.debug(f"Binary data received ({len(payload)} bytes): {payload[:32].hex()}...")

    def _on_connection_closed(self, conn_no: int, reason: int):
        """
        Handle connection_closed event from Rust.

        This is sent when the gateway/guacd closes the connection.
        """
        reason_name = self._close_reason_name(reason)
        logging.debug(f"Connection closed: conn_no={conn_no}, reason={reason} ({reason_name})")

        # Stop without sending disconnect (connection already closed)
        self.stop(skip_disconnect=True)

        if self.on_disconnect:
            try:
                self.on_disconnect(reason_name)
            except Exception as e:
                logging.error(f"Error in disconnect callback: {e}")

    def _on_args(self, args: List[str]) -> None:
        """
        Handle args instruction from guacd (via Gateway).

        This is the critical handshake step. When guacd receives 'select' from
        the Gateway, it responds with 'args' listing the parameters it needs.
        We must respond with 'connect' containing the parameter values,
        followed by 'size', 'audio', and 'image' instructions.

        Guacamole handshake sequence:
            1. Gateway sends 'select <protocol>' to guacd
            2. guacd responds with 'args' (list of required params)
            3. We respond with 'connect' (param values), 'size', 'audio', 'image'
            4. guacd responds with 'ready'

        Args:
            args: Parameter names that guacd expects (first is version, rest are params)
        """
        if self.handshake_sent:
            logging.debug(f"Ignoring duplicate 'args' instruction (handshake already sent)")
            return

        logging.debug(f"✓ Received 'args' from guacd: {list(args)}")

        try:
            # Build and send the handshake response
            self._send_handshake_response(list(args))
            self.handshake_sent = True
            logging.debug("✓ Guacamole handshake sent (connect+size+audio+image)")
        except Exception as e:
            logging.error(f"Error sending handshake response: {e}", exc_info=True)

    def _send_handshake_response(self, args_list: List[str]):
        """
        Send the complete Guacamole handshake response.

        Args:
            args_list: List of parameter names from guacd's 'args' instruction
        """
        settings = self.connection_settings

        # Get terminal dimensions (default to standard CLI size)
        width = settings.get('width', 800)
        height = settings.get('height', 600)
        dpi = settings.get('dpi', 96)

        # Get guacd parameters (hostname, port, username, password, etc.)
        guacd_params = settings.get('guacd_params', {})

        # Debug: Log what credentials we have
        logging.debug(f"DEBUG: guacd_params keys: {list(guacd_params.keys())}")
        logging.debug(f"DEBUG: guacd_params['username']: {'(set)' if guacd_params.get('username') else '(empty)'}")
        logging.debug(f"DEBUG: guacd_params['password']: {'(set)' if guacd_params.get('password') else '(empty)'}")
        logging.debug(f"DEBUG: guacd_params['private-key']: {'(set)' if guacd_params.get('private-key') else '(empty)'}")

        # Build connect args: first arg is version (from guacd), rest are param values
        connect_args = []

        # First arg from guacd is the version requirement
        if args_list:
            version = args_list[0] if args_list[0] else "VERSION_1_5_0"
            connect_args.append(version)

            # For each remaining parameter guacd requested, provide the value
            for param_name in args_list[1:]:
                # Normalize param name for lookup (remove hyphens/underscores, lowercase)
                normalized = param_name.replace('-', '').replace('_', '').lower()

                # Look up in guacd_params with various key formats
                value = ""
                for key in [param_name, normalized, param_name.replace('-', '_'), param_name.replace('_', '-')]:
                    if key in guacd_params:
                        value = str(guacd_params[key])
                        break
                    # Also try lowercase version
                    if key.lower() in guacd_params:
                        value = str(guacd_params[key.lower()])
                        break

                connect_args.append(value)

        # Send connect instruction
        connect_instruction = self._format_instruction('connect', *connect_args)
        self._send_to_gateway(connect_instruction)
        logging.debug(f"Sent 'connect' with {len(connect_args)} args")
        # Debug: Show which args were sent (without revealing secrets)
        if args_list:
            for i, param_name in enumerate(args_list[1:], start=1):
                value = connect_args[i] if i < len(connect_args) else "(missing)"
                is_secret = param_name.lower() in ['password', 'passphrase', 'private-key']
                display_value = '(set)' if (is_secret and value) else ('(empty)' if is_secret else value[:20] if isinstance(value, str) else value)
                logging.debug(f"DEBUG: connect arg '{param_name}' = {display_value}")

        # Send size instruction
        size_instruction = self._format_instruction('size', width, height, dpi)
        self._send_to_gateway(size_instruction)
        logging.debug(f"Sent 'size': {width}x{height} @ {dpi}dpi")

        # Send audio instruction (supported audio mimetypes)
        audio_mimetypes = settings.get('audio_mimetypes', [])
        audio_instruction = self._format_instruction('audio', *audio_mimetypes)
        self._send_to_gateway(audio_instruction)
        logging.debug(f"Sent 'audio': {audio_mimetypes}")

        # Send video instruction (supported video mimetypes - usually empty for terminal)
        video_mimetypes = settings.get('video_mimetypes', [])
        video_instruction = self._format_instruction('video', *video_mimetypes)
        self._send_to_gateway(video_instruction)
        logging.debug(f"Sent 'video': {video_mimetypes}")

        # Send image instruction (supported image mimetypes)
        image_mimetypes = settings.get('image_mimetypes', ['image/png', 'image/jpeg', 'image/webp'])
        image_instruction = self._format_instruction('image', *image_mimetypes)
        self._send_to_gateway(image_instruction)
        logging.debug(f"Sent 'image': {image_mimetypes}")

    def _on_sync(self, args: List[str]) -> None:
        """
        Handle sync instruction from guacd.

        Guacamole requires sync acknowledgments to maintain connection.

        IMPORTANT: The JS client uses the first sync as the TRUE readiness signal,
        transitioning from WAITING to CONNECTED state. We follow the same pattern.
        This is more reliable than waiting for 'ready' (which is a custom extension).

        Args:
            args: [timestamp] or [timestamp, frames]
        """
        timestamp = args[0] if args else "0"
        frames = args[1] if len(args) > 1 else "0"

        self.last_sync_timestamp = timestamp
        self.sync_count += 1

        # First sync = TRUE connection ready (matches JS client behavior)
        # JS Client.js line 1679: if (currentState === WAITING) setState(CONNECTED)
        if self.sync_count == 1:
            self.data_flowing.set()
            logging.debug(f"* First sync received - connection ready (timestamp={timestamp})")

            # Call on_ready callback if not already called by 'ready' instruction
            if self.on_ready and not self.handshake_complete.is_set():
                try:
                    self.on_ready()
                except Exception as e:
                    logging.error(f"Error in ready callback: {e}")

        # Log but don't spam
        logging.debug(f"SYNC #{self.sync_count}: timestamp={timestamp}, frames={frames}")

        # Send sync acknowledgment back to guacd
        try:
            ack = self._format_instruction('sync', timestamp)
            self._send_to_gateway(ack)
        except Exception as e:
            logging.error(f"Error sending sync ack: {e}")

    def _on_ready(self, args: List[str]) -> None:
        """
        Handle ready instruction from guacd.

        This indicates the Guacamole handshake is complete.
        NOTE: This is a custom extension - the JS client doesn't have a 'ready' handler.
        The TRUE readiness signal is the first 'sync' instruction.

        Args:
            args: [connection_id]
        """
        connection_id = args[0] if args else ""
        self.guac_connection_id = connection_id
        self.handshake_complete.set()

        # Also signal data_flowing for compatibility (in case ready comes before sync)
        # This ensures wait_for_ready() returns true on either signal
        self.data_flowing.set()

        logging.debug(f"✓ Guacamole ready! Connection established: connection_id={connection_id}")

        if self.on_ready:
            try:
                self.on_ready()
            except Exception as e:
                logging.error(f"Error in ready callback: {e}")

    def _on_guac_disconnect(self, args: List[str]) -> None:
        """Handle disconnect instruction from guacd."""
        logging.debug(f"Server sent disconnect instruction (args: {args})")

        # Stop without sending disconnect (server already disconnected)
        self.stop(skip_disconnect=True)

        if self.on_disconnect:
            try:
                self.on_disconnect("server_disconnect")
            except Exception as e:
                logging.error(f"Error in disconnect callback: {e}")

    def _on_error(self, args: List[str]) -> None:
        """Handle error instruction from guacd."""
        message = args[0] if args else "Unknown error"
        code = args[1] if len(args) > 1 else "0"

        logging.error(f"Guacamole error {code}: {message}")

    def _on_pipe(self, args: List[str]) -> None:
        """
        Handle pipe instruction - track STDOUT pipe opening for feature detection.

        When the server supports plaintext SSH/TTY mode, it sends a pipe with name "STDOUT".
        If this pipe never opens, the feature is not supported by the gateway/connection.

        Note: The instruction router handles STDOUT ack and blob decode before calling this.
        This handler just sets the event to signal that STDOUT pipe was opened.

        Args:
            args: [stream_index, mimetype, name]
        """
        if len(args) >= 3:
            stream_index, mimetype, name = args[0], args[1], args[2]
            logging.debug(f"[PIPE] stream={stream_index}, type={mimetype}, name={name}")

            if name == 'STDOUT':
                # Signal that STDOUT pipe was opened - CLI pipe mode is supported
                # Note: stream_index and ack are already handled by instruction router
                self.stdout_pipe_opened.set()
                logging.debug(f"STDOUT pipe opened on stream {stream_index} - CLI pipe mode supported")
        else:
            logging.debug(f"[PIPE] {args}")

    def _on_ack(self, args: List[str]) -> None:
        """
        Handle ack instruction - detect STDIN pipe failures.

        When we try to send input via STDIN pipe, the server should ack successfully.
        If the ack has a non-zero code, the STDIN pipe feature is not supported.

        Args:
            args: [stream_index, message, code]
        """
        if len(args) >= 3:
            stream_index, message, code = args[0], args[1], args[2]
            logging.debug(f"[ACK] stream={stream_index}, message='{message}', code={code}")

            # Check if this is an ack for our STDIN stream
            if self.pending_stdin_ack and int(stream_index) == self.stdin_stream_index:
                self.pending_stdin_ack = False
                if code != '0':
                    # Non-zero code means STDIN pipe failed
                    self.stdin_pipe_failed = True
                    logging.warning(
                        f"STDIN pipe failed (stream={stream_index}, code={code}, message='{message}'). "
                        f"CLI input mode may not be supported by this connection."
                    )
        else:
            logging.debug(f"[ACK] {args}")

    def _format_instruction(self, *elements) -> bytes:
        """Format elements into a Guacamole instruction."""
        # Use the new guacamole module's to_instruction function
        # It takes a list, returns str, we encode to bytes
        instruction_str = to_instruction(list(elements))
        return instruction_str.encode('utf-8')

    def _send_ack(self, stream_index: str, message: str, code: str):
        """
        Send ack instruction for stream acknowledgment.

        Used by the instruction router to acknowledge pipe/blob instructions.

        Args:
            stream_index: Stream index (as string)
            message: Acknowledgment message (usually "OK")
            code: Status code (usually "0" for success)
        """
        try:
            instruction = self._format_instruction('ack', stream_index, message, code)
            self._send_to_gateway(instruction)
            logging.debug(f"ACK sent: stream={stream_index}, message={message}, code={code}")
        except Exception as e:
            logging.error(f"Error sending ack: {e}")

    def _send_to_gateway(self, data: bytes):
        """
        Send Guacamole data back to gateway via Rust.

        Uses send_handler_data() which routes through the WebRTC channel.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            self.tube_registry.send_handler_data(
                self.conversation_id,
                self.conn_no,
                data
            )
            self.messages_sent += 1
            self.bytes_sent += len(data)
            logging.debug(f">>> GUACD SEND: {len(data)} bytes")
        except Exception as e:
            logging.error(f"Failed to send data to gateway: {e}")
            raise

    def send_stdin(self, data: bytes):
        """
        Send stdin data to guacd using the pipe/blob/end pattern.

        This is the preferred method for plaintext SSH/TTY streams.
        It matches the kcm-cli implementation:
        - pipe,0,text/plain,STDIN  (open stream)
        - blob,0,<base64_data>     (send data)
        - end,0                    (close stream)

        Only sends if session is active (running and data flowing).

        Args:
            data: Raw bytes to send as stdin (e.g., keyboard input)
        """
        # Guard: only send during active session
        if not self.running:
            logging.debug("Ignoring stdin - handler not running")
            return
        if not self.data_flowing.is_set():
            logging.debug("Ignoring stdin - connection not ready")
            return

        # Check if STDIN pipe previously failed
        if self.stdin_pipe_failed:
            logging.debug("Ignoring stdin - STDIN pipe not supported")
            return

        try:
            # Use stream index 0 for STDIN (matching kcm-cli)
            stream_index = '0'
            self.stdin_stream_index = int(stream_index)

            # Track that we're waiting for ack (for failure detection)
            self.pending_stdin_ack = True

            # Send pipe instruction to open STDIN stream
            pipe_instruction = self._format_instruction('pipe', stream_index, 'text/plain', 'STDIN')
            self._send_to_gateway(pipe_instruction)

            # Send blob with base64-encoded data
            data_base64 = base64.b64encode(data).decode('ascii')
            blob_instruction = self._format_instruction('blob', stream_index, data_base64)
            self._send_to_gateway(blob_instruction)

            # Send end to close the stream
            end_instruction = self._format_instruction('end', stream_index)
            self._send_to_gateway(end_instruction)

            # Log for debugging
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                preview = data[:20].decode('utf-8', errors='replace') if len(data) <= 20 else data[:20].decode('utf-8', errors='replace') + '...'
                logging.debug(f"STDIN: sent {len(data)} bytes: {repr(preview)}")

        except Exception as e:
            logging.error(f"Error sending stdin: {e}")

    def check_stdout_pipe_support(self, timeout: float = 10.0) -> bool:
        """
        Check if STDOUT pipe is supported with a timeout.

        This should be called after connection is established (after first sync).
        If the STDOUT pipe doesn't open within the timeout, warns the user that
        CLI pipe mode may not be supported.

        Args:
            timeout: Seconds to wait for STDOUT pipe (default 10.0)

        Returns:
            True if STDOUT pipe opened, False if timeout expired
        """
        if self.stdout_pipe_opened.wait(timeout):
            logging.debug("STDOUT pipe support confirmed")
            return True
        else:
            logging.warning(
                f"STDOUT pipe did not open within {timeout}s. "
                f"CLI pipe mode may not be supported by this gateway/connection."
            )
            print(
                "\nNo STDOUT stream has been received since the connection was opened. "
                "This may indicate the gateway/guacd does not support CLI mode. "
                "You can continue waiting, or press Ctrl+C to cancel."
            )
            return False

    def is_stdin_supported(self) -> bool:
        """
        Check if STDIN pipe is supported.

        Returns:
            True if STDIN pipe has not failed, False if it failed
        """
        return not self.stdin_pipe_failed

    def send_key(self, keysym: int, pressed: bool):
        """
        Send a key event to guacd using X11 keysym.

        NOTE: For plaintext SSH/TTY streams, use send_stdin() instead.
        This method is for graphical protocols (RDP, VNC) that use X11 keysyms.

        Only sends if session is active (running and data flowing).

        Args:
            keysym: X11 keysym value
            pressed: True for press, False for release
        """
        # Guard: only send keys during active session
        if not self.running:
            logging.debug(f"Ignoring key event - handler not running")
            return
        if not self.data_flowing.is_set():
            logging.debug(f"Ignoring key event - connection not ready")
            return

        try:
            instruction = self._format_instruction('key', keysym, 1 if pressed else 0)
            self._send_to_gateway(instruction)
            # Log key events for debugging (only press, not release to reduce spam)
            if pressed:
                # Show printable chars, hex for control/special keys
                if 32 <= keysym < 127:
                    logging.debug(f"KEY: '{chr(keysym)}' (0x{keysym:04X})")
                else:
                    logging.debug(f"KEY: 0x{keysym:04X} (special)")
        except Exception as e:
            logging.error(f"Error sending key event: {e}")

    def send_mouse(self, x: int, y: int, buttons: int = 0):
        """
        Send a mouse event to guacd.

        Only sends if session is active (running and data flowing).

        Args:
            x: X coordinate
            y: Y coordinate
            buttons: Button mask
        """
        if not self.running or not self.data_flowing.is_set():
            return

        try:
            instruction = self._format_instruction('mouse', x, y, buttons)
            self._send_to_gateway(instruction)
        except Exception as e:
            logging.error(f"Error sending mouse event: {e}")

    def send_size(self, width: int, height: int, dpi: int = 96):
        """
        Send terminal size to guacd.

        Only sends if session is active (running and data flowing).

        Args:
            width: Width in pixels
            height: Height in pixels
            dpi: DPI (default 96)
        """
        if not self.running or not self.data_flowing.is_set():
            return

        try:
            instruction = self._format_instruction('size', width, height, dpi)
            self._send_to_gateway(instruction)
        except Exception as e:
            logging.error(f"Error sending size: {e}")

    def send_clipboard(self, text: str):
        """
        Send clipboard data to guacd.

        Only sends if session is active (running and data flowing).

        Args:
            text: Clipboard text
        """
        if not self.running or not self.data_flowing.is_set():
            return

        try:
            instruction = self._format_instruction('clipboard', 'text/plain', text)
            self._send_to_gateway(instruction)
        except Exception as e:
            logging.error(f"Error sending clipboard: {e}")

    def wait_for_ready(self, timeout: float = 10.0) -> bool:
        """
        Wait for the Guacamole connection to be ready.

        Connection is considered ready when:
        - First 'sync' instruction is received (matches JS client behavior), OR
        - 'ready' instruction is received (custom extension)

        The JS Guacamole client (guacamole-common-js) considers the connection
        CONNECTED when the first sync is received, not when 'ready' is received.
        We follow the same pattern for reliability.

        Args:
            timeout: Maximum seconds to wait (default: 10.0, was 30.0)
                    Handshake typically completes in <500ms on normal networks.

        Returns:
            True if ready (sync or ready received), False if timeout
        """
        import time
        start = time.time()

        result = self.connection_ready.wait(timeout)

        elapsed = time.time() - start
        if result:
            logging.debug(f"Connection ready after {elapsed:.3f}s")
        else:
            # Provide diagnostic info on timeout
            logging.warning(
                f"Timeout after {elapsed:.1f}s waiting for ready - "
                f"received {self.messages_received} messages ({self.bytes_received} bytes), "
                f"syncs={self.sync_count}, handshake_sent={self.handshake_sent}"
            )

        return result

    def is_data_flowing(self) -> bool:
        """
        Check if data is flowing (sync messages being received).

        Returns:
            True if at least one sync has been received
        """
        return self.sync_count > 0

    @staticmethod
    def _close_reason_name(reason: int) -> str:
        """Convert close reason code to name."""
        reasons = {
            0: "unknown",
            1: "normal",
            2: "timeout",
            3: "error",
            4: "refused",
            5: "unreachable",
            6: "reset",
        }
        return reasons.get(reason, f"code_{reason}")

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False


def create_handler_callback(handler: GuacamoleHandler) -> Callable[[List[Dict]], None]:
    """
    Create a callback function for the Rust PythonHandler.

    This wraps the handler's handle_events method in a function
    that can be passed to the Rust create_tube() call.

    Args:
        handler: GuacamoleHandler instance

    Returns:
        Callback function that accepts a list of event dicts
    """
    def callback(events: List[Dict[str, Any]]):
        handler.handle_events(events)

    return callback


def create_python_handler(
    tube_registry,
    conversation_id: str,
    conn_no: int = 1,
    connection_settings: Optional[Dict[str, Any]] = None,
    on_ready: Optional[Callable[[], None]] = None,
    on_disconnect: Optional[Callable[[str], None]] = None,
) -> tuple:
    """
    Create a PythonHandler callback and handler for Guacamole CLI.

    This is the main entry point for setting up PythonHandler mode.
    It creates both the handler instance and the callback function
    that should be passed to tube_registry.create_tube().

    Args:
        tube_registry: PyTubeRegistry instance
        conversation_id: Conversation/channel ID
        conn_no: Connection number (default: 1)
        connection_settings: Connection parameters for Guacamole handshake:
            - protocol: Protocol type (ssh, telnet, mysql, etc.)
            - hostname: Target hostname
            - port: Target port
            - width: Terminal width in pixels
            - height: Terminal height in pixels
            - dpi: Display DPI (default 96)
            - audio_mimetypes: List of supported audio types
            - image_mimetypes: List of supported image types
            - guacd_params: Dict of guacd connection parameters
        on_ready: Optional callback when Guacamole connection is ready
        on_disconnect: Optional callback when connection closes

    Returns:
        Tuple of (callback_function, handler_instance)

    Example:
        callback, handler = create_python_handler(
            tube_registry,
            conversation_id,
            connection_settings={
                'protocol': 'ssh',
                'width': 800,
                'height': 600,
                'dpi': 96,
                'guacd_params': {
                    'hostname': '192.168.1.100',
                    'port': '22',
                    'username': 'admin',
                    'password': 'secret',
                }
            },
            on_ready=lambda: print("Connected!"),
            on_disconnect=lambda reason: print(f"Disconnected: {reason}")
        )

        # Pass callback to create_tube
        result = tube_registry.create_tube(
            conversation_id=conversation_id,
            settings={...},
            handler_callback=callback,
            ...
        )

        # Start handler
        handler.start()

        # Wait for connection
        if handler.wait_for_ready(timeout=30):
            print("Guacamole session ready!")
    """
    handler = GuacamoleHandler(
        tube_registry=tube_registry,
        conversation_id=conversation_id,
        conn_no=conn_no,
        connection_settings=connection_settings,
        on_ready=on_ready,
        on_disconnect=on_disconnect,
    )

    callback = create_handler_callback(handler)

    return callback, handler
