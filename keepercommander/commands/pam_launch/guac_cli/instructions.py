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
Guacamole Protocol Instruction Handlers

Terminal-focused instruction handlers for SSH/Telnet/Kubernetes sessions.
These handlers print diagnostic information about received instructions.

This module uses the new guacamole protocol library and provides an
instruction router that can be assigned to Parser.oninstruction.

For plaintext SSH/TTY streams, this module supports the pipe/blob/end pattern:
- Server sends `pipe` with name "STDOUT" to open terminal output stream
- Server sends `blob` with base64-encoded terminal output
- Client sends `ack` after each pipe/blob to acknowledge
- Server sends `end` when stream closes

Input uses the same pattern:
- Client sends `pipe` with name "STDIN" to open input stream
- Client sends `blob` with base64-encoded keyboard input
- Client sends `end` to close the stream
"""

import base64
import logging
import sys
from typing import Any, Callable, Dict, List, Optional


# Handler type: receives list of string arguments
InstructionHandler = Callable[[List[str]], None]

# Callback type for sending ack responses
AckCallback = Callable[[str, str, str], None]  # (stream_index, message, code)


# =============================================================================
# Instruction Handlers
# =============================================================================

def handle_sync(args: List[str]) -> None:
    """
    Handle sync instruction - Frame synchronization.

    This is critical - the server waits for sync acknowledgment.
    Note: The actual sync response is sent by the caller (GuacamoleHandler).

    Args:
        args: [timestamp] or [timestamp, frames]
    """
    timestamp = args[0] if args else "?"
    frames = args[1] if len(args) > 1 else "0"
    logging.debug(f"[SYNC] timestamp={timestamp}, frames={frames}")


def handle_name(args: List[str]) -> None:
    """
    Handle name instruction - Connection name/title.

    Args:
        args: [name]
    """
    name = args[0] if args else "?"
    logging.debug(f"[NAME] {name}")


def handle_size(args: List[str]) -> None:
    """
    Handle size instruction - Screen/terminal size.

    Size can have different formats:
    - size,layer,width,height (3 args)
    - size,layer,width,height,dpi (4 args)
    - size,width,height (2 args - client sending to server)
    """
    if len(args) == 2:
        width, height = args
        logging.debug(f"[SIZE] {width}x{height}")
    elif len(args) >= 3:
        layer, width, height = args[0], args[1], args[2]
        dpi = args[3] if len(args) > 3 else "96"
        logging.debug(f"[SIZE] layer={layer}, {width}x{height} @ {dpi}dpi")
    else:
        logging.debug(f"[SIZE] {args}")


def handle_png(args: List[str]) -> None:
    """
    Handle png instruction - PNG image data.

    Args:
        args: [channel, layer, x, y, ...data_args]
    """
    if len(args) < 4:
        logging.debug(f"[PNG] {args}")
        return

    channel, layer, x, y = args[0], args[1], args[2], args[3]
    data_args = args[4:]

    if data_args:
        data = data_args[0]
        if len(data) > 16:
            try:
                hex_preview = data[:16].encode('utf-8').hex()
            except:
                hex_preview = str(data[:16])
            logging.debug(f"[PNG] channel={channel}, layer={layer}, pos=({x},{y}), data=[{hex_preview}...] ({len(data)} chars)")
        else:
            logging.debug(f"[PNG] channel={channel}, layer={layer}, pos=({x},{y}), data={data}")
    else:
        logging.debug(f"[PNG] channel={channel}, layer={layer}, pos=({x},{y})")


def handle_jpeg(args: List[str]) -> None:
    """
    Handle jpeg instruction - JPEG image data.

    Args:
        args: [channel, layer, x, y, ...data_args]
    """
    if len(args) < 4:
        logging.debug(f"[JPEG] {args}")
        return

    channel, layer, x, y = args[0], args[1], args[2], args[3]
    data_args = args[4:]

    if data_args:
        data = data_args[0]
        if len(data) > 16:
            try:
                hex_preview = data[:16].encode('utf-8').hex()
            except:
                hex_preview = str(data[:16])
            logging.debug(f"[JPEG] channel={channel}, layer={layer}, pos=({x},{y}), data=[{hex_preview}...] ({len(data)} chars)")
        else:
            logging.debug(f"[JPEG] channel={channel}, layer={layer}, pos=({x},{y}), data={data}")
    else:
        logging.debug(f"[JPEG] channel={channel}, layer={layer}, pos=({x},{y})")


def handle_img(args: List[str]) -> None:
    """
    Handle img instruction - Streamed image data.

    Args:
        args: [stream, channel, layer, mimetype, x, y]
    """
    if len(args) >= 6:
        stream, channel, layer, mimetype, x, y = args[0], args[1], args[2], args[3], args[4], args[5]
        logging.debug(f"[IMG] stream={stream}, channel={channel}, layer={layer}, type={mimetype}, pos=({x},{y})")
    else:
        logging.debug(f"[IMG] {args}")


def handle_cursor(args: List[str]) -> None:
    """
    Handle cursor instruction - Cursor position/image.

    Args:
        args: [x, y, ...additional params]
    """
    if len(args) >= 2:
        x, y = args[0], args[1]
        extra = args[2:] if len(args) > 2 else []
        if extra:
            logging.debug(f"[CURSOR] hotspot=({x},{y}), args={extra}")
        else:
            logging.debug(f"[CURSOR] pos=({x},{y})")
    else:
        logging.debug(f"[CURSOR] {args}")


def handle_move(args: List[str]) -> None:
    """
    Handle move instruction - Move layer.

    Args:
        args: [layer, parent, x, y, z]
    """
    if len(args) >= 5:
        layer, parent, x, y, z = args[0], args[1], args[2], args[3], args[4]
        logging.debug(f"[MOVE] layer={layer}, parent={parent}, pos=({x},{y}), z={z}")
    else:
        logging.debug(f"[MOVE] {args}")


def handle_rect(args: List[str]) -> None:
    """
    Handle rect instruction - Draw rectangle path.

    Args:
        args: [layer, x, y, width, height]
    """
    if len(args) >= 5:
        layer, x, y, width, height = args[0], args[1], args[2], args[3], args[4]
        logging.debug(f"[RECT] layer={layer}, rect=({x},{y},{width},{height})")
    else:
        logging.debug(f"[RECT] {args}")


def handle_cfill(args: List[str]) -> None:
    """
    Handle cfill instruction - Fill with color.

    Args:
        args: [channel, layer, r, g, b, a]
    """
    if len(args) >= 6:
        channel, layer, r, g, b, a = args[0], args[1], args[2], args[3], args[4], args[5]
        logging.debug(f"[CFILL] channel={channel}, layer={layer}, color=rgba({r},{g},{b},{a})")
    else:
        logging.debug(f"[CFILL] {args}")


def handle_copy(args: List[str]) -> None:
    """
    Handle copy instruction - Copy rectangle between layers.

    Args:
        args: [src_layer, src_x, src_y, width, height, channel, dst_layer, dst_x, dst_y]
    """
    if len(args) >= 9:
        src_layer, src_x, src_y, width, height = args[0], args[1], args[2], args[3], args[4]
        channel, dst_layer, dst_x, dst_y = args[5], args[6], args[7], args[8]
        logging.debug(f"[COPY] from layer={src_layer} ({src_x},{src_y},{width},{height}) to layer={dst_layer} ({dst_x},{dst_y})")
    else:
        logging.debug(f"[COPY] {args}")


def handle_clipboard(args: List[str]) -> None:
    """
    Handle clipboard instruction - Clipboard data stream.

    Args:
        args: [stream, mimetype]
    """
    if len(args) >= 2:
        stream, mimetype = args[0], args[1]
        logging.debug(f"[CLIPBOARD] stream={stream}, type={mimetype}")
    else:
        logging.debug(f"[CLIPBOARD] {args}")


def handle_ack(args: List[str]) -> None:
    """
    Handle ack instruction - Acknowledgment.

    Args:
        args: [stream, message, code]
    """
    if len(args) >= 3:
        stream, message, code = args[0], args[1], args[2]
        logging.debug(f"[ACK] stream={stream}, message='{message}', code={code}")
    else:
        logging.debug(f"[ACK] {args}")


def handle_error(args: List[str]) -> None:
    """
    Handle error instruction - Error message from server.

    Args:
        args: [message, code]
    """
    if len(args) >= 2:
        message, code = args[0], args[1]
        logging.error(f"[ERROR] code={code}, message='{message}'")
    else:
        logging.error(f"[ERROR] {args}")


def handle_disconnect(args: List[str]) -> None:
    """
    Handle disconnect instruction - Server disconnecting.

    Args:
        args: Optional disconnect parameters
    """
    logging.debug(f"[DISCONNECT] {args if args else ''}")


def handle_mouse(args: List[str]) -> None:
    """
    Handle mouse instruction - Mouse position (server-side cursor).

    Args:
        args: [x, y]
    """
    # Don't print mouse movements to avoid spam
    if len(args) >= 2:
        x, y = args[0], args[1]
        logging.debug(f"MOUSE: ({x},{y})")


def handle_blob(args: List[str]) -> None:
    """
    Handle blob instruction - Binary blob data for stream.

    Args:
        args: [stream, data]
    """
    if len(args) >= 2:
        stream, data = args[0], args[1]
        data_preview = data[:16] if len(data) > 16 else data
        logging.debug(f"[BLOB] stream={stream}, data=[{data_preview}...] ({len(data)} chars)")
    else:
        logging.debug(f"[BLOB] {args}")


def handle_end(args: List[str]) -> None:
    """
    Handle end instruction - End of stream.

    Args:
        args: [stream]
    """
    stream = args[0] if args else "?"
    logging.debug(f"[END] stream={stream}")


def handle_pipe(args: List[str]) -> None:
    """
    Handle pipe instruction - Named pipe stream.

    For SSH/TTY sessions, the server sends pipe with name "STDOUT" to
    indicate terminal output will follow via blob instructions.

    Args:
        args: [stream_index, mimetype, name]
    """
    if len(args) >= 3:
        stream, mimetype, name = args[0], args[1], args[2]
        logging.debug(f"[PIPE] stream={stream}, type={mimetype}, name={name}")
    else:
        logging.debug(f"[PIPE] {args}")


def handle_args(args: List[str]) -> None:
    """
    Handle args instruction - Server requests connection parameters.

    This is CRITICAL - guacd sends this after receiving 'select' to ask what
    parameters are needed for the connection.

    Note: The actual handshake response is sent by the caller (GuacamoleHandler).

    Args:
        args: List of parameter names that guacd expects
    """
    logging.debug(f"[ARGS] Server requesting parameters: {list(args)}")


def handle_ready(args: List[str]) -> None:
    """
    Handle ready instruction - Server confirms connection is ready.

    This is sent by guacd after processing 'connect' instruction.

    Args:
        args: [connection_id]
    """
    connection_id = args[0] if args else None
    logging.debug(f"[READY] Connection ready (id: {connection_id})")


def handle_unknown(opcode: str, args: List[str]) -> None:
    """
    Handle any unrecognized instruction - default handler.

    Args:
        opcode: Instruction opcode
        args: Instruction arguments
    """
    # Truncate long arguments for display
    arg_preview = []
    for arg in args:
        arg_str = str(arg)
        if len(arg_str) > 32:
            arg_preview.append(arg_str[:32] + "...")
        else:
            arg_preview.append(arg_str)

    logging.debug(f"[{opcode.upper()}] {arg_preview}")


# =============================================================================
# Instruction Router
# =============================================================================

# Map of opcode -> handler function
_INSTRUCTION_HANDLERS: Dict[str, InstructionHandler] = {
    # Critical instructions
    'sync': handle_sync,
    'name': handle_name,
    'size': handle_size,

    # Image instructions
    'png': handle_png,
    'jpeg': handle_jpeg,
    'img': handle_img,

    # Display instructions
    'cursor': handle_cursor,
    'move': handle_move,
    'rect': handle_rect,
    'cfill': handle_cfill,
    'copy': handle_copy,

    # I/O instructions
    'clipboard': handle_clipboard,
    'pipe': handle_pipe,
    'blob': handle_blob,
    'end': handle_end,
    'ack': handle_ack,

    # Control instructions
    'error': handle_error,
    'disconnect': handle_disconnect,

    # Connection handshake (CRITICAL)
    'args': handle_args,
    'ready': handle_ready,

    # Mouse (logged but not printed)
    'mouse': handle_mouse,
}


def create_instruction_router(
    custom_handlers: Optional[Dict[str, InstructionHandler]] = None,
    send_ack_callback: Optional[AckCallback] = None,
    stdout_stream_tracker: Optional[Any] = None,
) -> Callable[[str, List[str]], None]:
    """
    Create an instruction router callback for use with Parser.oninstruction.

    The router dispatches instructions to the appropriate handler based on opcode.
    Custom handlers can override the default handlers.

    For plaintext SSH/TTY streams, the router can track STDOUT pipes and decode
    blob data to sys.stdout. This requires:
    - send_ack_callback: Function to send ack responses
    - stdout_stream_tracker: Object with `stdout_stream_index` attribute for tracking

    Args:
        custom_handlers: Optional dict of opcode -> handler to override defaults.
        send_ack_callback: Optional callback(stream, message, code) to send ack.
        stdout_stream_tracker: Optional object with `stdout_stream_index` attribute.
            When set, pipe/blob/end for STDOUT streams will be handled specially:
            - pipe with name "STDOUT" stores stream index and sends ack
            - blob with matching stream decodes base64 to stdout and sends ack
            - end with matching stream clears tracking

    Returns:
        A callback function with signature (opcode: str, args: List[str]) -> None
        suitable for assigning to Parser.oninstruction.

    Example:
        from guacamole import Parser
        from guac_cli.instructions import create_instruction_router

        parser = Parser()
        parser.oninstruction = create_instruction_router()
        parser.receive("4.sync,10.1234567890;")

    Example with STDOUT handling:
        class StreamTracker:
            stdout_stream_index = -1

        tracker = StreamTracker()
        parser.oninstruction = create_instruction_router(
            send_ack_callback=lambda s, m, c: send_ack(s, m, c),
            stdout_stream_tracker=tracker,
        )
    """
    # Merge default handlers with custom handlers
    handlers = _INSTRUCTION_HANDLERS.copy()
    if custom_handlers:
        handlers.update(custom_handlers)

    def router(opcode: str, args: List[str]) -> None:
        """Route instruction to appropriate handler."""

        # Special handling for pipe/blob/end when STDOUT tracking is enabled
        if stdout_stream_tracker is not None and send_ack_callback is not None:

            # Handle pipe - track STDOUT stream
            if opcode == 'pipe' and len(args) >= 3:
                stream_index, mimetype, name = args[0], args[1], args[2]
                if name == 'STDOUT':
                    stdout_stream_tracker.stdout_stream_index = int(stream_index)
                    send_ack_callback(stream_index, 'OK', '0')
                    logging.debug(f"STDOUT pipe opened on stream {stream_index}")
                    # Still call original handler for diagnostics
                    handler = handlers.get(opcode)
                    if handler:
                        try:
                            handler(args)
                        except Exception as e:
                            logging.error(f"Error in pipe handler: {e}")
                    return

            # Handle blob - decode STDOUT data to sys.stdout
            elif opcode == 'blob' and len(args) >= 2:
                stream_index = int(args[0])
                if stream_index == stdout_stream_tracker.stdout_stream_index:
                    # Decode base64 and write to stdout
                    try:
                        decoded = base64.b64decode(args[1])
                        # Try buffer.write for binary output, fall back to str for compatibility
                        if hasattr(sys.stdout, 'buffer'):
                            sys.stdout.buffer.write(decoded)
                        else:
                            sys.stdout.write(decoded.decode('utf-8', errors='replace'))
                        sys.stdout.flush()
                        send_ack_callback(args[0], 'OK', '0')
                    except Exception as e:
                        logging.error(f"Error decoding STDOUT blob: {e}")
                    return
                # Non-STDOUT blob falls through to default handler

            # Handle end - clear STDOUT tracking
            elif opcode == 'end' and len(args) >= 1:
                stream_index = int(args[0])
                if stream_index == stdout_stream_tracker.stdout_stream_index:
                    stdout_stream_tracker.stdout_stream_index = -1
                    logging.debug(f"STDOUT stream {stream_index} ended")
                    # Still call original handler for diagnostics
                    handler = handlers.get(opcode)
                    if handler:
                        try:
                            handler(args)
                        except Exception as e:
                            logging.error(f"Error in end handler: {e}")
                    return

        # Default routing
        handler = handlers.get(opcode)
        if handler:
            try:
                handler(args)
            except Exception as e:
                logging.error(f"Error handling instruction {opcode}: {e}", exc_info=True)
        else:
            handle_unknown(opcode, args)

    return router


def get_default_handlers() -> Dict[str, InstructionHandler]:
    """
    Get a copy of the default instruction handlers.

    Returns:
        Dict mapping opcode to handler function.
    """
    return _INSTRUCTION_HANDLERS.copy()
