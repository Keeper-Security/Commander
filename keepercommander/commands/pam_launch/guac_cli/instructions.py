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
import time
from typing import Any, Callable, Dict, List, Optional, cast

from ..terminal_size import default_handshake_dpi


def _streaming_crlf_to_lf(decoded: bytes, carry_cell: List[bytes]) -> bytes:
    """
    Map CRLF to LF across Guacamole STDOUT **blob** boundaries.

    A single per-blob CRLF→LF replace misses a carriage return at the end of one blob
    and a line feed at the start of the next; the local TTY then sees two motion
    operations (common symptom: double vertical step in mysql-style prompts).
    """
    data = carry_cell[0] + decoded
    carry_cell[0] = b''
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        if data[i] == 0x0D:
            if i + 1 < n and data[i + 1] == 0x0A:
                out.append(0x0A)
                i += 2
            elif i + 1 >= n:
                carry_cell[0] = b'\r'
                i += 1
            else:
                out.append(0x0D)
                i += 1
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def _collapse_adjacent_lf_pairs(data: bytes) -> bytes:
    """
    One left-to-right pass: each adjacent ``\\n\\n`` becomes a single ``\\n``.

    This only merges **pairs** (e.g. four consecutive LFs become two, six become three).
    It does **not** repeatedly collapse until a single LF (which would erase intentional
    blank lines from a long run in one blob).
    """
    if not data or b'\n\n' not in data:
        return data
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        if i + 1 < n and data[i] == 0x0A and data[i + 1] == 0x0A:
            out.append(0x0A)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def _drop_one_oob_lf_pair(data: bytes) -> bytes:
    """
    Remove at most one leading and at most one trailing ``\\n\\n`` pair (each -> single ``\\n``).

    ``_collapse_adjacent_lf_pairs`` already handles runs in the middle; mysql result blobs
    sometimes end with an extra ``\\r\\n\\r\\n`` / ``\\n\\n`` before the next prompt (see
    ``show databases``) where the duplicate is not a byte-identical repeat of the prior blob.
    """
    d = data
    if d.startswith(b'\n\n'):
        d = d[1:]
    if len(d) >= 2 and d.endswith(b'\n\n'):
        d = d[:-1]
    return d


# Guacamole sometimes delivers the same STDOUT blob twice (darwin/mysql); gaps can exceed
# 120ms (seen ~175ms). Suppress only the **second** of each identical pair (then allow the third).
_IDENTICAL_STDOUT_BLOB_PAIR_MAX_S = 0.75
_IDENTICAL_STDOUT_BLOB_PAIR_MAX_LEN = 512


def _identical_stdout_blob_pair_anchorable(to_write: bytes) -> bool:
    """Single-byte keystroke blobs must not replace the dedupe anchor (breaks prompt pair logic)."""
    return len(to_write) >= 8 or (b'\n' in to_write or b'\r' in to_write)


def _identical_stdout_blob_pair_should_skip(to_write: bytes, state: List[Any]) -> bool:
    if not to_write or len(to_write) > _IDENTICAL_STDOUT_BLOB_PAIR_MAX_LEN:
        return False
    now = time.monotonic()
    last_b, last_t, already_skipped = state[0], state[1], state[2]
    if last_b is None or to_write != last_b:
        return False
    if (now - last_t) >= _IDENTICAL_STDOUT_BLOB_PAIR_MAX_S:
        return False
    if already_skipped:
        return False
    state[2] = True
    return True


def _identical_stdout_blob_pair_note_emitted(to_write: bytes, state: List[Any]) -> None:
    now = time.monotonic()
    lb, _lt, sk = state[0], state[1], state[2]
    if _identical_stdout_blob_pair_anchorable(to_write):
        state[:] = [to_write, now, False]
    else:
        # Slide time only; keep anchor so a duplicate prompt line still matches after 1-byte blobs.
        state[:] = [lb, now, False]


def is_stdout_pipe_stream_name(name: str) -> bool:
    """True if Guacamole named pipe is the terminal STDOUT stream (case/whitespace tolerant)."""
    if not name:
        return False
    return str(name).strip().casefold() == 'stdout'


def is_stdin_pipe_stream_name(name: str) -> bool:
    """True if this named pipe is the client→server STDIN stream (do not treat as terminal output)."""
    if not name:
        return False
    return str(name).strip().casefold() == 'stdin'


def _pipe_looks_like_terminal_stdout(mimetype: str, name: str) -> bool:
    """
    Heuristic when guacr/gateway uses a non-STDOUT pipe name for TTY bytes (e.g. PAM clipboard flags).
    Require text/* and exclude STDIN. Only used when no stdout stream is tracked yet.
    """
    if is_stdin_pipe_stream_name(name):
        return False
    mt = (mimetype or '').strip().lower()
    return mt == 'text/plain' or mt.startswith('text/')


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
        dpi = args[3] if len(args) > 3 else str(default_handshake_dpi())
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
    *,
    normalize_stdout_crlf: bool = False,
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
        normalize_stdout_crlf: When True (``pam launch -n``), replace CRLF with LF in decoded STDOUT
            blobs only (terminal output), including **across** blob boundaries; then collapse
            adjacent ``\\n\\n`` to ``\\n`` **one pair at a time** per pass (see
            :func:`_collapse_adjacent_lf_pairs`). Does not alter stdin or other streams.

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

    # Per-router STDOUT CRLF tail when normalizing (see _streaming_crlf_to_lf).
    _stdout_crlf_carry: List[bytes] = [b'']
    # Previous STDOUT write ended with LF — if next chunk starts with LF, drop one (pairwise).
    _stdout_prev_emitted_ends_lf: List[bool] = [False]
    # [last_emitted_bytes|None, last_emit_mono, skipped_one_duplicate_of_last]
    _stdout_identical_pair: List[Any] = [None, 0.0, False]

    def router(opcode: str, args: List[str]) -> None:
        """Route instruction to appropriate handler."""

        # Special handling for pipe/blob/end when STDOUT tracking is enabled
        if stdout_stream_tracker is not None and send_ack_callback is not None:

            # Handle pipe - track STDOUT stream
            if opcode == 'pipe' and len(args) >= 3:
                stream_index, mimetype, name = args[0], args[1], args[2]
                _note = getattr(stdout_stream_tracker, 'note_guac_pipe_instruction', None)
                if callable(_note):
                    _note()
                use_as_stdout = is_stdout_pipe_stream_name(name)
                if (
                    not use_as_stdout
                    and stdout_stream_tracker.stdout_stream_index == -1
                    and _pipe_looks_like_terminal_stdout(mimetype, name)
                ):
                    use_as_stdout = True
                    logging.debug(
                        'CLI: using pipe name=%r mimetype=%r as terminal STDOUT (fallback)',
                        name,
                        mimetype,
                    )

                if use_as_stdout:
                    _stdout_crlf_carry[0] = b''
                    _stdout_prev_emitted_ends_lf[0] = False
                    _stdout_identical_pair[:] = [None, 0.0, False]
                    stdout_stream_tracker.stdout_stream_index = int(stream_index)
                    send_ack_callback(stream_index, 'OK', '0')
                    evt = getattr(stdout_stream_tracker, 'stdout_pipe_opened', None)
                    if evt is not None and hasattr(evt, 'set'):
                        evt.set()
                    logging.debug('Terminal output pipe on stream %s (name=%r)', stream_index, name)
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
                        if normalize_stdout_crlf:
                            decoded = _streaming_crlf_to_lf(decoded, _stdout_crlf_carry)
                            if _stdout_prev_emitted_ends_lf[0] and decoded.startswith(b'\n'):
                                decoded = decoded[1:]
                            decoded = _collapse_adjacent_lf_pairs(decoded)
                            decoded = _drop_one_oob_lf_pair(decoded)
                            if decoded and _identical_stdout_blob_pair_should_skip(
                                decoded, _stdout_identical_pair
                            ):
                                send_ack_callback(args[0], 'OK', '0')
                                return
                        # Try buffer.write for binary output, fall back to str for compatibility
                        if decoded:
                            if hasattr(sys.stdout, 'buffer'):
                                sys.stdout.buffer.write(decoded)
                            else:
                                sys.stdout.write(decoded.decode('utf-8', errors='replace'))
                            sys.stdout.flush()
                            if normalize_stdout_crlf:
                                _stdout_prev_emitted_ends_lf[0] = decoded.endswith(b'\n')
                                _identical_stdout_blob_pair_note_emitted(
                                    decoded, _stdout_identical_pair
                                )
                        send_ack_callback(args[0], 'OK', '0')
                    except Exception as e:
                        logging.error(f"Error decoding STDOUT blob: {e}")
                    return
                # Inbound Guacamole clipboard stream (server → client)
                clip_blob = getattr(stdout_stream_tracker, 'handle_remote_clipboard_blob', None)
                if clip_blob is not None:
                    if cast(Callable[[str, str], bool], clip_blob)(args[0], args[1]):
                        return
                # Non-STDOUT blob falls through to default handler

            # Handle end - clear STDOUT tracking
            elif opcode == 'end' and len(args) >= 1:
                stream_index = int(args[0])
                if stream_index == stdout_stream_tracker.stdout_stream_index:
                    _stdout_prev_emitted_ends_lf[0] = False
                    _stdout_identical_pair[:] = [None, 0.0, False]
                    if normalize_stdout_crlf and _stdout_crlf_carry[0]:
                        tail = _stdout_crlf_carry[0]
                        _stdout_crlf_carry[0] = b''
                        try:
                            if hasattr(sys.stdout, 'buffer'):
                                sys.stdout.buffer.write(tail)
                            else:
                                sys.stdout.write(tail.decode('utf-8', errors='replace'))
                            sys.stdout.flush()
                        except Exception as exc:
                            logging.debug('STDOUT CRLF carry flush at stream end: %s', exc)
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
                clip_end = getattr(stdout_stream_tracker, 'handle_remote_clipboard_end', None)
                if clip_end is not None:
                    if cast(Callable[[str], bool], clip_end)(args[0]):
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
