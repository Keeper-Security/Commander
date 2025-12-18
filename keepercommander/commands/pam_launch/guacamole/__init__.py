"""
Guacamole Protocol Library for Python.

A reusable implementation of the Apache Guacamole protocol, ported from
guacamole-common-js. This library provides protocol parsing, event handling,
and client functionality for building Guacamole-based applications.

Example usage:
    from guacamole import Parser, Client, Status

    # Parse incoming instructions
    parser = Parser()
    parser.oninstruction = lambda opcode, args: print(f"{opcode}: {args}")
    parser.receive("4.sync,10.1234567890;")

    # Create instruction strings
    instruction = Parser.to_instruction(["key", "65", "1"])

    # Build a client with a tunnel
    class MyTunnel(Tunnel):
        # ... implementation
        pass

    client = Client(my_tunnel)
    client.onstatechange = lambda state: print(f"State: {state}")
    client.connect()
"""

# Exceptions
from .exceptions import (
    GuacamoleError,
    InvalidInstructionError,
    ProtocolError,
    TunnelError,
    ClientError,
)

# Parser
from .parser import Parser, code_point_count, to_instruction

# Event system
from .event import Event, EventTarget

# Status
from .status import Status, StatusCode

# Integer pool
from .integer_pool import IntegerPool

# Tunnel
from .tunnel import Tunnel, TunnelState

# Client
from .client import Client, ClientState, ClientMessage, InputStream, OutputStream


__all__ = [
    # Exceptions
    "GuacamoleError",
    "InvalidInstructionError",
    "ProtocolError",
    "TunnelError",
    "ClientError",
    # Parser
    "Parser",
    "code_point_count",
    "to_instruction",
    # Event system
    "Event",
    "EventTarget",
    # Status
    "Status",
    "StatusCode",
    # Integer pool
    "IntegerPool",
    # Tunnel
    "Tunnel",
    "TunnelState",
    # Client
    "Client",
    "ClientState",
    "ClientMessage",
    "InputStream",
    "OutputStream",
]
