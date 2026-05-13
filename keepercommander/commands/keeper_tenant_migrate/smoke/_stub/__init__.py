"""Structurally-faithful Commander stub.

Exposes:
    StubCommander    — context manager that installs the stub
    StubAssertionError — raised when commander_clients sends an
                         unknown kwarg (mirrors what argparse would
                         reject in a live SDK call)

See _stub/runtime.py for the implementation details.
"""

from .runtime import (
    StubAssertionError,
    StubCommander,
    StubKwargRecorder,
    build_smoke_params,
    register_unknown_kwarg,
)

__all__ = [
    'StubAssertionError',
    'StubCommander',
    'StubKwargRecorder',
    'build_smoke_params',
    'register_unknown_kwarg',
]
