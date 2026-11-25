"""Throttle set_record_rotation calls (Vault: ~10 calls then 10s pause)."""
from __future__ import annotations

import logging
import time

from .throttle_retry import is_throttle_error

ROTATION_BATCH_SIZE = 10
ROTATION_PAUSE_SECONDS = 10


class RotationThrottle:
    """Pause every N rotation API calls to avoid Vault throttling."""

    def __init__(
        self,
        batch_size: int = ROTATION_BATCH_SIZE,
        pause_seconds: int = ROTATION_PAUSE_SECONDS,
    ):
        self.batch_size = max(1, batch_size)
        self.pause_seconds = max(0, pause_seconds)
        self._calls = 0

    @property
    def call_count(self) -> int:
        return self._calls

    def before_call(self) -> None:
        if self._calls > 0 and self._calls % self.batch_size == 0:
            logging.debug(
                'Rotation throttle: sleeping %ss after %s rotation call(s)',
                self.pause_seconds, self._calls,
            )
            time.sleep(self.pause_seconds)
        self._calls += 1

    @staticmethod
    def is_throttle_error(err: BaseException) -> bool:
        return is_throttle_error(err)
