#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import time

class AdaptiveThrottler:
    """Adaptive rate limiter for batched vault writes."""

    def __init__(self, base_delay: float = 0.5, max_delay: float = 5.0, batch_size: int = 100):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.batch_size = batch_size
        self.current_delay = base_delay
        self._recent_errors = 0
        self._recent_successes = 0

    def record_response(self, duration_ms: float, success: bool):
        if success:
            self._recent_successes += 1
            self._recent_errors = max(0, self._recent_errors - 1)
            if duration_ms < 1000 and self.current_delay > self.base_delay:
                self.current_delay = max(self.base_delay, self.current_delay * 0.8)
        else:
            self._recent_errors += 1
            self.current_delay = min(self.max_delay, self.current_delay * 1.5)

    def wait(self):
        if self.current_delay > 0:
            time.sleep(self.current_delay)
