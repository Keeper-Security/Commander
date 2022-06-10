#!/usr/bin/env python3

"""Provide a class for keeping track of the last server-interaction, and send keep-alives hidden to the user as needed."""

import logging
import time
from keepercommander import api
import keepercommander.error


class TimeToKeepalive:
    """Keep track of how soon the login timer is to expire, and send a keepalive if we're "too close"."""

    def __init__(self):
        """Initialize."""
        self.update_time_of_last_activity()
        self.server_logout_timer_window = None
        self.lookup_server_logout_window()

    def update_time_of_last_activity(self):
        """Update the time of last activity.  Used on server interaction and class initialization."""
        self.time_of_last_activity = time.time()

    def lookup_server_logout_window(self, params=None):
        """Get the logout_timer value.  If it doesn't exist yet, use None."""
        if self.server_logout_timer_window is not None:
            # We already have it.
            return
        if (
                params is not None and
                params.settings is not None and
                'logout_timer' in params.settings
        ):
            # We should be able to get it.
            self.server_logout_timer_window = float(params.settings['logout_timer']) / 1000.0
            try:
                if isinstance(params.enforcements, dict) and 'longs' in params.enforcements:
                    timeout = next((x['value'] for x in params.enforcements['longs']
                                    if x['key'] == 'logout_timer_desktop'), None)
                    if timeout:
                        timeout = int(timeout) * 60
                        if timeout < self.server_logout_timer_window:
                            self.server_logout_timer_window = timeout
            except Exception as e:
                logging.debug('Error reading logout timeout: %s', e)

    def update(self, params):
        """Update the timer, and possibly issue a keepalive."""
        if not params.session_token:
            return

        current_time = time.time()

        self.lookup_server_logout_window(params)

        if (
                self.server_logout_timer_window is not None and
                (self.server_logout_timer_window / 2) + self.time_of_last_activity < current_time
        ):
            try:
                api.send_keepalive(params)
            except keepercommander.error.KeeperApiError as kae:
                logging.warning(kae.message)


TTK = TimeToKeepalive()
