"""
SuperShell command - launches the full-screen TUI

This module contains the command that launches the SuperShell TUI interface.
"""

import logging
from typing import TYPE_CHECKING

from ...commands.base import Command

if TYPE_CHECKING:
    from ...params import KeeperParams


class SuperShellCommand(Command):
    """Command to launch the SuperShell TUI"""

    def get_parser(self):
        from argparse import ArgumentParser
        parser = ArgumentParser(prog='supershell', description='Launch full terminal vault UI with vim navigation')
        # -h/--help is automatically added by ArgumentParser
        return parser

    def is_authorised(self):
        """Don't require pre-authentication - TUI handles all auth"""
        return False

    def execute(self, params: 'KeeperParams', **kwargs):
        """Launch the SuperShell TUI - handles login if needed"""
        from ... import display
        from ...cli import debug_manager

        # Show government warning for GOV environments when entering SuperShell
        if params.server and 'govcloud' in params.server.lower():
            display.show_government_warning()

        # Disable debug mode for SuperShell to prevent log output from messing up the TUI
        saved_debug = getattr(params, 'debug', False)
        saved_log_level = logging.getLogger().level
        if saved_debug or logging.getLogger().level == logging.DEBUG:
            params.debug = False
            debug_manager.set_console_debug(False, params.batch_mode)
            # Also set root logger level to suppress all debug output
            logging.getLogger().setLevel(logging.WARNING)

        try:
            self._execute_supershell(params, **kwargs)
        finally:
            # Restore debug state when SuperShell exits
            if saved_debug:
                params.debug = saved_debug
                debug_manager.set_console_debug(True, params.batch_mode)
                logging.getLogger().setLevel(saved_log_level)

    def _execute_supershell(self, params: 'KeeperParams', **kwargs):
        """Internal method to run SuperShell"""
        import threading
        import time
        import sys

        class Spinner:
            """Animated spinner that runs in a background thread"""
            def __init__(self, message="Loading..."):
                self.message = message
                self.running = False
                self.thread = None
                self.chars = ['\u280b', '\u2819', '\u2839', '\u2838', '\u283c', '\u2834', '\u2826', '\u2827', '\u2807', '\u280f']
                self.colors = ['\033[36m', '\033[32m', '\033[33m', '\033[35m']

            def _spin(self):
                i = 0
                while self.running:
                    color = self.colors[i % len(self.colors)]
                    char = self.chars[i % len(self.chars)]
                    # Check running again before writing to avoid race condition
                    if not self.running:
                        break
                    sys.stdout.write(f"\r  {color}{char}\033[0m {self.message}")
                    sys.stdout.flush()
                    time.sleep(0.1)
                    i += 1

            def start(self):
                self.running = True
                self.thread = threading.Thread(target=self._spin, daemon=True)
                self.thread.start()

            def stop(self, success_message=None):
                self.running = False
                if self.thread:
                    self.thread.join(timeout=0.5)
                # Small delay to ensure thread has stopped writing
                time.sleep(0.15)
                # Clear spinner line (do it twice to handle any race condition)
                sys.stdout.write("\r\033[K")
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
                if success_message:
                    print(f"  \033[32m\u2713\033[0m {success_message}")

            def update(self, message):
                self.message = message

        # Check if authentication is needed
        if not params.session_token:
            from ..utils import LoginCommand
            try:
                # Run login (no spinner - login may prompt for 2FA, password, etc.)
                # show_help=False to suppress the batch mode help text
                LoginCommand().execute(params, email=params.user, password=params.password, new_login=False, show_help=False)

                if not params.session_token:
                    logging.error("\nLogin failed or was cancelled.")
                    return

                # Sync vault data with spinner (no success message - TUI will load immediately)
                sync_spinner = Spinner("Syncing vault data...")
                sync_spinner.start()
                try:
                    from ..utils import SyncDownCommand
                    SyncDownCommand().execute(params)
                    sync_spinner.stop()  # No success message - TUI loads immediately
                except Exception as e:
                    sync_spinner.stop()
                    raise

            except KeyboardInterrupt:
                print("\n\nLogin cancelled.")
                return
            except Exception as e:
                logging.error(f"\nLogin failed: {e}")
                return

        # Launch the TUI app - import here to avoid circular import
        from .app import SuperShellApp

        try:
            app = SuperShellApp(params)
            result = app.run()

            # If user pressed '!' to exit to shell, start the Keeper shell
            if result and "Exited to Keeper shell" in str(result):
                print(result)  # Show the exit message
                # Check if we were in batch mode BEFORE modifying it
                was_batch_mode = params.batch_mode
                # Clear batch mode and pending commands so the shell runs interactively
                params.batch_mode = False
                params.commands = [c for c in params.commands if c.lower() not in ('q', 'quit')]
                # Only start a new shell if we were in batch mode (ran 'keeper supershell' directly)
                # Otherwise, just return to the existing interactive shell
                if was_batch_mode:
                    from ...cli import loop as shell_loop
                    shell_loop(params, skip_init=True, suppress_goodbye=True)
                    # When the inner shell exits, queue 'q' so the outer batch-mode loop also exits
                    params.commands.append('q')
        except KeyboardInterrupt:
            logging.debug("SuperShell interrupted")
        except Exception as e:
            logging.error(f"Error running SuperShell: {e}")
            raise
