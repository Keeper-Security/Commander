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

import io
import sys
import re
from pathlib import Path
from typing import Optional
from ..decorators.logging import logger, debug_decorator
from ...params import KeeperParams

class CommandHandler:
    @debug_decorator
    def execute_cli_command(self, params: KeeperParams, command: str) -> str:
        """Execute a CLI command and capture output."""
        output = io.StringIO()
        sys.stdout = output
        try:
            # Set service mode flag to bypass master password enforcement
            original_service_mode = getattr(params, 'service_mode', False)
            params.service_mode = True
            
            from ... import cli
            cli.do_command(params, command)
            return output.getvalue()
        except Exception as e:
            logger.debug(f"Error executing CLI command '{command}': {e}")
            return ''
        finally:
            sys.stdout = sys.__stdout__
            # Restore original service mode flag
            params.service_mode = original_service_mode

    @debug_decorator
    def find_config_record(self, params: KeeperParams, title: str) -> Optional[str]:
        """Find existing config record and return its UID."""
        try:
            output = self.execute_cli_command(params, f"search -v '{title}'")
            if uid_match := re.search(r'UID: ([a-zA-Z0-9_-]+)', output):
                return uid_match.group(1)
        except Exception as e:
            logger.error(f"Error searching for record: {e}")
            print(f"Error searching for record: {e}")
        return None

    @debug_decorator
    def get_help_output(self, params: KeeperParams) -> str:
        """Get help output from CLI."""
        output = io.StringIO()
        sys.stdout = output
        try:
            # Set service mode flag to bypass master password enforcement
            original_service_mode = getattr(params, 'service_mode', False)
            params.service_mode = True
            
            from ... import cli
            cli.do_command(params, 'help')
            return output.getvalue()
        finally:
            sys.stdout = sys.__stdout__
            # Restore original service mode flag
            params.service_mode = original_service_mode
    
    @debug_decorator
    def download_config_from_vault(self, params: KeeperParams, title: str, config_dir: Path) -> bool:
        """Download config file from vault if it exists."""
        try:
            if record_uid := self.find_config_record(params, title):
                self.execute_cli_command(params, f"download-attachment {record_uid} --out-dir '{config_dir}'")
                return True
            return False
        except Exception as e:
            logger.error(f"Error downloading config from vault: {e}")
            return False