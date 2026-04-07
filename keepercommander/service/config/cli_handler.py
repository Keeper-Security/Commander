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
        """Find existing config record by exact title match using vault search."""
        try:
            from ... import vault_extensions
            
            logger.debug(f"Searching for record with exact title: '{title}'")
            records = list(vault_extensions.find_records(params, title))
            
            # Filter to exact title match only
            for record in records:
                logger.debug(f"Checking record: '{record.title}' (UID: {record.record_uid})")
                if record.title == title:
                    logger.debug(f"✓ Found exact title match: '{title}' (UID: {record.record_uid})")
                    return record.record_uid
            
            logger.debug(f"✗ No record found with exact title: '{title}'")
            return None
            
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
            cli.display_command_help(show_enterprise=True, show_shell=False, show_legacy=False)
            return output.getvalue()
        finally:
            sys.stdout = sys.__stdout__
            # Restore original service mode flag
            params.service_mode = original_service_mode
    
    @debug_decorator
    def download_config_from_vault(self, params: KeeperParams, title: str, config_dir: Path) -> bool:
        """Download config file from vault if it exists."""
        try:
            record_uid = self.find_config_record(params, title)
            if not record_uid:
                return False

            self.execute_cli_command(params, f"download-attachment {record_uid} --out-dir '{config_dir}'")

            json_path = config_dir / 'service_config.json'
            yaml_path = config_dir / 'service_config.yaml'
            if json_path.exists() or yaml_path.exists():
                return True

            return self._restore_config_from_custom_field(params, record_uid, config_dir)
        except Exception as e:
            logger.error(f"Error downloading config from vault: {e}")
            return False

    def _restore_config_from_custom_field(self, params: KeeperParams, record_uid: str, config_dir: Path) -> bool:
        """Write service_config content from a custom field to disk."""
        try:
            from ... import vault
            record = vault.KeeperRecord.load(params, record_uid)
            if not isinstance(record, vault.TypedRecord) or not record.custom:
                return False

            field_map = {
                'service_config_json': config_dir / 'service_config.json',
                'service_config_yaml': config_dir / 'service_config.yaml',
            }
            for field in record.custom:
                if field.label in field_map and field.get_default_value():
                    dest = field_map[field.label]
                    dest.write_text(field.get_default_value())
                    from ... import utils
                    utils.set_file_permissions(str(dest))
                    logger.debug(f"Restored {dest.name} from custom field")
                    return True

            return False
        except Exception as e:
            logger.error(f"Error restoring config from custom field: {e}")
            return False