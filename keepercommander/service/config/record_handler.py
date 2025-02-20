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

from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from keepercommander.params import KeeperParams
from ..util.api_key import generate_api_key
from ..util.exceptions import ValidationError
from ..decorators.logging import logger, debug_decorator
from .cli_handler import CommandHandler
from .config_validation import ConfigValidator

class RecordHandler:
    def __init__(self):
        self.validator = ConfigValidator()
        self.cli_handler = CommandHandler()

    @debug_decorator
    def create_record(self, is_advanced_security_enabled: str, commands: str) -> Dict[str, Any]:
        """Create a new configuration record."""
        api_key = generate_api_key()
        record = self._create_base_record(api_key, commands)
        
        if is_advanced_security_enabled == "y":
            logger.debug("Adding expiration to record (advanced security enabled)")
            self._add_expiration_to_record(record)
            
        print(f'Generated API key: {api_key}')
        return record

    def update_or_add_record(self, params: KeeperParams, title: str, config_path: Path) -> None:
        """Update existing record or add new one."""
        try:
            record_uid = self.cli_handler.find_config_record(params, title)
            config_path_str = f"'{config_path.as_posix()}'"

            command = (
                f"record-update --force --record {record_uid} "
                f"--title '{title}' --record-type legacy f.file={config_path_str}"
            ) if record_uid else (
                f"record-add --title='{title}' "
                f"--record-type=legacy f.file={config_path_str}"
            )
            if record_uid:
                self.cli_handler.execute_cli_command(params, f"delete-attachment {record_uid} --name service_config.json --name service_config.yaml")
            logger.debug(f"{'Updating' if record_uid else 'Creating'} record")
            
            self.cli_handler.execute_cli_command(params, command)

            if not record_uid:
                self.record_uid = self.cli_handler.find_config_record(params, title)

        except Exception as e:
            print(f"Error updating/adding record: {e}")

    @debug_decorator
    def _create_base_record(self, api_key: str, commands: str) -> Dict[str, Any]:
        """Create base record structure."""
        return {
            "api-key": api_key,
            "command_list": commands,
            "expiration_timestamp": datetime(9999, 12, 31, 23, 59, 59).isoformat(),
            "expiration_of_token": ""
        }

    @debug_decorator
    def _add_expiration_to_record(self, record: Dict[str, Any]) -> None:
        """Add expiration details to the record."""
        expiration_str = input(
            "Token Expiration Time (Xm, Xh, Xd) or empty for no expiration: "
        ).strip()

        if not expiration_str:
            record["expiration_of_token"] = ""
            record["expiration_timestamp"] = datetime(9999, 12, 31, 23, 59, 59).isoformat()
            print("API key set to never expire")
            return

        try:
            expiration_delta = self.validator.parse_expiration_time(expiration_str)
            expiration_time = datetime.now() + expiration_delta
            record["expiration_of_token"] = expiration_str
            record["expiration_timestamp"] = expiration_time.isoformat()
            print(f"API key will expire at: {record['expiration_timestamp']}")
        except ValidationError as e:
            print(f"Error: {str(e)}")
            self._add_expiration_to_record(record)