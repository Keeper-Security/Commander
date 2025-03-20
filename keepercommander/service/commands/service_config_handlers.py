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

from typing import Dict, Any
from keepercommander.params import KeeperParams
from keepercommander import resources
from configparser import ConfigParser
from pathlib import Path
from ..config.service_config import ServiceConfig
from ..decorators.logging import logger, debug_decorator
from ..util.exceptions import ValidationError

class ServiceConfigHandler:
    def __init__(self, service_config: ServiceConfig):
        self.service_config = service_config
        self.config = ConfigParser()
        config_path = Path(resources.__file__).parent / 'service_config.ini'
        self.config.read(config_path)
        self.messages = self.config['Messages']
        self.validation_messages = self.config['Validation_Messages']

    @debug_decorator
    def handle_streamlined_config(self, config_data: Dict[str, Any], args, params: KeeperParams) -> None:
        config_data.update({
            "port": self.service_config.validator.validate_port(args.port),
            "ngrok": "y" if args.ngrok else "n",
            "ngrok_auth_token": (
                self.service_config.validator.validate_ngrok_token(args.ngrok)
                if args.ngrok else ""
            )
        })

    @debug_decorator
    def handle_interactive_config(self, config_data: Dict[str, Any], params: KeeperParams) -> None:
        self._configure_port(config_data)
        self._configure_ngrok(config_data)

    def _configure_port(self, config_data: Dict[str, Any]) -> None:
        while True:
            try:
                port = input(self.messages['port_prompt'])
                logger.debug(f"Validating port: {port}")
                config_data["port"] = self.service_config.validator.validate_port(port)
                break
            except ValidationError as e:
                print(f"{self.validation_messages['invalid_port']} {str(e)}")

    def _configure_ngrok(self, config_data: Dict[str, Any]) -> None:
        config_data["ngrok"] = self.service_config._get_yes_no_input(self.messages['ngrok_prompt'])
        
        if config_data["ngrok"] == "y":
            while True:
                try:
                    token = input(self.messages['ngrok_token_prompt'])
                    config_data["ngrok_auth_token"] = self.service_config.validator.validate_ngrok_token(token)
                    break
                except ValidationError as e:
                    print(f"{self.validation_messages['invalid_ngrok_token']} {str(e)}")
        else:
            config_data["ngrok_auth_token"] = ""