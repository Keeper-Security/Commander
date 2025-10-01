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
from configparser import ConfigParser
from pathlib import Path
from ..decorators.logging import logger, debug_decorator
from ..config.service_config import ServiceConfig
from ..util.exceptions import ValidationError
from ...commands.base import Command
from ... import resources

class SecurityConfigHandler(Command):
    def __init__(self, service_config: ServiceConfig):
        self.service_config = service_config
        self.config = ConfigParser()
        config_path = Path(resources.__file__).parent / 'service_config.ini'
        self.config.read(config_path)
        self.messages = self.config['Messages']
        self.validation_messages = self.config['Validation_Messages']

    @debug_decorator
    def configure_security(self, config_data: Dict[str, Any]) -> None:
        config_data["is_advanced_security_enabled"] = (
            self.service_config._get_yes_no_input(self.messages['advanced_security_prompt'])
        )
        config_data["ip_allowed_list"] = '0.0.0.0/0,::/0'
        if config_data["is_advanced_security_enabled"] == "y":
            self._configure_advanced_security(config_data)

    def _configure_ip_allowed(self, config_data: Dict[str, Any]) -> None:
        while True:
            try:
                ip_list = input(self.messages['ip_allowed_list_prompt'])
                logger.debug(f"Allowed Ip list: {ip_list}")
                if ip_list:
                    logger.debug(f"Validating IP list: {ip_list}")
                    config_data["ip_allowed_list"] = (
                        self.service_config.validator.validate_ip_list(ip_list)
                    )
                break
            except ValidationError as e:
                print(f"{self.validation_messages['invalid_ip_list']} {str(e)}")

    def _configure_ip_blocking(self, config_data: Dict[str, Any]) -> None:
        while True:
            try:
                ip_list = input(self.messages['ip_denied_list_prompt'])
                logger.debug(f"Validating IP list: {ip_list}")
                config_data["ip_denied_list"] = (
                    self.service_config.validator.validate_ip_list(ip_list)
                )
                break
            except ValidationError as e:
                print(f"{self.validation_messages['invalid_ip_list']} {str(e)}")

    def _configure_advanced_security(self, config_data: Dict[str, Any]) -> None:
        self._configure_rate_limiting(config_data)
        self._configure_ip_allowed(config_data)
        self._configure_ip_blocking(config_data)
        self._configure_encryption(config_data)

    def _configure_rate_limiting(self, config_data: Dict[str, Any]) -> None:
        while True:
            try:
                rate_limit = input(self.messages['rate_limit_prompt'])
                logger.debug(f"Validating rate limit: {rate_limit}")
                config_data["rate_limiting"] = (
                    self.service_config.validator.validate_rate_limit(rate_limit)
                )
                break
            except ValidationError as e:
                print(f"{self.validation_messages['invalid_rate_limit']} {str(e)}")

    

    def _configure_encryption(self, config_data: Dict[str, Any]) -> None:
        config_data["encryption"] = self.service_config._get_yes_no_input(self.messages['encryption_prompt'])
        
        if config_data["encryption"] == "y":
            while True:
                try:
                    key = input(self.messages['encryption_key_prompt'])
                    logger.debug("Validating encryption key")
                    config_data["encryption_private_key"] = (
                        self.service_config.validator.validate_encryption_key(key)
                    )
                    break
                except ValidationError as e:
                    print(f"{self.validation_messages['invalid_encryption_key']} {str(e)}")