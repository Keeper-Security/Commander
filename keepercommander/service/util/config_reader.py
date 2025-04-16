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

from typing import Any
from ..decorators.logging import logger

class ConfigReader:
    _service_config = None

    @classmethod
    def _get_service_config(cls) -> Any:
        """Get or create ServiceConfig instance."""
        if cls._service_config is None:
            from ..config.service_config import ServiceConfig
            cls._service_config = ServiceConfig()
        return cls._service_config

    @classmethod
    def read_config(cls, service_config_param: str, api_key: str = "") -> Any:
        """Read configuration parameter from service config file."""
        service_config = cls._get_service_config()
        
        try:
            config_data = service_config.load_config()
            logger.debug(f"Successfully loaded config file")
            
            param_handlers = {
                'port': lambda: config_data.get('port', 5000),
                'rate_limiting': lambda: config_data.get('rate_limiting', ""),
                'ip_allowed_list': lambda: config_data.get('ip_allowed_list', ""),
                'ip_denied_list': lambda: config_data.get('ip_denied_list', ""),
                'is_advanced_security_enabled': lambda: config_data.get('is_advanced_security_enabled', "n"),
                'encryption_private_key': lambda: config_data.get('encryption_private_key', ""),
                'ngrok_public_url': lambda: config_data.get('ngrok_public_url', ""),
                'certfile': lambda: config_data.get('certfile', ""),
                'certpassword': lambda: config_data.get('certpassword', ""),
                'run_mode': lambda: config_data.get('run_mode', "")
            }

            if handler := param_handlers.get(service_config_param):
                value = handler()
                logger.debug(f"Retrieved value for {service_config_param}: {value}")
                return value

            if api_key:
                logger.debug(f"Searching for parameter in records with API key")
                records = config_data.get('records', [])
                
                if not isinstance(records, list):
                    return ""
                
                for record in records:
                    if record.get('api-key') == api_key:
                        value = record.get(service_config_param, "")
                        logger.debug(f"Found value for {service_config_param} in record")
                        return value
                        
                logger.debug(f"No matching record found for provided API key")
                return ""

            logger.debug(f"No API key provided and parameter not found in standard config")
            return ""

        except (FileNotFoundError, Exception) as e:
            default_value = 5000 if service_config_param == 'port' else ""
            logger.debug(f"Using default value for {service_config_param}: {default_value}")
            return default_value