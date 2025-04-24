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
from ..decorators.logging import logger, debug_decorator
from .service_config import ServiceConfig
from ..util.tunneling import generate_ngrok_url

class NgrokConfigurator:
    @staticmethod
    @debug_decorator
    def configure_ngrok(config_data: Dict[str, Any], service_config: ServiceConfig) -> None:
        """Configure ngrok if enabled."""
        if config_data.get("ngrok") == 'y':
            logger.debug("Configuring ngrok tunnel")
            config_data["ngrok_public_url"] = generate_ngrok_url(
                config_data["port"], 
                config_data["ngrok_auth_token"],
                config_data["ngrok_custom_domain"],
                config_data["run_mode"],
            )
            print(f'Generated ngrok URL: https://{config_data["ngrok_custom_domain"]}.ngrok.io')
            service_config.save_config(config_data)