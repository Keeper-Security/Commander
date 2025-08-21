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

from typing import Dict, Any, Optional
from ..decorators.logging import logger, debug_decorator
from .service_config import ServiceConfig
from ..util.tunneling import generate_ngrok_url

class NgrokConfigurator:
    @staticmethod
    @debug_decorator
    def configure_ngrok(config_data: Dict[str, Any], service_config: ServiceConfig) -> Optional[int]:
        """Configure ngrok if enabled. Returns ngrok PID if started in background mode, None otherwise."""
        if config_data.get("ngrok") == 'y':
            logger.debug("Configuring ngrok tunnel")
            result = generate_ngrok_url(
                config_data["port"], 
                config_data["ngrok_auth_token"],
                config_data["ngrok_custom_domain"],
                config_data["run_mode"],
            )
            if isinstance(result, tuple):
                config_data["ngrok_public_url"], ngrok_pid = result
                if config_data["ngrok_public_url"]:
                    print(f'Generated ngrok URL: {config_data["ngrok_public_url"]}')
                else:
                    print('Ngrok tunnel started, URL will be available in logs')
                return ngrok_pid
            else:
                config_data["ngrok_public_url"] = result
                print(f'Generated ngrok URL: {result}')
                return None
            # service_config.save_config(config_data)
        return None