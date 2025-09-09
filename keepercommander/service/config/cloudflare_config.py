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
from ..util.tunneling import generate_cloudflare_url

class CloudflareConfigurator:
    @staticmethod
    @debug_decorator
    def configure_cloudflare(config_data: Dict[str, Any], service_config: ServiceConfig) -> Optional[int]:
        """Configure Cloudflare tunnel if enabled. Returns tunnel PID if started in background mode, None otherwise."""
        if config_data.get("cloudflare") == 'y':
            logger.debug("Configuring Cloudflare tunnel")
            result = generate_cloudflare_url(
                config_data["port"], 
                config_data["cloudflare_tunnel_token"],
                config_data["cloudflare_custom_domain"],
                config_data["run_mode"],
            )
            if isinstance(result, tuple):
                config_data["cloudflare_public_url"], cloudflare_pid = result
                if config_data["cloudflare_public_url"]:
                    print(f'Generated Cloudflare tunnel URL: {config_data["cloudflare_public_url"]}')
                else:
                    print('Cloudflare tunnel started, URL will be available in logs')
                return cloudflare_pid
            else:
                config_data["cloudflare_public_url"] = result
                print(f'Generated Cloudflare tunnel URL: {result}')
                return None
            # service_config.save_config(config_data)
        return None

