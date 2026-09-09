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
from ..util.tunneling import (
    is_tailscale_installed,
    get_tailscale_install_guidance,
    install_tailscale,
    is_tailscale_daemon_running,
    get_tailscale_daemon_start_guidance,
    start_tailscale_daemon,
    tailscale_up,
    start_tailscale_funnel,
    get_tailscale_funnel_url,
)
from ..util.exceptions import ValidationError

class TailscaleConfigurator:

    @staticmethod
    def _validate_tailscale_config(config_data: Dict[str, Any], service_config: ServiceConfig) -> None:
        """Validate Tailscale configuration parameters."""
        required_keys = ["port", "tailscale_auth_key", "run_mode"]

        for key in required_keys:
            if key not in config_data:
                raise ValidationError(f"Missing required configuration key: {key}")

        service_config.validator.validate_port(config_data["port"])
        service_config.validator.validate_tailscale_auth_key(config_data["tailscale_auth_key"])

        if config_data["run_mode"] not in ["foreground", "background"]:
            raise ValidationError(f"Invalid run_mode: {config_data['run_mode']}")

        logger.debug("Tailscale configuration validation successful")

    @staticmethod
    @debug_decorator
    def configure_tailscale(config_data: Dict[str, Any], service_config: ServiceConfig) -> Optional[int]:
        """
        Configure Tailscale Funnel if enabled. Always returns None: unlike
        Ngrok/Cloudflare, Tailscale does not spawn a Commander-owned
        long-lived subprocess with a meaningful PID -- `tailscale` is a thin
        CLI over the pre-existing tailscaled system daemon. Funnel lifecycle
        state is tracked via ProcessInfo.tailscale_enabled/tailscale_port
        instead of a PID.
        """
        if config_data.get("tailscale") != 'y':
            return None

        logger.debug("Configuring Tailscale Funnel")

        try:
            if not is_tailscale_installed():
                guidance = get_tailscale_install_guidance()
                logger.error(guidance)
                print(guidance)

                install_choice = service_config._get_yes_no_input(
                    service_config.messages.get(
                        'tailscale_install_prompt',
                        'Tailscale CLI is not installed. Attempt automatic installation now? (y/n): '
                    )
                )

                if install_choice == 'y':
                    print('Attempting to install Tailscale automatically...')
                    install_tailscale()
                    if not is_tailscale_installed():
                        raise ValidationError(
                            f"Automatic Tailscale installation did not succeed. {guidance}"
                        )
                    logger.debug("Tailscale CLI installed successfully via automatic installation")
                else:
                    raise ValidationError(guidance)

            if not is_tailscale_daemon_running():
                daemon_guidance = get_tailscale_daemon_start_guidance()
                logger.error(daemon_guidance)
                print(daemon_guidance)

                start_choice = service_config._get_yes_no_input(
                    service_config.messages.get(
                        'tailscale_daemon_start_prompt',
                        'Tailscale daemon is not running. Attempt to start it now? (y/n): '
                    )
                )

                if start_choice == 'y':
                    print('Attempting to start the Tailscale daemon...')
                    start_tailscale_daemon()
                    if not is_tailscale_daemon_running():
                        raise ValidationError(
                            f"Could not start the Tailscale daemon automatically. {daemon_guidance}"
                        )
                    logger.debug("Tailscale daemon started successfully")
                else:
                    raise ValidationError(daemon_guidance)

            TailscaleConfigurator._validate_tailscale_config(config_data, service_config)

            # Auth key is used only for `tailscale up`; never logged, never used for API auth.
            tailscale_up(config_data["tailscale_auth_key"])

            start_tailscale_funnel(config_data["port"])

            public_url = get_tailscale_funnel_url(config_data["port"])
            config_data["tailscale_public_url"] = public_url or ""

            if public_url:
                print(f'Generated Tailscale Funnel URL: {public_url}')
            else:
                print('Tailscale Funnel started, URL will be available via `tailscale funnel status`')

            return None

        except ValidationError as e:
            logger.error(f"Invalid Tailscale configuration: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to configure Tailscale Funnel: {e}")
            raise
