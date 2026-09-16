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
    def _ensure_ready(service_config: ServiceConfig, check_fn, guidance_fn, action_fn,
                       prompt_key: str, prompt_default: str, action_label: str, failure_label: str) -> None:
        """
        Generic check -> guidance -> prompt -> attempt -> reverify flow, shared
        by the CLI-install and daemon-start checks below. Raises ValidationError
        if the user declines or the automatic attempt doesn't fix the check.
        """
        if check_fn():
            return

        guidance = guidance_fn()
        logger.error(guidance)
        print(guidance)

        choice = service_config._get_yes_no_input(service_config.messages.get(prompt_key, prompt_default))
        if choice != 'y':
            raise ValidationError(guidance)

        print(f'Attempting to {action_label} automatically...')
        action_fn()
        if not check_fn():
            raise ValidationError(f"{failure_label}. {guidance}")
        logger.debug(f"{action_label.capitalize()} succeeded")

    @staticmethod
    @debug_decorator
    def configure_tailscale(config_data: Dict[str, Any], service_config: ServiceConfig) -> Optional[int]:
        """
        Configure Tailscale Funnel if enabled. Always returns None -- unlike
        Ngrok/Cloudflare, Tailscale has no Commander-owned subprocess/PID to
        track; lifecycle state lives in ProcessInfo.tailscale_enabled/tailscale_port.
        """
        if config_data.get("tailscale") != 'y':
            return None

        logger.debug("Configuring Tailscale Funnel")

        try:
            logger.debug("Checking Tailscale CLI availability")
            TailscaleConfigurator._ensure_ready(
                service_config, is_tailscale_installed, get_tailscale_install_guidance, install_tailscale,
                'tailscale_install_prompt', 'Tailscale CLI is not installed. Attempt automatic installation now? (y/n): ',
                'install Tailscale', 'Automatic Tailscale installation did not succeed'
            )

            logger.debug("Checking Tailscale daemon status")
            TailscaleConfigurator._ensure_ready(
                service_config, is_tailscale_daemon_running, get_tailscale_daemon_start_guidance, start_tailscale_daemon,
                'tailscale_daemon_start_prompt', 'Tailscale daemon is not running. Attempt to start it now? (y/n): ',
                'start the Tailscale daemon', 'Could not start the Tailscale daemon automatically'
            )

            TailscaleConfigurator._validate_tailscale_config(config_data, service_config)

            # Auth key used only for `tailscale up`; never logged, never used for API auth.
            logger.debug("Authenticating with Tailscale")
            tailscale_up(config_data["tailscale_auth_key"], config_data.get("tailscale_advertise_tags"))

            logger.debug(f"Starting Tailscale Funnel for port {config_data['port']}")
            start_tailscale_funnel(config_data["port"])

            public_url = get_tailscale_funnel_url(config_data["port"])
            config_data["tailscale_public_url"] = public_url or ""

            if public_url:
                logger.info(f"Tailscale Funnel URL: {public_url}")
                print(f'Generated Tailscale Funnel URL: {public_url}')
            else:
                logger.warning("Tailscale Funnel started but URL could not be retrieved")
                print('Tailscale Funnel started, URL will be available via `tailscale funnel status`')

            return None

        except ValidationError as e:
            logger.error(f"Invalid Tailscale configuration: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to configure Tailscale Funnel: {e}")
            raise
