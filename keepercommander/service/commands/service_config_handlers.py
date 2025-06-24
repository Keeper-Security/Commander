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
from ..config.service_config import ServiceConfig
from ..decorators.logging import logger, debug_decorator
from ..util.exceptions import ValidationError
from ... import resources
from ...params import KeeperParams

class ServiceConfigHandler:
    def __init__(self, service_config: ServiceConfig):
        self.service_config = service_config
        self.config = ConfigParser()
        config_path = Path(resources.__file__).parent / 'service_config.ini'
        self.config.read(config_path)
        self.messages = self.config['Messages']
        self.validation_messages = self.config['Validation_Messages']

    def _get_validated_input(self, prompt_key: str, validation_func, error_key: str, required: bool = False):
        """Get and validate user input with consistent error handling."""
        while True:
            try:
                value = input(self.messages.get(prompt_key, '')).strip()
                if required and not value:
                    print(self.validation_messages.get(f'{error_key}_required', 'This field is required.'))
                    continue
                return validation_func(value) if value else ""
            except ValidationError as e:
                print(f"{self.validation_messages.get(error_key, 'Invalid input')} {str(e)}")
            except (KeyboardInterrupt, EOFError):
                print("\nInput cancelled by user.")
                raise
            except Exception as e:
                print(f"Unexpected error: {str(e)}")

    @debug_decorator
    def handle_streamlined_config(self, config_data: Dict[str, Any], args, params: KeeperParams) -> None:
        if args.allowedip is None:
            args.allowedip = '0.0.0.0/0,::/0'
        
        run_mode = args.run_mode if args.run_mode is not None else "foreground"
        if args.run_mode is not None and run_mode not in ['foreground', 'background']:
            raise ValidationError(f"Invalid run mode '{run_mode}'. Must be 'foreground' or 'background'.")
        
        if args.fileformat is not None and args.fileformat not in ['json', 'yaml']:
            raise ValidationError(f"Invalid file format '{args.fileformat}'. Must be 'json' or 'yaml'.")
        
        queue_enabled = args.queue_enabled if args.queue_enabled is not None else "y"
        if args.queue_enabled is not None and queue_enabled not in ['y', 'n']:
            raise ValidationError(f"Invalid queue setting '{queue_enabled}'. Must be 'y' or 'n'.")
        
        # Apply logical tunneling flow for streamlined config
        ngrok_enabled = "y" if args.ngrok else "n"
        cloudflare_enabled = "y" if args.cloudflare else "n"
        
        # Implement the same logic as interactive mode
        if ngrok_enabled == "y":
            # ngrok enabled → disable cloudflare and TLS
            cloudflare_enabled = "n"
            cloudflare_token = ""
            cloudflare_domain = ""
            tls_enabled = "n"
            certfile = ""
            certpassword = ""
            logger.debug("Ngrok enabled - disabling cloudflare and TLS")
        elif cloudflare_enabled == "y":
            # cloudflare enabled → disable TLS, but validate required fields
            if not args.cloudflare:
                raise ValidationError("Cloudflare tunnel token is required when using Cloudflare tunnel.")
            if not args.cloudflare_custom_domain:
                raise ValidationError("Cloudflare custom domain is required when using Cloudflare tunnel.")
            
            tls_enabled = "n"
            certfile = ""
            certpassword = ""
            cloudflare_token = self.service_config.validator.validate_cloudflare_token(args.cloudflare)
            cloudflare_domain = self.service_config.validator.validate_domain(args.cloudflare_custom_domain)
            logger.debug("Cloudflare enabled - disabling TLS")
        else:
            # Both ngrok and cloudflare disabled → allow TLS
            tls_enabled = "y" if args.certfile and args.certpassword else "n"
            certfile = args.certfile if args.certfile else ""
            certpassword = args.certpassword if args.certpassword else ""
            cloudflare_token = ""
            cloudflare_domain = ""
            logger.debug("No tunnels enabled - TLS configuration allowed")

        config_data.update({
            "port": self.service_config.validator.validate_port(args.port),
            "ip_allowed_list": self.service_config.validator.validate_ip_list(args.allowedip),
            "ip_denied_list": self.service_config.validator.validate_ip_list(args.deniedip),
            "ngrok": ngrok_enabled,
            "ngrok_auth_token": (
                self.service_config.validator.validate_ngrok_token(args.ngrok)
                if ngrok_enabled == "y" else ""
            ),
            "ngrok_custom_domain": args.ngrok_custom_domain if ngrok_enabled == "y" else "",
            "cloudflare": cloudflare_enabled,
            "cloudflare_tunnel_token": cloudflare_token,
            "cloudflare_custom_domain": cloudflare_domain,
            "tls_certificate": tls_enabled,
            "certfile": certfile,
            "certpassword": certpassword,
            "fileformat": args.fileformat,  # Keep original logic - can be None
            "run_mode": run_mode,
            "queue_enabled": queue_enabled
        })

    @debug_decorator
    def handle_interactive_config(self, config_data: Dict[str, Any], params: KeeperParams) -> None:
        self._configure_port(config_data)
        self._configure_tunneling_and_tls(config_data)  # New consolidated method
        self._configure_queue(config_data)
        
        config_data["fileformat"] = None
    
    def _configure_port(self, config_data: Dict[str, Any]) -> None:
        while True:
            try:
                port = input(self.messages['port_prompt'])
                logger.debug(f"Validating port: {port}")
                config_data["port"] = self.service_config.validator.validate_port(port)
                break
            except ValidationError as e:
                print(f"{self.validation_messages['invalid_port']} {str(e)}")
    
    def _configure_tunneling_and_tls(self, config_data: Dict[str, Any]) -> None:
        """
        Configure tunneling and TLS with logical flow:
        1. If ngrok = yes → Skip cloudflare and TLS (ngrok provides public access with SSL)
        2. If ngrok = no → Ask for cloudflare
        3. If ngrok = no AND cloudflare = no → Ask for TLS (local HTTPS)
        """
        # First, always ask for ngrok
        self._configure_ngrok(config_data)
        
        if config_data["ngrok"] == "y":
            # ngrok provides public access with SSL, so skip cloudflare and TLS
            config_data["cloudflare"] = "n"
            config_data["cloudflare_tunnel_token"] = ""
            config_data["cloudflare_custom_domain"] = ""
            config_data["tls_certificate"] = "n"
            config_data["certfile"] = ""
            config_data["certpassword"] = ""
        else:
            # ngrok = no, so ask for cloudflare
            self._configure_cloudflare(config_data)
            
            if config_data["cloudflare"] == "y":
                # cloudflare provides public access with SSL, so skip TLS
                config_data["tls_certificate"] = "n"
                config_data["certfile"] = ""
                config_data["certpassword"] = ""
            else:
                # Both ngrok and cloudflare = no, so ask for TLS for local HTTPS
                self._configure_tls(config_data)

    def _configure_ngrok(self, config_data: Dict[str, Any]) -> None:
        config_data["ngrok"] = self.service_config._get_yes_no_input(self.messages['ngrok_prompt'])
        
        if config_data["ngrok"] == "y":
            while True:
                try:
                    token = input(self.messages['ngrok_token_prompt'])
                    config_data["ngrok_auth_token"] = self.service_config.validator.validate_ngrok_token(token)
                    config_data["ngrok_custom_domain"]  = input(self.messages['ngrok_custom_domain_prompt'])
                    # print(f"ngrok custom domain >> "+{config_data["ngrok_custom_domain"]})
                    break
                except ValidationError as e:
                    print(f"{self.validation_messages['invalid_ngrok_token']} {str(e)}")
        else:
            config_data["ngrok_auth_token"] = ""

    def _configure_cloudflare(self, config_data: Dict[str, Any]) -> None:
        config_data["cloudflare"] = self.service_config._get_yes_no_input(
            self.messages.get('cloudflare_prompt', 'Do you want to use Cloudflare tunnel? (y/n): ')
        )
        
        if config_data["cloudflare"] == "y":
            config_data["cloudflare_tunnel_token"] = self._get_validated_input(
                prompt_key='cloudflare_token_prompt',
                validation_func=self.service_config.validator.validate_cloudflare_token,
                error_key='invalid_cloudflare_token',
                required=True
            )
            
            config_data["cloudflare_custom_domain"] = self._get_validated_input(
                prompt_key='cloudflare_custom_domain_prompt', 
                validation_func=self.service_config.validator.validate_domain,
                error_key='invalid_cloudflare_domain',
                required=True
            )
        else:
            config_data["cloudflare_tunnel_token"] = ""
            config_data["cloudflare_custom_domain"] = ""
        
    def _configure_tls(self, config_data: Dict[str, Any]) -> None:
        config_data["tls_certificate"] = self.service_config._get_yes_no_input(self.messages['tls_certificate'])
        
        if config_data["tls_certificate"] == "y":
            while True:
                try:
                    certfile = input(self.messages['certfile'])
                    certpassword = input(self.messages['certpassword'])
                    config_data["certfile"] = self.service_config.validator.validate_cert_file(certfile)
                    config_data["certpassword"]  = self.service_config.validator.validate_certpassword(certpassword)
                    # print(f"ngrok custom domain >> "+{config_data["ngrok_custom_domain"]})
                    break
                except ValidationError as e:
                    print(f"{self.validation_messages['invalid_certificate']} {str(e)}")
        else:
            config_data["certfile"] = ""
            config_data["certpassword"] = ""
    
    def _configure_queue(self, config_data: Dict[str, Any]) -> None:
        """Configure queue enabled setting with user prompt."""
        config_data["queue_enabled"] = self.service_config._get_yes_no_input(self.messages['queue_enabled_prompt'])
        logger.debug("Queue configuration completed")

    def _configure_run_mode(self, config_data: Dict[str, Any]) -> None:
        """Configure run mode with user prompt."""
        while True:
            run_mode = input(self.messages['run_mode_prompt']).strip().lower()
            if run_mode in ['foreground', 'background']:
                config_data["run_mode"] = run_mode
                logger.debug(f"Run mode set to: {run_mode}")
                break
            print(f"{self.validation_messages['invalid_run_mode']} Must be 'foreground' or 'background'.")
