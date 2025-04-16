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
        if args.allowedip is None:
            args.allowedip = '0.0.0.0/0'
        config_data.update({
            "port": self.service_config.validator.validate_port(args.port),
            "ip_allowed_list": self.service_config.validator.validate_ip_list(args.allowedip),
            "ip_denied_list": self.service_config.validator.validate_ip_list(args.deniedip),
            "ngrok": "y" if args.ngrok else "n",
            "ngrok_auth_token": (
                self.service_config.validator.validate_ngrok_token(args.ngrok)
                if args.ngrok else ""
            ),
            "ngrok_custom_domain": args.ngrok_custom_domain,
            "certfile": args.certfile,
            "certpassword": args.certpassword,
            "fileformat": args.fileformat,
            "run_mode": args.run_mode
        })

    @debug_decorator
    def handle_interactive_config(self, config_data: Dict[str, Any], params: KeeperParams) -> None:
        self._configure_port(config_data)
        self._configure_ngrok(config_data)
        self._configure_tls(config_data)
        config_data["run_mode"] = "background"
    
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
                    config_data["ngrok_custom_domain"]  = input(self.messages['ngrok_custom_domain_prompt'])
                    # print(f"ngrok custom domain >> "+{config_data["ngrok_custom_domain"]})
                    break
                except ValidationError as e:
                    print(f"{self.validation_messages['invalid_ngrok_token']} {str(e)}")
        else:
            config_data["ngrok_auth_token"] = ""
        
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
