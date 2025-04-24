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

import io, html
from pathlib import Path
import sys
import json
from typing import Any, Tuple, Optional
from keepercommander import cli, utils
from keepercommander.__main__ import get_params_from_config
from keepercommander.service.config.service_config import ServiceConfig
from .exceptions import CommandExecutionError
from .config_reader import ConfigReader
from ..core.globals import get_current_params
from .parse_keeper_response import parse_keeper_response
from keepercommander.crypto import encrypt_aes_v2
from ..decorators.logging import logger, debug_decorator

class CommandExecutor:
    @staticmethod
    @debug_decorator
    def validate_command(command: str) -> Optional[Tuple[dict, int]]:
        if not command:
            return {"error": "No command provided."}, 400
        return None

    @staticmethod
    @debug_decorator
    def validate_session() -> Optional[Tuple[dict, int]]:
        params = get_current_params()
        if not params:
            return {"error": "No active session. Please log in through the CLI first."}, 401
        return None

    @staticmethod
    @debug_decorator
    def capture_output(params: Any, command: str) -> Tuple[Any, str]:
        captured_output = io.StringIO()
        sys.stdout = captured_output
        try:
            return_value = cli.do_command(params, command)
            return return_value, captured_output.getvalue()
        except Exception as e:
            raise
        finally:
            sys.stdout = sys.__stdout__

    @staticmethod
    @debug_decorator
    def encrypt_response(response: Any) -> bytes:
        encryption_key = ConfigReader.read_config('encryption_private_key')
        if encryption_key:
            try:
                encryption_key_bytes = encryption_key.encode('utf-8')
                response_bytes = json.dumps(response).encode('utf-8')
                return encrypt_aes_v2(response_bytes, encryption_key_bytes)
            except Exception as e:
                raise
        return response

    @classmethod
    def execute(cls, command: str) -> Tuple[Any, int]:
        logger.debug(f"Executing command: {command}")
        
        validation_error = cls.validate_command(command)
        if validation_error:
            return validation_error
        
        service_config = ServiceConfig()
        config_data = service_config.load_config()

        if config_data.get("run_mode") == "background":
            try:
                config_path = utils.get_default_path() / "config.json"
                params = get_params_from_config(config_path)
            except FileNotFoundError:
                logger.error(f"Config file not found at {config_path}")
                raise
            except Exception as e:
                logger.error(f"Failed to load params from config file: {e}")
                raise
        else:
            params = get_current_params()

        try:
            command = html.unescape(command)
            return_value, printed_output = cls.capture_output(params, command)
            response = return_value if return_value else printed_output

            cli.do_command(params, 'sync-down')
            
            response = parse_keeper_response(command, response)
            response = cls.encrypt_response(response)
            if response:
                logger.debug("Command executed successfully")
                return response, 200
            else:
                return "Internal Server Error", 500
        except Exception as e:
            raise CommandExecutionError(f"Command execution failed: {str(e)}")