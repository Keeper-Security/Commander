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
from .config_reader import ConfigReader
from .exceptions import CommandExecutionError
from .parse_keeper_response import parse_keeper_response
from ..core.globals import get_current_params
from ..decorators.logging import logger, debug_decorator, sanitize_debug_data
from ... import cli, utils
from ...__main__ import get_params_from_config
from ...service.config.service_config import ServiceConfig
from ...crypto import encrypt_aes_v2

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
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        
        sys.stdout = captured_stdout
        sys.stderr = captured_stderr
        
        try:
            return_value = cli.do_command(params, command)
            stdout_content = captured_stdout.getvalue()
            stderr_content = captured_stderr.getvalue()
            
            # Combine both stderr and stdout to capture all command output
            stdout_clean = stdout_content.strip()
            stderr_clean = stderr_content.strip()
            
            if stderr_clean and stdout_clean:
                combined_output = stderr_clean + '\n' + stdout_clean
            else:
                combined_output = stderr_clean or stdout_clean
            
            return return_value, combined_output
        except Exception as e:
            # If there's an exception, capture any error output
            stderr_content = captured_stderr.getvalue()
            error_output = stderr_content.strip()
            
            if error_output:
                # Re-raise with the captured error message
                raise CommandExecutionError(f"Command failed: {error_output}")
            raise
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr



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
            return_value, printed_output = CommandExecutor.capture_output(params, command)
            response = return_value if return_value else printed_output

            # Debug logging with sanitization
            sanitized_output = sanitize_debug_data(printed_output)
            logger.debug(f"After capture_output - return_value: '{return_value}', printed_output: '{sanitized_output}'")
            sanitized_response = sanitize_debug_data(str(response))
            logger.debug(f"Final response: '{sanitized_response}', response type: {type(response)}")

            cli.do_command(params, 'sync-down')
            
            # Always let the parser handle the response (including empty responses)
            response = parse_keeper_response(command, response)
            
            response = CommandExecutor.encrypt_response(response)
            logger.debug("Command executed successfully")
            return response, 200
        except CommandExecutionError as e:
            # Return the actual command error instead of generic "server busy"
            logger.error(f"Command execution error: {e}")
            error_response = {
                "success": False,
                "error": str(e)
            }
            return error_response, 400
        except Exception as e:
            # Log unexpected errors and return a proper error response
            logger.error(f"Unexpected error during command execution: {e}")
            error_response = {
                "success": False,
                "error": f"Unexpected error: {str(e)}"
            }
            return error_response, 500