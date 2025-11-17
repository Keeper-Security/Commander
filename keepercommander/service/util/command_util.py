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
import logging
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
    def capture_output_and_logs(params: Any, command: str) -> Tuple[Any, str, str]:
        """Capture both stdout/stderr and logging output from command execution."""
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        captured_logs = io.StringIO()
        
        # Create a temporary log handler to capture command logs
        temp_handler = logging.StreamHandler(captured_logs)
        temp_handler.setFormatter(logging.Formatter('%(message)s'))
        
        # Get the root logger to capture all logging output
        root_logger = logging.getLogger()
        original_level = root_logger.level
        original_handlers = root_logger.handlers[:]
        
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        
        sys.stdout = captured_stdout
        sys.stderr = captured_stderr
        
        try:
            # Add our temporary handler and set appropriate level
            root_logger.addHandler(temp_handler)
            root_logger.setLevel(logging.INFO)
            
            return_value = cli.do_command(params, command)
            
            stdout_content = captured_stdout.getvalue()
            stderr_content = captured_stderr.getvalue()
            log_content = captured_logs.getvalue()
            
            # Combine stdout and stderr
            stdout_clean = stdout_content.strip()
            stderr_clean = stderr_content.strip()
            log_clean = log_content.strip()
            
            if stderr_clean and stdout_clean:
                combined_output = stderr_clean + '\n' + stdout_clean
            else:
                combined_output = stderr_clean or stdout_clean
            
            return return_value, combined_output, log_clean
        except Exception as e:
            # If there's an exception, capture any error output
            stderr_content = captured_stderr.getvalue()
            log_content = captured_logs.getvalue()
            error_output = stderr_content.strip()
            
            if error_output:
                raise CommandExecutionError(f"Command failed: {error_output}")
            raise
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            # Restore original logging configuration
            root_logger.removeHandler(temp_handler)
            root_logger.setLevel(original_level)
            temp_handler.close()


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
        
        from ..core.globals import ensure_params_loaded
        try:
            params = ensure_params_loaded()
            # Set service mode flag to bypass master password enforcement
            if params:
                params.service_mode = True

            command = html.unescape(command)
            return_value, printed_output, log_output = CommandExecutor.capture_output_and_logs(params, command)
            response = return_value if return_value else printed_output

            # Debug logging with sanitization
            sanitized_output = sanitize_debug_data(printed_output)
            sanitized_logs = sanitize_debug_data(log_output)
            logger.debug(f"After capture_output - return_value: '{return_value}', printed_output: '{sanitized_output}', log_output: '{sanitized_logs}'")
            sanitized_response = sanitize_debug_data(str(response))
            logger.debug(f"Final response: '{sanitized_response}', response type: {type(response)}")

            cli.do_command(params, 'sync-down')
            
            # Always let the parser handle the response (including empty responses and logs)
            response = parse_keeper_response(command, response, log_output)
            
            status_code = 200
            if isinstance(response, dict) and response.get("status") == "error":
                status_code = 400
            
            response = CommandExecutor.encrypt_response(response)
            logger.debug(f"Command executed successfully")
            return response, status_code
        except CommandExecutionError as e:
            # Return the actual command error instead of generic "server busy"
            logger.error(f"Command execution error: {e}")
            error_response = {
                "status": "error",
                "error": str(e)
            }
            return error_response, 400
        except Exception as e:
            # Log unexpected errors and return a proper error response
            logger.error(f"Unexpected error during command execution: {e}")
            error_response = {
                "status": "error",
                "error": f"Unexpected error: {str(e)}"
            }
            return error_response, 500