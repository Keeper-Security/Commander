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

from typing import Optional, Tuple, Dict, Any
from flask import request, jsonify
from html import escape
from ..decorators.logging import logger


class RequestValidator:
    """Shared validation utilities for API requests."""
    
    @staticmethod
    def validate_and_escape_command(request_data: Dict[str, Any]) -> Tuple[Optional[str], Optional[Tuple]]:
        """Validate and escape command from request data.
        
        Args:
            request_data: The request JSON data
            
        Returns:
            Tuple of (escaped_command, error_response) where error_response is None on success
        """
        if not request_data:
            logger.info("Request validation failed: No JSON data provided")
            return None, (jsonify({"success": False, "error": "Error: No JSON data provided"}), 400)
        
        command = request_data.get("command")
        if not command:
            logger.info("Request validation failed: No command provided")
            return None, (jsonify({"success": False, "error": "Error: No command provided"}), 400)
        
        if not isinstance(command, str):
            logger.warning("Request validation failed: Command must be a string")
            return None, (jsonify({"success": False, "error": "Error: Command must be a string"}), 400)
            
        # Escape HTML to prevent XSS
        escaped_command = escape(command)
        logger.debug(f"Command validated and escaped: {escaped_command}")
        return escaped_command, None
    
    @staticmethod
    def validate_request_json() -> Optional[Tuple]:
        """Validate that request contains valid JSON.
        
        Returns:
            Error response tuple if validation fails, None if valid
        """
        if not request.is_json:
            logger.info("Request validation failed: Content-Type must be application/json")
            return jsonify({"success": False, "error": "Error: Content-Type must be application/json"}), 400
        
        if not request.json:
            logger.info("Request validation failed: Invalid or empty JSON")
            return jsonify({"success": False, "error": "Error: Invalid or empty JSON"}), 400
        
        return None
