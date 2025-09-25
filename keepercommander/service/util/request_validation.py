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
import tempfile
import os
import json
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
            return None, (jsonify({"status": "error", "error": "No JSON data provided"}), 400)
        
        command = request_data.get("command")
        if not command:
            logger.info("Request validation failed: Missing required field 'command' or incorrect field name")
            return None, (jsonify({"status": "error", "error": "Missing required field \"command\" or incorrect field name"}), 400)
        
        if not isinstance(command, str):
            logger.warning("Request validation failed: Command must be a string")
            return None, (jsonify({"status": "error", "error": "Command must be a string"}), 400)
            
        # Escape HTML to prevent XSS
        escaped_command = escape(command)
        logger.debug(f"Command validated and escaped: {escaped_command}")
        return escaped_command, None
    
    @staticmethod
    def process_file_data(request_data: Dict[str, Any], command: str) -> Tuple[str, list]:
        """Process filedata in request and create temporary files, substituting FILEDATA placeholders.
        
        Args:
            request_data: The request JSON data
            command: The command string to process
            
        Returns:
            Tuple of (processed_command, temp_file_paths)
        """
        import re
        temp_files = []
        processed_command = command
        
        # Check if command contains FILEDATA placeholder and request has filedata
        if "FILEDATA" in command and "filedata" in request_data:
            filedata = request_data.get("filedata")
            if not isinstance(filedata, dict):
                logger.warning("filedata must be a JSON object")
                return processed_command, temp_files
            
            try:
                # Create temporary file with the filedata content
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as temp_file:
                    json.dump(filedata, temp_file, indent=2)
                    temp_file_path = temp_file.name
                    temp_files.append(temp_file_path)
                    
                    # Replace FILEDATA placeholder with temporary file path, but only when it's used as a file parameter
                    # Supports: PAM import (--filename), Import (positional), Enterprise-push (positional)
                    file_param_pattern = r'(--filename[=\s]+["\']?)FILEDATA(["\']?)'
                    processed_command = re.sub(file_param_pattern, f'\\1{temp_file_path}\\2', processed_command)
                    
                    # Also handle standalone FILEDATA (not in quotes)
                    standalone_pattern = r'\bFILEDATA\b(?!["\'])'
                    processed_command = re.sub(standalone_pattern, temp_file_path, processed_command)
                    
                    logger.debug(f"Created temporary file {temp_file_path} for filedata")
                    
            except Exception as e:
                logger.error(f"Error creating temporary file for filedata: {e}")
                # Clean up any created temp files
                for temp_path in temp_files:
                    try:
                        os.unlink(temp_path)
                    except Exception:
                        pass
                return command, []
        
        return processed_command, temp_files
    
    @staticmethod
    def cleanup_temp_files(temp_files: list) -> None:
        """Clean up temporary files.
        
        Args:
            temp_files: List of temporary file paths to clean up
        """
        for temp_path in temp_files:
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                    logger.debug(f"Cleaned up temporary file: {temp_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary file {temp_path}: {e}")
    
    @staticmethod
    def validate_request_json() -> Optional[Tuple]:
        """Validate that request contains valid JSON.
        
        Returns:
            Error response tuple if validation fails, None if valid
        """
        if not request.is_json:
            logger.info("Request validation failed: Content-Type must be application/json")
            return jsonify({"status": "error", "error": "Content-Type must be application/json"}), 400
        
        if not request.json:
            logger.info("Request validation failed: Invalid or empty JSON")
            return jsonify({"status": "error", "error": "Invalid or empty JSON"}), 400
        
        return None
