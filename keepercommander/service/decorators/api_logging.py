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

from functools import wraps
from typing import Callable, Any
from flask import request
import time
import re
from .logging import logger

def sanitize_password_in_command(data):
    """Sanitize password values in command string and filedata"""
    if not data:
        return data
    
    sanitized = data.copy()
    
    # Sanitize command string if present
    if 'command' in sanitized:
        command = sanitized['command']
        # Pattern to match password=value (with or without quotes)
        password_pattern = r"password=(['\"]?)([^'\"\s]{1,1024})\1"
        sanitized['command'] = re.sub(password_pattern, r"password=\1***\1", command)
    
    # Sanitize filedata if present
    if 'filedata' in sanitized:
        sanitized['filedata'] = _sanitize_nested_data(sanitized['filedata'])
    
    return sanitized

def _sanitize_nested_data(data):
    """Recursively sanitize nested data structures"""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Sanitize sensitive field names
            if key.lower() in ['password', 'login', 'secret', 'token', 'key']:
                if isinstance(value, str) and len(value) > 0:
                    sanitized[key] = '*' * min(len(value), 15)
                else:
                    sanitized[key] = '***'
            else:
                sanitized[key] = _sanitize_nested_data(value)
        return sanitized
    elif isinstance(data, list):
        return [_sanitize_nested_data(item) for item in data]
    elif isinstance(data, str):
        # Sanitize email addresses in string values to protect PII
        import re
        sanitized_str = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***', data)
        return sanitized_str
    else:
        return data

def _get_sanitized_request_data():
    """Extract and sanitize request data for logging (only for JSON POST requests)"""
    sanitized_data = None
    if request.method == 'POST' and request.content_type and 'application/json' in request.content_type:
        try:
            json_data = request.get_json(silent=True)
            sanitized_data = sanitize_password_in_command(json_data)
        except Exception:
            sanitized_data = None
    return f"data={sanitized_data}" if sanitized_data else "no-data"

def api_log_handler(fn: Callable) -> Callable:
    """Log API request information in a single line with color-coded status"""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip is None:
            ip = request.remote_addr
            
        start_time = time.time()
        try:
            result = fn(*args, **kwargs)
            duration = time.time() - start_time
            
            status_code = result[1] if isinstance(result, tuple) else 200
            
            # Color code based on status
            if status_code < 200:
                status_color = "\033[94m"  # Blue for informational
            elif status_code < 300:
                status_color = "\033[92m"  # Green for success
            elif status_code < 400:
                status_color = "\033[96m"  # Cyan for redirection
            elif status_code < 500:
                status_color = "\033[91m"  # Red for client errors
            else:
                status_color = "\033[93m"  # Yellow for server errors
            
            # Sanitize request data to hide passwords (only for JSON requests)
            data_str = _get_sanitized_request_data()
            
            log_parts = [
                f"\033[94m{request.method}\033[0m",  # Blue method
                f"\033[96m{request.path}\033[0m",    # Cyan path
                f"\033[95m{ip}\033[0m",              # Magenta IP
                data_str,
                str(status_code),
                f"{duration:.2f}s"
            ]
            
            logger.info(" | ".join(log_parts))
            return result
            
        except Exception as ex:
            duration = time.time() - start_time
            
            # Sanitize request data for error logs too (only for JSON requests)
            data_str = _get_sanitized_request_data()
            
            log_parts = [
                request.method,
                request.path,
                ip,
                data_str,
                "500",
                f"{duration:.2f}s",
                f"error='{str(ex)}'"
            ]
            logger.error(" | ".join(log_parts))
            raise
            
    return wrapper