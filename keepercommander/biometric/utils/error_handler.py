#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Centralized error handling utilities for biometric authentication
"""
import logging

from ...error import CommandError
from .constants import ERROR_MESSAGES

class BiometricErrorHandler:
    """Centralized error handling for biometric operations"""
    
    @staticmethod
    def handle_authentication_error(error: Exception, platform_name: str = "Biometric") -> Exception:
        """Handle authentication errors with consistent messaging"""
        error_msg = str(error).lower()
        error_str = str(error)
        
        if any(keyword in error_msg for keyword in ["cancelled", "denied"]):
            return Exception(f"{platform_name} authentication cancelled")
        elif "timeout" in error_msg:
            return Exception(f"{platform_name} authentication timed out")
        elif "not available" in error_msg:
            return Exception(f"{platform_name} is not available or not set up")
        elif any(phrase in error_msg for phrase in ["no identities are enrolled", "biometry is not enrolled", "not enrolled", "biometric not set up", "touch id not set up"]):
            return Exception(f"{platform_name} is not set up - please enroll your biometric credentials in system settings")
        elif "parameter is incorrect" in error_msg:
            return Exception(f"{platform_name} parameter error - please check your biometric setup")
        elif any(phrase in error_msg for phrase in ["not configured", "not enabled", "unavailable", "not supported"]):
            return Exception(f"{platform_name} is not available or not configured")
        elif "no matching credential found" in error_msg:
            return Exception(ERROR_MESSAGES['no_matching_credential'])
        else:
            if "error domain=" in error_msg or "code=" in error_msg:
                if "localizeddescription=" in error_msg:
                    desc_start = error_msg.find("localizeddescription=") + len("localizeddescription=")
                    desc_end = error_msg.find("}", desc_start)
                    if desc_end == -1:
                        desc_end = len(error_msg)
                    description = error_str[desc_start:desc_end].strip()
                    return Exception(f"{platform_name} error: {description}")
            
            return Exception(f"{platform_name} authentication failed: {error_str}")

    @staticmethod
    def handle_credential_creation_error(error: Exception, platform_name: str = "Biometric") -> Exception:
        """Handle credential creation errors with consistent messaging"""
        error_msg = str(error).lower()
        error_str = str(error)
        
        if any(keyword in error_msg for keyword in ["cancelled", "denied"]):
            return Exception(f"{platform_name} registration cancelled")
        elif ("object already exists" in error_msg or 
            ("oserror" in error_msg and "22" in error_msg and "object already exists" in error_msg)):
            return Exception(f"A biometric credential for this account already exists")
        elif "timeout" in error_msg:
            return Exception(f"{platform_name} registration timed out")
        elif "not available" in error_msg:
            return Exception(f"{platform_name} is not available or not set up")
        elif any(phrase in error_msg for phrase in ["no identities are enrolled", "biometry is not enrolled", "not enrolled", "biometric not set up", "touch id not set up"]):
            return Exception(f"{platform_name} is not set up - please enroll your biometric credentials in system settings")
        elif any(phrase in error_msg for phrase in ["not configured", "not enabled", "unavailable", "not supported"]):
            return Exception(f"{platform_name} is not available or not configured")
        else:
            if "error domain=" in error_msg or "code=" in error_msg:
                if "localizeddescription=" in error_msg:
                    desc_start = error_msg.find("localizeddescription=") + len("localizeddescription=")
                    desc_end = error_msg.find("}", desc_start)
                    if desc_end == -1:
                        desc_end = len(error_msg)
                    description = error_str[desc_start:desc_end].strip()
                    return Exception(f"{platform_name} error: {description}")
            
            return Exception(f"{platform_name} registration failed: {error_str}")

    @staticmethod
    def handle_command_error(command_name: str, operation: str, error: Exception):
        """Handle command errors with clean error messages"""
        raise CommandError(None, str(error))

    @staticmethod
    def handle_keyboard_interrupt(command_name: str, operation: str):
        """Handle keyboard interrupt with clean error messages"""
        raise CommandError(None, f'{operation} cancelled by user')

    @staticmethod
    def create_platform_error(platform_name: str, error_key: str, additional_info: str = "") -> str:
        """Create platform-specific error message"""
        base_message = ERROR_MESSAGES.get(error_key, f"Unknown error in {platform_name}")
        if additional_info:
            return f"{base_message}: {additional_info}"
        return base_message

    @staticmethod
    def validate_dependencies(required_modules: list, platform_name: str = "Platform") -> None:
        """Validate that required modules are available"""
        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            raise Exception(f"Required {platform_name} dependencies not available: {', '.join(missing_modules)}")

    @staticmethod
    def create_storage_error(operation: str, platform_name: str, error: Exception) -> None:
        """Log storage operation errors consistently"""
        logging.debug(f'Failed to {operation} {platform_name} biometric flag: {error}')

    @staticmethod
    def execute_with_error_handling(command_name: str, operation: str, func, *args, **kwargs):
        """Execute a function with consistent error handling"""
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            BiometricErrorHandler.handle_keyboard_interrupt(command_name, operation)
        except Exception as e:
            BiometricErrorHandler.handle_command_error(command_name, operation, e) 