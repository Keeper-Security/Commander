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

from abc import ABC, abstractmethod
import argparse
import platform

from ...commands.base import Command
from ...error import CommandError
from ..client import BiometricClient
from ..platforms.detector import BiometricDetector
from ..utils.constants import (
    FIDO2_AVAILABLE, 
    ERROR_MESSAGES, 
    CREDENTIAL_NAME_TEMPLATES,
)
from ..utils.error_handler import BiometricErrorHandler


class BiometricCommand(Command):
    """Base class for biometric commands with common functionality"""

    def __init__(self):
        super().__init__()
        self.client = BiometricClient()
        self.detector = BiometricDetector()

    def _get_default_credential_name(self) -> str:
        """Generate default credential name"""
        system = platform.system()
        hostname = platform.node() or 'Unknown'
        
        template = CREDENTIAL_NAME_TEMPLATES.get(system, CREDENTIAL_NAME_TEMPLATES['default'])
        return template.format(hostname=hostname)[:31]

    def _check_platform_support(self, force: bool = False):
        """Check if platform supports biometric authentication"""
        if not FIDO2_AVAILABLE:
            raise CommandError(None, ERROR_MESSAGES['no_fido2'])

        supported, message = self.detector.detect_platform_capabilities()

        if not supported and not force:
            raise CommandError(None, f'{ERROR_MESSAGES["platform_not_supported"]}: {message}')

        return supported, message

    def _check_biometric_flag(self, username: str) -> bool:
        """Check if biometric authentication is enabled for user"""
        try:
            handler = self.detector.get_platform_handler()
            return handler.get_biometric_flag(username)
        except Exception:
            return False

    def _delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric authentication flag for user"""
        try:
            handler = self.detector.get_platform_handler()
            return handler.delete_biometric_flag(username)
        except Exception:
            return False

    def _get_available_credentials_or_error(self, params):
        """Get available credentials with consistent error handling"""
        try:
            credentials = self.client.get_available_credentials(params)
            if not credentials:
                raise CommandError(None, ERROR_MESSAGES['no_credentials'])
            return credentials
        except Exception as e:
            raise CommandError(None, str(e))

    def _execute_with_error_handling(self, operation: str, func, *args, **kwargs):
        """Execute a function with consistent error handling"""
        return BiometricErrorHandler.execute_with_error_handling(
            self.__class__.__name__, operation, func, *args, **kwargs
        ) 