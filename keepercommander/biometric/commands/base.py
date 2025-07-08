from abc import ABC, abstractmethod
import argparse
import platform

from ...commands.base import Command
from ...error import CommandError
from ..core.client import BiometricClient
from ..core.detector import BiometricDetector

# Import FIDO2 availability check
try:
    from fido2.client import ClientError
    from fido2.ctap import CtapError
    from fido2.webauthn import (
        PublicKeyCredentialRequestOptions, 
        AuthenticationResponse,
        PublicKeyCredentialCreationOptions, 
        RegistrationResponse,
        UserVerificationRequirement
    )
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False


class BiometricCommand(Command):
    """Base class for biometric commands"""

    def __init__(self):
        super().__init__()
        self.client = BiometricClient()
        self.detector = BiometricDetector()

    def _get_default_credential_name(self) -> str:
        """Generate default credential name"""
        system = platform.system()
        hostname = platform.node() or 'Unknown'

        names = {
            'Windows': f"Windows Hello - {hostname}",
            'Darwin': f"Touch ID - {hostname}",
        }

        return names.get(system, f"Biometric - {hostname}")

    def _check_platform_support(self, force: bool = False):
        """Check if platform supports biometric authentication"""
        if not FIDO2_AVAILABLE:
            raise CommandError(self.__class__.__name__, 
                             'FIDO2 library not available. Please install: pip install fido2')

        supported, message = self.detector.detect_platform_capabilities()

        if not supported and not force:
            raise CommandError(self.__class__.__name__,
                             f'Biometric authentication not supported: {message}')

        return supported, message

    def _check_biometric_flag(self, username: str) -> bool:
        """Check if biometric authentication is enabled for user"""
        try:
            handler = self.detector.get_platform_handler()
            return handler.get_biometric_flag(username)
        except Exception:
            return False

    def _set_biometric_flag(self, username: str, enabled: bool) -> bool:
        """Set biometric authentication flag for user"""
        try:
            handler = self.detector.get_platform_handler()
            return handler.set_biometric_flag(username, enabled)
        except Exception:
            return False

    def _delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric authentication flag for user"""
        try:
            handler = self.detector.get_platform_handler()
            return handler.delete_biometric_flag(username)
        except Exception:
            return False 