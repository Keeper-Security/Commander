#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

# This file provides backward compatibility with the new structured biometric system
# The actual implementation has been moved to the structured modules under:
# - core/ (base classes, client, detector)
# - commands/ (command implementations)  
# - platforms/ (platform-specific handlers)

import logging

# Import the new structured implementations
from .commands.register import BiometricRegisterCommand
from .commands.list import BiometricListCommand
from .commands.unregister import BiometricUnregisterCommand
from .commands.verify import BiometricVerifyCommand
from .core.base import BiometricInteraction
from .core.detector import BiometricDetector
from .core.client import verify_rp_id_none
from ..commands.base import GroupCommand

# FIDO2 availability check for backward compatibility
try:
    from fido2.client import ClientError, DefaultClientDataCollector, UserInteraction, WebAuthnClient
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


def check_biometric_previously_used(username):
    """Check if biometric authentication was previously used for this user (backward compatibility)"""
    try:
        detector = BiometricDetector()
        handler = detector.get_platform_handler()
        return handler.get_biometric_flag(username)
    except Exception:
        return False


class PlatformBiometricDetector:
    """Detect and validate biometric capabilities across platforms (backward compatibility)"""
    
    @staticmethod
    def detect_platform_biometric():
        """Detect biometric capabilities for the current platform"""
        detector = BiometricDetector()
        return detector.detect_platform_capabilities()


class BiometricCommand(GroupCommand):
    """Main biometric command group"""
    
    def __init__(self):
        super().__init__()
        self.register_command('register', BiometricRegisterCommand(), 'Add biometric authentication method')
        self.register_command('list', BiometricListCommand(), 'List biometric authentication methods')
        self.register_command('unregister', BiometricUnregisterCommand(), 'Disable biometric authentication for this user')
        self.register_command('verify', BiometricVerifyCommand(), 'Verify biometric authentication with existing credentials') 