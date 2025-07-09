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
import logging

from ..commands.base import GroupCommand

# Import structured commands
from .commands.register import BiometricRegisterCommand
from .commands.list import BiometricListCommand
from .commands.unregister import BiometricUnregisterCommand
from .commands.verify import BiometricVerifyCommand

# Import core functionality
from .core.client import BiometricClient
from .core.detector import BiometricDetector
from .utils.constants import FIDO2_WARNING_MESSAGE

# Global state for warning display
_warned_on_fido_package = False

def display_fido2_warning():
    """Display FIDO2 package warning once"""
    global _warned_on_fido_package
    if not _warned_on_fido_package:
        logging.warning(FIDO2_WARNING_MESSAGE)
        _warned_on_fido_package = True

def check_biometric_previously_used(username):
    """Check if biometric authentication was previously used for this user"""
    try:
        detector = BiometricDetector()
        handler = detector.get_platform_handler()
        return handler.get_biometric_flag(username)
    except Exception:
        return False


class BiometricCommand(GroupCommand):
    """Main biometric command group"""
    
    def __init__(self):
        super().__init__()
        self.register_command('register', BiometricRegisterCommand(), 'Add biometric authentication method')
        self.register_command('list', BiometricListCommand(), 'List biometric authentication methods')
        self.register_command('unregister', BiometricUnregisterCommand(), 'Disable biometric authentication for this user')
        self.register_command('verify', BiometricVerifyCommand(), 'Verify biometric authentication with existing credentials')


# Export everything for backward compatibility
__all__ = [
    'BiometricCommand',
    'BiometricRegisterCommand',
    'BiometricListCommand', 
    'BiometricUnregisterCommand',
    'BiometricVerifyCommand',
    'BiometricClient',
    'BiometricDetector',
    'check_biometric_previously_used',
    'display_fido2_warning'
]
