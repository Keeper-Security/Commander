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

# Import new structured commands
from .commands.register import BiometricRegisterCommand
from .commands.list import BiometricListCommand
from .commands.unregister import BiometricUnregisterCommand
from .commands.verify import BiometricVerifyCommand

# Import core functionality
from .core.client import BiometricClient
from .core.detector import BiometricDetector

warned_on_fido_package = False
install_fido_package_warning = """
    You can use Security Key with Commander:
    Upgrade your Python interpreter to 3.10 or newer
    and make sure fido2 package is 2.0.0 or newer
"""

def display_fido2_warning():
    global warned_on_fido_package

    if not warned_on_fido_package:
        logging.warning(install_fido_package_warning)
    warned_on_fido_package = True

# Export backward compatibility functions
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
    'check_biometric_previously_used'
]
