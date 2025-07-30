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

from ..commands.base import GroupCommand

from .commands.register import BiometricRegisterCommand
from .commands.list import BiometricListCommand
from .commands.unregister import BiometricUnregisterCommand
from .commands.verify import BiometricVerifyCommand
from .commands.update_name import BiometricUpdateNameCommand

from .client import BiometricClient
from .platforms.detector import BiometricDetector

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
        self.register_command('update-name', BiometricUpdateNameCommand(), 'Update friendly name of a biometric passkey')

__all__ = [
    'BiometricCommand',
    'BiometricRegisterCommand',
    'BiometricListCommand', 
    'BiometricUnregisterCommand',
    'BiometricVerifyCommand',
    'BiometricClient',
    'BiometricDetector',
    'check_biometric_previously_used',
]
