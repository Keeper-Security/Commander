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

import logging

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


def sync_biometric_passkey_status(params):
    """Enable subsequent passkey login from account state after a successful login.

    The flag is not a credential ID: an existing roaming passkey can be used
    without registering a new credential on this device. Keep cached state on
    network/storage failures, and retry device data-key registration next login.
    """
    try:
        client = BiometricClient()
        if not client.platform_handler:
            return
        storage = client.platform_handler.storage_handler
        if not client.get_available_credentials(params):
            storage.delete_biometric_flag(params.user)
            return

        from ..loginv3 import LoginV3API
        # Idempotent, including devices with a legacy registration flag but no
        # encrypted data key. Do not enable a new flag until this succeeds.
        LoginV3API.register_encrypted_data_key_for_device(params)
        if not storage.store_biometric_flag(params.user):
            logging.debug("Failed to cache account passkey availability for %s", params.user)
    except Exception as e:
        # This optional sync must never turn a successful login into a failure.
        logging.debug("Sync biometric passkey status: %s", e)


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
    'sync_biometric_passkey_status',
]
