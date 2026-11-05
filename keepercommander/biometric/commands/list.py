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

import argparse

from .base import BiometricCommand
from ..utils.aaguid import get_provider_name_from_aaguid


class BiometricListCommand(BiometricCommand):
    """List biometric authentication methods"""

    parser = argparse.ArgumentParser(prog='biometric list', description='List biometric authentication methods')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """List registered biometric methods"""
        def _list():
            passkeys = self.client.get_available_credentials(params)
            self._display_credentials(passkeys)

        return self._execute_with_error_handling('list biometric methods', _list)

    def _display_credentials(self, passkeys):
        """Display credentials in table format"""
        if not passkeys:
            print("No biometric authentication methods found.")
        else:
            print("\nRegistered Biometric Authentication Methods:")
            print("-" * 70)
            for passkey in passkeys:
                created_date = self._format_timestamp(passkey.get('created'))
                last_used_date = self._format_timestamp(passkey.get('last_used'))
                
                # Match Manage Passkeys in Web Vault: the device name comes
                # from AAGUID metadata, not the user-supplied friendlyName.
                display_name = get_provider_name_from_aaguid(passkey.get('aaguid'))
                print(f"Name: {display_name}")
                if passkey.get('name'):
                    print(f"Friendly Name: {passkey['name']}")
                print(f"Created: {created_date}")
                print(f"Last Used: {last_used_date}")
                print("-" * 70)
