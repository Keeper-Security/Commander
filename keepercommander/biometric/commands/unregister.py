import argparse

from .base import BiometricCommand
from ...error import CommandError


class BiometricUnregisterCommand(BiometricCommand):
    """Unregister biometric authentication"""

    parser = argparse.ArgumentParser(prog='biometric unregister', description='Disable biometric authentication for this user')
    parser.add_argument('--confirm', dest='confirm', action='store_true',
                       help='Skip confirmation prompt')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """Disable biometric authentication for the current user"""
        
        if not self._check_biometric_flag(params.user):
            print(f"💡 Biometric authentication is already disabled for user '{params.user}'.")
            return

        if not kwargs.get('confirm'):
            confirm = input(f"Are you sure you want to disable biometric authentication for user '{params.user}'? (y/N): ")
            if confirm.lower() != 'y':
                print("Operation cancelled.")
                return

        try:
            success = self._set_biometric_flag(params.user, False)
            
            if success:
                flag_status = "Successfully unregistered biometric authentication"
            else:
                flag_status = "Failed to unregister biometric authentication"

            # Verify the flag was set correctly
            if not self._check_biometric_flag(params.user):
                print(f"✅ Biometric authentication has been disabled for user '{params.user}'.")
                print("Password authentication will be used for future logins.")
                print(f"{flag_status}")
            else:
                print(f"❌ Failed to disable biometric authentication. Please try again.")
                print(f"{flag_status}")

        except Exception as e:
            raise CommandError('biometric unregister', f'Failed to disable biometric authentication: {str(e)}') 