import argparse
import platform
import subprocess

from .base import BiometricCommand
from ..utils.constants import SUCCESS_MESSAGES, MACOS_KEYCHAIN_SERVICE_PREFIX


class BiometricUnregisterCommand(BiometricCommand):
    """Unregister biometric authentication"""

    parser = argparse.ArgumentParser(prog='biometric unregister', description='Disable biometric authentication for this user')
    parser.add_argument('--confirm', dest='confirm', action='store_true',
                       help='Skip confirmation prompt')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """Disable biometric authentication for the current user"""
        def _unregister():
            # Check if biometric is already disabled
            if not self._check_biometric_flag(params.user):
                print(f"Biometric authentication is already disabled for user '{params.user}'.")
                return

            # Get confirmation if not provided
            if not kwargs.get('confirm') and not self._get_user_confirmation(params.user):
                print("Operation cancelled.")
                return

            # Disable passkeys on server
            self._disable_server_passkeys(params)

            # Clean up local storage
            params.biometric = False
            delete_success = self._delete_biometric_flag(params.user)
            cleanup_success = self._cleanup_local_credentials(params.user)

            # Report results
            self._report_unregister_results(params.user, delete_success, cleanup_success)

        return self._execute_with_error_handling('disable biometric authentication', _unregister)

    def _get_user_confirmation(self, username: str) -> bool:
        """Get user confirmation for unregistering biometric authentication"""
        confirm = input(f"Are you sure you want to disable biometric authentication for user '{username}'? (y/n): ")
        return confirm.lower() == 'y'

    def _disable_server_passkeys(self, params):
        """Disable passkeys on the server"""
        try:
            passkey_result = self.client.disable_all_user_passkeys(params)
            self._process_passkey_results(passkey_result)
                        
        except Exception as e:
            print(f"Failed to disable passkeys on server: {str(e)}")

    def _process_passkey_results(self, passkey_result):
        """Process and display passkey disable results"""
        if isinstance(passkey_result, dict) and passkey_result.get('status') == 'SUCCESS':
            if 'results' in passkey_result:
                success_count = 0
                error_count = 0
                
                for result in passkey_result['results']:
                    if isinstance(result, dict):
                        if result.get('status') == 'SUCCESS':
                            success_count += 1
                        else:
                            error_count += 1
                            print(f"Failed to disable passkey '{result.get('credential_name', 'Unknown')}': {result.get('message', 'Unknown error')}")
                
                if success_count > 0:
                    credential_name = result.get('credential_name', 'Unknown') if isinstance(result, dict) else 'Unknown'
                    print(f"Disabled passkey: {credential_name}")
                if error_count > 0:
                    print(f"{error_count} passkey(s) failed to disable")
            else:
                print("No passkeys found to disable")
        else:
            message = passkey_result.get('message', 'Unknown error') if isinstance(passkey_result, dict) else 'Unknown error'
            print(f"Issue with passkey disable: {message}")

    def _cleanup_local_credentials(self, username: str) -> bool:
        """Clean up local biometric credentials (platform-specific)"""
        try:
            system = platform.system()
            
            if system == 'Darwin':  # macOS
                return self._cleanup_macos_keychain_credentials()
            elif system == 'Windows':  # Windows
                return self._cleanup_windows_credentials()
            else:
                # For other platforms, just return True as there's nothing specific to clean up
                return True
        except Exception as e:
            print(f"Warning: Could not clean up local credentials: {str(e)}")
            return False

    def _cleanup_macos_keychain_credentials(self) -> bool:
        """Clean up macOS keychain credentials for biometric authentication"""
        try:
            # Try to find and delete WebAuthn credentials in keychain
            services_to_clean = [
                f"{MACOS_KEYCHAIN_SERVICE_PREFIX} - keepersecurity.com",
                "Keeper Biometric Authentication"
            ]
            
            deleted_count = 0
            for service_name in services_to_clean:
                try:
                    result = subprocess.run([
                        'security', 'find-internet-password',
                        '-s', service_name,
                        '-g'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        delete_result = subprocess.run([
                            'security', 'delete-internet-password',
                            '-s', service_name
                        ], capture_output=True, text=True, timeout=10)
                        
                        if delete_result.returncode == 0:
                            deleted_count += 1
                except Exception:
                    continue
            
            return True  
        except Exception:
            return False

    def _cleanup_windows_credentials(self) -> bool:
        """Clean up Windows credentials for biometric authentication"""
        try:
            return True
        except Exception:
            return False

    def _report_unregister_results(self, username: str, delete_success: bool, cleanup_success: bool):
        """Report the results of the unregister operation"""
        flag_status = ("Successfully removed biometric authentication data" if delete_success
                      else "Failed to remove biometric authentication data")

        if not self._check_biometric_flag(username):
            print(SUCCESS_MESSAGES['unregistration_complete'] + f" for user '{username}'.")
            print(f"{flag_status}")
            if cleanup_success:
                print("Default authentication will be used for future logins.")
        else:
            print(f"Failed to remove biometric authentication. Please try again.")
            print(f"{flag_status}") 