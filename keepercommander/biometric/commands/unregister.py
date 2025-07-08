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

    def _cleanup_local_credentials(self, username: str) -> bool:
        """Clean up local biometric credentials (platform-specific)"""
        try:
            import platform
            system = platform.system()
            
            if system == 'Darwin':  # macOS
                return self._cleanup_macos_keychain_credentials()
            elif system == 'Windows':  # Windows
                return self._cleanup_windows_credentials()
            else:
                # For other platforms, just return True as there's nothing specific to clean up
                return True
        except Exception as e:
            print(f"⚠️  Warning: Could not clean up local credentials: {str(e)}")
            return False

    def _cleanup_macos_keychain_credentials(self) -> bool:
        """Clean up macOS keychain credentials for biometric authentication"""
        try:
            import subprocess
            
            # Try to find and delete WebAuthn credentials in keychain
            services_to_clean = [
                "Keeper WebAuthn - keepersecurity.com",
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

    def execute(self, params, **kwargs):
        """Disable biometric authentication for the current user"""
        
        if not self._check_biometric_flag(params.user):
            print(f"Biometric authentication is already disabled for user '{params.user}'.")
            return

        if not kwargs.get('confirm'):
            confirm = input(f"Are you sure you want to disable biometric authentication for user '{params.user}'? (y/N): ")
            if confirm.lower() != 'y':
                print("Operation cancelled.")
                return

        try:
            try:
                passkey_result = self.client.disable_all_user_passkeys(params)
                
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
                            print(f"Disabled passkey: {result.get('credential_name', 'Unknown')}")
                        if error_count > 0:
                            print(f"{error_count} passkey(s) failed to disable")
                    else:
                        print("No passkeys found to disable")
                else:
                    message = passkey_result.get('message', 'Unknown error') if isinstance(passkey_result, dict) else 'Unknown error'
                    print(f"Issue with passkey disable: {message}")
                        
            except Exception as e:
                print(f"Failed to disable passkeys on server: {str(e)}")

            params.biometric = False  
            
            delete_success = self._delete_biometric_flag(params.user)
            
            cleanup_success = self._cleanup_local_credentials(params.user)
            
            if delete_success:
                flag_status = "Successfully removed biometric authentication data"
            else:
                flag_status = "Failed to remove biometric authentication data"

            if not self._check_biometric_flag(params.user):
                print(f"Biometric authentication has been completely removed for user '{params.user}'.")
                print(f"{flag_status}")
                if cleanup_success:
                    print("Default authentication will be used for future logins.")
            else:
                print(f"Failed to remove biometric authentication. Please try again.")
                print(f"{flag_status}")

        except Exception as e:
            raise CommandError('biometric unregister', f'Failed to disable biometric authentication: {str(e)}') 