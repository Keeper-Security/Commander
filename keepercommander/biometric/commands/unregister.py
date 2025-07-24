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
import platform
import subprocess
from typing import Optional
import os

from .base import BiometricCommand
from ..utils.constants import (
    SUCCESS_MESSAGES, MACOS_KEYCHAIN_SERVICE_PREFIX,
    STATUS_SUCCESS, STATUS_NOT_FOUND, STATUS_ERROR, PLATFORM_DARWIN, PLATFORM_WINDOWS
)


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
                print("Operation cancelled by user")
                return

            # Get RP ID from server before disabling (needed for cleanup)
            rp_id = self._get_rp_id_from_server(params)

            # Disable passkeys on server
            self._disable_server_passkeys(params)

            # Clean up local storage
            params.biometric = False
            cleanup_success = self._cleanup_local_credentials(params.user, rp_id)
            delete_success = self._delete_biometric_flag(params.user)  

            # Verify that the biometric flag was actually cleared
            verification_success = not self._check_biometric_flag(params.user)
            
            # If deletion reported success but verification failed, try again
            if delete_success and not verification_success:
                delete_success = self._delete_biometric_flag(params.user)
                verification_success = not self._check_biometric_flag(params.user)

            # Report results
            self._report_unregister_results(params.user, delete_success and verification_success, cleanup_success)

        return self._execute_with_error_handling('disable biometric authentication', _unregister)

    def _get_user_confirmation(self, username: str) -> bool:
        """Get user confirmation for unregistering biometric authentication"""
        confirm = input(f"Are you sure you want to disable biometric authentication for user '{username}'? (y/n): ")
        return confirm.lower() == 'y'

    def _get_rp_id_from_server(self, params) -> Optional[str]:
        """Get RP ID from server authentication options"""
        try:
            # Generate authentication options to get RP ID from server response
            auth_options = self.client.generate_authentication_options(params, 'login')
            
            # Extract RP ID from the request options
            request_options = auth_options['request_options']
            pk_options = request_options.get('publicKeyCredentialRequestOptions', request_options)
            rp_id = pk_options.get('rpId')
            
            if not rp_id:
                print("Warning: Could not get RP ID from server - using limited cleanup")
                return None
                
            return rp_id
        except Exception as e:
            print(f"Warning: Could not get RP ID from server ({str(e)}) - using limited cleanup")
            return None

    def _disable_server_passkeys(self, params):
        """Disable the specific passkey stored for this device"""
        try:
            # Get the stored credential ID for this device
            stored_credential_id = self._get_stored_credential_id(params.user)
            
            if stored_credential_id:
                # Find and disable only the specific passkey for this device
                passkey_result = self._disable_specific_passkey(params, stored_credential_id)
                self._process_specific_passkey_result(passkey_result, stored_credential_id)
            else:
                print("Warning: No stored credential ID found for this device.")
                print("This could mean:")
                print("  - The credential was already removed")
                print("  - Registration was incomplete")
                print("")
                print("No passkeys will be disabled on the server.")
                        
        except Exception as e:
            print(f"Failed to disable passkey on server: {str(e)}")

    def _get_stored_credential_id(self, username: str) -> Optional[str]:
        """Get the stored credential ID for this device"""
        try:
            platform_handler = self.client.platform_handler
            if platform_handler and hasattr(platform_handler, 'storage_handler'):
                storage_handler = getattr(platform_handler, 'storage_handler')
                if storage_handler and hasattr(storage_handler, 'get_credential_id'):
                    return storage_handler.get_credential_id(username)
        except Exception as e:
            print(f"Warning: Could not retrieve stored credential ID: {str(e)}")
        return None

    def _disable_specific_passkey(self, params, credential_id: str):
        """Disable a specific passkey by credential ID"""
        try:
            # Get list of available credentials to find the matching passkey
            available_credentials = self.client.get_available_credentials(params)
            
            # Find the passkey with matching credential ID
            target_passkey = None
            for credential in available_credentials:
                # Convert stored credential ID to bytes for comparison if needed
                stored_cred_id_bytes = credential.get('credential_id')
                if isinstance(stored_cred_id_bytes, bytes):
                    # Compare base64url encoded versions
                    from ... import utils
                    stored_cred_id_b64 = utils.base64_url_encode(stored_cred_id_bytes)
                    if stored_cred_id_b64 == credential_id or credential_id == stored_cred_id_bytes:
                        target_passkey = credential
                        break
                elif credential_id == stored_cred_id_bytes:
                    target_passkey = credential
                    break
            
            if target_passkey:
                # Disable the specific passkey
                result = self.client.disable_passkey(params, target_passkey['id'], target_passkey['credential_id'])
                return result
            else:
                return {'status': STATUS_NOT_FOUND, 'message': f'Passkey with credential ID {credential_id} not found on server'}
                
        except Exception as e:
            return {'status': STATUS_ERROR, 'message': f'Error disabling specific passkey: {str(e)}'}

    def _process_specific_passkey_result(self, passkey_result, credential_id: str):
        """Process and display results for a specific passkey disable operation"""
        if isinstance(passkey_result, dict):
            status = passkey_result.get('status')
            message = passkey_result.get('message', 'Unknown result')
            
            if status == STATUS_NOT_FOUND:
                pass
            elif status == STATUS_SUCCESS:
                pass
            else:
                print(f"Failed to disable passkey: {message}")
        else:
            print(f"Unexpected result when disabling passkey: {passkey_result}")

    def _cleanup_local_credentials(self, username: str, rp_id: Optional[str] = None) -> bool:
        """Clean up local biometric credentials (platform-specific)"""
        try:
            system = platform.system()
            
            if system == PLATFORM_DARWIN:  # macOS
                return self._cleanup_macos_keychain_credentials(rp_id)
            elif system == PLATFORM_WINDOWS:  # Windows
                return self._cleanup_windows_credentials()
            else:
                # For other platforms, just return True as there's nothing specific to clean up
                return True
        except Exception as e:
            print(f"Warning: Could not clean up local credentials: {str(e)}")
            return False

    def _cleanup_macos_keychain_credentials(self, rp_id: Optional[str] = None) -> bool:
        """Clean up macOS keychain credentials for biometric authentication"""
        try:
            # Build list of services to clean up
            services_to_clean = ["Keeper Biometric Authentication"]
            
            # If we have the RP ID, also clean up WebAuthn-specific entries
            if rp_id:
                services_to_clean.append(f"{MACOS_KEYCHAIN_SERVICE_PREFIX} - {rp_id}")
            else:
                print("RP ID not available - performing limited cleanup")
            
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
        if delete_success:
            print(SUCCESS_MESSAGES['unregistration_complete'] + f" for user '{username}'.")
            if cleanup_success:
                print("Default authentication will be used for future logins.")
        else:
            print(f"Failed to remove biometric authentication for user '{username}'. Please try again.")

    def _get_detector(self):
        """Get biometric detector instance"""
        from ..platforms.detector import BiometricDetector
        return BiometricDetector() 