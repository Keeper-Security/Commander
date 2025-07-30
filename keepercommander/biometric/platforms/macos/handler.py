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
import os
import platform
import subprocess
from typing import Dict, Any, Tuple, Optional

from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from .... import utils
from ..base import BasePlatformHandler, StorageHandler
from .keychain import MacOSKeychainManager
from .webauthn import MacOSTouchIDWebAuthnClient
from ...utils.constants import (
    MACOS_PREFS_PATH,
    ERROR_MESSAGES,
    PLATFORM_DARWIN,
    DEFAULT_BIOMETRIC_TIMEOUT
)
from ...utils.error_handler import BiometricErrorHandler

MACOS_BIOUTIL_COMMAND = ['bioutil', '-r', '-s']

class MacOSStorageHandler(StorageHandler):
    """macOS plist storage handler"""

    def __init__(self):
        self.prefs_path = self._get_prefs_path()

    def _get_prefs_path(self):
        """Get macOS preferences path"""
        home_dir = os.path.expanduser("~")
        return os.path.join(home_dir, "Library", "Preferences", MACOS_PREFS_PATH)

    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag from macOS preferences - True if credential ID exists"""
        return self.get_credential_id(username) is not None

    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag from macOS preferences - removes credential ID"""
        return self.delete_credential_id(username)

    def store_credential_id(self, username: str, credential_id: str) -> bool:
        """Store credential ID for user in macOS preferences (also serves as biometric flag)"""
        try:
            import plistlib
            prefs = {}
            
            if os.path.exists(self.prefs_path):
                try:
                    with open(self.prefs_path, 'rb') as f:
                        prefs = plistlib.load(f)
                except Exception:
                    prefs = {}
            
            prefs[username] = credential_id
            
            os.makedirs(os.path.dirname(self.prefs_path), exist_ok=True)
            with open(self.prefs_path, 'wb') as f:
                plistlib.dump(prefs, f)
            
            logging.debug("Stored credential ID for user: %s", username)
            return True
        except Exception as e:
            logging.warning("Failed to store credential ID for %s: %s", username, str(e))
            BiometricErrorHandler.create_storage_error("store credential ID", "macOS", e)
            return False

    def get_credential_id(self, username: str) -> Optional[str]:
        """Get stored credential ID for user from macOS preferences"""
        try:
            import plistlib
            if not os.path.exists(self.prefs_path):
                return None
            
            with open(self.prefs_path, 'rb') as f:
                prefs = plistlib.load(f)
            
            value = prefs.get(username)
            
            if value:
                if isinstance(value, str):
                    return value
            
            return None
        except Exception as e:
            logging.warning("Failed to retrieve credential ID for %s: %s", username, str(e))
            BiometricErrorHandler.create_storage_error("get credential ID", "macOS", e)
            return None

    def delete_credential_id(self, username: str) -> bool:
        """Delete stored credential ID for user from macOS preferences"""
        try:
            import plistlib
            if not os.path.exists(self.prefs_path):
                return True 
            
            with open(self.prefs_path, 'rb') as f:
                prefs = plistlib.load(f)
            
            if username not in prefs:
                return True
                
            del prefs[username]
            
            with open(self.prefs_path, 'wb') as f:
                plistlib.dump(prefs, f)
            
            with open(self.prefs_path, 'rb') as f:
                verification_prefs = plistlib.load(f)
            
            return username not in verification_prefs
        except Exception as e:
            logging.warning("Failed to delete credential ID for %s: %s", username, str(e))
            BiometricErrorHandler.create_storage_error("delete credential ID", "macOS", e)
            return False

class MacOSHandler(BasePlatformHandler):
    """macOS-specific biometric handler"""

    def __init__(self):
        super().__init__()
        self.keychain_manager = MacOSKeychainManager()

    def _create_storage_handler(self) -> StorageHandler:
        return MacOSStorageHandler()

    def _get_platform_name(self) -> str:
        return "Touch ID"

    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect Touch ID availability on macOS"""
        if platform.system() != PLATFORM_DARWIN:
            return False, "Not running on macOS"

        error_messages = []

        try:
            # Try bioutil command first
            if self._check_bioutil_command(error_messages):
                return True, "Touch ID is available and configured"

            # Fallback: LocalAuthentication check
            if self._check_local_authentication(error_messages):
                return True, "Touch ID is available"

            # If we get here, all detection methods failed
            detailed_error = "Touch ID detection failed. " + "; ".join(error_messages)
            detailed_error += ". Please verify Touch ID is set up in System Preferences > Touch ID & Password"
            return False, detailed_error

        except Exception as e:
            return False, f"Error checking Touch ID: {str(e)}"

    def _check_bioutil_command(self, error_messages: list) -> bool:
        """Check Touch ID using bioutil command"""
        try:
            result = subprocess.run(MACOS_BIOUTIL_COMMAND, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                output = result.stdout.lower()
                if ('touch id' in output or 
                    'biometrics functionality: 1' in output or
                    'biometric' in output):
                    return True
                else:
                    error_messages.append("bioutil: ran successfully but no Touch ID detected")
            else:
                error_messages.append(f"bioutil: command failed (return code {result.returncode})")
        except FileNotFoundError:
            error_messages.append("bioutil: command not found")
        except Exception as e:
            error_messages.append(f"bioutil: {str(e)}")

        return False

    def _check_local_authentication(self, error_messages: list) -> bool:
        """Check Touch ID using LocalAuthentication framework"""
        try:
            import LocalAuthentication  # pylint: disable=import-error
            context = LocalAuthentication.LAContext.alloc().init()  # pylint: disable=no-member
            error = None
            
            policy_attr = getattr(LocalAuthentication, 'LAPolicyDeviceOwnerAuthenticationWithBiometrics', None)
            if policy_attr is None:
                error_messages.append("LocalAuthentication: biometric policy not available")
                return False
                
            can_evaluate = context.canEvaluatePolicy_error_(policy_attr, error)
            
            if can_evaluate:
                return True
            else:
                la_error = "LocalAuthentication: policy evaluation failed"
                if error:
                    la_error += f" (error: {error})"
                error_messages.append(la_error)
                
        except ImportError as e:
            error_messages.append(f"LocalAuthentication: import failed - {str(e)}")
            error_messages.append("LocalAuthentication: try 'pip install pyobjc-framework-LocalAuthentication'")
        except Exception as e:
            error_messages.append(f"LocalAuthentication: {str(e)}")

        return False

    def create_webauthn_client(self, data_collector):
        """Create macOS Touch ID WebAuthn client"""
        try:
            return MacOSTouchIDWebAuthnClient(data_collector, self.keychain_manager)
        except ImportError:
            raise Exception('macOS Touch ID client dependencies not available')

    def handle_credential_creation(self, creation_options: Dict[str, Any]) -> Dict[str, Any]:
        """Handle macOS-specific credential creation"""
        rp_id = creation_options.get('rp', {}).get('id')
        if not rp_id:
            raise Exception("No RP ID found in creation options - server configuration error")
            
        # Check for existing credentials before processing
        if 'excludeCredentials' in creation_options and creation_options['excludeCredentials']:
            for excluded_cred in creation_options['excludeCredentials']:
                cred_id = excluded_cred.get('id')
                if isinstance(cred_id, str):
                    cred_id_b64 = cred_id
                else:
                    cred_id_b64 = utils.base64_url_encode(cred_id)
                
                if self.keychain_manager.credential_exists(cred_id_b64, rp_id, DEFAULT_BIOMETRIC_TIMEOUT):
                    raise Exception(ERROR_MESSAGES['credential_exists'])

        return self._prepare_credential_creation_options(creation_options)

    def handle_authentication_options(self, pk_options: Dict[str, Any]) -> Dict[str, Any]:
        """Handle macOS-specific authentication options"""
        return self._prepare_authentication_options(pk_options)

    def perform_authentication(self, client, options: PublicKeyCredentialRequestOptions):
        """Perform macOS Touch ID authentication"""
        try:
            return client.get_assertion(options)
        except Exception as e:
            raise self._handle_authentication_error(e, self._get_platform_name())

    def perform_credential_creation(self, client, options: PublicKeyCredentialCreationOptions):
        """Perform macOS Touch ID credential creation"""
        try:
            return client.make_credential(options)
        except Exception as e:
            raise self._handle_credential_creation_error(e, self._get_platform_name()) 