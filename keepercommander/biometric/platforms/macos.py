import json
import logging
import os
import platform
import subprocess
import threading
import time
from typing import Dict, Any, Tuple

from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from ... import utils, crypto
from ..core.base import StorageHandler
from ..core.keychain_manager import MacOSKeychainManager
from ..utils.webauthn_client import MacOSTouchIDWebAuthnClient
from .base import BasePlatformHandler


class MacOSStorageHandler(StorageHandler):
    """macOS plist storage handler"""

    def __init__(self):
        self.prefs_path = self._get_prefs_path()

    def _get_prefs_path(self):
        """Get macOS preferences path"""
        home_dir = os.path.expanduser("~")
        return os.path.join(home_dir, "Library", "Preferences", "com.keepersecurity.commander.biometric.plist")

    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag from macOS preferences"""
        try:
            import plistlib
            if not os.path.exists(self.prefs_path):
                return False
            
            with open(self.prefs_path, 'rb') as f:
                prefs = plistlib.load(f)
            
            return prefs.get(username, False)
        except Exception as e:
            logging.debug(f'Failed to get macOS biometric flag: {e}')
            return False

    def set_biometric_flag(self, username: str, enabled: bool) -> bool:
        """Set biometric flag in macOS preferences"""
        try:
            import plistlib
            prefs = {}
            
            if os.path.exists(self.prefs_path):
                try:
                    with open(self.prefs_path, 'rb') as f:
                        prefs = plistlib.load(f)
                except Exception:
                    prefs = {}
            
            prefs[username] = enabled
            
            os.makedirs(os.path.dirname(self.prefs_path), exist_ok=True)
            with open(self.prefs_path, 'wb') as f:
                plistlib.dump(prefs, f)
            
            return True
        except Exception as e:
            logging.debug(f'Failed to set macOS biometric flag: {e}')
            return False

    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag from macOS preferences"""
        try:
            import plistlib
            if not os.path.exists(self.prefs_path):
                return True  # Already deleted/doesn't exist
            
            with open(self.prefs_path, 'rb') as f:
                prefs = plistlib.load(f)
            
            if username in prefs:
                del prefs[username]
                
                # Save the updated plist
                with open(self.prefs_path, 'wb') as f:
                    plistlib.dump(prefs, f)
            
            return True
        except Exception as e:
            logging.debug(f'Failed to delete macOS biometric flag: {e}')
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

    def _get_platform_settings(self) -> Dict[str, Any]:
        return {'residentKey': 'discouraged'}

    def _ensure_pam_configured(self):
        """Ensure Touch ID is configured for sudo if not already present"""
        try:
            with open('/etc/pam.d/sudo', 'r') as f:
                content = f.read()
            if 'pam_tid.so' not in content:
                print("\n" + "="*60)
                print("TOUCH ID CONFIGURATION REQUIRED")
                print("="*60)
                print("To enable Touch ID for sudo commands, Keeper needs to modify")
                print("the system configuration file (/etc/pam.d/sudo).")
                print("\nThis will allow you to use Touch ID instead of typing your")
                print("password when running sudo commands in the terminal.")
                print("\nYou will be prompted for your macOS account password to")
                print("authorize this system configuration change.")
                print("="*60)
                
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if line.strip() and not line.strip().startswith('#'):
                        lines.insert(i, 'auth       sufficient     pam_tid.so')
                        break
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                    tmp.write('\n'.join(lines))
                    tmp.flush()
                    subprocess.run(['sudo', 'cp', tmp.name, '/etc/pam.d/sudo'], check=True)
                    os.unlink(tmp.name)
                    print("✓ Touch ID for sudo has been successfully configured!")
        except Exception:
            pass  # Silently fail if cannot configure PAM

    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect Touch ID availability on macOS"""
        if platform.system() != 'Darwin':
            return False, "Not running on macOS"

        error_messages = []

        try:
            # Try bioutil command first
            try:
                result = subprocess.run([
                    'bioutil', '-r', '-s'
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    output = result.stdout.lower()
                    if ('touch id' in output or 
                        'biometrics functionality: 1' in output or
                        'biometric' in output):
                        self._ensure_pam_configured()
                        return True, "Touch ID is available and configured"
                    else:
                        error_messages.append(f"bioutil: ran successfully but no Touch ID detected")
                else:
                    error_messages.append(f"bioutil: command failed (return code {result.returncode})")
            except FileNotFoundError:
                error_messages.append("bioutil: command not found")
            except Exception as e:
                error_messages.append(f"bioutil: {str(e)}")

            # Fallback: LocalAuthentication check
            try:
                import LocalAuthentication  # pylint: disable=import-error
                context = LocalAuthentication.LAContext.alloc().init()  # pylint: disable=no-member
                error = None
                can_evaluate = context.canEvaluatePolicy_error_(
                    LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                    error
                )
                
                if can_evaluate:
                    self._ensure_pam_configured()
                    return True, "Touch ID is available"
                else:
                    la_error = f"LocalAuthentication: policy evaluation failed"
                    if error:
                        la_error += f" (error: {error})"
                    error_messages.append(la_error)
                    
            except ImportError as e:
                error_messages.append(f"LocalAuthentication: import failed - {str(e)}")
                error_messages.append("LocalAuthentication: try 'pip install pyobjc-framework-LocalAuthentication'")
            except Exception as e:
                error_messages.append(f"LocalAuthentication: {str(e)}")

            # System profiler as last resort
            try:
                result = subprocess.run([
                    'system_profiler', 'SPiBridgeDataType'
                ], capture_output=True, text=True, timeout=15)

                if result.returncode == 0:
                    output = result.stdout.lower()
                    if 'touch id' in output or 'biometric' in output:
                        self._ensure_pam_configured()
                        return True, "Touch ID hardware detected"
                    else:
                        error_messages.append("system_profiler: no Touch ID hardware found")
                else:
                    error_messages.append(f"system_profiler: failed (return code {result.returncode})")
            except Exception as e:
                error_messages.append(f"system_profiler: {str(e)}")

            # If we get here, all detection methods failed
            detailed_error = "Touch ID detection failed. " + "; ".join(error_messages)
            detailed_error += ". Please verify Touch ID is set up in System Preferences > Touch ID & Password"
            return False, detailed_error

        except Exception as e:
            return False, f"Error checking Touch ID: {str(e)}"

    def create_webauthn_client(self, data_collector, timeout: int = 30):
        """Create macOS Touch ID WebAuthn client"""
        try:
            from ..core.base import BiometricInteraction
            interaction = BiometricInteraction(timeout)
            return MacOSTouchIDWebAuthnClient(data_collector, interaction, self.keychain_manager, timeout)
        except ImportError:
            raise Exception('macOS Touch ID client dependencies not available')

    def handle_credential_creation(self, creation_options: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        """Handle macOS-specific credential creation"""
        # Check for existing credentials before processing
        if 'excludeCredentials' in creation_options and creation_options['excludeCredentials']:
            for excluded_cred in creation_options['excludeCredentials']:
                cred_id = excluded_cred.get('id')
                if isinstance(cred_id, str):
                    cred_id_b64 = cred_id
                else:
                    cred_id_b64 = utils.base64_url_encode(cred_id)
                
                if self.keychain_manager.credential_exists(cred_id_b64):
                    raise Exception("A biometric credential for this account already exists. Use 'biometric unregister' first.")

        # Use common preparation logic
        return self._prepare_credential_creation_options(
            creation_options, 
            timeout, 
            self._get_platform_settings()
        )

    def handle_authentication_options(self, pk_options: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
        """Handle macOS-specific authentication options"""
        return self._prepare_authentication_options(pk_options, timeout)

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