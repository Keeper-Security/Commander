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
from ..utils.constants import (
    MACOS_PREFS_PATH,
    MACOS_SETTINGS,
    ERROR_MESSAGES,
    AUTH_REASONS
)
from ..utils.error_handler import BiometricErrorHandler
from .base import BasePlatformHandler

# macOS platform detection commands
MACOS_BIOUTIL_COMMAND = ['bioutil', '-r', '-s']
MACOS_SYSTEM_PROFILER_COMMAND = ['system_profiler', 'SPiBridgeDataType']


class MacOSStorageHandler(StorageHandler):
    """macOS plist storage handler"""

    def __init__(self):
        self.prefs_path = self._get_prefs_path()

    def _get_prefs_path(self):
        """Get macOS preferences path"""
        home_dir = os.path.expanduser("~")
        return os.path.join(home_dir, "Library", "Preferences", MACOS_PREFS_PATH)

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
            BiometricErrorHandler.create_storage_error("get", "macOS", e)
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
            BiometricErrorHandler.create_storage_error("set", "macOS", e)
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
            BiometricErrorHandler.create_storage_error("delete", "macOS", e)
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
        return MACOS_SETTINGS

#     def _ensure_pam_configured(self):
#         """Ensure Touch ID is configured for sudo if not already present"""
#         try:
#             with open('/etc/pam.d/sudo', 'r') as f:
#                 content = f.read()
#             if 'pam_tid.so' not in content:
#                 # Show informational dialog with terminal icon
#                 # Get the path to the Keeper image for other dialogs
#                 import os
#                 current_dir = os.path.dirname(os.path.abspath(__file__))
#                 keeper_image_path = os.path.join(current_dir, '..', '..', '..', 'images', 'commander-black.png')
#                 keeper_image_path = os.path.abspath(keeper_image_path)
                
#                 # Use terminal icon for the first dialog since it's about terminal/sudo configuration
#                 info_script = '''
#                 display dialog "Touch ID Configuration Required

# To enable Touch ID for sudo commands, Keeper needs to modify the system configuration file (/etc/pam.d/sudo).

# You will be prompted for your macOS account password to authorize this system configuration change." buttons {"Cancel", "Continue"} default button "Continue" with title "Keeper Commander - Touch ID Setup" with icon caution
#                 '''
                
#                 try:
#                     result = subprocess.run(['osascript', '-e', info_script], capture_output=True, text=True, timeout=30)
#                     if result.returncode != 0:
#                         return  # User cancelled or dialog failed
#                 except (subprocess.TimeoutExpired, Exception):
#                     return  # Fallback to silent failure
                
#                 # Show password dialog with Keeper image
#                 icon_part = f'with icon file (POSIX file "{keeper_image_path}")' if os.path.exists(keeper_image_path) else 'with icon caution'
#                 password_script = f'''
#                 display dialog "Enter your macOS account password to configure Touch ID for sudo:" default answer "" with hidden answer buttons {{"Cancel", "OK"}} default button "OK" with title "Keeper Commander - Administrator Password" {icon_part}
#                 '''
                
#                 try:
#                     result = subprocess.run(['osascript', '-e', password_script], capture_output=True, text=True, timeout=60)
#                     if result.returncode != 0:
#                         return  # User cancelled or dialog failed
                        
#                     # Extract password from AppleScript result
#                     # AppleScript returns: "button returned:OK, text returned:password"
#                     output = result.stdout.strip()
#                     if 'text returned:' not in output:
#                         return  # Invalid response
                    
#                     password = output.split('text returned:')[1].strip()
#                     if not password:
#                         return  # Empty password
                        
#                 except (subprocess.TimeoutExpired, Exception):
#                     return  # Fallback to silent failure
                
#                 # Prepare the new sudo file content
#                 lines = content.split('\n')
#                 for i, line in enumerate(lines):
#                     if line.strip() and not line.strip().startswith('#'):
#                         lines.insert(i, 'auth       sufficient     pam_tid.so')
#                         break
                
#                 import tempfile
#                 import shlex
                
#                 with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
#                     tmp.write('\n'.join(lines))
#                     tmp.flush()
                    
#                     try:
#                         # Use password with sudo -S (read password from stdin)
#                         # Properly escape the password for shell usage
#                         escaped_password = shlex.quote(password)
#                         sudo_process = subprocess.Popen(
#                             ['sudo', '-S', 'cp', tmp.name, '/etc/pam.d/sudo'],
#                             stdin=subprocess.PIPE,
#                             stdout=subprocess.PIPE,
#                             stderr=subprocess.PIPE,
#                             text=True
#                         )
                        
#                         stdout, stderr = sudo_process.communicate(input=password + '\n', timeout=30)
                        
#                         if sudo_process.returncode == 0:
#                             # Show success dialog with Keeper image
#                             icon_part = f'with icon file (POSIX file "{keeper_image_path}")' if os.path.exists(keeper_image_path) else 'with icon note'
#                             success_script = f'''
#                             display dialog "Touch ID for sudo has been successfully configured!" buttons {{"OK"}} default button "OK" with title "Keeper Commander - Configuration Complete" {icon_part}
#                             '''
#                             subprocess.run(['osascript', '-e', success_script], timeout=10)
#                         else:
#                             # Show error dialog with appropriate icon
#                             icon_part = f'with icon file (POSIX file "{keeper_image_path}")' if os.path.exists(keeper_image_path) else 'with icon stop'
#                             error_script = f'''
#                             display dialog "Failed to configure Touch ID for sudo. Please check your password and try again." buttons {{"OK"}} default button "OK" with title "Keeper Commander - Configuration Failed" {icon_part}
#                             '''
#                             subprocess.run(['osascript', '-e', error_script], timeout=10)
                            
#                     except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
#                         # Show error dialog for timeout or other errors
#                         icon_part = f'with icon file (POSIX file "{keeper_image_path}")' if os.path.exists(keeper_image_path) else 'with icon stop'
#                         error_script = f'''
#                         display dialog "Failed to configure Touch ID for sudo. The operation timed out or failed." buttons {{"OK"}} default button "OK" with title "Keeper Commander - Configuration Failed" {icon_part}
#                         '''
#                         subprocess.run(['osascript', '-e', error_script], timeout=10)
#                     finally:
#                         # Clean up temporary file
#                         try:
#                             os.unlink(tmp.name)
#                         except OSError:
#                             pass
                        
#                         # Clear password from memory
#                         password = None
                        
#         except Exception:
#             pass  # Silently fail if cannot configure PAM

    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect Touch ID availability on macOS"""
        if platform.system() != 'Darwin':
            return False, "Not running on macOS"

        error_messages = []

        try:
            # Try bioutil command first
            if self._check_bioutil_command(error_messages):
                return True, "Touch ID is available and configured"

            # Fallback: LocalAuthentication check
            if self._check_local_authentication(error_messages):
                return True, "Touch ID is available"

            # System profiler as last resort
            if self._check_system_profiler(error_messages):
                return True, "Touch ID hardware detected"

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
            can_evaluate = context.canEvaluatePolicy_error_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                error
            )
            
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

    def _check_system_profiler(self, error_messages: list) -> bool:
        """Check Touch ID using system profiler"""
        try:
            result = subprocess.run(MACOS_SYSTEM_PROFILER_COMMAND, capture_output=True, text=True, timeout=15)

            if result.returncode == 0:
                output = result.stdout.lower()
                if 'touch id' in output or 'biometric' in output:
                    return True
                else:
                    error_messages.append("system_profiler: no Touch ID hardware found")
            else:
                error_messages.append(f"system_profiler: failed (return code {result.returncode})")
        except Exception as e:
            error_messages.append(f"system_profiler: {str(e)}")

        return False

    def create_webauthn_client(self, data_collector, timeout: int = 30):
        """Create macOS Touch ID WebAuthn client"""
        try:
            return MacOSTouchIDWebAuthnClient(data_collector, self.keychain_manager, timeout)
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
                    raise Exception(ERROR_MESSAGES['credential_exists'])

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