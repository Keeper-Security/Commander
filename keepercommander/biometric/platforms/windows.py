import json
import logging
import os
import subprocess
from typing import Dict, Any, Tuple, Optional

from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from ... import utils
from .base import StorageHandler
from ..utils.constants import (
    WINDOWS_REGISTRY_PATH
)
from ..utils.error_handler import BiometricErrorHandler
from .base import BasePlatformHandler

# Windows platform detection constant
WINDOWS_WEBAUTHN_DLL_PATH = r"System32\webauthn.dll"


class WindowsStorageHandler(StorageHandler):
    """Windows Registry storage handler"""

    def __init__(self):
        self.key_path = WINDOWS_REGISTRY_PATH

    def _get_registry_key(self):
        """Get Windows registry key"""
        try:
            import winreg
            try:
                return winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.key_path, 0, winreg.KEY_ALL_ACCESS)
            except FileNotFoundError:
                return winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.key_path)
        except ImportError:
            return None

    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag from Windows registry - True if credential ID exists"""
        return self.get_credential_id(username) is not None

    def set_biometric_flag(self, username: str, enabled: bool) -> bool:
        """Set biometric flag in Windows registry (deprecated - use store_credential_id)"""
        # This method is kept for backward compatibility but should not be used
        # The presence of credential_id now serves as the flag
        logging.warning("set_biometric_flag is deprecated, use store_credential_id instead")
        return True

    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag from Windows registry - removes credential ID"""
        return self.delete_credential_id(username)

    def store_credential_id(self, username: str, credential_id: str) -> bool:
        """Store credential ID for user in Windows registry (also serves as biometric flag)"""
        try:
            import winreg
            key = self._get_registry_key()
            if key:
                winreg.SetValueEx(key, username, 0, winreg.REG_SZ, credential_id)
                winreg.CloseKey(key)
                logging.debug(f'Stored credential ID for user: {username}')
                return True
        except Exception as e:
            logging.warning(f"Failed to store credential ID for {username}: {str(e)}")
            BiometricErrorHandler.create_storage_error("store credential ID", "Windows registry", e)
        return False

    def get_credential_id(self, username: str) -> Optional[str]:
        """Get stored credential ID for user from Windows registry"""
        try:
            import winreg
            key = self._get_registry_key()
            if key:
                try:
                    value, reg_type = winreg.QueryValueEx(key, username)
                    winreg.CloseKey(key)
                    # Handle both old DWORD format (1/0) and new string format (credential_id)
                    if reg_type == winreg.REG_DWORD:
                        # Old format - migrate to new format by returning None
                        logging.debug(f'Found old DWORD format for user {username}, needs migration')
                        return None
                    elif reg_type == winreg.REG_SZ and value:
                        logging.debug(f'Retrieved credential ID for user: {username}')
                        return str(value)
                    else:
                        return None
                except FileNotFoundError:
                    winreg.CloseKey(key)
                    logging.debug(f'No stored credential ID found for user: {username}')
                    return None
        except Exception as e:
            logging.warning(f"Failed to retrieve credential ID for {username}: {str(e)}")
            BiometricErrorHandler.create_storage_error("get credential ID", "Windows registry", e)
        return None

    def delete_credential_id(self, username: str) -> bool:
        """Delete stored credential ID for user from Windows registry"""
        try:
            import winreg
            key = self._get_registry_key()
            if key:
                try:
                    winreg.DeleteValue(key, username)
                    winreg.CloseKey(key)
                    logging.debug(f'Deleted stored credential ID for user: {username}')
                    return True
                except FileNotFoundError:
                    # Value doesn't exist, consider this a success
                    winreg.CloseKey(key)
                    logging.debug(f'Credential ID for user {username} was already deleted')
                    return True
        except Exception as e:
            logging.warning(f"Failed to delete credential ID for {username}: {str(e)}")
            BiometricErrorHandler.create_storage_error("delete credential ID", "Windows registry", e)
        return False


class WindowsHandler(BasePlatformHandler):
    """Windows-specific biometric handler"""

    def _create_storage_handler(self) -> StorageHandler:
        return WindowsStorageHandler()

    def _get_platform_name(self) -> str:
        return "Windows Hello"



    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect Windows Hello capabilities"""
        if os.name != 'nt':
            return False, "Not running on Windows"

        try:
            # Quick WebAuthn check first
            webauthn_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), WINDOWS_WEBAUTHN_DLL_PATH)
            if os.path.exists(webauthn_path):
                return True, "Windows Hello WebAuthn support detected"

            # Detailed PowerShell check
            result = self._run_powershell_detection()
            if result:
                return True, result

            return False, "Windows Hello not available"

        except Exception as e:
            return False, f"Error detecting Windows Hello: {str(e)}"

    def _run_powershell_detection(self) -> Optional[str]:
        """Run PowerShell detection script"""
        try:
            result = subprocess.run([
                'powershell', '-Command',
                '''
                $hello = @{
                    Face = (Get-WindowsOptionalFeature -Online -FeatureName "Windows-Hello-Face" -EA SilentlyContinue).State -eq "Enabled"
                    Fingerprint = (Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.Name -like "*fingerprint*" -or $_.Name -like "*biometric*" }).Count -gt 0
                    WebAuthn = Test-Path "$env:WINDIR\\System32\\webauthn.dll"
                }
                @{ Available = ($hello.Face -or $hello.Fingerprint -or $hello.WebAuthn); Details = $hello } | ConvertTo-Json -Compress
                '''
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                hello_info = json.loads(result.stdout.strip())
                if hello_info.get('Available'):
                    details = hello_info.get('Details', {})
                    features = []
                    if details.get('Face'): features.append("Face")
                    if details.get('Fingerprint'): features.append("Fingerprint")
                    if details.get('WebAuthn'): features.append("WebAuthn")
                    return f"Windows Hello available: {', '.join(features)}"
        except Exception:
            pass
        
        return None

    def create_webauthn_client(self, data_collector, timeout: int = 30):
        """Create Windows WebAuthn client"""
        try:
            from fido2.client.windows import WindowsClient
            return WindowsClient(client_data_collector=data_collector)
        except ImportError:
            raise Exception('Windows Hello client not available. Install fido2[pcsc]')

    def handle_credential_creation(self, creation_options: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        """Handle Windows-specific credential creation"""
        return self._prepare_credential_creation_options(creation_options, timeout)

    def handle_authentication_options(self, pk_options: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
        """Handle Windows-specific authentication options"""
        return self._prepare_authentication_options(pk_options, timeout)

    def perform_authentication(self, client, options: PublicKeyCredentialRequestOptions):
        """Perform Windows Hello authentication"""
        try:
            return client.get_assertion(options)
        except Exception as e:
            raise self._handle_authentication_error(e, self._get_platform_name())

    def perform_credential_creation(self, client, options: PublicKeyCredentialCreationOptions):
        """Perform Windows Hello credential creation"""
        try:
            return client.make_credential(options)
        except Exception as e:
            raise self._handle_credential_creation_error(e, self._get_platform_name()) 