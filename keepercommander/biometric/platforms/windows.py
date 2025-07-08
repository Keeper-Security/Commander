import json
import logging
import os
import subprocess
from typing import Dict, Any, Tuple

from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from ... import utils
from ..core.base import StorageHandler
from .base import BasePlatformHandler


class WindowsStorageHandler(StorageHandler):
    """Windows Registry storage handler"""

    def __init__(self):
        self.key_path = r"SOFTWARE\Keeper Security\Commander\Biometric"

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
        """Get biometric flag from Windows registry"""
        try:
            import winreg
            key = self._get_registry_key()
            if key:
                try:
                    value, _ = winreg.QueryValueEx(key, username)
                    winreg.CloseKey(key)
                    return bool(value)
                except FileNotFoundError:
                    winreg.CloseKey(key)
                    return False
        except Exception as e:
            logging.debug(f'Failed to get Windows registry biometric flag: {e}')
        return False

    def set_biometric_flag(self, username: str, enabled: bool) -> bool:
        """Set biometric flag in Windows registry"""
        try:
            import winreg
            key = self._get_registry_key()
            if key:
                winreg.SetValueEx(key, username, 0, winreg.REG_DWORD, 1 if enabled else 0)
                winreg.CloseKey(key)
                return True
        except Exception as e:
            logging.debug(f'Failed to set Windows registry biometric flag: {e}')
        return False

    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag from Windows registry"""
        try:
            import winreg
            key = self._get_registry_key()
            if key:
                try:
                    winreg.DeleteValue(key, username)
                    winreg.CloseKey(key)
                    logging.debug(f'Deleted Windows registry biometric flag for user: {username}')
                    return True
                except FileNotFoundError:
                    # Value doesn't exist, consider this a success
                    winreg.CloseKey(key)
                    logging.debug(f'Windows registry biometric flag for user {username} was already deleted')
                    return True
        except Exception as e:
            logging.debug(f'Failed to delete Windows registry biometric flag: {e}')
        return False


class WindowsHandler(BasePlatformHandler):
    """Windows-specific biometric handler"""

    def _create_storage_handler(self) -> StorageHandler:
        return WindowsStorageHandler()

    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect Windows Hello capabilities"""
        if os.name != 'nt':
            return False, "Not running on Windows"

        try:
            # Quick WebAuthn check first
            webauthn_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'webauthn.dll')
            if os.path.exists(webauthn_path):
                return True, "Windows Hello WebAuthn support detected"

            # Detailed PowerShell check
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
                    return True, f"Windows Hello available: {', '.join(features)}"

            return False, "Windows Hello not available"

        except Exception as e:
            return False, f"Error detecting Windows Hello: {str(e)}"

    def create_webauthn_client(self, data_collector, timeout: int = 30):
        """Create Windows WebAuthn client"""
        try:
            from fido2.client.windows import WindowsClient
            return WindowsClient(client_data_collector=data_collector)
        except ImportError:
            raise Exception('Windows Hello client not available. Install fido2[pcsc]')

    def handle_credential_creation(self, creation_options: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        """Handle Windows-specific credential creation"""
        # Convert user ID to bytes
        user_id = utils.base64_url_decode(creation_options['user']['id'])
        creation_options['user']['id'] = user_id

        # Remove unsupported options
        creation_options.pop('hints', None)
        creation_options.pop('extensions', None)

        # Remove empty excludeCredentials
        if 'excludeCredentials' in creation_options and not creation_options['excludeCredentials']:
            creation_options.pop('excludeCredentials')

        # Set authenticator selection
        if 'authenticatorSelection' not in creation_options:
            creation_options['authenticatorSelection'] = {}

        creation_options['authenticatorSelection'].update({
            'authenticatorAttachment': 'platform',
            'userVerification': 'required',
            'residentKey': 'required'
        })

        creation_options['attestation'] = 'none'
        
        if 'timeout' not in creation_options:
            creation_options['timeout'] = timeout * 1000

        return creation_options

    def handle_authentication_options(self, pk_options: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
        """Handle Windows-specific authentication options"""
        pk_options.pop('hints', None)
        pk_options.pop('extensions', None)

        # Clean up empty transports
        if 'allowCredentials' in pk_options:
            for cred in pk_options['allowCredentials']:
                if 'transports' in cred and not cred['transports']:
                    cred.pop('transports')

        pk_options['userVerification'] = 'required'
        
        if 'timeout' not in pk_options:
            pk_options['timeout'] = timeout * 1000

        return pk_options

    def perform_authentication(self, client, options: PublicKeyCredentialRequestOptions):
        """Perform Windows Hello authentication"""
        try:
            return client.get_assertion(options)
        except Exception as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ["cancelled", "denied"]):
                raise Exception("Windows Hello authentication cancelled")
            elif "timeout" in error_msg:
                raise Exception("Windows Hello authentication timed out")
            elif "not available" in error_msg:
                raise Exception("Windows Hello is not available or not set up")
            elif "parameter is incorrect" in error_msg:
                raise Exception("Windows Hello parameter error - please check your biometric setup")
            else:
                raise Exception(f"Windows Hello authentication failed: {str(e)}")

    def perform_credential_creation(self, client, options: PublicKeyCredentialCreationOptions):
        """Perform Windows Hello credential creation"""
        try:
            return client.make_credential(options)
        except Exception as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ["cancelled", "denied"]):
                raise Exception("Windows Hello registration cancelled")
            elif "timeout" in error_msg:
                raise Exception("Windows Hello registration timed out")
            elif "not available" in error_msg:
                raise Exception("Windows Hello is not available or not set up")
            else:
                raise Exception(f"Windows Hello registration failed: {str(e)}") 