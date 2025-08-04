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
import subprocess
import getpass
from contextlib import contextmanager
from typing import Dict, Any, Tuple, Optional

from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from .base import StorageHandler
from ..utils.constants import (
    ERROR_MESSAGES,
    WINDOWS_REGISTRY_PATH
)
from ..utils.error_handler import BiometricErrorHandler
from .base import BasePlatformHandler
import asyncio
from winrt.windows.security.credentials.ui import (
    UserConsentVerifier,
    UserConsentVerifierAvailability,
)


class WindowsStorageHandler(StorageHandler):
    """Windows Registry storage handler"""

    def __init__(self):
        self.key_path = WINDOWS_REGISTRY_PATH

    def _get_registry_key(self) -> Optional[Any]:
        """Get Windows registry key"""
        try:
            import winreg
            try:
                return winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.key_path, 0, winreg.KEY_ALL_ACCESS)
            except FileNotFoundError:
                return winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.key_path)
        except ImportError:
            return None

    @contextmanager
    def registry_key(self) -> Any:
        """Context manager for registry key handling"""
        import winreg
        key = None
        try:
            key = self._get_registry_key()
            if key is None:
                raise ImportError("winreg module not available")
            yield key
        finally:
            if key:
                winreg.CloseKey(key)

    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag from Windows registry - True if credential ID exists"""
        return self.get_credential_id(username) is not None

    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag from Windows registry - removes credential ID"""
        return self.delete_credential_id(username)

    def store_credential_id(self, username: str, credential_id: str) -> bool:
        """Store credential ID for user in Windows registry (also serves as biometric flag)"""
        try:
            import winreg
            with self.registry_key() as key:
                winreg.SetValueEx(key, username, 0, winreg.REG_SZ, credential_id)
                logging.debug("Stored credential ID for user: %s", username)
                return True
        except Exception as e:
            logging.warning("Failed to store credential ID for %s: %s", username, str(e))
            BiometricErrorHandler.create_storage_error("store credential ID", "Windows registry", e)
            return False

    def get_credential_id(self, username: str) -> Optional[str]:
        """Get stored credential ID for user from Windows registry"""
        try:
            import winreg
            with self.registry_key() as key:
                try:
                    value, reg_type = winreg.QueryValueEx(key, username)
                    if reg_type == winreg.REG_SZ and value:
                        logging.debug("Retrieved credential ID for user: %s", username)
                        return str(value)
                    else:
                        return None
                except FileNotFoundError:
                    logging.debug("No stored credential ID found for user: %s", username)
                    return None
        except Exception as e:
            logging.warning("Failed to retrieve credential ID for %s: %s", username, str(e))
            BiometricErrorHandler.create_storage_error("get credential ID", "Windows registry", e)
            return None

    def delete_credential_id(self, username: str) -> bool:
        """Delete stored credential ID for user from Windows registry"""
        try:
            import winreg
            with self.registry_key() as key:
                try:
                    winreg.DeleteValue(key, username)
                    logging.debug("Deleted stored credential ID for user: %s", username)
                    return True
                except FileNotFoundError:
                    logging.debug("Credential ID for user %s was already deleted", username)
                    return True
        except Exception as e:
            logging.warning("Failed to delete credential ID for %s: %s", username, str(e))
            BiometricErrorHandler.create_storage_error("delete credential ID", "Windows registry", e)
            return False


class WindowsHandler(BasePlatformHandler):
    """Windows-specific biometric handler"""

    def _create_storage_handler(self) -> StorageHandler:
        return WindowsStorageHandler()

    def _get_platform_name(self) -> str:
        return "Windows Hello"

    def _get_current_user_sid(self) -> Optional[str]:
        """Get current user SID using PowerShell and WMI"""
        try:
            cmd = ['powershell', '-Command', 
                   f"(Get-WmiObject -Class Win32_UserAccount -Filter \"Name='{getpass.getuser()}'\").SID"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            try:
                cmd = ['whoami', '/user', '/fo', 'csv']
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    sid_line = lines[1].split(',')
                    if len(sid_line) > 1:
                        return sid_line[1].strip('"')
            except subprocess.CalledProcessError:
                pass
            
            return None
        

    async def _check_biometrics(self) -> bool:
        """Check if biometrics (face/fingerprint) are enrolled using Windows Runtime API"""
        try:
            availability = await UserConsentVerifier.check_availability_async()

            if availability == UserConsentVerifierAvailability.AVAILABLE:
                return True
            else:
                return False
        except Exception as e:
            logging.debug("Failed to check biometrics availability: %s", str(e))
            return False

    # def _check_biometrics(self) -> bool:
    #     """Check if biometrics (face/fingerprint) are enrolled"""
    #     sid = self._get_current_user_sid()
    #     if not sid:
    #         return False
        
    #     reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\{}".format(sid)
    #     try:
    #         import winreg
    #         with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
    #             value, regtype = winreg.QueryValueEx(key, "EnrolledFactors")
    #             # 2 = Face, 8 = Fingerprint, 10 = Face and Fingerprint
    #             return value in [2, 8, 10]
    #     except (FileNotFoundError, ImportError):
    #         return False

    # def _check_pin_enrollment(self) -> bool:
    #     """Check if PIN is enrolled"""
    #     sid = self._get_current_user_sid()
    #     if not sid:
    #         return False
        
    #     reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{{D6886603-9D2F-4EB2-B667-1971041FA96B}}\{}".format(sid)
    #     try:
    #         import winreg
    #         with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
    #             value, regtype = winreg.QueryValueEx(key, "LogonCredsAvailable")
    #             return value == 1
    #     except (FileNotFoundError, ImportError):
    #         return False

    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect Windows Hello capabilities"""
        if os.name != 'nt':
            return False, "Not running on Windows"

        try:
            # Run the async biometrics check
            has_biometrics = asyncio.run(self._check_biometrics())
            
            if has_biometrics:
                return True, "Windows Hello available: Biometrics"
            else:
                return False, ERROR_MESSAGES['windows_hello_not_setup']

        except Exception as e:
            logging.warning("Error detecting Windows Hello: %s", str(e))
            return False, f"Error detecting Windows Hello: {str(e)}"

    def create_webauthn_client(self, data_collector):
        """Create Windows WebAuthn client"""
        try:
            from fido2.client.windows import WindowsClient
            return WindowsClient(client_data_collector=data_collector)
        except ImportError:
            raise Exception('Windows Hello client not available. Install fido2[pcsc]')

    def handle_credential_creation(self, creation_options: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Windows-specific credential creation"""
        return self._prepare_credential_creation_options(creation_options)

    def handle_authentication_options(self, pk_options: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Windows-specific authentication options"""
        return self._prepare_authentication_options(pk_options)

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