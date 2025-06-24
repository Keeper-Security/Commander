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
import subprocess
import base64
from typing import Optional

from .... import crypto
from ...utils.constants import MACOS_KEYCHAIN_SERVICE_PREFIX, DEFAULT_BIOMETRIC_TIMEOUT
from ...utils.error_handler import BiometricErrorHandler


class MacOSKeychainManager:
    """macOS Keychain credential manager"""
    
    def __init__(self):
        self.service_prefix = MACOS_KEYCHAIN_SERVICE_PREFIX
    
    def _authenticate_with_touchid(self, service_name: str, account_name: str, timeout_seconds: Optional[float] = None) -> Optional[str]:
        """Authenticate with Touch ID and return the credential data"""
        try:
            timeout = timeout_seconds or DEFAULT_BIOMETRIC_TIMEOUT
            return self._access_keychain_item(service_name, account_name, timeout)
        except Exception as e:
            logging.debug(f"Touch ID authentication failed: {str(e)}")
            return None

    def _access_keychain_item(self, service_name: str, account_name: str, timeout_seconds: float) -> Optional[str]:
        """Access keychain item with authentication"""
        try:
            result = subprocess.run([
                'security', 'find-internet-password',
                '-s', service_name,
                '-a', account_name,
                '-w'
            ], capture_output=True, text=True, timeout=timeout_seconds)
            
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception as e:
            logging.debug(f"Keychain access failed: {str(e)}")
            return None

    def store_credential(self, credential_id: str, private_key_data: bytes, rp_id: str, timeout_seconds: Optional[float] = None) -> bool:
        """Store private key in macOS keychain with Touch ID access control"""
        try:
            timeout = timeout_seconds or DEFAULT_BIOMETRIC_TIMEOUT
            encoded_key = base64.b64encode(private_key_data).decode('ascii')
            service_name = f"{self.service_prefix} - {rp_id}"
            account_name = f"webauthn-{credential_id}"
            
            success = self._store_with_touchid_access(service_name, account_name, encoded_key, rp_id, timeout)
            
            if success:
                self._set_touchid_access_control(service_name, account_name, timeout)
            
            return success
            
        except Exception as e:
            BiometricErrorHandler.create_storage_error("store", "macOS keychain", e)
            return False
    
    def _store_with_touchid_access(self, service_name: str, account_name: str, 
                                  encoded_key: str, rp_id: str, timeout_seconds: float) -> bool:
        """Store credential with Touch ID access control"""
        try:
            result = subprocess.run([
                'security', 'add-internet-password',
                '-s', service_name,
                '-a', account_name,
                '-w', encoded_key,
                '-D', 'WebAuthn Credential',
                '-j', f'Keeper biometric credential for {rp_id}',
                '-A',  # Allow access from any application
                '-T', '',  # No specific application restrictions
                '-U'  # Update if exists
            ], capture_output=True, text=True, timeout=timeout_seconds)
            
            if result.returncode == 0:
                return True
            
            return False
            
        except Exception as e:
            logging.warning(f"Failed to store credential: {str(e)}")
            return False
    
    def _set_touchid_access_control(self, service_name: str, account_name: str, timeout_seconds: float):
        """Set Touch ID access control for stored credential"""
        try:
            subprocess.run([
                'security', 'set-internet-password-partition-list',
                '-s', service_name,
                '-a', account_name,
                '-S', 'SmartCard,TouchID',
                '-k', ''
            ], capture_output=True, text=True, timeout=timeout_seconds)
            
        except Exception as e:
            logging.debug(f"Could not set Touch ID access control: {str(e)}")

    def load_credential(self, credential_id: str, rp_id: Optional[str] = None, timeout_seconds: Optional[float] = None) -> Optional[object]:
        """Load private key from macOS keychain using Touch ID"""
        try:
            timeout = timeout_seconds or DEFAULT_BIOMETRIC_TIMEOUT
            account_name = f"webauthn-{credential_id}"
            if not rp_id:
                raise Exception("RP ID is required for credential loading")
            service_names = [f"{self.service_prefix} - {rp_id}"]
            
            for service_name in service_names:
                encoded_key = self._load_from_service(service_name, account_name, timeout)
                if encoded_key:
                    key_data = base64.b64decode(encoded_key)
                    return crypto.load_ec_private_key(key_data)
            
            return None
            
        except Exception as e:
            BiometricErrorHandler.create_storage_error("load", "macOS keychain", e)
            return None
    
    def _load_from_service(self, service_name: str, account_name: str, timeout_seconds: float) -> Optional[str]:
        """Load credential from specific service"""
        try:
            result = subprocess.run([
                'security', 'find-internet-password',
                '-s', service_name,
                '-a', account_name,
                '-w'
            ], capture_output=True, text=True, timeout=timeout_seconds)
            
            if result.returncode == 0:
                return result.stdout.strip()
            
            if result.returncode == 44:
                return self._authenticate_with_touchid(service_name, account_name, timeout_seconds)
                
        except Exception:
            pass
        
        return None

    def delete_credential(self, credential_id: str, rp_id: Optional[str] = None, timeout_seconds: Optional[float] = None) -> bool:
        """Delete private key from macOS keychain"""
        try:
            timeout = timeout_seconds or DEFAULT_BIOMETRIC_TIMEOUT
            account_name = f"webauthn-{credential_id}"
            if not rp_id:
                raise Exception("RP ID is required for credential deletion")
            service_names = [f"{self.service_prefix} - {rp_id}"]
            
            success = False
            for service_name in service_names:
                try:
                    result = subprocess.run([
                        'security', 'delete-internet-password',
                        '-s', service_name,
                        '-a', account_name
                    ], capture_output=True, text=True, timeout=timeout)
                    
                    if result.returncode == 0:
                        success = True
                        
                except Exception:
                    continue
            
            return success
                    
        except Exception as e:
            BiometricErrorHandler.create_storage_error("delete", "macOS keychain", e)
            return False

    def credential_exists(self, credential_id: str, rp_id: Optional[str] = None, timeout_seconds: Optional[float] = None) -> bool:
        """Check if credential exists in macOS keychain"""
        try:
            timeout = timeout_seconds or DEFAULT_BIOMETRIC_TIMEOUT
            account_name = f"webauthn-{credential_id}"
            if not rp_id:
                raise Exception("RP ID is required for credential existence check")
            service_names = [f"{self.service_prefix} - {rp_id}"]
            
            for service_name in service_names:
                try:
                    result = subprocess.run([
                        'security', 'find-internet-password',
                        '-s', service_name,
                        '-a', account_name,
                        '-w'
                    ], capture_output=True, text=True, timeout=timeout)
                    
                    if result.returncode == 0:
                        return True
                        
                except Exception:
                    continue
            
            return False
            
        except Exception:
            return False 