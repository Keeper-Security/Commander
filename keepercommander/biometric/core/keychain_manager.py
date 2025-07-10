import logging
import subprocess
import base64
from abc import ABC, abstractmethod
from typing import Optional

from ... import crypto
from ..utils.constants import MACOS_KEYCHAIN_SERVICE_PREFIX, ERROR_MESSAGES
from ..utils.error_handler import BiometricErrorHandler


class KeychainManager(ABC):
    """Abstract base class for platform-specific credential storage"""
    
    @abstractmethod
    def store_credential(self, credential_id: str, private_key_data: bytes, rp_id: str) -> bool:
        """Store a credential in platform-specific storage"""
        pass
    
    @abstractmethod
    def load_credential(self, credential_id: str) -> Optional[object]:
        """Load a credential from platform-specific storage"""
        pass
    
    @abstractmethod
    def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential from platform-specific storage"""
        pass
    
    @abstractmethod
    def credential_exists(self, credential_id: str) -> bool:
        """Check if credential exists in platform-specific storage"""
        pass


class MacOSKeychainManager(KeychainManager):
    """macOS Keychain credential manager"""
    
    def __init__(self):
        self.service_prefix = MACOS_KEYCHAIN_SERVICE_PREFIX
    
    def _authenticate_with_touchid(self, service_name: str, account_name: str) -> Optional[str]:
        """Authenticate with Touch ID and return the credential data"""
        try:
            self._show_touchid_dialog()
            return self._access_keychain_item(service_name, account_name)
        except Exception as e:
            logging.debug(f"Touch ID authentication failed: {str(e)}")
            return None
    
    def _show_touchid_dialog(self):
        """Show Touch ID authentication dialog"""
        info_script = '''
        display dialog "Touch ID Authentication Required

Keeper needs to access your biometric credential from the keychain.

Please authenticate with Touch ID to continue." buttons {"Cancel", "Authenticate"} default button "Authenticate" with title "Keeper Commander - Touch ID Required" with icon note
        '''
        
        try:
            result = subprocess.run(['osascript', '-e', info_script], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return None  # User cancelled
        except Exception:
            pass  # Continue without dialog if AppleScript fails
    
    def _access_keychain_item(self, service_name: str, account_name: str) -> Optional[str]:
        """Access keychain item with authentication"""
        try:
            result = subprocess.run([
                'security', 'find-internet-password',
                '-s', service_name,
                '-a', account_name,
                '-w'
            ], capture_output=True, text=True, timeout=30)
            
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception as e:
            logging.debug(f"Keychain access failed: {str(e)}")
            return None

    def store_credential(self, credential_id: str, private_key_data: bytes, rp_id: str) -> bool:
        """Store private key in macOS keychain with Touch ID access control"""
        try:
            encoded_key = base64.b64encode(private_key_data).decode('ascii')
            service_name = f"{self.service_prefix} - {rp_id}"
            account_name = f"webauthn-{credential_id}"
            
            # Store in keychain with Touch ID access control
            success = self._store_with_touchid_access(service_name, account_name, encoded_key, rp_id)
            
            if success:
                self._set_touchid_access_control(service_name, account_name)
            
            return success
            
        except Exception as e:
            BiometricErrorHandler.create_storage_error("store", "macOS keychain", e)
            return False
    
    def _store_with_touchid_access(self, service_name: str, account_name: str, 
                                  encoded_key: str, rp_id: str) -> bool:
        """Store credential with Touch ID access control"""
        try:
            # Primary storage attempt
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
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return True
            
            # Fallback attempt with AppleScript
            return self._store_with_applescript_fallback(service_name, account_name, encoded_key, rp_id)
            
        except Exception as e:
            logging.warning(f"Failed to store credential: {str(e)}")
            return False
    
    def _store_with_applescript_fallback(self, service_name: str, account_name: str, 
                                       encoded_key: str, rp_id: str) -> bool:
        """Fallback storage method using AppleScript"""
        try:
            applescript = f'''
            tell application "Keychain Access"
                activate
            end tell
            
            do shell script "security add-internet-password -s '{service_name}' -a '{account_name}' -w '{encoded_key}' -D 'WebAuthn Credential' -j 'Keeper biometric credential for {rp_id}' -T '' -U"
            '''
            
            subprocess.run(['osascript', '-e', applescript], 
                         capture_output=True, text=True, timeout=30)
            return True
            
        except Exception as e:
            logging.warning(f"AppleScript fallback failed: {str(e)}")
            return False
    
    def _set_touchid_access_control(self, service_name: str, account_name: str):
        """Set Touch ID access control for stored credential"""
        try:
            subprocess.run([
                'security', 'set-internet-password-partition-list',
                '-s', service_name,
                '-a', account_name,
                '-S', 'SmartCard,TouchID',
                '-k', ''  # Use empty string to prompt for Touch ID
            ], capture_output=True, text=True, timeout=30)
            
        except Exception as e:
            logging.debug(f"Could not set Touch ID access control: {str(e)}")

    def load_credential(self, credential_id: str) -> Optional[object]:
        """Load private key from macOS keychain using Touch ID"""
        try:
            account_name = f"webauthn-{credential_id}"
            service_names = [f"{self.service_prefix} - keepersecurity.com"]
            
            for service_name in service_names:
                encoded_key = self._load_from_service(service_name, account_name)
                if encoded_key:
                    key_data = base64.b64decode(encoded_key)
                    return crypto.load_ec_private_key(key_data)
            
            return None
            
        except Exception as e:
            BiometricErrorHandler.create_storage_error("load", "macOS keychain", e)
            return None
    
    def _load_from_service(self, service_name: str, account_name: str) -> Optional[str]:
        """Load credential from specific service"""
        try:
            # Try direct access first
            result = subprocess.run([
                'security', 'find-internet-password',
                '-s', service_name,
                '-a', account_name,
                '-w'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return result.stdout.strip()
            
            # If access denied, try with Touch ID authentication
            if result.returncode == 44:  # Item exists but access denied
                return self._authenticate_with_touchid(service_name, account_name)
                
        except Exception:
            pass
        
        return None

    def delete_credential(self, credential_id: str) -> bool:
        """Delete private key from macOS keychain"""
        try:
            account_name = f"webauthn-{credential_id}"
            service_names = [f"{self.service_prefix} - keepersecurity.com"]
            
            success = False
            for service_name in service_names:
                try:
                    result = subprocess.run([
                        'security', 'delete-internet-password',
                        '-s', service_name,
                        '-a', account_name
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        success = True
                        
                except Exception:
                    continue
            
            return success
                    
        except Exception as e:
            BiometricErrorHandler.create_storage_error("delete", "macOS keychain", e)
            return False

    def credential_exists(self, credential_id: str) -> bool:
        """Check if credential exists in macOS keychain"""
        try:
            account_name = f"webauthn-{credential_id}"
            service_names = [f"{self.service_prefix} - keepersecurity.com"]
            
            for service_name in service_names:
                try:
                    result = subprocess.run([
                        'security', 'find-internet-password',
                        '-s', service_name,
                        '-a', account_name,
                        '-w'
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        return True
                        
                except Exception:
                    continue
            
            return False
            
        except Exception:
            return False


class WindowsKeychainManager(KeychainManager):
    """Windows credential storage manager (for future implementation)"""
    
    def store_credential(self, credential_id: str, private_key_data: bytes, rp_id: str) -> bool:
        """Store credential in Windows credential store (placeholder)"""
        logging.warning("Windows credential storage not yet implemented")
        return False
    
    def load_credential(self, credential_id: str) -> Optional[object]:
        """Load credential from Windows credential store (placeholder)"""
        return None
    
    def delete_credential(self, credential_id: str) -> bool:
        """Delete credential from Windows credential store (placeholder)"""
        return False
    
    def credential_exists(self, credential_id: str) -> bool:
        """Check if credential exists in Windows credential store (placeholder)"""
        return False 