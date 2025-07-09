import logging
import subprocess
import base64
from abc import ABC, abstractmethod
from typing import Optional

from ... import crypto


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
        self.service_prefix = "Keeper WebAuthn"
    
    def store_credential(self, credential_id: str, private_key_data: bytes, rp_id: str) -> bool:
        """Store private key in macOS keychain"""
        try:
            encoded_key = base64.b64encode(private_key_data).decode('ascii')
            service_name = f"{self.service_prefix} - {rp_id}"
            account_name = f"webauthn-{credential_id}"
            
            result = subprocess.run([
                'security', 'add-internet-password',
                '-s', service_name,
                '-a', account_name,
                '-w', encoded_key,
                '-D', 'WebAuthn Credential',
                '-j', f'Keeper biometric credential for {rp_id}',
                '-T', '',
                '-U'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logging.warning(f"Could not store in keychain: {result.stderr}")
                return False
                
            return True
            
        except Exception as e:
            logging.warning(f"Error storing in keychain: {str(e)}")
            return False
    
    def load_credential(self, credential_id: str) -> Optional[object]:
        """Load private key from macOS keychain"""
        try:
            account_name = f"webauthn-{credential_id}"
            possible_services = [
                f"{self.service_prefix} - keepersecurity.com",
                # Add other possible service names for backward compatibility
            ]
            
            for service_name in possible_services:
                try:
                    result = subprocess.run([
                        'security', 'find-internet-password',
                        '-s', service_name,
                        '-a', account_name,
                        '-w'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        encoded_key = result.stdout.strip()
                        if encoded_key:
                            key_data = base64.b64decode(encoded_key)
                            return crypto.load_ec_private_key(key_data)
                            
                except Exception:
                    continue
            
            return None
            
        except Exception as e:
            logging.warning(f"Error loading from keychain: {str(e)}")
            return None
    
    def delete_credential(self, credential_id: str) -> bool:
        """Delete private key from macOS keychain"""
        try:
            account_name = f"webauthn-{credential_id}"
            possible_services = [
                f"{self.service_prefix} - keepersecurity.com",
            ]
            
            success = False
            for service_name in possible_services:
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
            logging.warning(f"Error deleting from keychain: {str(e)}")
            return False
    
    def credential_exists(self, credential_id: str) -> bool:
        """Check if credential exists in macOS keychain"""
        try:
            account_name = f"webauthn-{credential_id}"
            possible_services = [
                f"{self.service_prefix} - keepersecurity.com",
            ]
            
            for service_name in possible_services:
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
        # TODO: Implement Windows credential storage
        logging.warning("Windows credential storage not yet implemented")
        return False
    
    def load_credential(self, credential_id: str) -> Optional[object]:
        """Load credential from Windows credential store (placeholder)"""
        # TODO: Implement Windows credential loading
        return None
    
    def delete_credential(self, credential_id: str) -> bool:
        """Delete credential from Windows credential store (placeholder)"""
        # TODO: Implement Windows credential deletion
        return False
    
    def credential_exists(self, credential_id: str) -> bool:
        """Check if credential exists in Windows credential store (placeholder)"""
        # TODO: Implement Windows credential existence check
        return False 