from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Tuple
import platform
import logging

from fido2.client import UserInteraction
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions


class BiometricInteraction(UserInteraction):
    """Cross-platform biometric authentication interaction handler"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._cancelled = False

    def prompt_up(self):
        """Prompt user for biometric authentication"""
        system = platform.system()
        message = {
            'Windows': "Please authenticate using Windows Hello...",
            'Darwin': "Please authenticate using Touch ID...",
        }.get(system, "Please authenticate using biometric authentication...")
        print(f"\n{message}")

    def request_pin(self, permissions, rp_id):
        """Request PIN if required"""
        if self._cancelled:
            raise Exception("Authentication cancelled by user")

        try:
            import getpass
            return getpass.getpass("Enter your security key PIN: ")
        except KeyboardInterrupt:
            self._cancelled = True
            raise Exception("Authentication cancelled by user")

    def request_uv(self, permissions, rp_id):
        """Request user verification"""
        return True

    def cancel(self):
        """Cancel the authentication process"""
        self._cancelled = True


class PlatformHandler(ABC):
    """Abstract base class for platform-specific biometric handlers"""

    @abstractmethod
    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect biometric capabilities for this platform"""
        pass

    @abstractmethod
    def create_webauthn_client(self, data_collector, timeout: int = 30):
        """Create platform-specific WebAuthn client"""
        pass

    @abstractmethod
    def handle_credential_creation(self, creation_options: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        """Handle platform-specific credential creation options"""
        pass

    @abstractmethod
    def handle_authentication_options(self, pk_options: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
        """Handle platform-specific authentication options"""
        pass

    @abstractmethod
    def perform_authentication(self, client, options: PublicKeyCredentialRequestOptions):
        """Perform platform-specific authentication"""
        pass

    @abstractmethod
    def perform_credential_creation(self, client, options: PublicKeyCredentialCreationOptions):
        """Perform platform-specific credential creation"""
        pass

    @abstractmethod
    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag for user"""
        pass

    @abstractmethod
    def set_biometric_flag(self, username: str, enabled: bool) -> bool:
        """Set biometric flag for user"""
        pass

    @abstractmethod
    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag for user"""
        pass


class StorageHandler(ABC):
    """Abstract base class for biometric flag storage"""

    @abstractmethod
    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag for user"""
        pass

    @abstractmethod
    def set_biometric_flag(self, username: str, enabled: bool) -> bool:
        """Set biometric flag for user"""
        pass

    @abstractmethod
    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag for user"""
        pass 