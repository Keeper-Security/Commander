from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Tuple

from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions


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