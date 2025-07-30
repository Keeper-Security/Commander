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

from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple

from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from ..utils.constants import DEFAULT_BIOMETRIC_TIMEOUT
from ... import utils


class PlatformHandler(ABC):
    """Abstract base class for platform-specific biometric handlers"""

    @abstractmethod
    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect biometric capabilities for this platform"""
        pass

    @abstractmethod
    def create_webauthn_client(self, data_collector):
        """Create platform-specific WebAuthn client"""
        pass

    @abstractmethod
    def handle_credential_creation(self, creation_options: Dict[str, Any]) -> Dict[str, Any]:
        """Handle platform-specific credential creation options"""
        pass

    @abstractmethod
    def handle_authentication_options(self, pk_options: Dict[str, Any]) -> Dict[str, Any]:
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


class StorageHandler(ABC):
    """Abstract base class for biometric flag storage"""

    @abstractmethod
    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag for user"""
        pass

    @abstractmethod
    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag for user"""
        pass


class BasePlatformHandler(PlatformHandler):
    """Base implementation for platform handlers with common functionality"""

    def __init__(self):
        self.storage_handler = self._create_storage_handler()

    @abstractmethod
    def _create_storage_handler(self) -> StorageHandler:
        """Create platform-specific storage handler"""
        pass

    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag for user"""
        return self.storage_handler.get_biometric_flag(username)

    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag for user"""
        return self.storage_handler.delete_biometric_flag(username)

    def _prepare_credential_creation_options(self, creation_options: Dict[str, Any]) -> Dict[str, Any]:
        """Common credential creation options preparation"""
        if isinstance(creation_options['user'].get('id'), str):
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

        # Apply default authenticator selection
        default_selection = {
            'authenticatorAttachment': 'platform',
            'userVerification': 'required',
            'residentKey': 'required'
        }
            
        creation_options['authenticatorSelection'].update(default_selection)
        
        if 'timeout' not in creation_options:
            creation_options['timeout'] = DEFAULT_BIOMETRIC_TIMEOUT * 1000

        return creation_options

    def _prepare_authentication_options(self, pk_options: Dict[str, Any]) -> Dict[str, Any]:
        """Common authentication options preparation"""
        pk_options.pop('hints', None)
        pk_options.pop('extensions', None)

        # Clean up empty transports
        if 'allowCredentials' in pk_options:
            for cred in pk_options['allowCredentials']:
                if 'transports' in cred and not cred['transports']:
                    cred.pop('transports')

        pk_options['userVerification'] = 'required'
        
        if 'timeout' not in pk_options:
            pk_options['timeout'] = DEFAULT_BIOMETRIC_TIMEOUT * 1000

        return pk_options

    def _handle_authentication_error(self, error: Exception, platform_name: str = "Biometric") -> Exception:
        """Common error handling for authentication failures"""
        from ..utils.error_handler import BiometricErrorHandler
        return BiometricErrorHandler.handle_authentication_error(error, platform_name)

    def _handle_credential_creation_error(self, error: Exception, platform_name: str = "Biometric") -> Exception:
        """Common error handling for credential creation failures"""
        from ..utils.error_handler import BiometricErrorHandler
        return BiometricErrorHandler.handle_credential_creation_error(error, platform_name)

    @abstractmethod
    def _get_platform_name(self) -> str:
        """Get platform-specific name for error messages"""
        pass 