from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any

from ..core.base import PlatformHandler, StorageHandler
from ..utils.constants import DEFAULT_REGISTRATION_TIMEOUT, DEFAULT_AUTHENTICATION_TIMEOUT
from ... import utils


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

    def set_biometric_flag(self, username: str, enabled: bool) -> bool:
        """Set biometric flag for user"""
        return self.storage_handler.set_biometric_flag(username, enabled)

    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag for user"""
        return self.storage_handler.delete_biometric_flag(username)

    def _prepare_credential_creation_options(self, creation_options: Dict[str, Any], 
                                           timeout: int = DEFAULT_REGISTRATION_TIMEOUT,
                                           platform_settings: Dict[str, Any] = None) -> Dict[str, Any]:
        """Common credential creation options preparation"""
        # Convert user ID to bytes
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
            'userVerification': 'required'
        }
        
        # Apply platform-specific settings
        if platform_settings:
            default_selection.update(platform_settings)
            
        creation_options['authenticatorSelection'].update(default_selection)
        creation_options['attestation'] = 'none'
        
        if 'timeout' not in creation_options:
            creation_options['timeout'] = timeout * 1000

        return creation_options

    def _prepare_authentication_options(self, pk_options: Dict[str, Any], 
                                      timeout: int = DEFAULT_AUTHENTICATION_TIMEOUT) -> Dict[str, Any]:
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
            pk_options['timeout'] = timeout * 1000

        return pk_options

    def _handle_authentication_error(self, error: Exception, platform_name: str = "Biometric") -> Exception:
        """Common error handling for authentication failures"""
        error_msg = str(error).lower()
        
        if any(keyword in error_msg for keyword in ["cancelled", "denied"]):
            return Exception(f"{platform_name} authentication cancelled")
        elif "timeout" in error_msg:
            return Exception(f"{platform_name} authentication timed out")
        elif "not available" in error_msg:
            return Exception(f"{platform_name} is not available or not set up")
        elif "parameter is incorrect" in error_msg:
            return Exception(f"{platform_name} parameter error - please check your biometric setup")
        else:
            return Exception(f"{platform_name} authentication failed: {str(error)}")

    def _handle_credential_creation_error(self, error: Exception, platform_name: str = "Biometric") -> Exception:
        """Common error handling for credential creation failures"""
        error_msg = str(error).lower()
        
        if any(keyword in error_msg for keyword in ["cancelled", "denied"]):
            return Exception(f"{platform_name} registration cancelled")
        elif "timeout" in error_msg:
            return Exception(f"{platform_name} registration timed out")
        elif "not available" in error_msg:
            return Exception(f"{platform_name} is not available or not set up")
        else:
            return Exception(f"{platform_name} registration failed: {str(error)}")

    @abstractmethod
    def _get_platform_name(self) -> str:
        """Get platform-specific name for error messages"""
        pass

    @abstractmethod
    def _get_platform_settings(self) -> Dict[str, Any]:
        """Get platform-specific settings for credential creation"""
        pass 