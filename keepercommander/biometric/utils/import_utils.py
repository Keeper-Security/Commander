"""
Import utilities for handling conditional platform-specific imports
"""
import logging
from typing import Optional, Any


class ConditionalImporter:
    """Utility class for handling conditional imports"""
    
    @staticmethod
    def import_module(module_name: str, platform_name: str = "Platform") -> Optional[Any]:
        """Import a module conditionally with consistent error handling"""
        try:
            return __import__(module_name)
        except ImportError as e:
            logging.debug(f"{platform_name} module '{module_name}' not available: {e}")
            return None

    @staticmethod
    def import_winreg() -> Optional[Any]:
        """Import Windows registry module conditionally"""
        return ConditionalImporter.import_module('winreg', 'Windows')

    @staticmethod
    def import_local_authentication() -> Optional[Any]:
        """Import macOS LocalAuthentication framework conditionally"""
        return ConditionalImporter.import_module('LocalAuthentication', 'macOS')

    @staticmethod
    def import_plistlib() -> Optional[Any]:
        """Import plistlib for macOS preference handling"""
        return ConditionalImporter.import_module('plistlib', 'macOS')

    @staticmethod
    def import_cbor2() -> Optional[Any]:
        """Import CBOR2 for WebAuthn data encoding"""
        return ConditionalImporter.import_module('cbor2', 'WebAuthn')

    @staticmethod
    def import_fido2_windows_client() -> Optional[Any]:
        """Import Windows FIDO2 client conditionally"""
        try:
            from fido2.client.windows import WindowsClient
            return WindowsClient
        except ImportError as e:
            logging.debug(f"Windows FIDO2 client not available: {e}")
            return None

    @staticmethod
    def check_fido2_availability() -> bool:
        """Check if FIDO2 libraries are available"""
        try:
            import fido2.client
            import fido2.webauthn
            return True
        except ImportError:
            return False

    @staticmethod
    def get_import_error_message(module_name: str, platform_name: str = "") -> str:
        """Generate consistent import error messages"""
        if platform_name:
            return f"{platform_name} dependency '{module_name}' not available"
        else:
            return f"Required dependency '{module_name}' not available" 