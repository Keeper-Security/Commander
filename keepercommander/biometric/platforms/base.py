from abc import ABC, abstractmethod
from typing import Tuple

from ..core.base import PlatformHandler, StorageHandler


class BasePlatformHandler(PlatformHandler):
    """Base implementation for platform handlers"""

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