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

from typing import Tuple
import platform
import logging

from .base import PlatformHandler
from ..utils.constants import PLATFORM_WINDOWS, PLATFORM_DARWIN


class BiometricDetector:
    """Centralized biometric capability detection"""

    def __init__(self):
        self._platform_handlers = self._load_platform_handlers()

    def _load_platform_handlers(self) -> dict:
        """Load available platform handlers"""
        handlers = {}

        try:
            if platform.system() == PLATFORM_WINDOWS:
                from .windows import WindowsHandler
                handlers[PLATFORM_WINDOWS] = WindowsHandler()
        except ImportError:
            logging.debug("Windows platform handler not available")

        try:
            if platform.system() == PLATFORM_DARWIN:
                from .macos import MacOSHandler
                handlers[PLATFORM_DARWIN] = MacOSHandler()
        except ImportError:
            logging.debug("macOS platform handler not available")

        return handlers

    def detect_platform_capabilities(self) -> Tuple[bool, str]:
        """Detect biometric capabilities for current platform"""
        current_platform = platform.system()

        if current_platform not in self._platform_handlers:
            return False, f"Biometric authentication not supported on {current_platform}"

        handler = self._platform_handlers[current_platform]
        return handler.detect_capabilities()

    def get_platform_handler(self) -> PlatformHandler:
        """Get platform handler for current system"""
        current_platform = platform.system()

        if current_platform not in self._platform_handlers:
            raise Exception(f"Biometric authentication not supported on {current_platform}")

        return self._platform_handlers[current_platform] 