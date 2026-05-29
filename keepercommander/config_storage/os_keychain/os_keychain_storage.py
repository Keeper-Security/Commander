#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""OS-native keychain storage backend for Keeper Commander (macOS Keychain, Windows Credential Manager, Linux Secret Service)."""

import json
import logging
from urllib.parse import urlparse
from typing import Optional

from ..loader import SecureStorageBase, SecureStorageException

# Top-level service / application name visible in the OS keychain UI.
# On macOS this appears in Keychain Access; on Windows in Credential Manager.
KEYRING_SERVICE = 'KeeperCommander'


class SecureStorage(SecureStorageBase):
    """Stores protected config fields as a JSON blob in the OS keychain via the keyring library.
    Supports macOS Keychain, Windows Credential Manager, and Linux SecretService.
    config.json retains only the config_storage pointer — no credentials on disk.
    """

    @staticmethod
    def _account_key(url: str) -> str:
        """Return keyring account key from URL netloc; falls back to 'config' for legacy entries."""
        netloc = urlparse(url).netloc if url else ''
        return netloc if netloc else 'config'

    def load_configuration(self, url: str, encrypted_data: Optional[bytes] = None) -> dict:
        """Retrieve protected fields from the OS keychain.

        ``encrypted_data`` is unused — the OS keychain handles encryption
        internally and returns plaintext to authorised callers.
        """
        try:
            import keyring
        except ImportError:
            raise SecureStorageException(
                'keyring package is not installed.\nRun: pip install keyring'
            )

        try:
            account_key = self._account_key(url)
            raw = keyring.get_password(KEYRING_SERVICE, account_key)
            if not raw:
                return {}

            config = json.loads(raw)
            if not isinstance(config, dict):
                raise SecureStorageException(
                    'Keychain entry is not a valid JSON object.'
                )

            logging.debug(
                'Loaded %d field(s) from OS keychain (%s / %s).',
                len(config), KEYRING_SERVICE, account_key
            )
            return config

        except SecureStorageException:
            raise
        except Exception as e:
            raise SecureStorageException(
                f'Failed to load configuration from OS keychain: {e}'
            )

    def store_configuration(self, url: str, configuration: dict) -> Optional[bytes]:
        """Store protected fields in the OS keychain as a single JSON blob.

        Returns ``None`` because no encrypted blob needs to be embedded in
        config.json — the keychain manages encryption internally.
        """
        try:
            import keyring
        except ImportError:
            raise SecureStorageException(
                'keyring package is not installed.\nRun: pip install keyring'
            )

        try:
            account_key = self._account_key(url)
            config_json = json.dumps(configuration, indent=4, sort_keys=True)
            keyring.set_password(KEYRING_SERVICE, account_key, config_json)

            logging.debug(
                'Stored %d field(s) in OS keychain (%s / %s).',
                len(configuration), KEYRING_SERVICE, account_key
            )
            return None

        except SecureStorageException:
            raise
        except Exception as e:
            raise SecureStorageException(
                f'Failed to store configuration in OS keychain: {e}'
            )
