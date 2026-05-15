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

"""
OS-native keychain storage backend for Keeper Commander.

Protected config fields are stored as a single JSON blob in one keyring entry.
The OS keychain (macOS Keychain / Windows Credential Manager / Linux Secret Service)
handles encryption and integrity natively, so no separate integrity hash is needed.
Backend availability is detected by inspecting the keyring backend module name,
consistent with KeyringConfigStorage.is_available() in the KSM CLI.

Storage layout in the OS keychain:
  service / application : KeeperCommander
  account / key         : <url netloc>  →  JSON blob of all protected fields

The account key is derived from the netloc of the storage URL (e.g. the 8-char
SHA-256 prefix of the config file path written by _make_os_keychain_url).  This
allows multiple Commander config files on the same OS user to coexist without
overwriting each other's keychain entry.  Legacy entries written with the old
hardcoded key 'config' are handled by _keychain_account_from_url in loader.py.
"""

import json
import logging
from urllib.parse import urlparse
from typing import Optional

from ..loader import SecureStorageBase, SecureStorageException

# Top-level service / application name visible in the OS keychain UI.
# On macOS this appears in Keychain Access; on Windows in Credential Manager.
KEYRING_SERVICE = 'KeeperCommander'


class SecureStorage(SecureStorageBase):
    """OS-native keychain storage backend for Commander configuration.

    Delegates to the appropriate OS facility via the Python ``keyring`` library:
      - macOS   → Keychain (Security framework)
      - Windows → Credential Manager (DPAPI-backed)
      - Linux desktop → SecretService API (GNOME Keyring / KWallet)

    The entire set of protected configuration fields is serialised to a single
    JSON blob and stored under one keyring entry.  The OS keychain provides
    encryption and access control natively.

    No sensitive data is written back to config.json; the file only retains the
    ``config_storage`` key that points to this backend.
    """

    @staticmethod
    def _account_key(url: str) -> str:
        """Derive the keyring account key from the storage URL netloc.

        Each config file gets a unique netloc (an 8-char path hash) via
        _make_os_keychain_url in loader.py, so multiple profiles on the
        same OS user do not overwrite each other.  Falls back to 'config'
        for legacy entries written before per-profile keys were introduced.
        """
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
