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
  account / key         : config  →  JSON blob of all protected fields
"""

import json
import logging
from typing import Optional

from ..loader import SecureStorageBase, SecureStorageException

# Top-level service / application name visible in the OS keychain UI.
# On macOS this appears in Keychain Access; on Windows in Credential Manager.
KEYRING_SERVICE = 'KeeperCommander'

# Keyring account name used to store the config blob.
KEYRING_CONFIG_KEY = 'config'


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
            raw = keyring.get_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY)
            if not raw:
                return {}

            config = json.loads(raw)
            if not isinstance(config, dict):
                raise SecureStorageException(
                    'Keychain entry is not a valid JSON object.'
                )

            logging.debug(
                'Loaded %d field(s) from OS keychain (%s).', len(config), KEYRING_SERVICE
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
            config_json = json.dumps(configuration, indent=4, sort_keys=True)
            keyring.set_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY, config_json)

            logging.debug(
                'Stored %d field(s) in OS keychain (%s).', len(configuration), KEYRING_SERVICE
            )
            return None

        except SecureStorageException:
            raise
        except Exception as e:
            raise SecureStorageException(
                f'Failed to store configuration in OS keychain: {e}'
            )
