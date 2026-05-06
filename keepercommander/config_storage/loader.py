#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import importlib
import json
import logging
import os
import pkgutil
from typing import Tuple, Union, List, Optional

from urllib.parse import urlparse
from ..params import KeeperParams
from .. import config_storage, utils

CONFIG_STORAGE_URL = 'config_storage'
PROTECTED_PROPERTIES = ['server', 'device_token', ('private_key', 'device_private_key')]   # type: List[Union[str, Tuple[str, str]]]
PROTECTED_CONNECTED_PROPERTIES = ['user', 'clone_code']   # type: List[Union[str, Tuple[str, str]]]
PROTECTED_READONLY_PROPERTIES = ['password']
EDITABLE_PROPERTIES = ['proxy']
BOOL_PROPERTIES = ['debug', 'batch_mode', 'unmask_all']
INT_PROPERTIES = ['timedelay', 'logout_timer']
ENCRYPTED_DATA = 'encrypted_data'

# URL used when Commander auto-selects the OS-native keychain backend.
OS_KEYCHAIN_URL = 'os-keychain://default'


def is_os_keychain_available():  # type: () -> bool
    """Return True if a real OS-native keychain is available and usable.

    Uses the same detection logic as KeyringConfigStorage.is_available() in the
    Keeper Secrets Manager CLI (KSM-800): checks whether the keyring backend
    module name contains 'fail', which is the indicator used by the keyring
    library when no real OS backend is found (e.g. headless Linux).

    Returns False when:
    - keyring is not installed
    - the runtime is headless Linux with no SecretService daemon
    - keyring fell back to a plaintext or fail backend
    - any other error prevents keychain access
    """
    try:
        import keyring
        backend = keyring.get_keyring()
        if 'fail' in backend.__class__.__module__.lower():
            logging.debug(
                'OS keychain not available (backend module: %s). '
                'Falling back to file-based config storage.',
                backend.__class__.__module__
            )
            return False
        logging.debug(
            'OS keychain available via backend: %s.%s',
            backend.__class__.__module__, backend.__class__.__name__
        )
        return True
    except ImportError:
        logging.debug('OS keychain not available: keyring package is not installed.')
        return False
    except Exception as e:
        logging.debug('OS keychain probe failed: %s', e)
        return False


class SecureStorageException(Exception):
    pass


class SecureStorageBase(abc.ABC):
    @abc.abstractmethod
    def load_configuration(self, url, encrypted_data=None):   # type: (str, Optional[bytes]) -> dict
        pass

    @abc.abstractmethod
    def store_configuration(self, url, configuration):   # type: (str, dict) -> Optional[bytes]
        pass


def _get_plugin(url):  # type: (str) -> SecureStorageBase
    if not url:
        raise SecureStorageException(f'Configuration file error: "{CONFIG_STORAGE_URL}" cannot be empty')
    par = urlparse(url)
    if not par.scheme:
        raise SecureStorageException(f'Configuration file error: "{CONFIG_STORAGE_URL}" is not URL')

    plugin_name = par.scheme
    if not any(x for x in pkgutil.iter_modules(config_storage.__path__) if x.name == plugin_name):
        raise SecureStorageException(f'Protected storage "{plugin_name}" is not supported')

    module_name = f'keepercommander.config_storage.{plugin_name}'
    try:
        logging.debug('Importing config storage module "%s"', module_name)
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as me:
        dependency_not_installed = f'{plugin_name} requires {me.name} package to be installed\n' \
                                   f'pip install {me.name}'
        raise SecureStorageException(dependency_not_installed)
    if not hasattr(module, 'SecureStorage'):
        raise SecureStorageException(f'Protected storage "{plugin_name}" is invalid')
    storage_class = getattr(module, 'SecureStorage')
    storage = storage_class()     # type: SecureStorageBase
    if not isinstance(storage, SecureStorageBase):
        raise SecureStorageException(f'Protected storage "{plugin_name}" is invalid')
    return storage


def split_name(name):   # type: (Union[str, Tuple[str, str]]) -> Tuple[str, str]
    if isinstance(name, tuple):
        return name
    return name, name


_KEYCHAIN_SERVICE = 'KeeperCommander'
_KEYCHAIN_CONFIG_KEY = 'config'


def _clear_os_keychain_if_present():
    """Delete Commander's keychain entry if it exists.

    Called when switching to file-based storage so that stale credentials
    are not left orphaned in the OS keychain.  Silently ignored if the
    keyring package is not installed or no entry exists.
    """
    try:
        import keyring
        try:
            if keyring.get_password(_KEYCHAIN_SERVICE, _KEYCHAIN_CONFIG_KEY) is not None:
                keyring.delete_password(_KEYCHAIN_SERVICE, _KEYCHAIN_CONFIG_KEY)
                logging.debug('Deleted keychain entry: service=%s account=%s',
                              _KEYCHAIN_SERVICE, _KEYCHAIN_CONFIG_KEY)
        except keyring.errors.PasswordDeleteError:
            pass  # Entry didn't exist — nothing to do.
    except Exception as exc:
        logging.debug('Could not clear OS keychain entries: %s', exc)


def store_config_properties(params):
    if not isinstance(params, KeeperParams):
        return
    if not isinstance(params.config, dict):
        params.config = {}

    protected_properties = PROTECTED_PROPERTIES
    if params.session_token:
        protected_properties += PROTECTED_CONNECTED_PROPERTIES
    # commit changes from params to config
    for name in protected_properties + EDITABLE_PROPERTIES:
        config_name, params_name = split_name(name)
        if hasattr(params, params_name):
            value = getattr(params, params_name)
            if value:
                params.config[config_name] = value
            elif config_name in params.config:
                del params.config[config_name]

    config_json = params.config.copy()

    # ------------------------------------------------------------------ #
    # Storage backend selection — mirrors KSM CLI's Profile.init() logic  #
    # ------------------------------------------------------------------ #
    # Sentinel value written by `keeper login --config-file` (or the
    # KEEPER_CONFIG_STORAGE=file env var) to explicitly opt into file-based
    # storage.  We strip it from config_json before writing so the JSON file
    # stays clean, but keep it in params.config so it persists for the
    # lifetime of this process (the next startup reads it from the file,
    # which won't have the sentinel — that is intentional: if the user runs
    # `keeper login` next time without --config-file, auto-detection runs
    # again).  Persisting across restarts requires the file sentinel to stay
    # in config.json, so we leave it in config_json as-is below.

    explicitly_use_file = (
        config_json.get(CONFIG_STORAGE_URL) == 'file'
        or os.getenv('KEEPER_CONFIG_STORAGE', '').lower() == 'file'
    )

    if explicitly_use_file:
        # User opted into file storage.  Remove any existing keychain URL so
        # the plugin dispatch block below is skipped entirely, and keep the
        # 'file' sentinel in the written JSON so the choice survives restarts.
        logging.debug('File-based config storage selected (--config-file or KEEPER_CONFIG_STORAGE=file).')
        config_json[CONFIG_STORAGE_URL] = 'file'

        # Clear any stale keychain entry so orphaned credentials don't linger
        # in the OS keychain after the user switches to file-based storage.
        # Mirrors the principle that only one storage backend is authoritative
        # at a time (consistent with KSM CLI behaviour).
        _clear_os_keychain_if_present()

    elif CONFIG_STORAGE_URL not in config_json:
        # No explicit choice and no previously persisted backend.
        # Auto-activate the OS-native keychain, matching KSM CLI's default
        # behaviour of using the keychain whenever it is available.
        # Skipped when running in headless/CI environments (keychain unavailable).
        if is_os_keychain_available():
            logging.debug('Auto-selecting OS keychain backend for config storage.')
            params.config[CONFIG_STORAGE_URL] = OS_KEYCHAIN_URL
            config_json[CONFIG_STORAGE_URL] = OS_KEYCHAIN_URL

    if CONFIG_STORAGE_URL in config_json and config_json[CONFIG_STORAGE_URL] != 'file':
        url = config_json[CONFIG_STORAGE_URL]
        try:
            storage = _get_plugin(url)

            # Build the protected payload and a candidate config_json that has
            # those fields removed. We only commit the removal once the store
            # succeeds — this prevents data loss if the keychain call fails.
            conf_protected = {}
            config_json_committed = config_json.copy()
            for name in protected_properties + PROTECTED_READONLY_PROPERTIES:
                config_name, _ = split_name(name)
                if config_name in config_json:
                    value = config_json[config_name] or ''
                    if value:
                        conf_protected[config_name] = value
                    config_json_committed.pop(config_name, None)

            encrypted_data = storage.store_configuration(url, conf_protected)
            # Store succeeded — commit the cleaned config_json.
            config_json = config_json_committed
            if isinstance(encrypted_data, bytes):
                config_json[ENCRYPTED_DATA] = utils.base64_url_encode(encrypted_data)

        except SecureStorageException as sse:
            # If the OS keychain fails (e.g. permission denied on macOS), fall
            # back to file-based storage rather than silently losing config data.
            # config_json is still unmodified here, so all fields are preserved.
            logging.warning(
                'OS keychain store failed (%s). '
                'Falling back to file-based config storage.', sse
            )
            # Undo the auto-selected backend so the file write includes the
            # protected fields in plaintext (with chmod 600 as before).
            if config_json.get(CONFIG_STORAGE_URL) == OS_KEYCHAIN_URL:
                del config_json[CONFIG_STORAGE_URL]
                params.config.pop(CONFIG_STORAGE_URL, None)

    if params.config_filename:
        try:
            with open(params.config_filename, 'w') as fd:
                json.dump(config_json, fd, ensure_ascii=False, indent=2)
            # Set secure file permissions (600) for configuration files containing sensitive data
            utils.set_file_permissions(params.config_filename)
        except Exception as error:
            logging.debug(error, exc_info=True)
            logging.error(f'Failed to write configuration to {params.config_filename}. '
                          'Type "debug" to toggle verbose logging.', error)


def load_config_properties(params):
    if not isinstance(params, KeeperParams):
        return

    if not isinstance(params.config, dict):
        return

    # Check and fix permissions for existing config files
    if hasattr(params, 'config_filename') and params.config_filename:
        utils.ensure_config_permissions(params.config_filename)

    if CONFIG_STORAGE_URL in params.config:
        url = params.config[CONFIG_STORAGE_URL]
        # 'file' is the sentinel written by `keeper login --config-file`.
        # All protected fields are already in the JSON, so no plugin needed.
        if url != 'file':
            storage = _get_plugin(url)
            encrypted_data = None
            if ENCRYPTED_DATA in params.config:
                ed = params.config[ENCRYPTED_DATA]
                if isinstance(ed, str):
                    encrypted_data = utils.base64_url_decode(ed)
            conf = storage.load_configuration(url, encrypted_data)
            if isinstance(conf, dict):
                params.config.update(conf)

    for name in PROTECTED_PROPERTIES + PROTECTED_CONNECTED_PROPERTIES + PROTECTED_READONLY_PROPERTIES:
        config_name, params_name = split_name(name)
        if config_name in params.config:
            value = params.config.get(config_name) or ''
            if value and hasattr(params, params_name):
                setattr(params, params_name, value)

    for name in EDITABLE_PROPERTIES:
        config_name, params_name = split_name(name)
        if hasattr(params, params_name):
            value = params.config.get(config_name) or ''
            setattr(params, params_name, value)

    for name in BOOL_PROPERTIES:
        config_name, params_name = split_name(name)
        if hasattr(params, params_name):
            value = params.config.get(config_name)
            if isinstance(value, bool):
                setattr(params, params_name, value)

    for name in INT_PROPERTIES:
        config_name, params_name = split_name(name)
        if hasattr(params, params_name):
            value = params.config.get(config_name)
            if isinstance(value, int):
                setattr(params, params_name, value)
