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
import hashlib
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

# Scheme used for the OS-native keychain backend.
_OS_KEYCHAIN_SCHEME = 'os-keychain'

# Fallback URL used when no config filename is available.
OS_KEYCHAIN_URL = 'os-keychain://default'


def _make_os_keychain_url(config_filename=None):  # type: (Optional[str]) -> str
    """Return an os-keychain URL with the netloc derived from a SHA-256 hash of the config path."""
    if config_filename:
        path_hash = hashlib.sha256(
            os.path.abspath(config_filename).encode()
        ).hexdigest()[:8]
        return f'{_OS_KEYCHAIN_SCHEME}://{path_hash}'
    return OS_KEYCHAIN_URL


def _is_os_keychain_url(url):  # type: (Optional[str]) -> bool
    """Return True if *url* refers to the OS-native keychain backend."""
    if not url:
        return False
    return urlparse(url).scheme == _OS_KEYCHAIN_SCHEME


def is_os_keychain_available():  # type: () -> bool
    """Return True if a real OS-native keychain is available and usable.



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

    plugin_name = par.scheme.replace('-', '_')
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


def _keychain_account_from_url(url):  # type: (Optional[str]) -> str
    """Return the keyring account key from the URL netloc; falls back to 'config' for legacy entries."""
    if url:
        netloc = urlparse(url).netloc
        if netloc:
            return netloc
    return 'config'


def _clear_os_keychain_if_present(url=None):  # type: (Optional[str]) -> None
    """Delete the keychain entry for *url* if it exists. Called after switching to file storage."""
    account_key = _keychain_account_from_url(url)
    try:
        import keyring
        try:
            if keyring.get_password(_KEYCHAIN_SERVICE, account_key) is not None:
                keyring.delete_password(_KEYCHAIN_SERVICE, account_key)
                logging.debug('Deleted keychain entry: service=%s account=%s',
                              _KEYCHAIN_SERVICE, account_key)
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

    explicitly_use_file = (
        config_json.get(CONFIG_STORAGE_URL) == 'file'
        or os.getenv('KEEPER_CONFIG_STORAGE', '').lower() == 'file'
    )

    previous_keychain_url = (
        config_json.get(CONFIG_STORAGE_URL)
        if _is_os_keychain_url(config_json.get(CONFIG_STORAGE_URL))
        else None
    )

    if explicitly_use_file:
        logging.debug('File-based config storage selected (--config-file or KEEPER_CONFIG_STORAGE=file).')
        config_json[CONFIG_STORAGE_URL] = 'file'

    elif CONFIG_STORAGE_URL not in config_json:
        # Auto-select keychain on fresh login; pre-keychain installs are handled
        # in load_config_properties before this runs.
        if is_os_keychain_available():
            logging.debug('Auto-selecting OS keychain backend for config storage.')
            keychain_url = _make_os_keychain_url(params.config_filename)
            params.config[CONFIG_STORAGE_URL] = keychain_url
            config_json[CONFIG_STORAGE_URL] = keychain_url

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
            if not _is_os_keychain_url(url):
                raise  # Non-OS backends must not silently downgrade to plaintext.
            logging.warning('OS keychain store failed (%s). Falling back to file-based config storage.', sse)
            del config_json[CONFIG_STORAGE_URL]
            params.config.pop(CONFIG_STORAGE_URL, None)

    if params.config_filename:
        try:
            with open(params.config_filename, 'w') as fd:
                json.dump(config_json, fd, ensure_ascii=False, indent=2)
            # Set secure file permissions (600) for configuration files containing sensitive data
            utils.set_file_permissions(params.config_filename)
            if explicitly_use_file and previous_keychain_url:
                _clear_os_keychain_if_present(previous_keychain_url)
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
        if url != 'file':  # 'file' sentinel means credentials are in the JSON already
            storage = _get_plugin(url)
            encrypted_data = None
            if ENCRYPTED_DATA in params.config:
                ed = params.config[ENCRYPTED_DATA]
                if isinstance(ed, str):
                    encrypted_data = utils.base64_url_decode(ed)
            conf = storage.load_configuration(url, encrypted_data)
            if isinstance(conf, dict):
                params.config.update(conf)
    else:
        # No backend recorded. If credentials already exist in the file, this is a
        # pre-keychain install — mark as file mode to prevent silent migration.
        if params.config.get('device_token') or params.config.get('private_key'):
            params.config[CONFIG_STORAGE_URL] = 'file'
            logging.debug('Detected pre-keychain config.json — keeping file-based storage.')

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
