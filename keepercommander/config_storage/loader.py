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
import pkgutil
from typing import Tuple, Union, List, Optional

from urllib.parse import urlparse
from ..params import KeeperParams
from .. import config_storage, utils

CONFIG_STORAGE_URL = 'config_storage'
PROTECTED_PROPERTIES = [
    'user', 'server', 'device_token', ('private_key', 'device_private_key'),
    'clone_code']   # type: List[Union[str, Tuple[str, str]]]
PROTECTED_READONLY_PROPERTIES = ['password']
EDITABLE_PROPERTIES = ['proxy']
BOOL_PROPERTIES = ['debug', 'batch_mode', 'unmask_all']
INT_PROPERTIES = ['timedelay', 'logout_timer']
ENCRYPTED_DATA = 'encrypted_data'


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


def store_config_properties(params):
    if not isinstance(params, KeeperParams):
        return
    if not isinstance(params.config, dict):
        params.config = {}

    # commit changes from params to config
    for name in PROTECTED_PROPERTIES + EDITABLE_PROPERTIES:
        config_name, params_name = split_name(name)
        if hasattr(params, params_name):
            value = getattr(params, params_name)
            if value:
                params.config[config_name] = value
            elif config_name in params.config:
                del params.config[config_name]

    config_json = params.config.copy()

    if CONFIG_STORAGE_URL in config_json:
        url = config_json[CONFIG_STORAGE_URL]
        storage = _get_plugin(url)
        conf_protected = {}
        for name in PROTECTED_PROPERTIES + PROTECTED_READONLY_PROPERTIES:
            config_name, _ = split_name(name)
            if config_name in config_json:
                value = config_json[config_name] or ''
                if value:
                    conf_protected[config_name] = value
                del config_json[config_name]

        encrypted_data = storage.store_configuration(url, conf_protected)
        if isinstance(encrypted_data, bytes):
            config_json[ENCRYPTED_DATA] = utils.base64_url_encode(encrypted_data)

    if params.config_filename:
        try:
            with open(params.config_filename, 'w') as fd:
                json.dump(config_json, fd, ensure_ascii=False, indent=2)
        except Exception as error:
            logging.debug(error, exc_info=True)
            logging.error(f'Failed to write configuration to {params.config_filename}. '
                          'Type "debug" to toggle verbose logging.', error)


def load_config_properties(params):
    if not isinstance(params, KeeperParams):
        return

    if not isinstance(params.config, dict):
        return

    if CONFIG_STORAGE_URL in params.config:
        url = params.config[CONFIG_STORAGE_URL]
        storage = _get_plugin(url)
        encrypted_data = None
        if ENCRYPTED_DATA in params.config:
            ed = params.config[ENCRYPTED_DATA]
            if isinstance(ed, str):
                encrypted_data = utils.base64_url_decode(ed)
        conf = storage.load_configuration(url, encrypted_data)
        if isinstance(conf, dict):
            params.config.update(conf)

    for name in PROTECTED_PROPERTIES + PROTECTED_READONLY_PROPERTIES:
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
