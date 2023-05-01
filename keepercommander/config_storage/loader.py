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
from typing import Tuple, Union, List

from urllib.parse import urlparse
from ..params import KeeperParams
from .. import config_storage

CONFIG_STORAGE_URL = 'config_storage'
PROTECTED_PROPERTIES = [
    'user', 'password', 'server', 'device_token', ('private_key', 'device_private_key'),
    'clone_code']   # type: List[Union[str, Tuple[str, str]]]
EDITABLE_PROPERTIES = ['proxy']
BOOL_PROPERTIES = ['debug', 'batch_mode', 'unmask_all']
INT_PROPERTIES = ['timedelay', 'logout_timer']


class SecureStorageException(Exception):
    pass


class SecureStorageBase(abc.ABC):
    @abc.abstractmethod
    def load_configuration(self, url):   # type: (str) -> dict
        pass

    @abc.abstractmethod
    def store_configuration(self, url, configuration):   # type: (str, dict) -> None
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
    if not params.config_filename:
        params.config_filename = 'config.json'

    should_store_file = False
    if CONFIG_STORAGE_URL in params.config:
        url = params.config[CONFIG_STORAGE_URL]
        storage = _get_plugin(url)
        conf = {}
        for name in PROTECTED_PROPERTIES:
            config_name, params_name = split_name(name)
            if hasattr(params, params_name):
                value = getattr(params, params_name)
                if isinstance(value, str) and value:
                    conf[config_name] = value
        storage.store_configuration(url, conf)
        for name in PROTECTED_PROPERTIES:
            config_name, _ = split_name(name)
            if config_name in params.config:
                del params.config[config_name]
                should_store_file = True
    else:
        should_store_file = True
        for name in PROTECTED_PROPERTIES:
            config_name, params_name = split_name(name)
            if hasattr(params, params_name):
                value = getattr(params, params_name)
                if isinstance(value, str) and value:
                    params.config[config_name] = value
                else:
                    if config_name in params.config:
                        del params.config[config_name]

    for name in EDITABLE_PROPERTIES:
        config_name, params_name = split_name(name)
        if hasattr(params, params_name):
            value = getattr(params, params_name) or ''
            config_value = params.config.get(config_name) or ''
            if value != config_value:
                params.config[config_name] = value

    if should_store_file:
        with open(params.config_filename, 'w') as fd:
            json.dump(params.config, fd, ensure_ascii=False, indent=2)


def load_config_properties(params):
    if not isinstance(params, KeeperParams):
        return

    if not isinstance(params.config, dict):
        return

    for name in EDITABLE_PROPERTIES:
        config_name, params_name = split_name(name)
        if hasattr(params, params_name):
            value = params.config.get(config_name) or ''
            setattr(params, params_name, value)

    if CONFIG_STORAGE_URL in params.config:
        url = params.config[CONFIG_STORAGE_URL]
        storage = _get_plugin(url)
        conf = storage.load_configuration(url)
        if isinstance(conf, dict):
            for name in PROTECTED_PROPERTIES:
                config_name, params_name = split_name(name)
                if hasattr(params, params_name) and config_name in conf:
                    setattr(params, params_name, conf[config_name] or '')

    for name in PROTECTED_PROPERTIES:
        config_name, params_name = split_name(name)
        if config_name in params.config:
            value = params.config.get(config_name) or ''
            if value and hasattr(params, params_name):
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
