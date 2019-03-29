#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#

import importlib
import logging

from . import noop

imported_plugins = {}


def load_plugin(module_name):
    """Load plugin based on name"""
    full_name = 'keepercommander.plugins.' + module_name
    try:
        logging.info('Importing %s', str(full_name))
        imported_plugins[module_name] = importlib.import_module(full_name)
    except Exception as e:
        logging.error(e.args[0])
        logging.error('Unable to load module %s', full_name)


def get_plugin(module_name):
    """Return the specified plugin"""
    if module_name == 'noop':
        return noop

    if module_name not in imported_plugins:
        """Load the specified plugin dynamically"""
        load_plugin(module_name)

    if not module_name in imported_plugins:
        """Module failed to load"""
        return ''

    return imported_plugins[module_name]
