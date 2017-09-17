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
import sys

imported_plugins = {}


def load_plugin(module_name):
    """Load plugin based on name"""
    full_name = 'keepercommander.plugins.' + module_name
    try:
        print('Importing ' + str(full_name))
        imported_plugins[module_name] = \
            importlib.import_module(full_name)
    except Exception as e:
        print(e.args[0])
        print('Unable to load module ' + full_name)


def get_plugin(module_name):
    """Return the specified plugin"""
    if not module_name in imported_plugins:
        """Load the specified plugin dynamically"""
        load_plugin(module_name)

    if not module_name in imported_plugins:
        """Module failed to load"""
        return ''

    return imported_plugins[module_name]
