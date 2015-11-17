#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2015 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import sys
import importlib

imported_plugins = {}

def load_plugin(module_name):
    """Load plugin based on name"""
    try:
        full_name = 'plugins.' + module_name + '.' + module_name
        print('Importing ' + str(full_name))
        imported_plugins[module_name] = \
            importlib.import_module(full_name)
    except:
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