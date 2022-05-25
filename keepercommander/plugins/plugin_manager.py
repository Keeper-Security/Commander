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
from urllib.parse import urlparse

from . import noop


REQUIRED_PLUGIN_KWARGS = {
    'ssh': ['host', 'login', 'password']
}
PORT_TO_PLUGIN = {
    22: 'ssh'
}
URL_SCHEME_TO_PLUGIN = {
    'ssh': 'ssh'
}
imported_plugins = {}


def load_plugin(module_name):
    """Load plugin based on name"""
    if module_name == 'noop':
        return noop

    if module_name not in imported_plugins:
        full_name = 'keepercommander.plugins.' + module_name
        try:
            logging.info('Importing %s', str(full_name))
            imported_plugins[module_name] = importlib.import_module(full_name)
        except Exception as e:
            logging.error(e.args[0])
            logging.error('Unable to load module %s', full_name)

    if module_name in imported_plugins:
        return imported_plugins[module_name]
    else:
        return ''


def detect_plugin(record):
    """Attempt detection of plugin name without "cmdr:plugin" field

    Return plugin_name and plugin_kwargs
    """
    plugin_name = None
    kwargs = {}
    if record.login_url:
        url = urlparse(record.login_url)
        if url.port in PORT_TO_PLUGIN:
            plugin_name = PORT_TO_PLUGIN[url.port]
            kwargs['host'] = url.netloc
            kwargs['port'] = url.port
        if url.scheme in URL_SCHEME_TO_PLUGIN:
            plugin_name = URL_SCHEME_TO_PLUGIN[url.scheme]
            kwargs['host'] = url.netloc
    if not plugin_name and record.record_type:
        # Search for host field in v3 record
        host_field = next((
            f['value'] for f in record.custom_fields
            if isinstance(f.get('value'), dict) and 'hostName' in f['value'] and 'port' in f['value']
        ), None)
        if host_field and host_field['port'].isnumeric() and int(host_field['port']) in PORT_TO_PLUGIN:
            kwargs['host'] = host_field['hostName']
            kwargs['port'] = int(host_field['port'])
            plugin_name = PORT_TO_PLUGIN[kwargs['port']]
    return plugin_name, kwargs


def get_plugin(record, alt_identifier):
    """Load plugin based on given record and alt identifier

    Return plugin_name (str), plugin (object with rotate method)
    """
    plugin_name = None

    plugins = [x for x in record.custom_fields if 'cmdr:plugin' in x.get('name', x.get('label', ''))]
    if plugins and alt_identifier:
        plugins = [x for x in plugins if x.get('name', x.get('label')).endswith('cmdr:plugin:' + alt_identifier)]
    if plugins:
        plugin_name = plugins[0]['value']
    if isinstance(plugin_name, list):
        plugin_name = plugin_name[0]

    if plugin_name:
        custom_cmdr_field_kwargs = {
            f.get('name', f.get('label')).split('cmdr:')[-1]: f['value'] for f in record.custom_fields
            if 'cmdr:' in f.get('name', f.get('label'))
        }
        plugin_kwargs = {k: v for k, v in custom_cmdr_field_kwargs.items() if ':' not in k}
        if 'port' in plugin_kwargs:
            if plugin_kwargs['port'].isnumeric():
                plugin_kwargs['port'] = int(plugin_kwargs['port'])
            else:
                plugin_kwargs.pop('port')
    else:
        plugin_name, plugin_kwargs = detect_plugin(record)

    if plugin_name:
        if record.login:
            plugin_kwargs['login'] = record.login
        if record.password:
            plugin_kwargs['password'] = record.password
        if plugin_name in REQUIRED_PLUGIN_KWARGS:
            missing_kwargs = []
            for kw in REQUIRED_PLUGIN_KWARGS[plugin_name]:
                if kw not in plugin_kwargs:
                    missing_kwargs.append(kw)
            if len(missing_kwargs) > 0:
                missing_txt = ', '.join(missing_kwargs)
                logging.error(
                    f'The following parameters are missing from the target record for password rotation: {missing_txt}'
                )
                return None, None
    else:
        logging.error('Record is not marked for password rotation (i.e. \'cmdr:plugin\' custom field).\n'
                      'Add custom field \'cmdr:plugin\'=\'noop\' to enable password rotation for this record')
        return None, None

    plugin = load_plugin(plugin_name)
    if hasattr(plugin, 'Rotator'):
        return plugin_name, plugin.Rotator(**plugin_kwargs)
    else:
        return plugin_name, plugin
