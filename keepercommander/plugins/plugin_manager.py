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


CONVERT_KWARG_TO_INT = ('port', 'length')
REQUIRED_PLUGIN_KWARGS = {
    'awskey': ['login', 'aws_key_id'],
    'awspswd': ['login'],
    'mssql': ['login', 'password'],
    'mysql': ['host', 'login', 'password'],
    'oracle': ['login', 'password'],
    'postgresql': ['host', 'login', 'password'],
    'pspasswd': ['login', 'password'],
    'ssh': ['host', 'login', 'password'],
    'windows': ['login'],
}
PORT_TO_PLUGIN = {
    22: 'ssh',
    1433: 'mssql',
    3306: 'mysql',
    1521: 'oracle',
    5432: 'postgresql'
}
URL_SCHEME_TO_PLUGIN = {
    'mssql': 'mssql',
    'mysql': 'mysql',
    'oracledb': 'oracle',
    'postgres': 'postgresql',
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
            logging.debug('Importing %s', str(full_name))
            imported_plugins[module_name] = importlib.import_module(full_name)
        except ModuleNotFoundError as e:
            logging.error('The required module is not installed:\n\tpip install %s', e.name)

    if module_name in imported_plugins:
        return imported_plugins[module_name]
    else:
        return ''


def get_host_field_dict(record):
    return next((
        f.value for f in record.custom
        if isinstance(f.value, dict) and 'hostName' in f.value and 'port' in f.value
    ), None)


def detect_plugin(record, plugin_kwargs):
    """Attempt detection of plugin name without "cmdr:plugin" fields

    This function also returns the corresponding kwargs for the detected plugin
    Return plugin_name and plugin_kwargs
    """
    plugin_name = None
    if record.get_version() == 3:
        # Search for host field in v3 record
        host_field = get_host_field_dict(record)
        if host_field and host_field['port'].isnumeric() and int(host_field['port']) in PORT_TO_PLUGIN:
            plugin_name = PORT_TO_PLUGIN[int(host_field['port'])]
            if 'host' not in plugin_kwargs:
                plugin_kwargs['host'] = host_field['hostName']
            if 'port' not in plugin_kwargs:
                plugin_kwargs['port'] = int(host_field['port'])
    if not plugin_name and 'url' in plugin_kwargs:
        url = urlparse(plugin_kwargs['url'])
        if url.port in PORT_TO_PLUGIN:
            plugin_name = PORT_TO_PLUGIN[url.port]
            if 'host' not in plugin_kwargs:
                plugin_kwargs['host'] = url.hostname
            if 'port' not in plugin_kwargs:
                plugin_kwargs['port'] = url.port
        if url.scheme in URL_SCHEME_TO_PLUGIN:
            plugin_name = URL_SCHEME_TO_PLUGIN[url.scheme]
            if 'host' not in plugin_kwargs:
                plugin_kwargs['host'] = url.hostname
            if 'port' not in plugin_kwargs and url.port:
                plugin_kwargs['port'] = url.port
    return plugin_name


def detect_kwargs(record, plugin_name, plugin_kwargs):
    # Look elsewhere in record if host or port parameter is missing
    if 'host' in REQUIRED_PLUGIN_KWARGS.get(plugin_name, []) and 'host' not in plugin_kwargs:
        host_field = get_host_field_dict(record)
        if host_field:
            plugin_kwargs['host'] = host_field['hostName']
            if all((host_field['port'].isnumeric(),
                    'port' in REQUIRED_PLUGIN_KWARGS[plugin_name],
                    'port' not in plugin_kwargs)):
                plugin_kwargs['port'] = int(host_field['port'])
        elif 'url' in plugin_kwargs:
            url = urlparse(plugin_kwargs['url'])
            if url.netloc:
                plugin_kwargs['host'] = url.netloc
                if url.port and 'port' in REQUIRED_PLUGIN_KWARGS[plugin_name] and 'port' not in plugin_kwargs:
                    plugin_kwargs['port'] = host_field['port']


def check_missing_kwargs(plugin_name, plugin_kwargs):
    """Returns True if kwargs for specified plugin are missing"""
    missing_kwargs = []
    if plugin_name in REQUIRED_PLUGIN_KWARGS:
        for kw in REQUIRED_PLUGIN_KWARGS[plugin_name]:
            if kw not in plugin_kwargs:
                missing_kwargs.append(kw)
        if len(missing_kwargs) > 0:
            missing_txt = ', '.join(missing_kwargs)
            logging.error(
                f'The following parameters are missing from the target record for password rotation: {missing_txt}'
            )
    return len(missing_kwargs) > 0


def get_custom_field_attr(record):
    record_version = record.get_version()
    if record_version not in (2, 3):
        logging.error('Invalid record for rotation')
        return None
    else:
        return 'label' if record_version == 3 else 'name'


def get_custom_cmdr_fields(record):
    fld_attr = get_custom_field_attr(record)
    if fld_attr is None:
        return None
    else:
        return {
            getattr(f, fld_attr)[len('cmdr:'):]: next((v for v in f.value), None) if isinstance(f.value, list) else f.value
            for f in record.custom if getattr(f, fld_attr).startswith('cmdr:')
        }


def get_plugin(record, rotate_name, plugin_name=None, host=None, port=None):
    """Load plugin based on given record and alt identifier

    Return plugin_name (str), plugin (object with rotate method)
    """
    cmdr_kwargs = get_custom_cmdr_fields(record)
    if cmdr_kwargs is None:
        return

    if plugin_name is None and len(cmdr_kwargs) > 0:
        rotate_value = cmdr_kwargs.get(f'plugin:{rotate_name}') if rotate_name else None
        plugin_name = rotate_value if rotate_value else cmdr_kwargs.get('plugin')

    plugin_kwargs = {k: v for k, v in cmdr_kwargs.items() if ':' not in v}
    plugin_kwargs.update({
        k[1:-1]: v for k, v in record.enumerate_fields() if k in ('(login)', '(password)', '(url)', '(host)') and v
    })
    if 'host' in plugin_kwargs:
        server = plugin_kwargs['host']
        h, sep, p = server.partition(':')
        if sep == ':':
            plugin_kwargs['host'] = h
            plugin_kwargs['port'] = p

    if host:
        plugin_kwargs['host'] = host
    if port:
        plugin_kwargs['port'] = port

    for convert_kwarg in CONVERT_KWARG_TO_INT:
        if convert_kwarg in plugin_kwargs:
            if plugin_kwargs[convert_kwarg].isnumeric():
                plugin_kwargs[convert_kwarg] = int(plugin_kwargs[convert_kwarg])
            else:
                logging.warning(
                    f'Argument "{convert_kwarg}", value "{plugin_kwargs[convert_kwarg]}"'
                    ' ignored because unable to convert to integer'
                )
                plugin_kwargs.pop(convert_kwarg)

    if plugin_name is None:
        if port and port in PORT_TO_PLUGIN:
            plugin_name = PORT_TO_PLUGIN[port]

    if plugin_name is None:
        plugin_name = detect_plugin(record, plugin_kwargs)
    else:
        detect_kwargs(record, plugin_name, plugin_kwargs)

    if not plugin_name:
        logging.error('Record is not marked for password rotation (i.e. \'cmdr:plugin\' custom field).\n'
                      'Add custom field \'cmdr:plugin\'=\'noop\' to enable password rotation for this record')
        return
    elif check_missing_kwargs(plugin_name, plugin_kwargs):
        return

    plugin = load_plugin(plugin_name)
    if hasattr(plugin, 'Rotator'):
        return plugin_name, plugin_kwargs, plugin.Rotator(**plugin_kwargs)
    else:
        return plugin_name, plugin_kwargs, plugin
