#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import logging
import re

from tabulate import tabulate

from keepercommander.commands import recordv3
from ..params import KeeperParams
from .. import api
from ..commands.base import raise_parse_exception, suppress_exit, Command
from . import plugin_manager
from .. import generator
from ..subfolder import find_folders, get_folder_path
from ..utils import confirm


def register_commands(commands):
    commands['rotate'] = RecordRotateCommand()


def register_command_info(aliases, command_info):
    aliases['r'] = 'rotate'
    for p in [rotate_parser]:
        command_info[p.prog] = p.description


rotate_parser = argparse.ArgumentParser(
    prog='rotate|r', description='Rotate the password for a Keeper record from this Commander.'
)
rotate_parser.add_argument(
    '--print', dest='print', action='store_true', help='display the record content after rotation'
)
rotate_parser.add_argument(
    '-m', '--match', dest='match', action='store', help='regular expression to select records for password rotation'
)
rotate_parser.add_argument('--plugin', dest='plugin', action='store', help='Force rotation plugin (optional)')
rotate_parser.add_argument('--host', dest='host', action='store', help='Optional host (override record value)')
rotate_parser.add_argument('--port', dest='port', action='store', help='Optional port (override record value)')
rotate_parser.add_argument('--rules', dest='rules', action='store', help='Optional rules (override record value)')
rotate_parser.add_argument('--password', dest='password', action='store', help='Optional new password')
rotate_parser.add_argument(
    '--force', dest='force', action='store_true', help='force all matches to rotate without prompt'
)
rotate_parser.add_argument(
    'name', nargs='?', type=str, action='store', help='record UID or name assigned to rotate command'
)
rotate_parser.error = raise_parse_exception
rotate_parser.exit = suppress_exit


def adjust_password(password):   # type: (str) -> str
    if not password:
        return password
    if password[0].isalnum():
        return password
    for i in range(1, len(password)):
        if password[i].isalnum():
            return password[i] + password[1:i] + password[0] + password[i+1:]
    return 'a' + password


def get_v2_or_v3_custom_field_value(record, custom_field_name, default_value=None):
    if record.record_type:  # V3 record
        matches = [x for x in record.custom_fields if x.get('name', x.get('label')).endswith(custom_field_name)]
        if len(matches) > 0:
            value_list = matches[0].get('value') or default_value
            if isinstance(value_list, list):
                ret_val = value_list[0] if len(value_list) > 0 else default_value
            else:
                ret_val = value_list
        else:
            ret_val = default_value

    else:  # V2 record
        matches = [x for x in record.custom_fields if x['name'] == custom_field_name]
        ret_val = matches[0]['value'] if len(matches) > 0 else default_value

    return ret_val


def update_v2_or_v3_password(params, record, new_password):
    if record.record_type:  # V3 record
        return_result = {}
        option = [f'f.password={new_password}']
        recordv3.RecordEditCommand().execute(
            params, command='edit', option=option, record=record.record_uid, return_result=return_result
        )
        return return_result.get('update_record_v3', False)

    else:  # V2 record
        record.password = new_password
        return api.update_record(params, record)


def get_new_password(record, plugin, rules=None):
    if hasattr(plugin, 'disallow_special_characters'):
        pw_special_characters = generator.PW_SPECIAL_CHARACTERS.translate(
            str.maketrans('', '', plugin.disallow_special_characters)
        )
    else:
        pw_special_characters = generator.PW_SPECIAL_CHARACTERS
    if rules is None:
        rules = get_v2_or_v3_custom_field_value(record, "cmdr:rules")
    if rules:
        logging.debug("Rules found for record")
        upper, lower, digits, symbols = (int(n) for n in rules.split(','))
        kpg = generator.KeeperPasswordGenerator(
            length=upper + lower + digits + symbols, symbols=symbols, digits=digits, caps=upper, lower=lower,
            special_characters=pw_special_characters
        )
    else:
        logging.debug("No rules, just generate")
        kpg = generator.KeeperPasswordGenerator(32, 8, 8, 8, 8, special_characters=pw_special_characters)
    new_password = kpg.generate()

    # ensure password starts with alpha numeric character
    new_password = adjust_password(new_password)

    # Some plugins might need to change the password in the process of rotation
    # f.e. windows plugin gets rid of certain characters.
    if hasattr(plugin, "adjust"):
        new_password = plugin.adjust(new_password)

    return new_password


def rotate_password(params, record_uid, rotate_name=None, plugin_name=None, host=None, port=None, rules=None,
                    new_password=None):
    """ Rotate the password for the specified record """
    api.sync_down(params)
    record = api.get_record(params, record_uid)
    if api.resolve_record_write_path(params, record_uid) is None:
        logging.error(
            f'Password rotation failed for record "{record.title}" (uid=[{record.record_uid}]):\n'
            'The target record is not editable but needs to be updated with the new password to complete the rotation.'
        )
        return False

    plugin_name, plugin = plugin_manager.get_plugin(record, rotate_name, plugin_name, host, port)
    if not plugin:
        return False

    if new_password is None:
        new_password = get_new_password(record, plugin, rules)

    api.sync_down(params)
    record = api.get_record(params, record_uid)

    if record.password == new_password:
        logging.warning('Rotation aborted because the old and new passwords are the same.')
        success = False
    else:
        if hasattr(plugin, 'rotate_start_msg'):
            plugin.rotate_start_msg()
        else:
            logging.info(f'Rotating with plugin {plugin_name}')
        success = plugin.rotate(record, new_password)

    if success:
        logging.debug(f'Password rotation successful for "{plugin_name}".')
    else:
        logging.warning(
            f'Password rotation failed for record "{record.title}" (uid=[{record.record_uid}]), plugin "{plugin_name}".'
        )
        return False

    if update_v2_or_v3_password(params, record, new_password):
        new_record = api.get_record(params, record_uid)
        logging.info(f'Password rotation successful for record "{new_record.title}".')
        return True
    elif hasattr(plugin, 'revert') and plugin.revert(record, new_password):
        logging.warning(
            f'Couldn\'t update the record "{record.title}" (uid=[{record.record_uid}]), so the rotation was reverted.'
        )
    else:
        logging.error(
            f"Rotated to new password {new_password} but couldn't update the record "
            f'"{record.title}" (uid=[{record.record_uid}]). The new password will be needed for access.'
        )

    return False


class RotateEndpoint:
    def __init__(self, name, type, description, record_uid, record_title, paths):
        self.name = name
        self.type = type
        self.description = description
        self.record_uid = record_uid
        self.record_title = record_title
        self.paths = paths


rotate_pattern =  re.compile(r'^cmdr:plugin(:[^:]*)?$')
rotate_desc_pattern =  re.compile(r'^cmdr:plugin:([^:]+):description$')


class RecordRotateCommand(Command):
    def get_parser(self):
        return rotate_parser

    def execute(self, params, **kwargs):
        print_result = kwargs['print'] if 'print' in kwargs else None
        name = kwargs['name'] if 'name' in kwargs else None
        match = kwargs['match'] if 'match' in kwargs else None
        force = kwargs['force'] if 'force' in kwargs else None
        if name:
            record_uid = None
            rotate_name = None
            if name in params.record_cache:
                record_uid = name
            else:
                RecordRotateCommand.find_endpoints(params)
                nl = name.lower()
                endpoints = [
                    x for x in RecordRotateCommand.Endpoints if x.record_title.lower() == nl or x.name.lower() == nl
                ]
                if len(endpoints) > 0:
                    if len(endpoints) == 1:
                        record_uid = endpoints[0].record_uid
                        rotate_name = endpoints[0].name
                    else:
                        logging.error('There are more than one rotation records with name %s. Please use record UID.', name)
                        return
            if record_uid:
                rotate_password(
                    params, record_uid, rotate_name=rotate_name, plugin_name=kwargs.get('plugin'),
                    host=kwargs.get('host'), port=kwargs.get('port'), rules=kwargs.get('rules'),
                    new_password=kwargs.get('password')
                )
                if print_result:
                    record = api.get_record(params, record_uid)
                    record.display()
            else:
                logging.error('Rotate {0}: not found'.format(name))
        elif match:
            results = api.search_records(params, match)
            for r in results:
                if force or confirm(f'Rotate password for record {r.title}?'):
                    rotate_password(
                        params, r.record_uid, plugin_name=kwargs.get('plugin'), new_password=kwargs.get('password'),
                        host=kwargs.get('host'), port=kwargs.get('port'), rules=kwargs.get('rules')
                    )
                    if print_result:
                        record = api.get_record(params, r.record_uid)
                        record.display()
        else:
            RecordRotateCommand.find_endpoints(params)
            if RecordRotateCommand.Endpoints:
                logging.info("Available records for password rotation")
                logging.info('')
                headers = ["#", 'Name', 'Type', 'Record UID', 'Record Title', 'Folder(s)']
                table = []
                for i in range(len(RecordRotateCommand.Endpoints)):
                    endpoint = RecordRotateCommand.Endpoints[i]
                    title = endpoint.record_title
                    folder = endpoint.paths[0] if len(endpoint.paths) > 0 else '/'
                    if len(title) > 23:
                        title = title[:20] + '...'
                    table.append([i + 1, endpoint.name, endpoint.type, endpoint.record_uid,  title, folder])
                print(tabulate(table, headers=headers))
                print('')

    LastRevision = 0
    Endpoints = [] # type: [RotateEndpoint]

    @staticmethod
    def find_endpoints(params):
        # type: (KeeperParams) -> None
        if RecordRotateCommand.LastRevision < params.revision:
            RecordRotateCommand.LastRevision = params.revision
            RecordRotateCommand.Endpoints.clear()
            for record_uid in params.record_cache:
                record = api.get_record(params, record_uid)
                if record.custom_fields:
                    endpoints = {}    # type: {str, str}
                    endpoints_desc = {}
                    for field in record.custom_fields:
                        field_name = field.get('name', field.get('label'))
                        if field_name:
                            m = rotate_pattern.match(field_name)
                            if m and 'value' in field:
                                endpoints[field_name] = field['value']
                            else:
                                m = rotate_desc_pattern.match(field_name)
                                if m:
                                    endpoints_desc[m[1]] = field.get('value') or ''
                    if endpoints:
                        paths = []
                        for folder_uid in find_folders(params, record_uid):
                            path = '/' + get_folder_path(params, folder_uid, '/')
                            paths.append(path)
                        for endpoint in endpoints:
                            name = endpoint
                            if name.startswith('cmdr:plugin'):
                                name = name[len('cmdr:plugin'):]
                                if name and name[0] == ':':
                                    name = name[1:]
                            epoint = RotateEndpoint(name, endpoints[endpoint], endpoints_desc.get(endpoint) or '', record_uid, record.title, paths)
                            RecordRotateCommand.Endpoints.append(epoint)
            RecordRotateCommand.Endpoints.sort(key=lambda x: x.name)
