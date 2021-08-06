#_  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import datetime
import logging
import re

from tabulate import tabulate

from ..params import KeeperParams
from .. import api
from ..commands.base import raise_parse_exception, suppress_exit, Command
from . import plugin_manager
from .. import generator
from ..subfolder import find_folders, get_folder_path


def register_commands(commands):
    commands['rotate'] = RecordRotateCommand()


def register_command_info(aliases, command_info):
    aliases['r'] = 'rotate'
    for p in [rotate_parser]:
        command_info[p.prog] = p.description


rotate_parser = argparse.ArgumentParser(prog='rotate|r', description='Rotate the password for a Keeper record from this Commander.')
rotate_parser.add_argument('--print', dest='print', action='store_true', help='display the record content after rotation')
rotate_parser.add_argument('--match', dest='match', action='store', help='regular expression to select records for password rotation')
rotate_parser.add_argument('--password', dest='password', action='store', help='new password (optional)')
rotate_parser.add_argument('name', nargs='?', type=str, action='store', help='record UID or name assigned to rotate command')
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


def rotate_password(params, record_uid, name=None, new_password=None):
    """ Rotate the password for the specified record """
    api.sync_down(params)
    record = api.get_record(params, record_uid)

    # execute rotation plugin associated with this record
    plugin_name = None
    plugins = [x for x in record.custom_fields if x['name'].startswith('cmdr:plugin')]
    if plugins:
        if name:
            plugins = [x for x in plugins if x['name'] == 'cmdr:plugin:' + name]
    if plugins:
        plugin_name = plugins[0]['value']
    if not plugin_name:
        logging.error('Record is not marked for password rotation (i.e. \'cmdr:plugin\' custom field).\n'
                      'Add custom field \'cmdr:plugin\'=\'noop\' to enable password rotation for this record')
        return False

    plugin = plugin_manager.get_plugin(plugin_name)
    if not plugin:
        return False

    if not new_password:
        # generate a new password with any specified rules
        rules = record.get("cmdr:rules")
        if rules:
            logging.debug("Rules found for record")
            new_password = generator.generateFromRules(rules)
        else:
            logging.debug("No rules, just generate")
            new_password = generator.generate()

        # ensure password starts with alpha numeric character
        new_password = adjust_password(new_password)

        # Some plugins might need to change the password in the process of rotation
        # f.e. windows plugin gets rid of certain characters.
        if hasattr(plugin, "adjust"):
            new_password = plugin.adjust(new_password)

    # log_message = 'Rotated on {0}'.format(datetime.datetime.now().ctime())
    # if record.notes:
    #     record.notes += '\n' + log_message
    # else:
    #     record.notes = log_message
    #
    # if not api.update_record(params, record, silent=True):
    #     return False

    api.sync_down(params)
    record = api.get_record(params, record_uid)

    logging.info("Rotating with plugin %s", plugin_name)
    success = plugin.rotate(record, new_password)
    if success:
        logging.debug("Password rotation is successful for \"%s\".", plugin_name)
    else:
        logging.warning("Password rotation failed for record uid=[%s], plugin \"%s\"." % (record.record_uid, plugin_name))
        return False

    if api.update_record(params, record):
        new_record = api.get_record(params, record_uid)
        logging.info('Rotation successful for record_uid=%s, revision=%d', new_record.record_uid, new_record.revision)
        return True

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
        if name:
            record_uid = None
            rotate_name = None
            if name in params.record_cache:
                record_uid = name
            else:
                RecordRotateCommand.find_endpoints(params)
                endpoints = [x for x in RecordRotateCommand.Endpoints if x.name.lower() == name.lower()]
                if len(endpoints) > 0:
                    if len(endpoints) == 1:
                        record_uid = endpoints[0].record_uid
                        rotate_name = endpoints[0].name
                    else:
                        logging.error('There are more than one rotation records with name %s. Please use record UID.', name)
                        return
            if record_uid:
                rotate_password(params, record_uid, name=rotate_name, new_password=kwargs.get('password'))
                if print_result:
                    record = api.get_record(params, record_uid)
                    record.display()
            else:
                logging.error('Rotate {0}: not found'.format(name))
        elif match:
            results = api.search_records(params, match)
            for r in results:
                rotate_password(params, r.record_uid)
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
                        if 'name' in field:
                            field_name = field['name']
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
