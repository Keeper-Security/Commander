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
import logging

from .. import api, display
from ..commands.base import raise_parse_exception, suppress_exit, Command
from . import plugin_manager
from .. import generator


def register_commands(commands):
    commands['rotate'] = RecordRotateCommand()


def register_command_info(aliases, command_info):
    aliases['r'] = 'rotate'
    for p in [rotate_parser]:
        command_info[p.prog] = p.description


rotate_parser = argparse.ArgumentParser(prog='rotate|r', description='Rotate Keeper record')
rotate_parser.add_argument('--print', dest='print', action='store_true', help='display the record content after rotation')
rotate_parser.add_argument('--match', dest='match', action='store', help='regular expression to select records for password rotation')
rotate_parser.add_argument('uid', nargs='?', type=str, action='store', help='record UID')
rotate_parser.error = raise_parse_exception
rotate_parser.exit = suppress_exit


def rotate_password(params, record_uid):
    """ Rotate the password for the specified record """
    record = api.get_record(params, record_uid)

    # generate a new password with any specified rules
    rules = record.get("cmdr:rules")
    if rules:
        logging.debug("Rules found for record")
        new_password = generator.generateFromRules(rules)
    else:
        logging.debug("No rules, just generate")
        new_password = generator.generate()

    # execute rotation plugin associated with this record
    plugin_name = record.get("cmdr:plugin")
    if plugin_name:
        # Some plugins might need to change the password in the process of rotation
        # f.e. windows plugin gets rid of certain characters.
        plugin = plugin_manager.get_plugin(plugin_name)
        if plugin:
            if hasattr(plugin, "adjust"):
                new_password = plugin.adjust(new_password)

            logging.info("Rotating with plugin %s", plugin_name)
            success = plugin.rotate(record, new_password)
            if success:
                logging.debug("Password rotation is successful for \"%s\".", plugin_name)
            else:
                logging.warning("Password rotation failed for \"%s\".", plugin_name)
                return False
        else:
            return False
    else:
        logging.info("Password rotated %s", new_password)
        record.password = new_password

    if api.update_record(params, record):
        new_record = api.get_record(params, record_uid)
        logging.info('Rotation successful for record_uid=%s, revision=%d', new_record.record_uid, new_record.revision)

    return True


class RecordRotateCommand(Command):
    def get_parser(self):
        return rotate_parser

    def execute(self, params, **kwargs):
        print_result = kwargs['print'] if 'print' in kwargs else None
        uid = kwargs['uid'] if 'uid' in kwargs else None
        match = kwargs['match'] if 'match' in kwargs else None
        if uid:
            rotate_password(params, uid)
            if print_result:
                display.print_record(params, uid)
        elif match:
            results = api.search_records(params, match)
            for r in results:
                rotate_password(params, r.record_uid)
                if print_result:
                    display.print_record(params, r.record_uid)
