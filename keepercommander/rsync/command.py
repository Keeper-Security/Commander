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
import importlib
import json
import logging
import os
import pathlib
import shutil

from types import ModuleType
from typing import Dict, List, Optional

from . import rsync
from ..commands.base import Command, RecordMixin, user_choice
from ..error import CommandError
from .. import vault


def register_commands(commands):
    commands['rsync'] = RSyncCommand()


def register_command_info(aliases, command_info):
    for p in [rsync_parser]:
        command_info[p.prog] = p.description


rsync_parser = argparse.ArgumentParser(prog='rsync', description='Remote file storage sync.')
rsync_parser.add_argument('--plugin', dest='plugin', action='store', choices=['sftp'],
                          help='rsync plugin. Optional once configured.')
rsync_parser.add_argument('--remote-path', dest='remote_path', action='store',
                          help='remote root directory. Optional once configured.')
rsync_parser.add_argument('--record', action='store',
                          help='record UID or path with credentials, Optional once configured.')
rsync_parser.add_argument('--force', dest='force', action='store_true', help='do not prompt for confirmation')
rsync_parser.add_argument('local_path', nargs='?', type=str, action='store', help='local rsync directory. Required')


class RSyncCommand(Command, RecordMixin):
    def get_parser(self):
        return rsync_parser

    def execute(self, params, **kwargs):
        local_path = kwargs.get('local_path')
        if not local_path:
            self.get_parser().print_help()
            return

        local_path = os.path.expanduser(local_path)
        local_path = os.path.abspath(local_path)
        local_path = os.path.join(local_path, '')
        if os.path.exists(local_path):
            if not os.path.isdir(local_path):
                raise CommandError('rsync', f'Local path \"{local_path}\" is expected to be directory')
        else:
            os.mkdir(local_path)

        should_save = False
        rsync_info = None    # type: Optional[dict]
        rsync_info_path = os.path.join(local_path, '.rsync.json')
        if rsync_info_path and os.path.exists(rsync_info_path):
            if not os.path.isfile(rsync_info_path):
                raise CommandError('rsync', f'Path \"{rsync_info_path}\" is expected to be a JSON file')
            with open(rsync_info_path, 'r') as f:
                rsync_info = json.load(f)
                if not isinstance(rsync_info, dict):
                    raise CommandError('rsync', f'Path \"{rsync_info_path}\" is expected to be a JSON object')

        if not rsync_info:
            if not kwargs.get('force'):
                answer = user_choice(f'Do you want to setup rsync storage in directory: \"{local_path}\"?', 'yn', 'n')
                if answer.lower() == 'yes':
                    answer = 'y'
                if answer.lower() != 'y':
                    return
            rsync_info = {}
            should_save = True

        plugin_name = rsync_info.get('plugin')
        arg_plugin_name = kwargs.get('plugin')
        if not plugin_name and not arg_plugin_name:
            raise CommandError('rsync', f'\"--plugin\" parameter is required to setup rsync')
        elif plugin_name and arg_plugin_name:
            # TODO warn on plugin override
            plugin_name = arg_plugin_name
        elif arg_plugin_name:
            plugin_name = arg_plugin_name

        try:
            plugin_module = self.load_plugin(plugin_name)
        except ModuleNotFoundError as e:
            raise CommandError('rsync', f'The required module is not installed:\n\tpip install {e.name}')

        if not hasattr(plugin_module, 'RSyncPlugin'):
            raise CommandError('rsync', f'Invalid RSync Plugin \"{plugin_name}\"')
        plugin = plugin_module.RSyncPlugin()    # type: rsync.RSyncPluginBase
        if not isinstance(plugin, rsync.RSyncPluginBase):
            raise CommandError('rsync', f'Invalid RSync Plugin \"{plugin_name}\"')

        if rsync_info.get('plugin') != plugin_name:
            rsync_info['plugin'] = plugin_name
            should_save = True

        record = None    # type: Optional[vault.KeeperRecord]
        record_uid = rsync_info.get('record_uid')
        if record_uid and record_uid in params.record_cache:
            record = vault.KeeperRecord.load(params, record_uid)

        arg_record_name = kwargs.get('record')
        if arg_record_name:
            arg_record = self.resolve_single_record(params, arg_record_name)
            if not arg_record:
                raise CommandError('rsync', f'Invalid record name \"{arg_record}\". '
                                            f'Enter record UID or full record path of existing record')
            if record:
                if record.record_uid != arg_record.record_uid:
                    # TODO warn on record override
                    record = arg_record
            else:
                record = arg_record
        if not record:
            raise CommandError('rsync', f'\"--record\" parameter is required to setup rsync')

        if rsync_info.get('record_uid') != record.record_uid:
            rsync_info['record_uid'] = record.record_uid
            should_save = True

        remote_path = rsync_info.get('remote_path')
        arg_remote_path = kwargs.get('remote_path')
        if remote_path:
            if arg_remote_path and arg_remote_path != remote_path:
                answer = user_choice(
                    f'Remote path parameter is different: was \"{remote_path}\" now \"{arg_remote_path}\".\n'
                    f'Do you want to reset local storage?: \"{local_path}\"', 'yn', 'n')
                if answer.lower() == 'yes':
                    answer = 'y'
                if answer.lower() != 'y':
                    return
                rsync_info.pop('remote_path')
                remote_path = arg_remote_path
        else:
            remote_path = arg_remote_path

        if not remote_path:
            raise CommandError('rsync', f'\"--remote-path\" parameter is required to setup rsync')

        if rsync_info.get('remote_path') != remote_path:
            rsync_info['remote_path'] = remote_path
            should_save = True

        local_entries = {}   # type: Dict[str, rsync.RSyncFileEntry]
        for e in os.walk(local_path):
            current_dir = os.path.abspath(e[0])
            current_dir = os.path.join(current_dir, '')
            for name in e[2]:
                if name.startswith('.'):
                    continue
                full_path = os.path.join(current_dir, name)
                rel_path = full_path[len(local_path):]
                entry = rsync.RSyncFileEntry(rel_path)
                stat_rs = os.stat(full_path)
                entry.size = stat_rs.st_size
                entry.last_modified = int(stat_rs.st_mtime)
                local_entries[entry.path] = entry

        plugin.connect(record)
        try:
            to_download = []   # type: List[rsync.RSyncFileEntry]
            for remote_entry in plugin.get_entries(remote_path):
                if remote_entry.path in local_entries:
                    local_entry = local_entries[remote_entry.path]
                    if remote_entry.size != local_entry.size:
                        to_download.append(remote_entry)
                    del local_entries[remote_entry.path]
                else:
                    to_download.append(remote_entry)

            if len(to_download) > 0:
                logging.info('Downloading %d file(s):', len(to_download))
                verified_folders = set()
                for file in to_download:
                    absolute_path = os.path.join(local_path, file.path)
                    logging.info(absolute_path)
                    folder_name = os.path.dirname(absolute_path)
                    if folder_name not in verified_folders:
                        if not os.path.isdir(folder_name):
                            pathlib.Path(folder_name).mkdir(parents=True, exist_ok=True)
                        verified_folders.add(folder_name)
                    with plugin.get_entry_stream(file) as src, open(absolute_path, 'wb') as dst:
                        shutil.copyfileobj(src, dst, 100 * 1024)
                    if file.last_modified > 0:
                        os.utime(absolute_path, (file.last_modified, file.last_modified))
            logging.info('Successfully synced using \"%s\" record.', record.title)
        finally:
            plugin.disconnect()
            if should_save:
                with open(rsync_info_path, 'w') as f:
                    json.dump(rsync_info, f, indent=4)

    @staticmethod
    def load_plugin(plugin_name):    # type: (str) -> ModuleType
        full_name = f'keepercommander.rsync.{plugin_name}'
        logging.debug('Importing %s', full_name)
        return importlib.import_module(full_name)
