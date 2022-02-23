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

from .base import dump_report_data, Command
from .. import api, display, vault, vault_extensions
from ..team import Team

from ..params import KeeperParams
from ..subfolder import try_resolve_path


def register_commands(commands):
    commands['search'] = SearchCommand()
    commands['list'] = RecordListCommand()
    commands['list-sf'] = RecordListSfCommand()
    commands['list-team'] = RecordListTeamCommand()


def register_command_info(aliases, command_info):
    aliases['s'] = 'search'
    aliases['l'] = 'list'
    aliases['lsf'] = 'list-sf'
    aliases['lt'] = 'list-team'

    for p in [search_parser, list_parser, list_sf_parser, list_team_parser]:
        command_info[p.prog] = p.description


search_parser = argparse.ArgumentParser(prog='search', description='Search the vault. Can use a regular expression.')
search_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
search_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
search_parser.add_argument('-c', '--categories', dest='categories', action='store',
                           help='One or more of these letters for categories to search: "r" = records, '
                                '"s" = shared folders, "t" = teams')


list_parser = argparse.ArgumentParser(prog='list', description='List records.')
list_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
list_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'], default='table',
                         help='output format')
list_parser.add_argument('--output', dest='output', action='store',
                         help='output file name. (ignored for table format)')
list_parser.add_argument('-t', '--type', dest='record_type', action='append',
                         help='List records of certain types. Can be repeated')
list_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')


list_sf_parser = argparse.ArgumentParser(prog='list-sf', description='List shared folders.')
list_sf_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'],
                            default='table', help='output format')
list_sf_parser.add_argument('--output', dest='output', action='store',
                            help='output file name. (ignored for table format)')
list_sf_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')


list_team_parser = argparse.ArgumentParser(prog='list-team', description='List teams.')
list_team_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'],
                              default='table', help='output format')
list_team_parser.add_argument('--output', dest='output', action='store',
                              help='output file name. (ignored for table format)')


def find_record(params, record_name):  # type: (KeeperParams, str) -> vault.KeeperRecord
    record_uid = None
    if record_name in params.record_cache:
        record_uid = record_name
    else:
        rs = try_resolve_path(params, record_name)
        if rs is not None:
            folder, record_name = rs
            if folder is not None and record_name is not None:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for uid in params.subfolder_record_cache[folder_uid]:
                        r = api.get_record(params, uid)
                        if r.title.lower() == record_name.lower():
                            record_uid = uid
                            break
    if not record_uid:
        raise Exception(f'Record "{record_name}" not found.')

    return vault.KeeperRecord.load(params, record_uid)


class SearchCommand(Command):
    def get_parser(self):
        return search_parser

    def execute(self, params, **kwargs):
        pattern = (kwargs['pattern'] if 'pattern' in kwargs else None) or ''
        if pattern == '*':
            pattern = '.*'

        categories = (kwargs.get('categories') or 'rst').lower()
        verbose = kwargs.get('verbose', False)
        skip_details = not verbose

        # Search records
        if 'r' in categories:
            results = api.search_records(params, pattern)
            if results:
                print('')
                display.formatted_records(results, verbose=verbose)

        # Search shared folders
        if 's' in categories:
            results = api.search_shared_folders(params, pattern)
            if results:
                print('')
                display.formatted_shared_folders(results, params=params, skip_details=skip_details)

        # Search teams
        if 't' in categories:
            results = api.search_teams(params, pattern)
            if results:
                print('')
                display.formatted_teams(results, params=params, skip_details=skip_details)


class RecordListCommand(Command):
    def get_parser(self):
        return list_parser

    def execute(self, params, **kwargs):
        verbose = kwargs.get('verbose', False)
        fmt = kwargs.get('format', 'table')
        pattern = kwargs['pattern'] if 'pattern' in kwargs else None
        record_type = kwargs['record_type'] if 'record_type' in kwargs else None

        records = [x for x in vault_extensions.find_records(params, pattern, record_type)
                   if (True if (verbose or record_type) else x.version in {2, 3})]
        if any(records):
            table = []
            headers = ['record_uid', 'type', 'title', 'description'] if fmt == 'json' else \
                ['Record UID', 'Type', 'Title', 'Description']
            for record in records:
                row = [record.record_uid, record.record_type, record.title,
                       vault_extensions.get_record_description(record)]
                table.append(row)
            table.sort(key=lambda x: (x[2] or '').lower())

            return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True, column_width=None if verbose else 40)
        else:
            logging.info('No records are found')


class RecordListSfCommand(Command):
    def get_parser(self):
        return list_sf_parser

    def execute(self, params, **kwargs):
        fmt = kwargs.get('format', 'table')
        pattern = kwargs['pattern'] if 'pattern' in kwargs else None
        results = api.search_shared_folders(params, pattern or '')
        if any(results):
            table = []
            headers = ['shared_folder_uid', 'name'] if fmt == 'json' else ['Shared Folder UID', 'Name']
            for sf in results:
                row = [sf.shared_folder_uid, sf.name]
                table.append(row)
            table.sort(key=lambda x: (x[1] or '').lower())

            return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True)
        else:
            logging.info('No shared folders are found')


class RecordListTeamCommand(Command):
    def get_parser(self):
        return list_team_parser

    def execute(self, params, **kwargs):
        fmt = kwargs.get('format', 'table')
        api.load_available_teams(params)
        results = []
        if type(params.available_team_cache) == list:
            for team in params.available_team_cache:
                team = Team(team_uid=team['team_uid'], name=team['team_name'])
                results.append(team)
        if any(results):
            table = []
            headers = ['team_uid', 'name'] if fmt == 'json' else ['Team UID', 'Name']
            for team in results:
                row = [team.team_uid, team.name]
                table.append(row)
            table.sort(key=lambda x: (x[1] or '').lower())

            return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True)
        else:
            logging.info('No teams are found')
