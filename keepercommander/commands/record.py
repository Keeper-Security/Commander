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
import collections
import datetime
import fnmatch
import itertools
import json
import logging
import os
import re
from functools import reduce
from typing import Dict, Any, List, Optional, Iterable, Tuple, Set

from colorama import Fore, Back, Style

from . import record_edit, base, record_totp, record_file_report
from .base import Command, GroupCommand, RecordMixin, FolderMixin, fields_to_titles
from .. import api, display, crypto, utils, vault, vault_extensions, subfolder, record_types
from ..breachwatch import BreachWatch
from ..error import CommandError
from ..params import KeeperParams
from ..proto import record_pb2, folder_pb2, enterprise_pb2
from ..record import get_totp_code
from ..subfolder import try_resolve_path, get_folder_path, find_folders, find_all_folders, BaseFolderNode, \
    get_folder_uids
from ..team import Team

def handle_empty_result(fmt, message, filename=None):
    """
    Handle 'no data found' scenarios for different output formats.
    
    Args:
        fmt (str): Output format ('json', 'table', etc.)
        message (str): Message to display/return
        filename (str, optional): Output filename for JSON format
    
    Returns:
        dict: For JSON format, returns {"message": message}
        None: For other formats, logs the message and returns None
    """
    if fmt == 'json':
        result = {"message": message}
        if filename:
            _, ext = os.path.splitext(filename)
            if not ext:
                filename += '.json'
            logging.info('Report path: %s', os.path.abspath(filename))
            with open(filename, 'w') as fd:
                json.dump(result, fd, indent=2, default=base.json_serialized)
            return None
        return result
    logging.info(message)
    return None

def register_commands(commands):
    commands['search'] = SearchCommand()
    commands['get'] = RecordGetUidCommand()
    commands['rm'] = RecordRemoveCommand()
    commands['trash'] = TrashCommand()
    commands['list'] = RecordListCommand()
    commands['list-sf'] = RecordListSfCommand()
    commands['list-team'] = RecordListTeamCommand()
    commands['record-history'] = RecordHistoryCommand()
    commands['shared-records-report'] = SharedRecordsReport()
    commands['record-add'] = record_edit.RecordAddCommand()
    commands['record-update'] = record_edit.RecordUpdateCommand()
    commands['append-notes'] = record_edit.RecordAppendNotesCommand()
    commands['delete-attachment'] = record_edit.RecordDeleteAttachmentCommand()
    commands['download-attachment'] = record_edit.RecordDownloadAttachmentCommand()
    commands['upload-attachment'] = record_edit.RecordUploadAttachmentCommand()
    commands['clipboard-copy'] = ClipboardCommand()
    commands['totp'] = record_totp.TotpCommand()
    commands['file-report'] = record_file_report.RecordFileReportCommand()


def register_command_info(aliases, command_info):
    aliases['g'] = 'get'
    aliases['s'] = 'search'
    aliases['l'] = 'list'
    aliases['lsf'] = 'list-sf'
    aliases['lt'] = 'list-team'
    aliases['rh'] = 'record-history'
    aliases['srr'] = 'shared-records-report'
    aliases['ra'] = 'record-add'
    aliases['ru'] = 'record-update'
    aliases['cc'] = 'clipboard-copy'
    aliases['find-password'] = ('clipboard-copy', '--output=stdout')
    aliases['sh'] = ('clipboard-copy', '--output=stdouthidden')
    aliases['an'] = 'append-notes'
    aliases['da'] = 'download-attachment'
    aliases['ua'] = 'upload-attachment'

    for p in [get_info_parser, search_parser, list_parser, list_sf_parser, list_team_parser,
              record_history_parser, shared_records_report_parser, record_edit.record_add_parser,
              record_edit.record_update_parser, record_edit.append_parser, record_edit.download_parser,
              record_edit.upload_parser, record_edit.delete_attachment_parser, clipboard_copy_parser, record_totp.totp_parser,
              rm_parser, record_file_report.file_report_parser]:
        command_info[p.prog] = p.description
    command_info['trash'] = 'Manage records in the deleted items'
    command_info['find-password'] = 'Find and display password for a record'


get_info_parser = argparse.ArgumentParser(prog='get', description='Get the details of a record/folder/team by UID or title')
get_info_parser.add_argument('--unmask', dest='unmask', action='store_true', help='display hidden field content')
get_info_parser.add_argument('--legacy', dest='legacy', action='store_true',
                             help='json output: display typed records as legacy')
get_info_parser.add_argument('--include-dag', dest='include_dag', action='store_true',
                             help='include DAG/GraphSync information in json output')
get_info_parser.add_argument(
    '--format', dest='format', action='store', choices=['detail', 'json', 'password', 'fields'],
    default='detail', help='output format')
get_info_parser.add_argument('uid', type=str, action='store', help='UID or title to search for')


search_parser = argparse.ArgumentParser(prog='search', description='Search the vault using a regular expression')
search_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
search_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
search_parser.add_argument('-c', '--categories', dest='categories', action='store',
                           help='One or more of these letters for categories to search: "r" = records, '
                                '"s" = shared folders, "t" = teams')
search_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                           default='table', help='output format')


list_parser = argparse.ArgumentParser(prog='list', description='List all records', parents=[base.report_output_parser])
list_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
list_parser.add_argument('-t', '--type', dest='record_type', action='append',
                         help='List records of certain types. Can be repeated')
list_parser.add_argument('--field', dest='field', action='append', help='Filter records by specific field(s). Can be specified multiple times.')
list_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')


list_sf_parser = argparse.ArgumentParser(prog='list-sf', description='List all shared folders', parents=[base.report_output_parser])
list_sf_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')


list_team_parser = argparse.ArgumentParser(prog='list-team', description='List all teams', parents=[base.report_output_parser])
verbose_group = list_team_parser.add_mutually_exclusive_group()
verbose_group.add_argument('-v', '--verbose', action='store_true', help="verbose output (include team membership info)")
verbose_group.add_argument('-vv', '--very-verbose', action='store_true', help="more verbose output (fetches team membership info not in cache)")
list_team_parser.add_argument('-a', '--all', action='store_true',
                              help="show all teams in your contacts (including those outside your primary organization)")
list_team_parser.add_argument('--sort', dest='sort', choices=['company', 'team_uid', 'name'], default='company',
                              help="sort teams by column (default: company)")


record_history_parser = argparse.ArgumentParser(prog='record-history', parents=[base.report_output_parser],
                                                description='Show the revision history of a record')
record_history_parser.add_argument(
    '-a', '--action', dest='action', choices=['list', 'diff', 'view', 'restore'], action='store',
    help="filter by record history type. (default: 'list'). --revision required with 'restore' action.",
)
record_history_parser.add_argument(
    '-r', '--revision', dest='revision', type=int, action='store',
    help='only show the details for a specific revision.')
record_history_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help="verbose output")
record_history_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')


shared_records_report_parser = argparse.ArgumentParser(prog='shared-records-report', parents=[base.report_output_parser],
                                                       description='Report shared records for a logged-in user')
shared_records_report_parser.add_argument('-tu', '--show-team-users', dest='show_team_users', action='store_true',
                                          help='show members of team for records shared via share team folders.')
shared_records_report_parser.add_argument('--all-records', dest='all_records', action='store_true',
                                          help='report on all records in the vault. only owned records are included if this argument is omitted.')
shared_folder_help = 'Optional (w/ multiple values allowed). Path or UID of folder containing the records to be shown'
shared_records_report_parser.add_argument('folder', type=str, nargs='*', help=shared_folder_help)

clipboard_copy_parser = argparse.ArgumentParser(
    prog='clipboard-copy', description='Retrieve the password for a specific record')
clipboard_copy_parser.add_argument('--username', dest='username', action='store', help='match login name (optional)')
clipboard_copy_parser.add_argument(
    '--output', dest='output', choices=['clipboard', 'stdout', 'stdouthidden', 'variable'], default='clipboard', action='store',
    help='password output destination')
clipboard_copy_parser.add_argument(
    '--name', dest='name', action='store', help='Variable name if output is set to variable')
clipboard_copy_parser.add_argument(
    '-cu', '--copy-uid', dest='copy_uid', action='store_true', help='output uid instead of password')
clipboard_copy_parser.add_argument(
    '-l', '--login', dest='login', action='store_true', help='output login name')
clipboard_copy_parser.add_argument(
    '-t', '--totp', dest='totp', action='store_true', help='output totp code')
clipboard_copy_parser.add_argument(
    '--field', dest='field', action='store', help='output custom field')
clipboard_copy_parser.add_argument(
    '-r', '--revision', dest='revision', type=int, action='store',
    help='use a specific record revision')
clipboard_copy_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')


rm_parser = argparse.ArgumentParser(prog='rm', description='Remove or delete a record from the vault')
rm_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
rm_parser.add_argument('records', nargs='*', type=str, help='record path or UID. Can be repeated.')


def find_record(params, record_name, types=None):
    # type: (KeeperParams, str, Optional[Iterable[str]]) -> vault.KeeperRecord
    if not record_name:
        raise Exception(f'Record name cannot be empty.')

    if record_name in params.record_cache:
        return vault.KeeperRecord.load(params, record_name)
    else:
        rs = try_resolve_path(params, record_name)
        if rs is not None:
            folder, record_name = rs
            if folder is not None and record_name is not None:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for uid in params.subfolder_record_cache[folder_uid]:
                        r = vault.KeeperRecord.load(params, uid)
                        if r and r.title.lower() == record_name.lower():
                            return r

    if types:
        ls = RecordListCommand()
        result = ls.execute(params, record_type=types, format='json', verbose=True)
        if result:
            try:
                recs = json.loads(result)
                records = []
                if isinstance(recs, list):
                    for rec in recs:
                        if isinstance(rec, dict):
                            if 'title' in rec:
                                title = rec.get('title', '').strip().lower()
                                if title == record_name.lower():
                                    records.append(rec)
                                    continue
                            if 'description' in rec:
                                description = rec.get('description', '').lower()
                                if description:
                                    if {'serverCredentials', 'databaseCredentials', 'sskKeys'}.issuperset(types):
                                        user, sep, host = description.partition("@")
                                        if sep == '@':
                                            description = host
                                        hostname, _, _ = description.strip().partition(':')
                                        if hostname == record_name.lower():
                                            records.append(rec)
                                            continue
                if len(records) == 1:
                    return vault.KeeperRecord.load(params, records[0].get('record_uid'))
                elif len(records) > 1:
                    raise Exception(f'More than one record found for \"{record_name}\". Please use record UID or full record path.')
            except:
                pass
    raise Exception(f'Record "{record_name}" not found.')


class RecordGetUidCommand(Command):
    def get_parser(self):
        return get_info_parser

    def execute(self, params, **kwargs):
        uid = kwargs.get('uid')
        if not uid:
            raise CommandError('get', 'UID parameter is required')

        fmt = kwargs.get('format') or 'detail'

        # First try to interpret as UID
        direct_match = False
        
        if api.is_shared_folder(params, uid):
            admins = api.get_share_admins_for_shared_folder(params, uid)
            sf = api.get_shared_folder(params, uid)
            if fmt == 'json':
                sfo = {
                    "shared_folder_uid": sf.shared_folder_uid,
                    "name": sf.name,
                    "manage_users": sf.default_manage_users,
                    "manage_records": sf.default_manage_records,
                    "can_edit": sf.default_can_edit,
                    "can_share": sf.default_can_share
                }
                if sf.records:
                    sfo['records'] = [{
                        'record_uid': r['record_uid'],
                        'can_edit': r['can_edit'],
                        'can_share': r['can_share']
                    } for r in sf.records]
                if sf.users:
                    sfo['users'] = [{
                        'username': u['username'],
                        'manage_records': u['manage_records'],
                        'manage_users': u['manage_users']
                    } for u in sf.users]
                if sf.teams:
                    sfo['teams'] = [{
                        'name': t['name'],
                        'manage_records': t['manage_records'],
                        'manage_users': t['manage_users']
                    } for t in sf.teams]

                if admins:
                    sfo['share_admins'] = admins

                print(json.dumps(sfo, indent=2))
            else:
                if admins:
                    sf.share_admins = admins
                sf.display()
            direct_match = True
            return

        if uid in params.folder_cache:
            f = params.folder_cache[uid]
            if fmt == 'json':
                fo = {
                    'folder_uid': f.uid,
                    'type': f.type,
                    'name': f.name
                }
                if isinstance(f, (subfolder.SharedFolderFolderNode, subfolder.SharedFolderNode)):
                    fo['shared_folder_uid'] = f.shared_folder_uid if isinstance(f, subfolder.SharedFolderFolderNode) \
                        else f.uid
                if f.parent_uid:
                    fo['parent_folder_uid'] = f.parent_uid
                print(json.dumps(fo, indent=2))
            else:
                f.display()
            direct_match = True
            return

        if api.is_team(params, uid):
            team = api.get_team(params, uid)
            if fmt == 'json':
                to = {
                    'team_uid': team.team_uid,
                    'name': team.name,
                    'restrict_edit': team.restrict_edit,
                    'restrict_view': team.restrict_view,
                    'restrict_share': team.restrict_share
                }
                print(json.dumps(to, indent=2))
            else:
                team.display()
            direct_match = True
            return

        if params.available_team_cache is None:
            api.load_available_teams(params)

        if params.available_team_cache:
            for team in params.available_team_cache:
                if team.get('team_uid') == uid:
                    team_uid = team['team_uid']
                    team_name = team['team_name']
                    if fmt == 'json':
                        fo = {
                            'team_uid': team_uid,
                            'name': team_name
                        }
                        print(json.dumps(fo, indent=2))
                    else:
                        print('')
                        print('User {0} does not belong to team {1}'.format(params.user, team_name))
                        print('')
                        print('{0:>20s}: {1:<20s}'.format('Team UID', team_uid))
                        print('{0:>20s}: {1}'.format('Name', team_name))
                        print('')
                    direct_match = True
                    return

        if uid not in params.record_cache:
            if params.config and 'skip_records' in params.config and params.config['skip_records'] is True:
                for shared_folder_uid in params.shared_folder_cache:
                    sf = params.shared_folder_cache[shared_folder_uid]
                    if 'records' in sf:
                        if any((True for x in sf['records'] if x['record_uid'] == uid)):
                            api.load_records_in_shared_folder(params, shared_folder_uid, (uid,))
                            break
        if uid in params.record_cache:
            api.get_record_shares(params, [uid])
            rec = params.record_cache[uid]
            admins = api.get_share_admins_for_record(params, uid)
            version = rec.get('version', 0)
            r = api.get_record(params, uid)
            if r:
                params.queue_audit_event('open_record', record_uid=uid)
                if fmt == 'json':

                    ro = {
                        'record_uid': uid,
                    }
                    if version < 3 or kwargs.get('legacy') is True:
                        ro['title'] = r.title
                        if r.login:
                            ro['login'] = r.login
                        if r.password:
                            ro['password'] = r.password
                        if r.login_url:
                            ro['login_url'] = r.login_url
                        if r.custom_fields:
                            ro['custom_fields'] = r.custom_fields
                        if r.totp:
                            ro['totp'] = r.totp
                        if r.attachments:
                            ro['attachments'] = [{
                                'id': a.get('id'),
                                'name': a.get('name'),
                                'size': a.get('size')
                            } for a in r.attachments]
                    else:
                        data = rec['data_unencrypted'] if 'data_unencrypted' in rec else b'{}'
                        data = json.loads(data.decode())
                        ro.update(data)
                    if r.notes:
                        ro['notes'] = r.notes
                    ro['version'] = r.version
                    ro['shared'] = rec.get('shared', False)
                    if 'client_modified_time' in rec:
                        cmt = rec['client_modified_time']
                        if isinstance(cmt, (int, float)):
                            cmt = int(cmt / 1000)
                            dt = datetime.datetime.fromtimestamp(cmt)
                            ro['client_modified_time'] = dt.isoformat()

                    if 'shares' in rec:
                        if 'user_permissions' in rec['shares']:
                            ro['user_permissions'] = rec['shares']['user_permissions'].copy()
                        if 'shared_folder_permissions' in rec['shares']:
                            ro['shared_folder_permissions'] = rec['shares']['shared_folder_permissions'].copy()
                    if admins:
                        ro['share_admins'] = admins

                    ro['revision'] = r.revision
                    if version == 3 and kwargs.get('include_dag') is True:
                        self.include_dag(params, ro, r)

                    print(json.dumps(ro, indent=2))
                elif fmt == 'password':
                    if r.password:
                        print(r.password)
                elif fmt == 'fields':
                    fields = []
                    # todo: combine with cli.py format_field_name()
                    normalize_titles = {}
                    # Record properties
                    record_props = {
                        'title': r.title,
                        'record_uid': r.record_uid,
                        'revision': r.revision,
                        'version': r.version,
                        'shared': rec.get('shared', False),
                    }
                    for prop_name, prop_value in record_props.items():
                        normalize_titles[prop_name.lower()] = prop_name
                        key = prop_name
                        field = {
                            'name': key,
                            'value': prop_value,
                        }
                        fields.append(field)
                    # unmasked fields
                    for key, value in r.get_unmasked_field_params():
                        key = key.replace('_', ' ').title()
                        normalize_titles[key.lower()] = key
                        field = {
                            'name': key,
                            'value': value,
                        }
                        fields.append(field)
                    # masked fields
                    for key, value in r.get_masked_field_params():
                        unmask = kwargs.get('unmask') is True
                        field = {
                            'name': key.replace('_', ' ').title(),
                            'value': value if unmask else '********',
                        }
                        fields.append(field)
                    # typed fields
                    for field in r.get_typed_fields():
                        key = field.type
                        if key and key in field.type_name:
                            key = field.type_name[key]
                            if key in normalize_titles:
                                key = normalize_titles[key.lower()]
                            normalize_titles[key.lower()] = key
                            var_value = ''
                            unmask = kwargs.get('unmask') is True
                            if field.value and unmask or not field.sensitive:
                                var_value = field.value
                            elif field.value:
                                var_value = '********'

                            field = {
                                'name': key,
                                'value': var_value,
                            }
                            fields.append(field)
                    # notes
                    if r.notes:
                        field = {
                            'name': 'Notes',
                            'value': r.notes,
                        }
                        fields.append(field)

                    print(json.dumps(fields, indent=2))
                else:
                    unmask = kwargs.get('unmask') is True
                    r.display(unmask=unmask)
                    if rec.get('shares'):
                        if 'user_permissions' in rec['shares'] and rec['shares']['user_permissions']:
                            print('')
                            print('User Permissions:')
                            for user in rec['shares']['user_permissions']:
                                print('')
                                if 'username' in user:
                                    print('User: ' + user['username'])
                                if 'user_uid' in user:
                                    print('User UID: ' + user['user_uid'])
                                elif 'accountUid' in user:
                                    print('User UID: ' + user['accountUid'])
                                
                                # Handle both possible spellings of sharable/shareable
                                if 'sharable' in user:
                                    shareable = user['sharable']
                                elif 'shareable' in user:
                                    shareable = user['shareable']
                                else:
                                    shareable = False
                                
                                if shareable is None:
                                    shareable = False
                                
                                # Handle both possible spellings of readable
                                if 'readable' in user:
                                    readable = user['readable']
                                else:
                                    readable = False
                                
                                if readable is None:
                                    readable = False
                                
                                print('Shareable: ' + ('Yes' if shareable else 'No'))
                                print('Read-Only: ' + ('Yes' if not shareable else 'No'))
                            print('')
                        if 'shared_folder_permissions' in rec['shares'] and rec['shares']['shared_folder_permissions']:
                            print('')
                            print('Shared Folder Permissions:')
                            for sf in rec['shares']['shared_folder_permissions']:
                                print('')
                                if 'shared_folder_uid' in sf:
                                    print('Shared Folder UID: ' + sf['shared_folder_uid'])
                                if 'user_uid' in sf:
                                    print('User UID: ' + sf['user_uid'])
                                elif 'accountUid' in sf:
                                    print('User UID: ' + sf['accountUid'])
                                
                                # Safely access boolean fields with fallback to False
                                if sf.get('manage_users', False) is True:
                                    print('Manage Users: True')
                                if sf.get('manage_records', False) is True:
                                    print('Manage Records: True')
                                if sf.get('can_edit', False) is True:
                                    print('Can Edit: True')
                                if sf.get('can_share', False) is True:
                                    print('Can Share: True')
                            print('')
                        if 'team_permissions' in rec['shares'] and rec['shares']['team_permissions']:
                            print('')
                            print('Team Permissions:')
                            for team in rec['shares']['team_permissions']:
                                print('')
                                if 'team_uid' in team:
                                    print('Team UID: ' + team['team_uid'])
                                if 'name' in team:
                                    print('Name: ' + team['name'])
                            print('')
                    if admins:
                        print('')
                        print('Share Admins:')
                        for admin in admins:
                            print(admin)
                direct_match = True
                return

        # If we didn't find a direct match by UID, try searching by title
        if not direct_match:
            # Find all title matches
            matched_records = []
            for record_uid in params.record_cache:
                record = vault.KeeperRecord.load(params, record_uid)
                if record and record.title and uid.lower() in record.title.lower():
                    matched_records.append(record)
            
            matched_folders = []
            for folder_uid in params.folder_cache:
                folder = params.folder_cache[folder_uid]
                if folder and folder.name and uid.lower() in folder.name.lower():
                    matched_folders.append(folder)
            
            matched_teams = []
            if params.available_team_cache:
                for team in params.available_team_cache:
                    team_name = team.get('team_name')
                    if team_name and uid.lower() in team_name.lower():
                        matched_teams.append(team)
            
            total_matches = len(matched_records) + len(matched_folders) + len(matched_teams)
            
            if total_matches == 0:
                # No matches found by title either, show original error
                raise CommandError('get', 'Cannot find any object with UID: {0}'.format(uid))
            
            if total_matches == 1:
                # If only one match, display it directly
                if len(matched_records) == 1:
                    return self.execute(params, uid=matched_records[0].record_uid, format=fmt, unmask=kwargs.get('unmask'), legacy=kwargs.get('legacy'))
                elif len(matched_folders) == 1:
                    uid = matched_folders[0].uid
                    f = params.folder_cache[uid]
                    if fmt == 'json':
                        fo = {
                            'folder_uid': f.uid,
                            'type': f.type,
                            'name': f.name
                        }
                        if isinstance(f, (subfolder.SharedFolderFolderNode, subfolder.SharedFolderNode)):
                            fo['shared_folder_uid'] = f.shared_folder_uid if isinstance(f, subfolder.SharedFolderFolderNode) \
                                else f.uid
                        if f.parent_uid:
                            fo['parent_folder_uid'] = f.parent_uid
                        print(json.dumps(fo, indent=2))
                    else:
                        f.display()
                    return
                elif len(matched_teams) == 1:
                    team_uid = matched_teams[0].get('team_uid')
                    if api.is_team(params, team_uid):
                        team = api.get_team(params, team_uid)
                        if fmt == 'json':
                            to = {
                                'team_uid': team.team_uid,
                                'name': team.name,
                                'restrict_edit': team.restrict_edit,
                                'restrict_view': team.restrict_view,
                                'restrict_share': team.restrict_share
                            }
                            print(json.dumps(to, indent=2))
                        else:
                            team.display()
                        return
                    else:
                        team_uid = matched_teams[0].get('team_uid')
                        team_name = matched_teams[0].get('team_name')
                        if fmt == 'json':
                            fo = {
                                'team_uid': team_uid,
                                'name': team_name
                            }
                            print(json.dumps(fo, indent=2))
                        else:
                            print('')
                            print('User {0} does not belong to team {1}'.format(params.user, team_name))
                            print('')
                            print('{0:>20s}: {1:<20s}'.format('Team UID', team_uid))
                            print('{0:>20s}: {1}'.format('Name', team_name))
                            print('')
                        return
            
            # Multiple matches, show summary
            logging.info(f'Found {total_matches} items with title containing "{uid}":')
            
            # Create a unified table for all types of items
            table = []
            headers = ['UID', 'Type', 'Title']
            
            # Create a list for JSON output if needed
            json_results = []
            
            # Add records to the unified table
            for r in matched_records:
                # For records, include both "Record" and the record_type
                type_display = f"Record ({r.record_type})" if r.record_type else "Record"
                row = [r.record_uid, type_display, r.title]
                table.append(row)
                
                # Add to JSON results
                json_results.append({
                    "uid": r.record_uid,
                    "type": "record",
                    "record_type": r.record_type,
                    "title": r.title
                })
            
            # Add folders to the unified table
            for f in matched_folders:
                path = get_folder_path(params, f.uid)
                # For folders, display "Shared Folder"
                title = f.name + (" - " + path if path else "")
                row = [f.uid, "Shared Folder", title]
                table.append(row)
                
                # Add to JSON results
                json_results.append({
                    "uid": f.uid,
                    "type": "shared_folder",
                    "folder_type": f.type,
                    "name": f.name,
                    "path": path
                })
            
            # Add teams to the unified table
            for t in matched_teams:
                # For teams, just display "Team"
                row = [t.get('team_uid'), "Team", t.get('team_name')]
                table.append(row)
                
                # Add to JSON results
                json_results.append({
                    "uid": t.get('team_uid'),
                    "type": "team",
                    "name": t.get('team_name')
                })
            
            # Sort the table by type first (records on top) and then by title
            def sort_key(row):
                # Assign a priority number based on type to sort records first
                type_text = row[1]
                if type_text.startswith("Record"):
                    type_priority = 1
                elif type_text == "Shared Folder":
                    type_priority = 2
                else:  # "Team"
                    type_priority = 3
                return (type_priority, row[2].lower())
            
            table.sort(key=sort_key)
            
            # Get the format from kwargs
            fmt = kwargs.get('format') or 'detail'
            
            # For both table and JSON formats, use dump_report_data
            # This is consistent with how other commands use this function
            if fmt == 'json':
                # For JSON format, convert our hierarchical data to a flattened table format
                # But ensure we preserve all the information
                json_table = []
                for item in json_results:
                    row = []
                    row.append(item['uid'])
                    row.append(item['type'])
                    if item['type'] == 'record' and 'record_type' in item:
                        row.append(item['record_type'])
                    else:
                        row.append('')
                    row.append(item.get('title', item.get('name', '')))
                    if item['type'] == 'shared_folder' and 'path' in item:
                        row.append(item['path'])
                    else:
                        row.append('')
                    json_table.append(row)
                
                # Sort the JSON table the same way we sorted the display table
                json_table.sort(key=lambda x: (
                    1 if x[1] == 'record' else 2 if x[1] == 'shared_folder' else 3,
                    x[3].lower()
                ))
                
                json_headers = ['uid', 'type', 'subtype', 'title', 'path']
                # Use dump_report_data with fmt='json'
                # This matches the pattern used in discoveryrotation.py
                base.dump_report_data(json_table, json_headers, fmt='json')
            else:
                # Display the unified table using dump_report_data for tabular format
                base.dump_report_data(table, headers, row_number=True)
                
                # Display a helpful message about using UID for precise access
                logging.info('\nTo view details of a specific item, use the get command with its UID.')
            return

    def include_dag(self, params, ro, r):
        """Include DAG/GraphSync information for the record.

        Args:
            params: Command parameters
            ro: Record output dictionary to be modified
            r: Record object
        """
        valid_record_types = {'pamDatabase', 'pamDirectory', 'pamMachine'}
        if r.record_type not in valid_record_types:
            return

        # Initialize structures once - always present with nullable values
        ro['associatedCredentials'] = {
            'adminCredential': None,
            'launchCredential': None,
            'linkedCredentials': None
        }
        ro['pamSettingsEnabled'] = {
            'connections': None,
            'tunneling': None,
            'rotation': None,
            'sessionRecording': None,
            'typescriptRecording': None,
            'remoteBrowserIsolation': None
        }

        try:
            # Get keeper tokens for DAG access
            from .tunnel.port_forward.tunnel_helpers import get_keeper_tokens
            from .tunnel.port_forward.TunnelGraph import TunnelDAG
            from ..keeper_dag import EdgeType

            encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(params)
            tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, r.record_uid)

            if not tdag.linking_dag.has_graph:
                return

            record_vertex = tdag.linking_dag.get_vertex(r.record_uid)
            if record_vertex is None:
                return

            # Extract allowedSettings from vertex content
            try:
                content = record_vertex.content_as_dict
                if content and 'allowedSettings' in content:
                    allowed_settings = content['allowedSettings']
                    if isinstance(allowed_settings, dict):
                        ro['pamSettingsEnabled']['connections'] = allowed_settings.get('connections')
                        ro['pamSettingsEnabled']['tunneling'] = allowed_settings.get('portForwards')
                        ro['pamSettingsEnabled']['rotation'] = allowed_settings.get('rotation')
                        ro['pamSettingsEnabled']['sessionRecording'] = allowed_settings.get('sessionRecording')
                        ro['pamSettingsEnabled']['typescriptRecording'] = allowed_settings.get('typescriptRecording')
                        ro['pamSettingsEnabled']['remoteBrowserIsolation'] = allowed_settings.get('remoteBrowserIsolation')
            except Exception:
                pass

            # Find all ACL links where Head is recordUID
            admin_credential = None
            launch_credential = None
            linked_credentials = []

            # Get vertices that have ACL edges pointing to this record (has_vertices)
            for user_vertex in record_vertex.has_vertices(EdgeType.ACL):
                acl_edge = user_vertex.get_edge(record_vertex, EdgeType.ACL)
                if acl_edge:
                    try:
                        content = acl_edge.content_as_dict or {}
                        # belongs_to = content.get('belongs_to', False)
                        is_admin = content.get('is_admin', False)
                        is_launch_credential = content.get('is_launch_credential', None)

                        # Add to linked credentials list
                        if user_vertex.uid not in linked_credentials:
                            linked_credentials.append(user_vertex.uid)

                        if is_admin and admin_credential is None:
                            admin_credential = user_vertex.uid

                        if is_launch_credential and launch_credential is None:
                            launch_credential = user_vertex.uid
                    except Exception:
                        pass

            # Update associatedCredentials with found values
            ro['associatedCredentials']['adminCredential'] = admin_credential
            ro['associatedCredentials']['launchCredential'] = launch_credential
            ro['associatedCredentials']['linkedCredentials'] = linked_credentials if linked_credentials else None

        except Exception as e:
            logging.debug(f"Error accessing DAG for record {r.record_uid}: {e}")


class SearchCommand(Command):
    def get_parser(self):
        return search_parser

    def execute(self, params, **kwargs):
        pattern = kwargs.get('pattern') or ''
        if pattern == '*':
            pattern = '.*'

        categories = (kwargs.get('categories') or 'rst').lower()
        verbose = kwargs.get('verbose') is True
        skip_details = not verbose
        fmt = kwargs.get('format', 'table')

        all_results = []

        if 'r' in categories:
            records = list(vault_extensions.find_records(params, pattern))
            if records:
                if fmt == 'json':
                    for record in records:
                        result_item = {
                            'type': 'record',
                            'record_uid': record.record_uid,
                            'record_type': record.record_type,
                            'title': record.title,
                            'description': vault_extensions.get_record_description(record)
                        }
                        all_results.append(result_item)
                else:
                    logging.info('')
                    table = []
                    headers = ['Record UID', 'Type', 'Title', 'Description']
                    for record in records:
                        row = [record.record_uid, record.record_type, record.title,
                               vault_extensions.get_record_description(record)]
                        table.append(row)
                    table.sort(key=lambda x: (x[2] or '').lower())

                    base.dump_report_data(table, headers, row_number=True, column_width=None if verbose else 40)
                    if verbose and len(records) < 5:
                        get_command = RecordGetUidCommand()
                        for record in records:
                            get_command.execute(params, uid=record.record_uid)

        # Search shared folders
        if 's' in categories:
            results = api.search_shared_folders(params, pattern)
            if results:
                if fmt == 'json':
                    for sf in results:
                        result_item = {
                            'type': 'shared_folder',
                            'shared_folder_uid': sf.shared_folder_uid,
                            'name': sf.name,
                            'can_edit': getattr(sf, 'can_edit', False),
                            'can_share': getattr(sf, 'can_share', False)
                        }
                        all_results.append(result_item)
                else:
                    logging.info('')
                    display.formatted_shared_folders(results, params=params, skip_details=skip_details)

        # Search teams
        if 't' in categories:
            results = api.search_teams(params, pattern)
            if results:
                if fmt == 'json':
                    for team in results:
                        result_item = {
                            'type': 'team',
                            'team_uid': team.team_uid,
                            'name': team.name,
                            'restrict_edit': getattr(team, 'restrict_edit', False),
                            'restrict_view': getattr(team, 'restrict_view', False),
                            'restrict_share': getattr(team, 'restrict_share', False)
                        }
                        all_results.append(result_item)
                else:
                    logging.info('')
                    display.formatted_teams(results, params=params, skip_details=skip_details)

        if fmt == 'json':
            if all_results:
                table = []
                headers = ['type', 'uid', 'name', 'details']
                
                for item in all_results:
                    if item['type'] == 'record':
                        row = [item['type'], item['record_uid'], item['title'], 
                               f"Type: {item['record_type']}, Description: {item['description']}"]
                    elif item['type'] == 'shared_folder':
                        row = [item['type'], item['shared_folder_uid'], item['name'],
                               f"Can Edit: {item['can_edit']}, Can Share: {item['can_share']}"]
                    elif item['type'] == 'team':
                        row = [item['type'], item['team_uid'], item['name'],
                               f"Restrict Edit: {item['restrict_edit']}, Restrict View: {item['restrict_view']}, Restrict Share: {item['restrict_share']}"]
                    table.append(row)
                
                return base.dump_report_data(table, headers, fmt='json')
            else:
                return base.dump_report_data([], ['type', 'uid', 'name', 'details'], fmt='json')


class RecordListCommand(Command):
    def get_parser(self):
        return list_parser

    def execute(self, params, **kwargs):
        verbose = kwargs.get('verbose', False)
        fmt = kwargs.get('format', 'table')
        # Use the --field parameter(s) if provided.
        search_fields = kwargs.get('field')  # Can be a list if passed multiple times.
        pattern = kwargs.get('pattern')

        record_types = kwargs.get('record_type')
        if record_types:
            record_version = set()
            record_type = set()
            if isinstance(record_types, str):
                record_types = [record_types]
            for rt in record_types:
                if rt == 'app':
                    record_version.add(5)
                elif rt == 'file':
                    record_version.update((3, 4))
                    record_type.add('file')
                elif rt in ('general', 'legacy'):
                    record_version.update((1, 2))
                elif rt == 'pam':
                    record_version.add(6)
                else:
                    record_version.update((3, 6))
                    record_type.add(rt)
        else:
            record_version = None if verbose else (1, 2, 3)
            record_type = None

        records = [x for x in vault_extensions.find_records(
            params,
            pattern,
            record_type=record_type,
            record_version=record_version,
            search_fields=search_fields)]
        if any(records):
            headers = ['record_uid', 'type', 'title', 'description', 'shared']
            if fmt == 'table':
                headers = [base.field_to_title(x) for x in headers]
            table = []
            for record in records:
                row = [record.record_uid, record.record_type, record.title,
                       vault_extensions.get_record_description(record), record.shared]
                table.append(row)
            table.sort(key=lambda x: (x[2] or '').lower())
            if fmt != 'json':
                headers = [base.field_to_title(x) for x in headers]
            return base.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                         row_number=True, column_width=None if verbose else 40)
        else:
            return handle_empty_result(fmt, 'No records are found', kwargs.get('output'))


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

            return base.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True)
        else:
            return handle_empty_result(fmt, 'No shared folders are found', kwargs.get('output'))


class RecordListTeamCommand(Command):
    def get_parser(self):
        return list_team_parser

    def execute(self, params, **kwargs):
        fmt = kwargs.get('format', 'table')
        show_all_teams = kwargs.get('all')
        show_team_users = kwargs.get('verbose') or kwargs.get('very_verbose', False)
        fetch_missing_users = kwargs.get('very_verbose', False)
        share_targets = api.get_share_objects(params)
        teams = share_targets.get('teams', {})
        orgs = share_targets.get('enterprises', {})
        enterprise_id = params.license.get('enterprise_id') if params.license else None
        is_included = lambda t: show_all_teams or t.get('enterprise_id') == enterprise_id
        teams = [Team(team_uid=uid, enterprise_id=t.get('enterprise_id'), name=t.get('name')) for uid, t in teams.items() if is_included(t)]

        # The endpoint above returns max 500 teams; Fill in the missing teams using a different endpoint if necessary
        if len(teams)  >= 500:
            team_uids = [uid for uid in share_targets.get('teams', {}).keys()]
            api.load_available_teams(params)
            teams.extend(
                 [Team(team_uid=team.get('team_uid'), name=team.get('team_name'), enterprise_id=enterprise_id) for team in params.available_team_cache if team.get('team_uid') not in team_uids]
            )

        teams = self.get_team_members(params, teams, fetch_missing_users) if show_team_users else teams
        if teams:
            table = []
            headers = ['company', 'team_uid', 'name']
            if show_team_users:
                headers.append('member')
            headers = fields_to_titles(headers) if 'fmt' != 'json' else headers
            for team in teams:
                row = [orgs.get(team.enterprise_id), team.team_uid, team.name]
                if show_team_users:
                    row.append(team.members)
                table.append(row)
            
            # Sort by the specified column
            sort_column = kwargs.get('sort', 'company')
            if sort_column == 'company':
                table.sort(key=lambda x: (x[0] or '').lower())
            elif sort_column == 'team_uid':
                table.sort(key=lambda x: x[1].lower())
            elif sort_column == 'name':
                table.sort(key=lambda x: x[2].lower())

            return base.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True)
        else:
            return handle_empty_result(fmt, 'No teams are found', kwargs.get('output'))

    @classmethod
    def get_team_members(self, params, teams, allow_fetch):
        # type: (KeeperParams, List[Team], bool) -> List[Team]
        if not params.enterprise_ec_key:
            return teams

        def get_enterprise_teams():
            if not params.enterprise:
                return {}
            users = {x.get('enterprise_user_id'): x.get('username') for x in params.enterprise.get('users', [])}
            return reduce(
                lambda a, b: {**a, b.get('team_uid'): [*a.get(b.get('team_uid'), []), users.get(b.get('enterprise_user_id'))]},
                params.enterprise.get('team_users', {}),
                dict()
            )

        def fetch_members(team_uid):    # type: (str) -> List[str]
            if not allow_fetch:
                return []
            rq = enterprise_pb2.GetTeamMemberRequest()
            rq.teamUid = utils.base64_url_decode(team_uid)
            rs = api.communicate_rest(params, rq, 'vault/get_team_members', rs_type=enterprise_pb2.GetTeamMemberResponse)
            return [x.email for x in rs.enterpriseUser]

        enterprise_teams = get_enterprise_teams()
        for t in teams:
            t.members = enterprise_teams.get(t.team_uid) or fetch_members(t.team_uid)

        return teams



trash_list_parser = argparse.ArgumentParser(prog='trash list', description='Displays a list of deleted records',
                                            parents=[base.report_output_parser])
trash_list_parser.add_argument('--reload', dest='reload', action='store_true', help='reload deleted records')
trash_list_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help="verbose output")
trash_list_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')


trash_get_parser = argparse.ArgumentParser(prog='trash get', description='Get the details of a deleted record')
trash_get_parser.add_argument('record', action='store', help='Deleted record UID')

trash_restore_parser = argparse.ArgumentParser(prog='trash restore', description='Restores deleted records')
trash_restore_parser.add_argument('-f', '--force', dest='force', action='store_true',
                                  help='do not prompt for confirmation')
trash_restore_parser.add_argument('records', nargs='+', type=str, action='store',
                                  help='Record UID or search pattern')

trash_unshare_parser = argparse.ArgumentParser(prog='trash unshare', description='Remove shares from deleted records')
trash_unshare_parser.add_argument('-f', '--force', dest='force', action='store_true',
                                  help='do not prompt for confirmation')
trash_unshare_parser.add_argument('records', nargs='+', type=str, action='store',
                                  help='Record UID or search pattern. \"*\" ')

trash_purge_parser = argparse.ArgumentParser(prog='trash purge',
                                             description='Removes all deleted records from the trash bin')
trash_purge_parser.add_argument('-f', '--force', dest='force', action='store_true',
                                help='do not prompt for confirmation')


class TrashMixin:
    last_revision = 0
    deleted_record_cache = {}
    orphaned_record_cache = {}
    deleted_shared_folder_cache = {}

    @staticmethod
    def _ensure_deleted_records_loaded(params, reload=False):   # type: (KeeperParams, bool) -> None
        if params.revision != TrashMixin.last_revision or reload:
            # 1
            folder_rs = api.communicate_rest(params, None, 'vault/get_deleted_shared_folders_and_records',
                                             rs_type=folder_pb2.GetDeletedSharedFoldersAndRecordsResponse)
            users = {utils.base64_url_encode(x.accountUid): x.username for x in folder_rs.usernames}  # type: Dict[str, str]

            folder_keys = {}   # type: Dict[str, Tuple[bytes, str]]
            for shared_folder_uid, sf in params.shared_folder_cache.items():
                if 'shared_folder_key_unencrypted' in sf:
                    folder_keys[shared_folder_uid] = (sf['shared_folder_key_unencrypted'], shared_folder_uid)
            folders = {}  # type: Dict[str, Dict[str, Any]]
            for sf in folder_rs.sharedFolders:
                shared_folder_uid = utils.base64_url_encode(sf.sharedFolderUid)
                folder_uid = utils.base64_url_encode(sf.folderUid)
                try:
                    folder_key = None
                    if sf.folderKeyType == record_pb2.ENCRYPTED_BY_DATA_KEY:
                        folder_key = crypto.decrypt_aes_v1(sf.sharedFolderKey, params.data_key)
                    elif sf.folderKeyType == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                        folder_key = crypto.decrypt_rsa(sf.sharedFolderKey, params.rsa_key2)
                    elif sf.folderKeyType == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                        folder_key = crypto.decrypt_aes_v2(sf.sharedFolderKey, params.data_key)
                    elif sf.folderKeyType == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                        folder_key = crypto.decrypt_ec(sf.sharedFolderKey, params.ecc_key)
                    elif sf.folderKeyType in (record_pb2.ENCRYPTED_BY_ROOT_KEY_CBC, record_pb2.ENCRYPTED_BY_ROOT_KEY_GCM):
                        if shared_folder_uid in folder_keys:
                            shared_folder_key, _ = folder_keys.get(shared_folder_uid)
                            if sf.folderKeyType == record_pb2.ENCRYPTED_BY_ROOT_KEY_CBC:
                                folder_key = crypto.decrypt_aes_v1(sf.sharedFolderKey, shared_folder_key)
                            elif sf.folderKeyType == record_pb2.ENCRYPTED_BY_ROOT_KEY_GCM:
                                folder_key = crypto.decrypt_aes_v2(sf.sharedFolderKey, shared_folder_key)
                            else:
                                continue
                        else:
                            continue
                    folder_keys[folder_uid] = (folder_key, shared_folder_uid)
                    decrypted_data = crypto.decrypt_aes_v1(sf.data, folder_key)
                except Exception as e:
                    logging.debug('Shared folder key decryption: %s', e)
                    continue

                folder_dict = {
                    'shared_folder_uid': shared_folder_uid,
                    'folder_uid': folder_uid,
                    'data': utils.base64_url_encode(sf.data),
                    'data_unencrypted': decrypted_data,
                    'folder_key_unencrypted': folder_key,
                    'date_deleted': sf.dateDeleted,
                }
                if len(sf.parentUid) > 0:
                    folder_dict['parent_uid'] = utils.base64_url_encode(sf.parentUid)
                folders[folder_uid] = folder_dict

            record_keys = {}    # type: Dict[str, Tuple[bytes, str, int]]
            for rk in folder_rs.sharedFolderRecords:
                folder_uid = utils.base64_url_encode(rk.folderUid)
                if folder_uid not in folder_keys:
                    continue
                _, shared_folder_uid = folder_keys.get(folder_uid)
                if shared_folder_uid not in folder_keys:
                    continue
                folder_key, _ = folder_keys.get(shared_folder_uid)
                record_uid = utils.base64_url_encode(rk.recordUid)
                try:
                    if len(rk.sharedRecordKey) == 60:
                        record_key = crypto.decrypt_aes_v2(rk.sharedRecordKey, folder_key)
                    else:
                        record_key = crypto.decrypt_aes_v1(rk.sharedRecordKey, folder_key)
                    record_keys[record_uid] = (record_key, folder_uid, rk.dateDeleted)
                except Exception as e:
                    logging.debug('Record "%s" key decryption: %s', record_uid, e)
                    continue

            records = {}    # type: Dict[str, Dict[str, Any]]
            for r in folder_rs.deletedRecordData:
                record_uid = utils.base64_url_encode(r.recordUid)
                if record_uid not in record_keys:
                    continue
                record_key, folder_uid, time_deleted = record_keys[record_uid]

                try:
                    if r.version < 3:
                        decrypted_data = crypto.decrypt_aes_v1(r.data, record_key)
                    else:
                        decrypted_data = crypto.decrypt_aes_v2(r.data, record_key)
                except Exception as e:
                    logging.debug('Record "%s" decryption: %s', record_uid, e)
                    continue

                record_dict = {
                    'record_uid': record_uid,
                    'folder_uid': folder_uid,
                    'revision': r.revision,
                    'version': r.version,
                    'owner': users.get(utils.base64_url_encode(r.ownerUid)),
                    'client_modified_time': r.clientModifiedTime,
                    'date_deleted': time_deleted,
                    'data': utils.base64_url_encode(r.data),
                    'data_unencrypted': decrypted_data,
                    'record_key_unencrypted': record_key,
                }
                records[record_uid] = record_dict

            cache = TrashMixin.deleted_shared_folder_cache
            cache.clear()
            if len(folders) > 0:
                cache['folders'] = folders
            if len(records) > 0:
                cache['records'] = records

            # 2
            rq = {
                'command': 'get_deleted_records',
                'client_time': utils.current_milli_time()
            }
            rs = api.communicate(params, rq)
            for prop in ['records', 'non_access_records']:
                if prop in rs:
                    deleted_uids = set()
                    cache = TrashMixin.deleted_record_cache if prop == 'records' else TrashMixin.orphaned_record_cache
                    for record in rs[prop]:
                        record_uid = record['record_uid']
                        deleted_uids.add(record_uid)
                        if record_uid in cache:
                            continue
                        try:
                            key_type = record['record_key_type']
                            record_key = utils.base64_url_decode(record['record_key'])
                            if key_type == 1:
                                record_key = crypto.decrypt_aes_v1(record_key, params.data_key)
                            elif key_type == 2:
                                record_key = crypto.decrypt_rsa(record_key, params.rsa_key2)
                            elif key_type == 3:
                                record_key = crypto.decrypt_aes_v2(record_key, params.data_key)
                            elif key_type == 4:
                                record_key = crypto.decrypt_ec(record_key, params.ecc_key)
                            else:
                                logging.debug('Cannot decrypt record key %s', record_uid)
                                continue
                            record['record_key_unencrypted'] = record_key

                            data = utils.base64_url_decode(record['data'])
                            version = record['version']
                            record['data_unencrypted'] = \
                                crypto.decrypt_aes_v2(data, record_key) if version >= 3 else \
                                    crypto.decrypt_aes_v1(data, record_key)

                            cache[record_uid] = record
                        except Exception as e:
                            logging.debug('Cannot decrypt deleted record %s: %s', record_uid, e)

                    for record_uid in list(cache.keys()):
                        if record_uid not in deleted_uids:
                            del cache[record_uid]

            TrashMixin.last_revision = params.revision

    @staticmethod
    def get_deleted_records(params, reload=False):    # type: (KeeperParams, bool) -> Dict[str, Any]
        TrashMixin._ensure_deleted_records_loaded(params, reload)
        return TrashMixin.deleted_record_cache

    @staticmethod
    def get_orphaned_records(params, reload=False):    # type: (KeeperParams, bool) -> Dict[str, Any]
        TrashMixin._ensure_deleted_records_loaded(params, reload)
        return TrashMixin.orphaned_record_cache

    @staticmethod
    def get_shared_folders(params, reload=False):    # type: (KeeperParams, bool) -> Dict[str, Any]
        TrashMixin._ensure_deleted_records_loaded(params, reload)
        return TrashMixin.deleted_shared_folder_cache


class TrashCommand(GroupCommand):
    def __init__(self):
        super(TrashCommand, self).__init__()
        self.register_command('list', TrashListCommand())
        self.register_command('get', TrashGetCommand())
        self.register_command('restore', TrashRestoreCommand())
        self.register_command('unshare', TrashUnshareCommand())
        self.register_command('purge', TrashPurgeCommand())
        self.default_verb = 'list'


class TrashListCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_list_parser

    def execute(self, params, **kwargs):
        deleted_records = self.get_deleted_records(params, kwargs.get('reload', False))
        orphaned_records = self.get_orphaned_records(params)
        shared_folders = self.get_shared_folders(params)
        verbose = kwargs.get('verbose') is True

        if len(deleted_records) == 0 and len(orphaned_records) == 0 and len(shared_folders) == 0:
            fmt = kwargs.get('format', 'table')
            return handle_empty_result(fmt, 'Trash is empty', kwargs.get('output'))

        pattern = kwargs.get('pattern')
        if pattern:
            if pattern == '*':
                pattern = None

        title_pattern = None
        if pattern:
            title_pattern = re.compile(fnmatch.translate(pattern), re.IGNORECASE)

        record_table = []
        headers = ['Folder UID', 'Record UID', 'Name', 'Record Type', 'Deleted At', 'Status']

        for shared in (False, True):
            for rec in (orphaned_records if shared else deleted_records).values():
                record = vault.KeeperRecord.load(params, rec)

                if pattern:
                    if pattern == record.record_uid:
                        pass
                    elif title_pattern and title_pattern.match(record.title):
                        pass
                    else:
                        continue

                date_deleted = None
                if shared:
                    status = 'Share'
                else:
                    status = 'Record'
                    dd = rec.get('date_deleted', 0)
                    if dd:
                        date_deleted = datetime.datetime.fromtimestamp(int(dd / 1000))
                record_table.append(['', record.record_uid, record.title, record.record_type, date_deleted, status])

        record_table.sort(key=lambda x: x[2].casefold())
        folder_table = []

        if shared_folders and len(shared_folders) > 0:
            folders = shared_folders.get('folders', {})    # type: Dict[str, dict]
            records = shared_folders.get('records', {})    # type: Dict[str, dict]
            if verbose:
                for rec in records.values():
                    folder_uid = rec.get('folder_uid')
                    record_uid = rec.get('record_uid')
                    record = vault.KeeperRecord.load(params, rec)
                    if not record:
                        continue

                    date_deleted = None
                    dd = rec.get('date_deleted', 0)
                    if dd:
                        date_deleted = datetime.datetime.fromtimestamp(int(dd / 1000))
                    folder_table.append([folder_uid, record_uid, record.title, record.record_type, date_deleted, 'Folder'])
            else:
                rec_in_fol = {}    # type: Dict[str, int]
                for rec in records.values():
                    folder_uid = rec.get('folder_uid')
                    if folder_uid not in rec_in_fol:
                        rec_in_fol[folder_uid] = 0
                    rec_in_fol[folder_uid] = rec_in_fol[folder_uid] + 1

                for fol in folders.values():
                    folder_uid = fol.get('folder_uid')
                    date_deleted = None
                    dd = fol.get('date_deleted', 0)
                    if dd:
                        date_deleted = datetime.datetime.fromtimestamp(int(dd / 1000))
                    rec_count = rec_in_fol.get(folder_uid)
                    rc = None
                    if isinstance(rec_count, int) and rec_count > 0:
                        rc = f'{rec_count} record(s)'
                    try:
                        data = json.loads(fol.get('data_unencrypted'))
                        folder_name = data.get('name') or folder_uid
                    except Exception as e:
                        logging.debug('Load folder data: %s', e)
                        folder_name = folder_uid
                    folder_table.append([folder_uid, rc, folder_name, '', date_deleted, 'Folder'])

        folder_table.sort(key=lambda x: x[2].casefold())

        return base.dump_report_data(record_table + folder_table, headers, fmt=kwargs.get('format'),
                                     filename=kwargs.get('output'), row_number=True)


class TrashGetCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_get_parser

    def execute(self, params, **kwargs):
        deleted_records = self.get_deleted_records(params)
        orphaned_records = self.get_orphaned_records(params)
        if len(deleted_records) == 0 and len(orphaned_records) == 0:
            logging.info('Trash is empty')
            return

        record_uid = kwargs.get('record')
        if not record_uid:
            logging.info('Record UID parameter is required')
            return

        is_shared = False
        rec = deleted_records.get(record_uid)
        if not rec:
            rec = orphaned_records.get(record_uid)
            is_shared = True
        if not rec:
            logging.info('%s is not a valid deleted record UID', record_uid)
            return

        record = vault.KeeperRecord.load(params, rec)
        if not record:
            logging.info('Cannot restore record %s', record_uid)
            return

        for name, value in record.enumerate_fields():
            if value:
                if isinstance(value, list):
                    value = '\n'.join(value)
                if len(value) > 100:
                    value = value[:99] + '...'
                print('{0:>21s}: {1}'.format(name, value))
        if is_shared:
            if 'shares' not in rec:
                rec['shares'] = {}
                shares = api.get_record_shares(params, (record_uid,), True)
                if isinstance(shares, list):
                    record_shares = next(iter(x.get('shares') for x in shares if x.get('record_uid') == record_uid), None)
                    if isinstance(record_shares, dict):
                        rec['shares'] = record_shares

            if 'shares' in rec:
                if 'user_permissions' in rec['shares']:
                    perm = rec['shares']['user_permissions'].copy()
                    perm.sort(key=lambda r: (' 1' if r.get('owner') else
                                             ' 2' if r.get('editable') else
                                             ' 3' if r.get('shareable') else
                                             '') + r.get('username'))
                    no = 0
                    for uo in perm:
                        flags = ''
                        if uo.get('owner'):
                            continue
                        if uo.get('editable'):
                            flags = 'Can Edit'
                        if uo.get('shareable'):
                            if flags:
                                flags = flags + ' & '
                            else:
                                flags = 'Can '
                            flags = flags + 'Share'
                        if not flags:
                            flags = 'Read Only'
                        print('{0:>21s}: {1:<26s} ({2}) {3}'.format(
                            'Direct User Shares' if no == 0 else '', uo['username'], flags,
                            'self' if uo['username'] == params.user else ''))
                        no += 1


class TrashRestoreCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_restore_parser

    def execute(self, params, **kwargs):
        deleted_records = self.get_deleted_records(params)
        orphaned_records = self.get_orphaned_records(params)
        shared_folders = self.get_shared_folders(params)
        deleted_shared_records = shared_folders.get('records') or {}
        deleted_shared_folders = shared_folders.get('folders') or {}
        if len(deleted_records) == 0 and len(orphaned_records) == 0 and len(deleted_shared_records) == 0 and len(deleted_shared_folders) == 0:
            logging.info('Trash is empty')
            return

        records = kwargs.get('records')
        if not isinstance(records, (tuple, list)):
            records = None
        if not records:
            logging.info('records parameter is empty.')
            return

        records_to_restore = set()   # type: Set[str]
        folders_to_restore = set()   # type: Set[str]
        folder_records_to_restore = {}  # type: Dict[str, List[str]]
        for rec in records:
            if rec in deleted_records:
                records_to_restore.add(rec)
            elif rec in orphaned_records:
                records_to_restore.add(rec)
            elif rec in deleted_shared_records:
                dsr = deleted_shared_records.get(rec)
                folder_uid = dsr.get('folder_uid')
                record_uid = dsr.get('record_uid')
                if folder_uid and record_uid:
                    if folder_uid not in folder_records_to_restore:
                        folder_records_to_restore[folder_uid] = []
                    folder_records_to_restore[folder_uid].append(record_uid)
            elif rec in deleted_shared_folders:
                folders_to_restore.add(rec)
            else:
                title_pattern = re.compile(fnmatch.translate(rec), re.IGNORECASE)
                for record_uid, del_rec in itertools.chain(deleted_records.items(), orphaned_records.items()):
                    if record_uid in records_to_restore:
                        continue
                    record = vault.KeeperRecord.load(params, del_rec)
                    if title_pattern.match(record.title):
                        records_to_restore.add(record_uid)
                for record_uid, sh_rec in deleted_shared_records.items():
                    if record_uid in folder_records_to_restore:
                        continue
                    record = vault.KeeperRecord.load(params, sh_rec)
                    if title_pattern.match(record.title):
                        folder_uid = sh_rec.get('folder_uid')
                        if folder_uid not in folder_records_to_restore:
                            folder_records_to_restore[folder_uid] = []
                        folder_records_to_restore[folder_uid].append(record_uid)
                for folder_uid, sh_fol in deleted_shared_folders.items():
                    if folder_uid in folders_to_restore:
                        continue
                    try:
                        data = json.loads(sh_fol.get('data_unencrypted'))
                        folder_name = data.get('name') or folder_uid
                        if title_pattern.match(folder_name):
                            folders_to_restore.add(folder_uid)
                    except Exception:
                        pass

        for folder_uid in folders_to_restore:
            if folder_uid in folder_records_to_restore:
                del folder_records_to_restore[folder_uid]

        record_count = len(records_to_restore)
        for drf in folder_records_to_restore.values():
            record_count += len(drf)
        folder_count = len(folders_to_restore)
        if record_count == 0 and folder_count == 0:
            logging.info('There are no records to restore')
            return

        if not kwargs.get('force'):
            to_do = []
            if record_count > 0:
                to_do.append(f'{record_count} record(s)')
            if folder_count > 0:
                to_do.append(f'{folder_count} folder(s)')
            question = f'Do you want to restore {" and ".join(to_do)}?'
            answer = base.user_choice(question, 'yn', default='n')
            if answer.lower() == 'y':
                answer = 'yes'
            if answer.lower() != 'yes':
                return

        batch = []
        for record_uid in records_to_restore:
            rec = deleted_records[record_uid] if record_uid in deleted_records else orphaned_records[record_uid]
            rq = {
                'command': 'undelete_record',
                'record_uid': record_uid,
            }
            if 'revision' in rec:
                rq['revision'] = rec['revision']
            batch.append(rq)

        api.execute_batch(params, batch)

        shared_folder_rqs = []
        for folder_uid in folders_to_restore:
            sfrq = folder_pb2.RestoreSharedObject()
            sfrq.folderUid = utils.base64_url_decode(folder_uid)
            shared_folder_rqs.append(sfrq)

        shared_folder_record_rqs = []
        for folder_uid, record_uids in folder_records_to_restore.items():
            sfrq = folder_pb2.RestoreSharedObject()
            sfrq.folderUid = utils.base64_url_decode(folder_uid)
            sfrq.recordUids.extend((utils.base64_url_decode(x) for x in record_uids))
            shared_folder_record_rqs.append(sfrq)

        while len(shared_folder_rqs) > 0 or len(shared_folder_record_rqs) > 0:
            rq = folder_pb2.RestoreDeletedSharedFoldersAndRecordsRequest()
            left = 1000
            if len(shared_folder_rqs) > 0:
                chunk = shared_folder_rqs[:left]
                shared_folder_rqs = shared_folder_rqs[left:]
                left -= len(chunk)
                rq.folders.extend(chunk)
            if len(shared_folder_record_rqs) > 0 and left > 100:
                chunk = shared_folder_record_rqs[:left]
                shared_folder_record_rqs = shared_folder_record_rqs[left:]
                left -= len(chunk)
                rq.records.extend(chunk)
            api.communicate_rest(params, rq, 'vault/restore_deleted_shared_folders_and_records')

        api.sync_down(params)
        TrashMixin.last_revision = 0
        for record_uid in records_to_restore:
            BreachWatch.scan_and_update_security_data(params, record_uid, params.breach_watch,
                                                      force_update=False, set_reused_pws=False)
            params.queue_audit_event('record_restored', record_uid=record_uid)

        params.sync_data = True
        BreachWatch.save_reused_pw_count(params)


class TrashUnshareCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_unshare_parser

    def execute(self, params, **kwargs):
        orphaned_records = self.get_orphaned_records(params)
        if len(orphaned_records) == 0:
            logging.info('Trash is empty')
            return

        records = kwargs.get('records')
        if not isinstance(records, (tuple, list)):
            records = None
        if not records:
            logging.info('records parameter is empty.')
            return

        to_restore = set()
        for rec in records:
            if rec in orphaned_records:
                to_restore.add(rec)
            else:
                title_pattern = re.compile(fnmatch.translate(rec), re.IGNORECASE)
                for record_uid, del_rec in orphaned_records.items():
                    if record_uid in to_restore:
                        continue
                    record = vault.KeeperRecord.load(params, del_rec)
                    if title_pattern.match(record.title):
                        to_restore.add(record_uid)

        if len(to_restore) == 0:
            logging.info('There are no records to unshare')
            return

        if not kwargs.get('force'):
            answer = base.user_choice(f'Do you want to remove shares from {len(to_restore)} record(s)?', 'yn', default='n')
            if answer.lower() == 'y':
                answer = 'yes'
            if answer.lower() != 'yes':
                return

        record_shares = api.get_record_shares(params, to_restore, True)
        if record_shares:
            remove_shares = []   # type: List[record_pb2.SharedRecord]
            for record_share in record_shares:
                if 'shares' in record_share:
                    shares = record_share['shares']
                    if 'user_permissions' in shares:
                        for user_permission in shares['user_permissions']:
                            if user_permission.get('owner') is False:
                                rs_rq = record_pb2.SharedRecord()
                                rs_rq.toUsername = user_permission['username']
                                rs_rq.recordUid = utils.base64_url_decode(record_share['record_uid'])
                                remove_shares.append(rs_rq)

            while len(remove_shares) > 0:
                chunk = remove_shares[:900]
                remove_shares = remove_shares[900:]
                rsu_rq = record_pb2.RecordShareUpdateRequest()
                rsu_rq.removeSharedRecord.extend(chunk)

                rsu_rs = api.communicate_rest(params, rsu_rq, 'vault/records_share_update',
                                              rs_type=record_pb2.RecordShareUpdateResponse)
                for srs in rsu_rs.removeSharedRecordStatus:
                    if srs.status.lower() != 'success':
                        record_uid = utils.base64_url_encode(srs.recordUid)
                        logging.info('Remove share \"%s\" from record UID \"%s\" error: %s',
                                     srs.username, record_uid, srs.message)

            TrashMixin.last_revision = 0


class TrashPurgeCommand(Command, TrashMixin):
    def get_parser(self):
        return trash_purge_parser

    def execute(self, params, **kwargs):
        if not kwargs.get('force'):
            answer = base.user_choice(f'Do you want empty your Trash Bin?', 'yn', default='n')
            if answer.lower() == 'y':
                answer = 'yes'
            if answer.lower() != 'yes':
                return

        rq = {
            'command': 'purge_deleted_records'
        }
        api.communicate(params, rq)
        TrashMixin.last_revision = 0


class RecordHistoryCommand(Command, RecordMixin):
    def get_parser(self):
        return record_history_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None
        if not record_name:
            self.get_parser().print_help()
            return

        verbose = kwargs.get('verbose') or False

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

        if record_uid is None:
            raise CommandError('history', 'Enter name of existing record')

        history = self.load_record_history(params, record_uid)
        if isinstance(history, list):
            action = kwargs.get('action') or 'list'
            length = len(history)
            if length == 0:
                logging.info('Record does not have history of edit')
                return

            if action == 'list':
                fmt = kwargs.get('format') or ''
                headers = ['version', 'modified_by', 'time_modified']
                if fmt != 'json':
                    headers = [base.field_to_title(x) for x in headers]
                rows = []
                for i, version in enumerate(history):
                    dt = None
                    if 'client_modified_time' in version:
                        dt = datetime.datetime.fromtimestamp(int(version['client_modified_time'] / 1000.0))
                    rows.append([f'V.{length-i}' if i > 0 else 'Current', version.get('user_name') or '', dt])
                return base.dump_report_data(rows, headers, fmt=fmt, filename=kwargs.get('output'))

            revision = kwargs.get('revision') or 0
            if revision < 0 or revision >= length:
                raise ValueError(f'Invalid revision {revision}: valid revisions 1..{length - 1}')

            index = 0 if revision == 0 else length - revision

            if action == 'view':
                rev = history[index]
                record = vault.KeeperRecord.load(params, rev)

                rows = []
                for name, value in record.enumerate_fields():
                    if value:
                        if isinstance(value, list):
                            value = '\n'.join(value)
                        # if len(value) > 100:
                        #     value = value[:99] + '...'
                        rows.append([name, value])
                modified = datetime.datetime.fromtimestamp(int(rev['client_modified_time'] / 1000.0))
                rows.append(['Modified', modified])
                fmt = kwargs.get('format') or ''
                return base.dump_report_data(rows, headers=['Name', 'Value'],
                                 title=f'Record Revision V.{revision}', no_header=True, right_align=(0,),
                                 fmt=fmt, filename=kwargs.get('output'))

            elif action == 'diff':
                count = length - 1
                current = vault.KeeperRecord.load(params, history[index])
                rows = []
                while count >= 0 and current:
                    previous = vault.KeeperRecord.load(params, history[index + 1]) if index < (length - 1) else None
                    cur = collections.OrderedDict()
                    last_pos = len(rows)
                    for name, value in current.enumerate_fields():
                        if isinstance(value, list):
                            value = '\n'.join(value)
                        cur[name] = value
                    pre = collections.OrderedDict()
                    if previous:
                        for name, value in previous.enumerate_fields():
                            if isinstance(value, list):
                                value = '\n'.join(value)
                            pre[name] = value
                    for name, value in cur.items():
                        if name in pre:
                            pre_value = pre[name]
                            if pre_value != value:
                                rows.append(['', name, value, pre_value])
                            del pre[name]
                        else:
                            if value:
                                rows.append(['', name, value, ''])
                    for name, value in pre.items():
                        if value:
                            if isinstance(value, list):
                                value = '\n'.join(value)
                            rows.append(['', name, '', value])

                    version = 'Current' if index == 0 else f'V.{length - index}'
                    if len(rows) > last_pos:
                        rows[last_pos][0] = version
                    else:
                        rows.append([version, '', '', ''])
                    count -= 1
                    index += 1
                    current = previous

                headers = ('Version', 'Field', 'New Value', 'Old Value')
                if not verbose:
                    for row in rows:
                        for index in (2, 3):
                            value = row[index]
                            if not value:
                                continue
                            lines = [x[:50]+'...' if len(x) > 52 else x for x in value.split('\n')]
                            if len(lines) > 3:
                                lines = lines[:2]
                                lines.append('...')
                            row[index] = '\n'.join(lines)

                fmt = kwargs.get('format') or ''
                return base.dump_report_data(rows, headers, fmt=fmt, filename=kwargs.get('output'))

            elif action == 'restore':
                if revision == 0:
                    raise CommandError('history', f'Invalid revision to restore: Revisions: 1-{length - 1}')
                rev = history[index]
                record = vault.KeeperRecord.load(params, rev)

                r_uid = utils.base64_url_decode(record.record_uid)
                roq = record_pb2.RecordRevert()
                roq.record_uid = r_uid
                roq.revert_to_revision = record.revision

                rq = record_pb2.RecordsRevertRequest()
                rq.records.append(roq)

                rs = api.communicate_rest(params, rq, 'vault/records_revert', rs_type=record_pb2.RecordsModifyResponse)

                ros = next((x for x in rs.records if x.record_uid == r_uid), None)
                if ros:
                    if ros.status != record_pb2.RS_SUCCESS:
                        raise CommandError('history', f'Failed to restore record \"{record.record_uid}\": {ros.message}')

                del params.record_history[record.record_uid]
                params.queue_audit_event('revision_restored', record_uid=record_uid)
                params.sync_data = True
                logging.info('Record \"%s\" revision V.%d has been restored', record.title, revision)


class SharedRecordsReport(Command):
    def get_parser(self):
        return shared_records_report_parser

    @staticmethod
    def permissions_text(*, can_share=None, can_edit=None, can_view=True):  # type: (Any, Optional[bool], Optional[bool], Optional[bool]) -> str
        if not can_edit and not can_share:
            return 'Read Only' if can_view else 'Launch Only'
        else:
            privs = [can_share and 'Share', can_edit and 'Edit']
            return f'Can {" & ".join([p for p in privs if p])}'

    def execute(self, params, **kwargs):
        export_format = kwargs['format'] if 'format' in kwargs else None
        export_name = kwargs.get('output')

        all_records = kwargs.get('all_records') is True
        records = {}   # type: Dict[str, vault.KeeperRecord]
        containers = kwargs.get('folder')
        filter_folders = None
        versions = (0, 1, 2, 3, 5, 6) if all_records else (2, 3)
        if isinstance(containers, list) and len(containers) > 0:
            filter_folders = set()
            log_folder_fn = lambda f_name: logging.info(f'Folder {f_name} could not be found.')
            def on_folder_fn(f):   # type: (BaseFolderNode) -> None
                filter_folders.add(f.uid)
                for record_uid in params.subfolder_record_cache.get(f.uid or '', []):
                    if record_uid not in records:
                        record = vault.KeeperRecord.load(params, record_uid)
                        if not record:
                            continue
                        if not record.shared:
                            continue
                        if not all_records:
                            ro = params.record_owner_cache.get(record.record_uid)
                            if not ro or not ro.owner:
                                continue
                        if record.version not in versions:
                            continue
                        records[record.record_uid] = record
            for name in containers:
                folder_uids = get_folder_uids(params, name)
                if not folder_uids:
                    log_folder_fn(name)
                    continue
                for uid in folder_uids:
                    FolderMixin.traverse_folder_tree(params, uid, on_folder_fn)
        else:
            for record in vault_extensions.find_records(params, record_version=versions):
                if not record.shared:
                    continue
                if not all_records:
                    ro = params.record_owner_cache.get(record.record_uid)
                    if not ro or not ro.owner:
                        continue
                records[record.record_uid] = record

        expand_teams = kwargs.get('show_team_users') is True
        team_membership = None   # type: Optional[Dict[str, List[str]]]
        if expand_teams:
            team_membership = {}
            if params.enterprise is not None:
                user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise['users'] if x.get('status') == 'active'}
                if 'team_users' in params.enterprise:
                    for tu in params.enterprise['team_users']:
                        team_uid = tu['team_uid']
                        enterprise_user_id = tu['enterprise_user_id']
                        if enterprise_user_id in user_lookup:
                            members = team_membership.get(team_uid)
                            if members is None:
                                members = []
                                team_membership[team_uid] = members
                            members.append(user_lookup[enterprise_user_id])

        rows = []
        fields = ['record_uid', 'title', 'share_type', 'shared_to', 'permissions', 'folder_path']
        if all_records:
            fields.insert(0, 'owner')
        api.get_record_shares(params, records.keys())

        shared_from_mapping = {
            1: "Direct Share",
            2: "Share Folder",
            3: "Share Team Folder"
        }

        for record_uid, record in records.items():
            r = params.record_cache.get(record_uid)
            if not r:
                continue
            if 'shares' not in r:
                continue
            record_title = record.title
            if export_format == 'table' and len(record_title) > 40:
                record_title = record_title[:38] + '...'
            shares = r['shares']
            owner = next((x.get('username') for x in shares.get('user_permissions', []) if x.get('owner') is True), None)
            record_folders = set(find_folders(params, record_uid))
            if filter_folders is not None:
                record_folders.intersection_update(filter_folders)
            folder_path = '\n'.join((get_folder_path(params, x) for x in record_folders))
            for up in shares.get('user_permissions', []):
                username = up.get('username')
                if not username:
                    continue
                if not all_records and username == params.user:
                    continue
                permission = self.permissions_text(can_share=up.get('shareable'), can_edit=up.get('editable'))
                row = [record_uid, record_title, shared_from_mapping[1], username, permission, folder_path]
                if all_records:
                    row.insert(0, owner)
                rows.append(row)
            for sfp in shares.get('shared_folder_permissions', []):
                shared_folder_uid = sfp.get('shared_folder_uid')
                can_share = sfp.get('reshareable')
                can_edit = sfp.get('editable')
                permission = self.permissions_text(can_share=can_share, can_edit=can_edit)
                if shared_folder_uid in params.shared_folder_cache:
                    shared_folder = api.get_shared_folder(params, shared_folder_uid)
                    folder_path = get_folder_path(params, shared_folder_uid)
                    for sfu in shared_folder.users or []:
                        username = sfu.get('username')
                        if not all_records and username == params.user:
                            continue
                        row = [record_uid, record_title, shared_from_mapping[2], username, permission, folder_path]
                        if all_records:
                            row.insert(0, owner)
                        rows.append(row)
                    for sft in shared_folder.teams or []:
                        team_uid = sft['team_uid']
                        team_name = sft['name']
                        team_permission = permission
                        if team_uid in params.team_cache:
                            team = api.get_team(params, team_uid)
                            team_permission = self.permissions_text(can_share=can_share and not team.restrict_share,
                                                                    can_edit=can_edit and not team.restrict_edit,
                                                                    can_view=not team.restrict_view)
                        if team_membership and team_uid in team_membership:
                            for u in team_membership[team_uid]:
                                row = [record_uid, record_title, shared_from_mapping[3], f'({team_name}) {u}', team_permission, folder_path]
                                if all_records:
                                    row.insert(0, owner)
                                rows.append(row)
                        else:
                            row = [record_uid, record_title, shared_from_mapping[3], team_name, team_permission, folder_path]
                            if all_records:
                                row.insert(0, owner)
                            rows.append(row)
                else:
                    row = [record_uid, record_title, shared_from_mapping[2], '***', permission, shared_folder_uid]
                    if all_records:
                        row.insert(0, owner)
                    rows.append(row)

        sort_by = (1,3) if all_records else (0,2)
        if export_format == 'table':
            fields = [base.field_to_title(x) for x in fields]
        return base.dump_report_data(rows, fields, fmt=export_format, filename=export_name, row_number=True, sort_by=sort_by)


class ClipboardCommand(Command, RecordMixin):
    def get_parser(self):
        return clipboard_copy_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else ''

        if not record_name:
            self.get_parser().print_help()
            return

        user_pattern = None
        if kwargs['username']:
            user_pattern = re.compile(kwargs['username'], re.IGNORECASE)

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
                            r = vault.KeeperRecord.load(params, uid)
                            if not isinstance(r, (vault.PasswordRecord, vault.TypedRecord)):
                                continue
                            if r.title.lower() == record_name.lower():
                                if user_pattern:
                                    login = ''
                                    if isinstance(r, vault.PasswordRecord):
                                        login = r.login
                                    elif isinstance(r, vault.TypedRecord):
                                        login_field = r.get_typed_field('login')
                                        if login_field is None:
                                            login_field = r.get_typed_field('email')
                                        if login_field:
                                            login = login_field.get_default_value(str)
                                    if not login:
                                        continue
                                    if not user_pattern.match(login):
                                        continue
                                record_uid = uid
                                break

        if record_uid is None:
            records = []    # type: List[vault.KeeperRecord]
            for r in vault_extensions.find_records(params, record_name):
                if isinstance(r, (vault.PasswordRecord, vault.TypedRecord)):
                    if user_pattern:
                        login = ''
                        if isinstance(r, vault.PasswordRecord):
                            login = r.login
                        elif isinstance(r, vault.TypedRecord):
                            login_field = r.get_typed_field('login')
                            if login_field is None:
                                login_field = r.get_typed_field('email')
                            if login_field:
                                login = login_field.get_default_value(str)
                        if not login:
                            continue
                        if not user_pattern.match(login):
                            continue
                    records.append(r)

            if len(records) > 1:
                try:
                    pattern = re.compile(record_name, re.IGNORECASE).search
                    exact_title = [x for x in records if pattern(x.title)]
                    if len(exact_title) == 1:
                        records = exact_title
                except:
                    pass

            if len(records) == 1:
                if kwargs['output'] == 'clipboard':
                    logging.info('Record Title: %s', records[0].title)
                record_uid = records[0].record_uid
            else:
                if len(records) == 0:
                    raise CommandError('', 'Enter name or uid of existing record')
                else:
                    raise CommandError('', f'More than one record are found for search criteria: {record_name}')

        revision = kwargs.get('revision')
        if revision:
            history = self.load_record_history(params, record_uid)
            length = len(history) if isinstance(history, list) else 0
            if length == 0:
                logging.info('Record does not have history of edit')
                return
            if revision < 0:
                revision = length + revision
            if revision <= 0 or revision >= length:
                logging.info(f'Invalid revision {revision}: valid revisions 1..{length - 1}')
                return
            revision = 0 if revision == 0 else length - revision
            rec = vault.KeeperRecord.load(params, history[revision])
        else:
            rec = vault.KeeperRecord.load(params, record_uid)
        if not rec:
            logging.info(f'Record UID {record_uid} cannot be loaded.')
            return

        copy_item = 'Login'
        txt = ''
        if kwargs.get('copy_uid') is True:
            copy_item = 'Record UID'
            txt = rec.record_uid
        else:
            if kwargs.get('login') is True:
                copy_item = 'Login'
                if isinstance(rec, vault.PasswordRecord):
                    txt = rec.login
                elif isinstance(rec, vault.TypedRecord):
                    login_field = rec.get_typed_field('login')
                    if login_field is None:
                        login_field = rec.get_typed_field('email')
                    if login_field:
                        txt = login_field.get_default_value(str)
            elif kwargs.get('totp') is True:
                copy_item = 'TOTP Code'
                totp_url = None
                if isinstance(rec, vault.PasswordRecord):
                    totp_url = rec.totp
                elif isinstance(rec, vault.TypedRecord):
                    totp_field = rec.get_typed_field('oneTimeCode')
                    if totp_field is None:
                        totp_field = rec.get_typed_field('otp')
                    if totp_field:
                        totp_url = totp_field.get_default_value(str)
                if totp_url:
                    res = get_totp_code(totp_url)
                    if res:
                        txt, _, _ = res
            elif kwargs.get('field'):
                field_name = kwargs['field']
                if field_name == 'notes':
                    copy_item = f'Notes'
                    if isinstance(rec, vault.PasswordRecord):
                        txt = rec.notes
                    elif isinstance(rec, vault.TypedRecord):
                        txt = rec.notes
                else:
                    copy_item = f'Custom Field "{field_name}"'
                    pre, sep, prop = field_name.rpartition(':')
                    if sep == ':':
                        field_name = pre
                        field_property = prop
                    else:
                        field_property = ''
                    if isinstance(rec, vault.PasswordRecord):
                        txt = rec.get_custom_value(field_name)
                    elif isinstance(rec, vault.TypedRecord):
                        field_type, sep, field_label = field_name.partition('.')
                        rf = record_types.RecordFields.get(field_type)
                        ft = record_types.FieldTypes.get(rf.type) if rf else None
                        if ft is None:
                            field_label = field_name
                            field_type = 'text'
                        field = rec.get_typed_field(field_type, field_label)
                        if field:
                            copy_item = f'Field "{field_name}"'
                        if field:
                            if ft and field_property and isinstance(ft.value, dict):
                                f_value = field.get_default_value(dict)
                                if f_value:
                                    field_property = next((x for x in ft.value.keys() if x.lower().startswith(field_property.lower())), None)
                                    if field_property:
                                        txt = f_value.get(field_property)
                                    else:
                                        txt = json.dumps(f_value, indent=2)
                            else:
                                txt = '\n'.join(field.get_external_value())
            else:
                copy_item = 'Password'
                if isinstance(rec, vault.PasswordRecord):
                    txt = rec.password
                elif isinstance(rec, vault.TypedRecord):
                    password_field = rec.get_typed_field('password')
                    if password_field:
                        txt = password_field.get_default_value(str)
                if txt:
                    params.queue_audit_event('copy_password', record_uid=record_uid)
        if txt:
            if kwargs['output'] == 'clipboard':
                import pyperclip
                pyperclip.copy(txt)
                logging.info(f'{copy_item} copied to clipboard')
            elif kwargs['output'] == 'stdouthidden':
                print(f'{Fore.RED}{Back.RED}{txt}{Style.RESET_ALL}')
            elif kwargs['output'] == 'variable':
                var_name = kwargs.get('name')
                if not var_name:
                    raise CommandError('', '"name" parameter is required when "output" is set to "variable"')
                params.environment_variables[var_name] = txt
                logging.info(f'{copy_item} is set to variable "{var_name}"')
            else:
                print(txt)


class RecordRemoveCommand(Command):
    def get_parser(self):
        return rm_parser

    def execute(self, params, **kwargs):
        from ..enforcement import MasterPasswordReentryEnforcer
        if not MasterPasswordReentryEnforcer.check_and_enforce(params, "record_level"):
            raise CommandError('rm', 'Operation cancelled: Re-authentication failed')

        records_to_delete = []     # type: List[Tuple[BaseFolderNode, str]]
        record_names = kwargs.get('records')
        rq_obj_limit = 999
        if not isinstance(record_names, list):
            if isinstance(record_names, str):
                record_names = [record_names]
            else:
                record_names = []
        record_name = kwargs.get('record')
        if isinstance(record_name, str):
            record_names.append(record_name)

        for name in record_names:
            if name in params.record_cache:
                record_uid = name
                folders = list(find_all_folders(params, record_uid))
                if len(folders) > 0:
                    for folder in folders:
                        records_to_delete.append((folder, record_uid))
                else:
                    records_to_delete.append((params.root_folder, record_uid))
            else:
                orig_len = len(records_to_delete)
                rs = try_resolve_path(params, name, find_all_matches=True)
                if rs:
                    folders, record_name = rs
                    if record_name:
                        if not isinstance(folders, list):
                            if isinstance(folders, BaseFolderNode):
                                folders = [folders]
                            else:
                                folders = [params.root_folder]
                        for folder in folders:
                            if not isinstance(folder, BaseFolderNode):
                                continue
                            folder_uid = folder.uid or ''
                            if folder_uid not in params.subfolder_record_cache:
                                continue
                            for record_uid in params.subfolder_record_cache[folder_uid]:
                                if record_name == record_uid:
                                    records_to_delete.append((folder, record_uid))
                                else:
                                    record = vault.KeeperRecord.load(params, record_uid)
                                    if record:
                                        if record.title.casefold() == record_name.casefold():
                                            records_to_delete.append((folder, record_uid))
                if len(records_to_delete) == orig_len:
                    raise CommandError('rm', f'Record {name} cannot be resolved')

        vault_changed = False
        while len(records_to_delete) > 0:
            rq = {
                'command': 'pre_delete',
                'objects': []
            }

            chunk = records_to_delete[:rq_obj_limit]
            records_to_delete = records_to_delete[rq_obj_limit:]
            for folder, record_uid in chunk:
                del_obj = {
                    'delete_resolution': 'unlink',
                    'object_uid': record_uid,
                    'object_type': 'record'
                }
                if folder.type in {BaseFolderNode.RootFolderType, BaseFolderNode.UserFolderType}:
                    del_obj['from_type'] = 'user_folder'
                    if folder.type == BaseFolderNode.UserFolderType:
                        del_obj['from_uid'] = folder.uid
                else:
                    del_obj['from_type'] = 'shared_folder_folder'
                    del_obj['from_uid'] = folder.uid
                rq['objects'].append(del_obj)

            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                pdr = rs['pre_delete_response']

                force = kwargs.get('force') or False
                np = 'y'
                if force is not True:
                    summary = pdr['would_delete']['deletion_summary']
                    for x in summary:
                        print(x)
                    np = base.user_choice('Do you want to proceed with deletion?', 'yn', default='n')
                if np.lower() == 'y':
                    rq = {
                        'command': 'delete',
                        'pre_delete_token': pdr['pre_delete_token']
                    }
                    api.communicate(params, rq)
                    vault_changed = True

        if vault_changed:
            BreachWatch.save_reused_pw_count(params)
            params.sync_data = True
