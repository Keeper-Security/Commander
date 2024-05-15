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
import datetime
import getpass
import hashlib
import itertools
import json
import logging
import math
import re
import time
import urllib.parse
from typing import Optional, Dict, Iterable, Any, Set, List
from urllib.parse import urlunparse

from tabulate import tabulate

from . import base
from .base import dump_report_data, field_to_title, fields_to_titles, raise_parse_exception, suppress_exit, Command, \
    GroupCommand, FolderMixin
from .helpers.record import get_record_uids
from .helpers.timeout import parse_timeout
from .record import RecordRemoveCommand
from .utils import SyncDownCommand
from .. import api, utils, crypto, constants, rest_api
from ..display import bcolors
from ..error import KeeperApiError, CommandError, Error
from ..params import KeeperParams
from ..proto import APIRequest_pb2, folder_pb2, record_pb2, enterprise_pb2
from ..shared_record import SharePermissions, get_shared_records, SharedRecord
from ..sox.sox_types import Record
from ..subfolder import BaseFolderNode, SharedFolderNode, SharedFolderFolderNode, try_resolve_path, get_folder_path, \
    get_folder_uids, get_contained_record_uids
from ..loginv3 import LoginV3API
from ..utils import confirm


def register_commands(commands):
    commands['share-record'] = ShareRecordCommand()
    commands['share-folder'] = ShareFolderCommand()
    commands['share-report'] = ShareReportCommand()
    commands['record-permission'] = RecordPermissionCommand()
    commands['find-duplicate'] = FindDuplicateCommand()
    commands['one-time-share'] = OneTimeShareCommand()
    commands['create-account'] = CreateRegularUserCommand()
    commands['find-ownerless'] = FindOwnerlessCommand()
    # commands['file-report'] = FileReportCommand()


def register_command_info(aliases, command_info):
    aliases['sr'] = 'share-record'
    aliases['sf'] = 'share-folder'
    aliases['ots'] = 'one-time-share'
    aliases['share'] = 'one-time-share'

    for p in [share_record_parser, share_folder_parser, share_report_parser, record_permission_parser,
              find_duplicate_parser]:
        command_info[p.prog] = p.description

    command_info['share'] = 'Manage One-Time Shares'


share_record_parser = argparse.ArgumentParser(prog='share-record', description='Change the sharing permissions of an individual record')
share_record_parser.add_argument('-e', '--email', dest='email', action='append', required=True, help='account email')
share_record_parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke', 'owner', 'cancel'],
                                 default='grant', action='store', help='user share action. \'grant\' if omitted')
share_record_parser.add_argument('-s', '--share', dest='can_share', action='store_true', help='can re-share record')
share_record_parser.add_argument('-w', '--write', dest='can_edit', action='store_true', help='can modify record')
share_record_parser.add_argument('-R', '--recursive', dest='recursive', action='store_true', help='apply command to shared folder hierarchy')
share_record_parser.add_argument('--dry-run', dest='dry_run', action='store_true', help='display the permissions changes without committing them')
expiration = share_record_parser.add_mutually_exclusive_group()
expiration.add_argument('--expire-at', dest='expire_at', action='store',
                        help='share expiration: never or UTC datetime')
expiration.add_argument('--expire-in', dest='expire_in', action='store',
                        metavar='<NUMBER>[(mi)nutes|(h)ours|(d)ays|(mo)nths|(y)ears]',
                        help='share expiration: never or period')
share_record_parser.add_argument('record', nargs='?', type=str, action='store', help='record/shared folder path/UID')

share_folder_parser = argparse.ArgumentParser(prog='share-folder', description='Change a shared folders permissions.')
share_folder_parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke', 'remove'], default='grant',
                                 action='store', help='shared folder action. \'grant\' if omitted')
share_folder_parser.add_argument('-e', '--email', dest='user', action='append',
                                 help='account email, team, @existing for all users and teams in the folder, '
                                      'or \'*\' as default folder permission')
share_folder_parser.add_argument('-r', '--record', dest='record', action='append',
                                 help='record name, record UID, @existing for all records in the folder,'
                                      ' or \'*\' as default folder permission')
share_folder_parser.add_argument('-p', '--manage-records', dest='manage_records', action='store_true',
                                 help='account permission: can manage records.')
share_folder_parser.add_argument('-o', '--manage-users', dest='manage_users', action='store_true',
                                 help='account permission: can manage users.')
share_folder_parser.add_argument('-s', '--can-share', dest='can_share', action='store_true',
                                 help='record permission: can be shared')
share_folder_parser.add_argument('-d', '--can-edit', dest='can_edit', action='store_true',
                                 help='record permission: can be modified.')
share_folder_parser.add_argument('-f', '--force', dest='force', action='store_true',
                                 help='Apply permission changes ignoring default folder permissions. Used on the '
                                      'initial sharing action')
expiration = share_folder_parser.add_mutually_exclusive_group()
expiration.add_argument('--expire-at', dest='expire_at', action='store', metavar='TIMESTAMP',
                        help='share expiration: never or ISO datetime (yyyy-MM-dd[ hh:mm:ss])')
expiration.add_argument('--expire-in', dest='expire_in', action='store', metavar='PERIOD',
                        help='share expiration: never or period (<NUMBER>[(y)ears|(mo)nths|(d)ays|(h)ours(mi)nutes]')
share_folder_parser.add_argument('folder', nargs='+', type=str, action='store', help='shared folder path or UID')

share_report_parser = argparse.ArgumentParser(prog='share-report', description='Display report of shared records.')
share_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json', 'csv'],
                                 default='table', help='output format.')
share_report_parser.add_argument('--output', dest='output', action='store',
                                 help='output file name. (ignored for table format)')
share_report_parser.add_argument('-r', '--record', dest='record', action='append', help='record name or UID')
share_report_parser.add_argument('-e', '--email', dest='user', action='append', help='user email or team name')
share_report_parser.add_argument('-o', '--owner', dest='owner', action='store_true',
                                 help='record ownership information')
share_report_parser.add_argument('--share-date', dest='share_date', action='store_true',
                                 help='include date when the record was shared. This flag will only apply to the '
                                      'detailed owner report. This data is available only to those users who have '
                                      'permissions to execute reports for their company. Example of the report that '
                                      'includes shared date: `share-report -v -o --share-date --format table`')
share_report_parser.add_argument('-sf', '--shared-folders', dest='shared_folders', action='store_true',
                                 help='display shared folder detail information. If omitted then records.')
share_report_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                                 help='display verbose information')
share_report_parser.add_argument('-f', '--folders', dest='folders', action='store_true', default=False,
                                 help='limit report to shared folders (excludes shared records)')
tu_help = 'show shared-folder team members (to be used with "--folders"/ "-f" flag, ignored for non-admin accounts)'
share_report_parser.add_argument('-tu', '--show-team-users', action='store_true', help=tu_help)
container_filter_help = 'path(s) or UID(s) of container(s) by which to filter records'
share_report_parser.add_argument('container', nargs='*', type=str, action='store', help=container_filter_help)

record_permission_parser = argparse.ArgumentParser(prog='record-permission', description='Modify a records permissions.')
record_permission_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                                      help='Display the permissions changes without committing them')
record_permission_parser.add_argument('--force', dest='force', action='store_true',
                                      help='Apply permission changes without any confirmation')
record_permission_parser.add_argument('-R', '--recursive', dest='recursive', action='store_true',
                                      help='Apply permission changes to all sub-folders')
record_permission_parser.add_argument('--share-record', dest='share_record', action='store_true',
                                      help='Change a records sharing permissions')
record_permission_parser.add_argument('--share-folder', dest='share_folder', action='store_true',
                                      help='Change a folders sharing permissions')
record_permission_parser.add_argument('-a', '--action', dest='action', action='store', choices=['grant', 'revoke'],
                                      required=True, help='The action being taken')
record_permission_parser.add_argument('-s', '--can-share', dest='can_share', action='store_true',
                                      help='Set record permission: can be shared')
record_permission_parser.add_argument('-d', '--can-edit', dest='can_edit', action='store_true',
                                      help='Set record permission: can be edited')
record_permission_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or folder UID')
record_permission_parser.error = raise_parse_exception
record_permission_parser.exit = suppress_exit

find_ownerless_desc = 'List (and, optionally, claim) records in the user\'s vault that currently do not have an owner'
find_ownerless_parser = argparse.ArgumentParser(prog='find-ownerless', description=find_ownerless_desc)
find_ownerless_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'],
                                   default='table', help='output format')
find_ownerless_parser.add_argument('--output', dest='output', action='store',
                                   help='output file name (ignored for table format)')
find_ownerless_parser.add_argument('--claim', dest='claim', action='store_true', help='claim records found')
find_ownerless_parser.add_argument('-v', '--verbose', action='store_true', help='output details for each record found')
folder_help = 'path or UID of folder to search (optional, with multiple values allowed)'
find_ownerless_parser.add_argument('folder', nargs='*', type=str, action='store', help=folder_help)
find_ownerless_parser.error = raise_parse_exception
find_ownerless_parser.exit = suppress_exit

find_duplicate_parser = argparse.ArgumentParser(prog='find-duplicate', description='List duplicated records.')
find_duplicate_parser.add_argument('--title', dest='title', action='store_true', help='Match duplicates by title.')
find_duplicate_parser.add_argument('--login', dest='login', action='store_true', help='Match duplicates by login.')
find_duplicate_parser.add_argument('--password', dest='password', action='store_true', help='Match duplicates by password.')
find_duplicate_parser.add_argument('--url', dest='url', action='store_true', help='Match duplicates by URL.')
find_duplicate_parser.add_argument('--shares', action='store_true', help='Match duplicates by share permissions')
find_duplicate_parser.add_argument('--full', dest='full', action='store_true', help='Match duplicates by all fields.')
merge_help = 'Consolidate duplicate records (matched by all fields, including shares)'
find_duplicate_parser.add_argument('-m', '--merge', action='store_true', help=merge_help)
ignore_shares_txt = 'ignore share permissions when grouping duplicate records to merge'
find_duplicate_parser.add_argument('--ignore-shares-on-merge', action='store_true', help=ignore_shares_txt)
force_help = 'Delete duplicates w/o being prompted for confirmation (valid only w/ --merge option)'
find_duplicate_parser.add_argument('-f', '--force', action='store_true', help=force_help)
dry_run_help = 'Simulate removing duplicates (with this flog, no records are ever removed or modified). ' \
               'Valid only w/ --merge flag'
find_duplicate_parser.add_argument('-n', '--dry-run', action='store_true', help=dry_run_help)
find_duplicate_parser.add_argument('-q', '--quiet', action='store_true',
                                   help='Suppress screen output, valid only w/ --force flag')
scope_help = 'The scope of the search (limited to current vault if not specified)'
find_duplicate_parser.add_argument('-s', '--scope', action='store', choices=['vault', 'enterprise'], default='vault',
                                   help=scope_help)
refresh_help = 'Populate local cache with latest compliance data . Valid only w/ --scope=enterprise option.'
find_duplicate_parser.add_argument('-r', '--refresh-data', action='store_true', help=refresh_help)
find_duplicate_parser.add_argument('--format', action='store', choices=['table', 'csv', 'json'], default='table',
                                   help='output format.')
find_duplicate_parser.add_argument('--output', action='store', help='output file name. (ignored for table format)')
find_duplicate_parser.error = raise_parse_exception
find_duplicate_parser.exit = suppress_exit

one_time_share_create_parser = argparse.ArgumentParser(prog='one-time-share-create', description='Creates one-time share URL for a record')
one_time_share_create_parser.add_argument('--output', dest='output', choices=['clipboard', 'stdout'],
                                          action='store', help='password output destination')
one_time_share_create_parser.add_argument('--name', dest='share_name', action='store', help='one-time share URL name')
one_time_share_create_parser.add_argument('-e', '--expire', dest='expire', action='store', metavar='<NUMBER>[(m)inutes|(h)ours|(d)ays]',
                                          help='Time period record share URL is valid.')
one_time_share_create_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')

one_time_share_list_parser = argparse.ArgumentParser(prog='one-time-share-list', description='Displays a list of one-time shares for a records')
one_time_share_list_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output.')
one_time_share_list_parser.add_argument('-a', '--all', dest='show_all', action='store_true', help='show all one-time shares including expired.')
one_time_share_list_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                        default='table', help='output format.')
one_time_share_list_parser.add_argument('--output', dest='output', action='store',
                                        help='output file name. (ignored for table format)')
one_time_share_list_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')

one_time_share_remove_parser = argparse.ArgumentParser(prog='one-time-share-remove', description='Removes one-time share URL for a record')
one_time_share_remove_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
one_time_share_remove_parser.add_argument('share', nargs='?', type=str, action='store', help='one-time share name or ID')

create_account_parser = argparse.ArgumentParser(prog='create-account', description='Create Keeper Account')
create_account_parser.add_argument('email', help='email')

def get_share_expiration(expire_at, expire_in):     # (Optional[str], Optional[str]) -> Optional[int]
    if not expire_at and not expire_in:
        return

    dt = None      # type: Optional[datetime.datetime]
    if isinstance(expire_at, str):
        if expire_at == 'never':
            return -1
        dt = datetime.datetime.fromisoformat(expire_at)
    elif isinstance(expire_in, str):
        if expire_in == 'never':
            return -1
        td = parse_timeout(expire_in)
        dt = datetime.datetime.now() + td
    if dt is None:
        raise ValueError(f'Incorrect expiration: {expire_at or expire_in}')

    return int(dt.timestamp())


class ShareFolderCommand(Command):
    def get_parser(self):
        return share_folder_parser

    def execute(self, params, **kwargs):
        def get_share_admin_obj_uids(obj_names, obj_type):
            # type: (List[Optional[str], int], int) -> Optional[Set[str]]
            if not obj_names:
                return None
            try:
                rq = record_pb2.AmIShareAdmin()
                for name in obj_names:
                    try:
                        uid = utils.base64_url_decode(name)
                        if isinstance(uid, bytes) and len(uid) == 16:
                            osa = record_pb2.IsObjectShareAdmin()
                            osa.uid = uid
                            osa.objectType = obj_type
                            rq.isObjectShareAdmin.append(osa)
                    except:
                        pass
                if len(rq.isObjectShareAdmin) > 0:
                    rs = api.communicate_rest(params, rq, 'vault/am_i_share_admin', rs_type=record_pb2.AmIShareAdmin)
                    sa_obj_uids = {sa_obj.uid for sa_obj in rs.isObjectShareAdmin if sa_obj.isAdmin}
                    sa_obj_uids = {utils.base64_url_encode(uid) for uid in sa_obj_uids}
                    return sa_obj_uids
            except Error as e:
                print(f'get_share_admin: msg = {e.message}')
                return None

        names = kwargs.get('folder')
        if not isinstance(names, list):
            names = [names]

        all_folders = any(True for x in names if x == '*')
        if all_folders:
            names = [x for x in names if x != '*']

        shared_folder_uids = set()    # type: Set[str]
        if all_folders:
            shared_folder_uids.update(params.shared_folder_cache.keys())
        else:
            get_folder_by_uid = lambda uid: params.folder_cache.get(uid)
            folder_uids = {uid for name in names for uid in get_folder_uids(params, name)}
            folders = {get_folder_by_uid(uid) for uid in folder_uids}
            shared_folder_uids.update([uid for uid in folder_uids if uid in params.shared_folder_cache])
            sf_subfolders = {f for f in folders if f.type == 'shared_folder_folder'}
            shared_folder_uids.update({subfolder.shared_folder_uid for subfolder in sf_subfolders})
            unresolved_names = [name for name in names if not get_folder_uids(params, name)]
            share_admin_folder_uids = get_share_admin_obj_uids(unresolved_names, record_pb2.CHECK_SA_ON_SF)
            shared_folder_uids.update(share_admin_folder_uids or [])

        if not shared_folder_uids:
            raise CommandError('share-folder', 'Enter name of at least one existing folder')

        action = kwargs.get('action') or 'grant'

        share_expiration = None
        if action == 'grant':
            share_expiration = get_share_expiration(kwargs.get('expire_at'), kwargs.get('expire_in'))

        as_users = set()
        as_teams = set()

        all_users = False
        default_account = False
        if 'user' in kwargs:
            for u in (kwargs.get('user') or []):
                if u == '*':
                    default_account = True
                elif u in ('@existing', '@current'):
                    all_users = True
                else:
                    em = re.match(constants.EMAIL_PATTERN, u)
                    if em is not None:
                        as_users.add(u.lower())
                    else:
                        api.load_available_teams(params)
                        team = next((x for x in params.available_team_cache
                                     if u == x.get('team_uid') or
                                     u.lower() == (x.get('team_name') or '').lower()), None)
                        if team:
                            team_uid = team['team_uid']
                            as_teams.add(team_uid)
                        else:
                            logging.warning('User %s could not be resolved as email or team', u)

        record_uids = set()
        all_records = False
        default_record = False
        unresolved_names = []
        if 'record' in kwargs:
            records = kwargs.get('record') or []
            for r in records:
                if r == '*':
                    default_record = True
                elif r in ('@existing', '@current'):
                    all_records = True
                else:
                    r_uids = get_record_uids(params, r)
                    record_uids.update(r_uids) if r_uids else unresolved_names.append(r)

            if unresolved_names:
                sa_record_uids = get_share_admin_obj_uids(unresolved_names, record_pb2.CHECK_SA_ON_RECORD)
                record_uids.update(sa_record_uids or {})

        if len(as_users) == 0 and len(as_teams) == 0 and len(record_uids) == 0 and \
                not default_record and not default_account and \
                not all_users and not all_records:
            logging.info('Nothing to do')
            return

        rq_groups = []

        def prep_rq(recs, users, curr_sf):
            return self.prepare_request(params, kwargs, curr_sf, users, sf_teams, recs, default_record=default_record,
                                        default_account=default_account, share_expiration=share_expiration)

        for sf_uid in shared_folder_uids:
            sf_users = as_users.copy()
            sf_teams = as_teams.copy()
            sf_records = record_uids.copy()

            if sf_uid in params.shared_folder_cache:
                sh_fol = params.shared_folder_cache[sf_uid]
                if all_users or all_records:
                    if all_users:
                        if 'users' in sh_fol:
                            sf_users.update((x['username'] for x in sh_fol['users'] if x['username'] != params.user))
                        if 'teams' in sh_fol:
                            sf_teams.update((x['team_uid'] for x in sh_fol['teams']))
                    if all_records:
                        if 'records' in sh_fol:
                            sf_records.update((x['record_uid'] for x in sh_fol['records']))
            else:
                sh_fol = {
                    'shared_folder_uid': sf_uid,
                    'users': [{'username': x, 'manage_records': action != 'grant', 'manage_users': action != 'grant'}
                              for x in as_users],
                    'teams': [{'team_uid': x, 'manage_records': action != 'grant', 'manage_users': action != 'grant'}
                              for x in as_teams],
                    'records': [{'record_uid': x, 'can_share': action != 'grant', 'can_edit': action != 'grant'}
                                for x in record_uids]
                }
            chunk_size = 500
            rec_list = list(sf_records)
            user_list = list(sf_users)
            num_rec_chunks = math.ceil(len(sf_records) / chunk_size)
            num_user_chunks = math.ceil(len(sf_users) / chunk_size)
            num_rq_groups = num_user_chunks or 1 * num_rec_chunks or 1
            while len(rq_groups) < num_rq_groups:
                rq_groups.append([])
            rec_chunks = [rec_list[i * chunk_size:(i + 1) * chunk_size] for i in range(num_rec_chunks)] or [[]]
            user_chunks = [user_list[i * chunk_size:(i + 1) * chunk_size] for i in range(num_user_chunks)] or [[]]
            group_idx = 0
            for r_chunk in rec_chunks:
                for u_chunk in user_chunks:
                    sf_info = sh_fol.copy()
                    if group_idx:
                        del sf_info['revision']
                    rq_groups[group_idx].append(prep_rq(r_chunk, u_chunk, sf_info))
                    group_idx += 1
        self.send_requests(params, rq_groups)

    @staticmethod
    def prepare_request(params, kwargs, curr_sf, users, teams, rec_uids, *,
                        default_record=False, default_account=False,
                        share_expiration=None):
        rq = folder_pb2.SharedFolderUpdateV3Request()
        rq.sharedFolderUid = utils.base64_url_decode(curr_sf['shared_folder_uid'])
        if 'revision' in curr_sf:
            rq.revision = curr_sf['revision']
        else:
            rq.forceUpdate = True
        action = kwargs.get('action') or 'grant'
        mr = kwargs.get('manage_records')
        mu = kwargs.get('manage_users')
        if default_account and action != 'remove':
            if mr:
                rq.defaultManageRecords = folder_pb2.BOOLEAN_TRUE if action == 'grant' else folder_pb2.BOOLEAN_FALSE
            else:
                rq.defaultManageRecords = folder_pb2.BOOLEAN_NO_CHANGE
            if mu:
                rq.defaultManageUsers = folder_pb2.BOOLEAN_TRUE if action == 'grant' else folder_pb2.BOOLEAN_FALSE
            else:
                rq.defaultManageUsers = folder_pb2.BOOLEAN_NO_CHANGE

        if len(users) > 0:
            existing_users = {x['username'] for x in curr_sf.get('users', [])}
            for email in users:
                uo = folder_pb2.SharedFolderUpdateUser()
                uo.username = email
                if isinstance(share_expiration, int):
                    if share_expiration > 0:
                        uo.expiration = share_expiration * 1000
                        uo.timerNotificationType = record_pb2.NOTIFY_OWNER
                    elif share_expiration < 0:
                        uo.expiration = -1
                if email in existing_users:
                    if action == 'grant':
                        uo.manageRecords = folder_pb2.BOOLEAN_TRUE if mr else folder_pb2.BOOLEAN_NO_CHANGE
                        uo.manageUsers = folder_pb2.BOOLEAN_TRUE if mu else folder_pb2.BOOLEAN_NO_CHANGE
                        rq.sharedFolderUpdateUser.append(uo)
                    elif action == 'revoke':
                        uo.manageRecords = folder_pb2.BOOLEAN_FALSE if mr else folder_pb2.BOOLEAN_NO_CHANGE
                        uo.manageUsers = folder_pb2.BOOLEAN_FALSE if mu else folder_pb2.BOOLEAN_NO_CHANGE
                        rq.sharedFolderUpdateUser.append(uo)
                    elif action == 'remove':
                        rq.sharedFolderRemoveUser.append(uo.username)
                elif action == 'grant':
                    invited = api.load_user_public_keys(params, [email], send_invites=True)
                    if invited:
                        for username in invited:
                            logging.warning('Share invitation has been sent to \'%s\'', username)
                        logging.warning('Please repeat this command when invitation is accepted.')
                    keys = params.key_cache.get(email)
                    if keys and keys.rsa:
                        uo.manageRecords = folder_pb2.BOOLEAN_TRUE if mr or curr_sf.get('default_manage_records') is True else folder_pb2.BOOLEAN_FALSE
                        uo.manageUsers = folder_pb2.BOOLEAN_TRUE if mu or curr_sf.get('default_manage_users') is True else folder_pb2.BOOLEAN_FALSE
                        sf_key = curr_sf.get('shared_folder_key_unencrypted')  # type: Optional[bytes]
                        if sf_key:
                            rsa_key = crypto.load_rsa_public_key(keys.rsa)
                            uo.sharedFolderKey = crypto.encrypt_rsa(sf_key, rsa_key)

                        rq.sharedFolderAddUser.append(uo)
                    else:
                        logging.warning('User %s not found', email)

        if len(teams) > 0:
            existing_teams = {x['team_uid']: x for x in curr_sf.get('teams', [])}
            for team_uid in teams:
                to = folder_pb2.SharedFolderUpdateTeam()
                to.teamUid = utils.base64_url_decode(team_uid)
                if isinstance(share_expiration, int):
                    if share_expiration > 0:
                        to.expiration = share_expiration * 1000
                        to.timerNotificationType = record_pb2.NOTIFY_OWNER
                    elif share_expiration < 0:
                        to.expiration = -1
                if team_uid in existing_teams:
                    team = existing_teams[team_uid]
                    if action == 'grant':
                        to.manageRecords = True if mr else team.get('manage_records', False)
                        to.manageUsers = True if mu else team.get('manage_users', False)
                        rq.sharedFolderUpdateTeam.append(to)
                    elif action == 'revoke':
                        to.manageRecords = False if mr else team.get('manage_records', False)
                        to.manageUsers = False if mu else team.get('manage_users', False)
                        rq.sharedFolderUpdateTeam.append(to)
                    elif action == 'remove':
                        rq.sharedFolderRemoveTeam.append(to.teamUid)
                elif action == 'grant':
                    to.manageRecords = True if mr else curr_sf.get('default_manage_records') is True
                    to.manageUsers = True if mu else curr_sf.get('default_manage_users') is True
                    sf_key = curr_sf.get('shared_folder_key_unencrypted')  # type: Optional[bytes]
                    if sf_key:
                        if team_uid in params.team_cache:
                            team = params.team_cache[team_uid]
                            to.sharedFolderKey = crypto.encrypt_aes_v1(sf_key, team['team_key_unencrypted'])
                        else:
                            api.load_team_keys(params, [team_uid])
                            keys = params.key_cache.get(team_uid)
                            if keys:
                                if keys.aes:
                                    to.sharedFolderKey = crypto.encrypt_aes_v1(sf_key, keys.aes)
                                elif keys.rsa:
                                    rsa_key = crypto.load_rsa_public_key(keys.rsa)
                                    to.sharedFolderKey = crypto.encrypt_rsa(sf_key, rsa_key)
                                else:
                                    continue
                            else:
                                continue
                    else:
                        logging.info('Shared folder key is not available.')
                    rq.sharedFolderAddTeam.append(to)

        ce = kwargs.get('can_edit')
        cs = kwargs.get('can_share')

        if default_record:
            if ce and action != 'remove':
                rq.defaultCanEdit = folder_pb2.BOOLEAN_TRUE if action == 'grant' else folder_pb2.BOOLEAN_FALSE
            else:
                rq.defaultCanEdit = folder_pb2.BOOLEAN_NO_CHANGE
            if cs and action != 'remove':
                rq.defaultCanShare = folder_pb2.BOOLEAN_TRUE if action == 'grant' else folder_pb2.BOOLEAN_FALSE
            else:
                rq.defaultCanShare = folder_pb2.BOOLEAN_NO_CHANGE

        if len(rec_uids) > 0:
            existing_records = {x['record_uid'] for x in curr_sf.get('records', [])}
            for record_uid in rec_uids:
                ro = folder_pb2.SharedFolderUpdateRecord()
                ro.recordUid = utils.base64_url_decode(record_uid)
                if isinstance(share_expiration, int):
                    if share_expiration > 0:
                        ro.expiration = share_expiration * 1000
                        ro.timerNotificationType = record_pb2.NOTIFY_OWNER
                    elif share_expiration < 0:
                        ro.expiration = -1

                if record_uid in existing_records:
                    if action == 'grant':
                        ro.canEdit = folder_pb2.BOOLEAN_TRUE if ce else folder_pb2.BOOLEAN_NO_CHANGE
                        ro.canShare = folder_pb2.BOOLEAN_TRUE if cs else folder_pb2.BOOLEAN_NO_CHANGE
                        rq.sharedFolderUpdateRecord.append(ro)
                    elif action == 'revoke':
                        ro.canEdit = folder_pb2.BOOLEAN_FALSE if ce else folder_pb2.BOOLEAN_NO_CHANGE
                        ro.canShare = folder_pb2.BOOLEAN_FALSE if cs else folder_pb2.BOOLEAN_NO_CHANGE
                        rq.sharedFolderUpdateRecord.append(ro)
                    elif action == 'remove':
                        rq.sharedFolderRemoveRecord.append(ro.recordUid)
                else:
                    if action == 'grant':
                        ro.canEdit = folder_pb2.BOOLEAN_TRUE if ce or curr_sf.get('default_can_edit') is True else folder_pb2.BOOLEAN_FALSE
                        ro.canShare = folder_pb2.BOOLEAN_TRUE if cs or curr_sf.get('default_can_share') is True else folder_pb2.BOOLEAN_FALSE
                        sf_key = curr_sf.get('shared_folder_key_unencrypted')
                        if sf_key:
                            rec = params.record_cache[record_uid]
                            rec_key = rec['record_key_unencrypted']
                            if rec.get('version', 0) < 3:
                                ro.encryptedRecordKey = crypto.encrypt_aes_v1(rec_key, sf_key)
                            else:
                                ro.encryptedRecordKey = crypto.encrypt_aes_v2(rec_key, sf_key)
                        rq.sharedFolderAddRecord.append(ro)
        return rq

    @staticmethod
    def send_requests(params, partitioned_requests):
        for requests in partitioned_requests:
            while requests:
                params.sync_data = True
                chunk = requests[:999]
                requests = requests[999:]
                rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                rqs.sharedFoldersUpdateV3.extend(chunk)
                try:
                    rss = api.communicate_rest(params, rqs, 'vault/shared_folder_update_v3', payload_version=1,
                                               rs_type=folder_pb2.SharedFolderUpdateV3ResponseV2)
                    for rs in rss.sharedFoldersUpdateV3Response:
                        team_cache = params.available_team_cache or []
                        for attr in (
                                'sharedFolderAddTeamStatus', 'sharedFolderUpdateTeamStatus',
                                'sharedFolderRemoveTeamStatus'):
                            if hasattr(rs, attr):
                                statuses = getattr(rs, attr)
                                for t in statuses:
                                    team_uid = utils.base64_url_encode(t.teamUid)
                                    team = next((x for x in team_cache if x.get('team_uid') == team_uid), None)
                                    if team:
                                        status = t.status
                                        if status == 'success':
                                            logging.info('Team share \'%s\' %s', team['team_name'],
                                                         'added' if attr == 'sharedFolderAddTeamStatus' else
                                                         'updated' if attr == 'sharedFolderUpdateTeamStatus' else
                                                         'removed')
                                        else:
                                            logging.warning('Team share \'%s\' failed', team['team_name'])

                        for attr in (
                                'sharedFolderAddUserStatus', 'sharedFolderUpdateUserStatus',
                                'sharedFolderRemoveUserStatus'):
                            if hasattr(rs, attr):
                                statuses = getattr(rs, attr)
                                for s in statuses:
                                    username = s.username
                                    status = s.status
                                    if status == 'success':
                                        logging.info('User share \'%s\' %s', username,
                                                     'added' if attr == 'sharedFolderAddUserStatus' else
                                                     'updated' if attr == 'sharedFolderUpdateUserStatus' else
                                                     'removed')
                                    elif status == 'invited':
                                        logging.info('User \'%s\' invited', username)
                                    else:
                                        logging.warning('User share \'%s\' failed', username)

                        for attr in ('sharedFolderAddRecordStatus', 'sharedFolderUpdateRecordStatus',
                                     'sharedFolderRemoveRecordStatus'):
                            if hasattr(rs, attr):
                                statuses = getattr(rs, attr)
                                for r in statuses:
                                    record_uid = utils.base64_url_encode(r.recordUid)
                                    status = r.status
                                    if record_uid in params.record_cache:
                                        rec = api.get_record(params, record_uid)
                                        title = rec.title
                                    else:
                                        title = record_uid
                                    if status == 'success':
                                        logging.info('Record share \'%s\' %s', title,
                                                     'added' if attr == 'sharedFolderAddRecordStatus' else
                                                     'updated' if attr == 'sharedFolderUpdateRecordStatus' else
                                                     'removed')
                                    else:
                                        logging.warning('Record share \'%s\' failed', title)
                except KeeperApiError as kae:
                    if kae.result_code != 'bad_inputs_nothing_to_do':
                        raise kae


class ShareRecordCommand(Command):
    def get_parser(self):
        return share_record_parser

    def execute(self, params, **kwargs):
        emails = kwargs.get('email') or []
        if not emails:
            raise CommandError('share-record', '\'email\' parameter is missing')

        action = kwargs.get('action') or 'grant'

        if action == 'cancel':
            answer = base.user_choice(
                bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC + 'This action cannot be undone.\n\n' +
                'Do you want to cancel all shares with user(s): ' + ', '.join(emails) + ' ?', 'yn', 'n')
            if answer.lower() in {'y', 'yes'}:
                for email in emails:
                    rq = {
                        'command': 'cancel_share',
                        'to_email': email
                    }
                    try:
                        api.communicate(params, rq)
                    except KeeperApiError as kae:
                        if kae.result_code == 'share_not_found':
                            logging.info('{0}: No shared records are found.'.format(email))
                        else:
                            logging.warning('{0}: {1}.'.format(email, kae.message))
                    except Exception as e:
                        logging.warning('{0}: {1}.'.format(email, e))
                params.sync_data = True
            return

        name = kwargs.get('record')
        if not name:
            self.get_parser().print_help()
            return

        share_expiration = None
        if action == 'grant':
            share_expiration = get_share_expiration(kwargs.get('expire_at'), kwargs.get('expire_in'))

        record_uid = None
        folder_uid = None
        shared_folder_uid = None
        if name in params.record_cache:
            record_uid = name
        elif name in params.folder_cache:
            folder = params.folder_cache[name]   # type: BaseFolderNode
            if isinstance(folder, (SharedFolderNode, SharedFolderFolderNode)):
                folder_uid = folder.uid
                if isinstance(folder, SharedFolderFolderNode):
                    shared_folder_uid = folder.shared_folder_uid
                else:
                    shared_folder_uid = folder.uid
        elif name in params.shared_folder_cache:
            shared_folder_uid = name
        else:
            for shared_folder in params.shared_folder_cache.values():
                shared_folder_name = shared_folder.get('name_unencrypted', '').lower()
                if name == shared_folder_name:
                    shared_folder_uid = shared_folder['shared_folder_uid']
                    break
                if 'records' in shared_folder:
                    if any((True for x in shared_folder['records'] if x['record_uid'] == name)):
                        record_uid = name
                        shared_folder_uid = shared_folder['shared_folder_uid']
                        break

            if shared_folder_uid is None and record_uid is None:
                rs = try_resolve_path(params, name)
                if rs is not None:
                    folder, name = rs
                    if name:
                        for uid in params.subfolder_record_cache.get(folder.uid or ''):
                            r = api.get_record(params, uid)
                            if r.title.lower() == name.lower():
                                record_uid = uid
                                break
                    else:
                        if isinstance(folder, (SharedFolderNode, SharedFolderFolderNode)):
                            folder_uid = folder.uid
                            shared_folder_uid = folder_uid if isinstance(folder, SharedFolderNode) \
                                else folder.shared_folder_uid

        is_share_admin = False
        if record_uid is None and folder_uid is None and shared_folder_uid is None:
            if params.enterprise:
                try:
                    uid = utils.base64_url_decode(name)
                    if isinstance(uid, bytes) and len(uid) == 16:
                        rq = record_pb2.AmIShareAdmin()
                        osa = record_pb2.IsObjectShareAdmin()
                        osa.uid = uid
                        osa.objectType = record_pb2.CHECK_SA_ON_RECORD
                        rq.isObjectShareAdmin.append(osa)
                        rs = api.communicate_rest(params, rq, 'vault/am_i_share_admin', rs_type=record_pb2.AmIShareAdmin)
                        if rs.isObjectShareAdmin:
                            if rs.isObjectShareAdmin[0].isAdmin:
                                is_share_admin = True
                                record_uid = name
                except:
                    pass

        if record_uid is None and folder_uid is None and shared_folder_uid is None:
            raise CommandError('share-record', 'Enter name or uid of existing record or shared folder')

        record_uids = set()
        if record_uid:
            record_uids.add(record_uid)
        elif folder_uid:
            folders = set()
            folders.add(folder_uid)
            if kwargs.get('recursive'):
                FolderMixin.traverse_folder_tree(params, folder_uid, lambda x: folders.add(x.uid))
            for uid in folders:
                if uid in params.subfolder_record_cache:
                    record_uids.update(params.subfolder_record_cache[uid])
        elif shared_folder_uid:
            if not kwargs.get('recursive'):
                raise CommandError('share-record', '--recursive parameter is required')
            sf = api.get_shared_folder(params, shared_folder_uid)
            record_uids.update((x['record_uid'] for x in sf.records))

        if len(record_uids) == 0:
            raise CommandError('share-record', 'There are no records to share selected')

        if action == 'owner' and len(emails) > 1:
            raise CommandError('share-record', 'You can transfer ownership to a single account only')

        all_users = set((x.casefold() for x in emails))
        if action in ('grant', 'owner'):
            invited = api.load_user_public_keys(params, list(all_users), send_invites=True)
            if invited:
                for email in invited:
                    logging.warning('Share invitation has been sent to \'%s\'', email)
                logging.warning('Please repeat this command when invitation is accepted.')
                all_users.difference_update(invited)
            all_users.intersection_update(params.key_cache.keys())

        if len(all_users) == 0:
            raise CommandError('share-record', 'Nothing to do.')

        can_edit = kwargs.get('can_edit') or False
        can_share = kwargs.get('can_share') or False
        if shared_folder_uid:
            api.load_records_in_shared_folder(params, shared_folder_uid, record_uids)

        not_owned_records = {} if is_share_admin else None
        for x in api.get_record_shares(params, record_uids, False) or []:
            if not_owned_records:
                record_uid = x.get('record_uid')
                if record_uid:
                    not_owned_records[record_uid] = x

        rq = record_pb2.RecordShareUpdateRequest()
        existing_shares = {}
        record_titles = {}
        transfer_ruids = set()
        for record_uid in record_uids:
            if record_uid in params.record_cache:
                rec = params.record_cache[record_uid]
            elif not_owned_records and record_uid in not_owned_records:
                rec = not_owned_records[record_uid]
            elif is_share_admin:
                rec = {
                    'record_uid': record_uid,
                    'shares': {
                        'user_permissions': [{
                            'username': x,
                            'owner': False,
                            'share_admin': False,
                            'shareable': True if action == 'revoke' else False,
                            'editable': True if action == 'revoke' else False,
                        } for x in all_users]
                    }
                }
            else:
                continue

            existing_shares.clear()
            if 'shares' in rec:
                shares = rec['shares']
                if 'user_permissions' in shares:
                    for po in shares['user_permissions']:
                        existing_shares[po['username'].lower()] = po
                del rec['shares']
            if 'data_unencrypted' in rec:
                try:
                    data = json.loads(rec['data_unencrypted'].decode())
                    if isinstance(data, dict):
                        if 'title' in data:
                            record_titles[record_uid] = data['title']
                except:
                    pass

            record_path = api.resolve_record_share_path(params, record_uid)
            for email in all_users:
                ro = record_pb2.SharedRecord()
                ro.toUsername = email
                ro.recordUid = utils.base64_url_decode(record_uid)
                if record_path:
                    if 'shared_folder_uid' in record_path:
                        ro.sharedFolderUid = utils.base64_url_decode(record_path['shared_folder_uid'])
                    if 'team_uid' in record_path:
                        ro.teamUid = utils.base64_url_decode(record_path['team_uid'])

                if action in {'grant', 'owner'}:
                    record_key = rec.get('record_key_unencrypted')
                    if record_key and email not in existing_shares and email in params.key_cache:
                        keys = params.key_cache[email]
                        if keys.ec:
                            ec_key = crypto.load_ec_public_key(keys.ec)
                            ro.recordKey = crypto.encrypt_ec(record_key, ec_key)
                            ro.useEccKey = True
                        elif keys.rsa:
                            rsa_key = crypto.load_rsa_public_key(keys.rsa)
                            ro.recordKey = crypto.encrypt_rsa(record_key, rsa_key)
                            ro.useEccKey = False
                        if action == 'owner':
                            ro.transfer = True
                            transfer_ruids.add(record_uid)
                        else:
                            ro.editable = can_edit
                            ro.shareable = can_share
                            if isinstance(share_expiration, int):
                                if share_expiration > 0:
                                    ro.expiration = share_expiration * 1000
                                    ro.timerNotificationType = record_pb2.NOTIFY_OWNER
                                elif share_expiration < 0:
                                    ro.expiration = -1
                        rq.addSharedRecord.append(ro)
                    else:
                        current = existing_shares[email]
                        if action == 'owner':
                            ro.transfer = True
                            transfer_ruids.add(record_uid)
                        else:
                            ro.editable = True if can_edit else current.get('editable')
                            ro.shareable = True if can_share else current.get('shareable')
                        rq.updateSharedRecord.append(ro)
                else:
                    if can_share or can_edit:
                        current = existing_shares[email]
                        ro.editable = False if can_edit else current.get('editable')
                        ro.shareable = False if can_share else current.get('shareable')
                        rq.updateSharedRecord.append(ro)
                    else:
                        rq.removeSharedRecord.append(ro)

        if kwargs.get('dry_run'):
            headers = ['Username', 'Record UID', 'Title', 'Share Action', 'Expiration']
            table = []
            for attr in ['addSharedRecord', 'updateSharedRecord', 'removeSharedRecord']:
                if hasattr(rq, attr):
                    for obj in getattr(rq, attr):
                        record_uid = utils.base64_url_encode(obj.recordUid)
                        username = obj.toUsername
                        row = [username, record_uid, record_titles.get(record_uid, '')]
                        if attr in ['addSharedRecord', 'updateSharedRecord']:
                            if obj.transfer:
                                row.append('Transfer Ownership')
                            elif obj.editable or obj.shareable:
                                if obj.editable and obj.shareable:
                                    row.append('Can Edit & Share')
                                elif obj.editable:
                                    row.append('Can Edit')
                                else:
                                    row.append('Can Share')
                            else:
                                row.append('Read Only')
                        else:
                            row.append('Remove Share')
                        if obj.expiration > 0:
                            dt = datetime.datetime.fromtimestamp(obj.expiration//1000)
                            row.append(str(dt))
                        else:
                            row.append(None)
                        table.append(row)
            dump_report_data(table, headers, row_number=True, group_by=0)
            return

        while len(rq.addSharedRecord) > 0 or len(rq.updateSharedRecord) > 0 or len(rq.removeSharedRecord) > 0:
            rq1 = record_pb2.RecordShareUpdateRequest()
            left = 990
            if left > 0 and len(rq.addSharedRecord) > 0:
                rq1.addSharedRecord.extend(rq.addSharedRecord[0:left])
                added = len(rq1.addSharedRecord)
                del rq.addSharedRecord[0:added]
                left -= added
            if left > 0 and len(rq.updateSharedRecord) > 0:
                rq1.updateSharedRecord.extend(rq.updateSharedRecord[0:left])
                added = len(rq1.updateSharedRecord)
                del rq.updateSharedRecord[0:added]
                left -= added
            if left > 0 and len(rq.removeSharedRecord) > 0:
                rq1.removeSharedRecord.extend(rq.removeSharedRecord[0:left])
                added = len(rq1.removeSharedRecord)
                del rq.removeSharedRecord[0:added]
                left -= added

            rs = api.communicate_rest(params, rq1, 'vault/records_share_update', rs_type=record_pb2.RecordShareUpdateResponse)
            for attr in ['addSharedRecordStatus', 'updateSharedRecordStatus', 'removeSharedRecordStatus']:
                if hasattr(rs, attr):
                    statuses = getattr(rs, attr)
                    for status_rs in statuses:
                        record_uid = utils.base64_url_encode(status_rs.recordUid)
                        status = status_rs.status
                        email = status_rs.username
                        if status == 'success':
                            verb = 'granted to' if attr == 'addSharedRecordStatus' else 'changed for' if attr == 'updateSharedRecordStatus' else 'revoked from'
                            logging.info('Record \"%s\" access permissions has been %s user \'%s\'', record_uid, verb, email)
                        else:
                            verb = 'grant' if attr == 'addSharedRecordStatus' else 'change' if attr == 'updateSharedRecordStatus' else 'revoke'
                            logging.info('Failed to %s record \"%s\" access permissions for user \'%s\': %s', record_uid, verb, email, status_rs.message)
        if transfer_ruids:
            from keepercommander.breachwatch import BreachWatch
            BreachWatch.save_reused_pw_count(params)


class ShareReportCommand(Command):
    def get_parser(self):
        return share_report_parser

    @staticmethod
    def sf_report(params, out=None, fmt=None, show_team_users=False):
        def get_share_info(share_target, name_key):  # type: (Dict[str, Any], str) -> Dict[str, str]
            manage_users = share_target.get('manage_users')
            manage_records = share_target.get('manage_records')
            if not manage_users and not manage_records:
                permissions = "No User Permissions"
            elif not manage_users and manage_records:
                permissions = "Cam Manage Records"
            elif manage_users and not manage_records:
                permissions = "Can Manage Users"
            else:
                permissions = "Can Manage Users & Records"

            share = {
                'name': share_target.get(name_key),
                'permissions': permissions
            }
            return share

        def get_username(user_uid, users):  # type: (int, Iterable[Dict[str, Any]]) -> str
            for u in users:
                if user_uid == u.get('enterprise_user_id'):
                    return u.get('username')

        def get_team_shares(share_target):
            t_shares = [share_target]
            if params.enterprise and show_team_users:
                e_team_users = params.enterprise.get('team_users') or []
                e_teams = params.enterprise.get('teams') or []
                e_users = params.enterprise.get('users') or []
                for team in e_teams:
                    if team.get('name') == share_target.get('name'):
                        share = {**share_target}
                        team_users = [u for u in e_team_users if u.get('team_uid') == team.get('team_uid')]
                        t_shares.extend(get_team_user_shares(share, e_users, team_users))
            share_target['name'] = '(Team) ' + share_target.get('name')
            return t_shares

        def get_team_user_shares(team_share, users, team_users):
            team_user_shares = []
            for tu in team_users:
                t_u_share = {**team_share, 'name': '(Team User) ' + get_username(tu.get('enterprise_user_id'), users)}
                team_user_shares.append(t_u_share)
            return team_user_shares

        title = 'Shared folders'
        headers = ['Folder UID', 'Folder Name', 'Shared To', 'Permissions', 'Folder Path']
        shared_folders = {**params.shared_folder_cache}
        table = []
        for uid, props in shared_folders.items():
            path = get_folder_path(params, uid)
            name = props['name_unencrypted']
            row = [uid, name]
            users = props.get('users') or []
            teams = props.get('teams') or []
            user_shares = [get_share_info(u, 'username') for u in users]
            shared_to = [*user_shares]
            team_shares = [get_share_info(t, 'name') for t in teams]
            for ts in team_shares:
                shared_to.extend(get_team_shares(ts))
            rows = [(*row, target.get('name'), target.get('permissions'), path) for target in shared_to]
            table += rows
        return dump_report_data(table, headers, title=title, fmt=fmt, filename=out)

    def execute(self, params, **kwargs):
        verbose = kwargs.get('verbose') is True
        show_team_users = kwargs.get('show_team_users') is True
        if show_team_users:
            verbose = True
        output_format = kwargs.get('format', 'table')
        user_filter = set()
        record_filter = set()

        if kwargs.get('folders'):
            report = ShareReportCommand.sf_report(
                params,
                out=kwargs.get('output'),
                fmt=kwargs.get('format'),
                show_team_users=show_team_users
            )
            return report

        containers = kwargs.get('container') or []
        containers = [get_folder_uids(params, container) for container in containers]
        containers = [uid for uids in containers for uid in uids]
        containers = [uid for uid in containers if uid]
        recs_by_containers = {k: v for c in containers for k, v in get_contained_record_uids(params, c, False).items()}
        contained_records = {r for k, recs in recs_by_containers.items() for r in recs}

        if kwargs.get('record'):
            records = kwargs.get('record') or []
            for r in records:
                if r in params.record_cache:
                    record_filter.add(r)
                else:
                    r_uid = None
                    rs = try_resolve_path(params, r)
                    if rs is not None:
                        sf, name = rs
                        if name:
                            shared_folder_uid = sf.uid or ''
                            if shared_folder_uid in params.subfolder_record_cache:
                                for uid in params.subfolder_record_cache[shared_folder_uid]:
                                    rec = api.get_record(params, uid)
                                    if name in {rec.title, rec.record_uid}:
                                        r_uid = rec.record_uid
                                        break
                    if r_uid:
                        record_filter.add(r_uid)
                    else:
                        raise CommandError('share-report', '\'{0}\' is not an existing record title or UID'.format(r))

            record_uids = {x for x in record_filter}
        elif kwargs.get('user'):
            for u in kwargs['user']:
                user_filter.add(u)

            record_uids = {x['record_uid'] for x in params.record_cache.values() if x['shared']}
        else:
            record_uids = {x['record_uid'] for x in params.record_cache.values() if x['shared']}

        record_uids = record_uids.intersection(contained_records) if contained_records else record_uids

        from keepercommander.shared_record import get_shared_records
        shared_records = get_shared_records(params, record_uids, not show_team_users)

        def get_record_shares():
            # Group shared-record uids by share target
            rec_shares = {}
            for sr in shared_records.values():
                for p in sr.permissions.values():
                    if user_filter and p.to_name in user_filter or not user_filter:
                        user_rec_shares = rec_shares.get(p.to_name, set())
                        user_rec_shares.add(sr.uid)
                        rec_shares[p.to_name] = user_rec_shares
            return rec_shares

        def get_sf_shares():
            # Group shared-folder uids by share target
            shared_folder_shares = {}
            for sr in shared_records.values():
                for sf_uid, share_targets in sr.sf_shares.items():
                    for target in share_targets:
                        if user_filter and target in user_filter or not user_filter:
                            user_sf_uids = shared_folder_shares.get(target, set())
                            user_sf_uids.add(sf_uid)
                            shared_folder_shares[target] = user_sf_uids
            return shared_folder_shares

        if not kwargs.get('owner'):
            sf_shares = get_sf_shares()
            record_shares = get_record_shares()
            if kwargs.get('record'):
                for shared_record in shared_records.values():
                    print('')
                    print('{0:>20s}   {1}'.format('Record UID:', shared_record.uid))
                    print('{0:>20s}   {1}'.format('Title:', shared_record.name))
                    for i, p in enumerate(shared_record.permissions.values()):
                        print('{0:>20s}   {1}'.format('Shared with:' if i == 0 else '', p.get_target(show_team_users)))
                    print('')
            elif kwargs.get('user'):
                if kwargs.get('shared_folders'):
                    headers = ['username', 'shared_folder_uid', 'name']
                    table = []
                    for user in sf_shares:
                        for shared_folder_uid in sf_shares[user]:
                            sf = api.get_shared_folder(params, shared_folder_uid)
                            row = [user, shared_folder_uid, sf.name if sf else '']
                            table.append(row)

                    if output_format == 'table':
                        headers = [field_to_title(x) for x in headers]
                    return dump_report_data(
                        table, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'),
                        group_by=0, row_number=True)

                else:
                    headers = ['username', 'record_owner', 'record_uid', 'record_title']
                    table = []
                    for user in record_shares:
                        for record_uid in record_shares[user]:
                            shared_record = shared_records.get(record_uid)
                            table.append([user, shared_record.owner, record_uid, shared_record.name])

                    if output_format == 'table':
                        headers = [field_to_title(x) for x in headers]
                    return dump_report_data(
                        table, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'),
                        group_by=0, row_number=True)
            else:
                if params.user in record_shares:
                    del record_shares[params.user]
                if params.user in sf_shares:
                    del sf_shares[params.user]

                headers = ['shared_to', 'records', 'shared_folders']
                table = []
                names = set(itertools.chain(record_shares.keys(), sf_shares.keys()))
                for name in names:
                    records = len(record_shares[name]) if name in record_shares else None
                    shared_folders = len(sf_shares[name]) if name in sf_shares else None
                    table.append([name, records, shared_folders])

                if output_format == 'table':
                    headers = [field_to_title(x) for x in headers]
                return dump_report_data(
                    table, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'),
                    group_by=0, row_number=True)
        else:
            include_share_date = kwargs.get('share_date')
            aram_enabled = True
            if shared_records:
                headers = ['record_owner', 'record_uid', 'record_title', 'shared_with', 'folder_path']
                table = []
                for uid, shared_record in shared_records.items():
                    share_events = include_share_date and aram_enabled and self.get_record_share_activities(params, uid)
                    aram_enabled = share_events is not False
                    folder_paths = '\n'.join(shared_record.folder_paths)
                    permissions = shared_record.get_ordered_permissions() if verbose \
                        else shared_record.user_permissions.values()
                    permissions = [p for p in permissions if shared_record.owner != p.to_name]
                    if not show_team_users and verbose:
                        permissions = [p for p in permissions if SharePermissions.SharePermissionsType.TEAM_USER not in p.types or len(p.types) > 1]

                    if not verbose:
                        share_info = len(permissions)
                    else:
                        share_info = []
                        if show_team_users:
                            share_info.append(f'{shared_record.owner} => Owner')
                        for p in permissions:
                            is_direct_share = SharePermissions.SharePermissionsType.USER in p.types
                            share_date = self.get_date_for_share(share_events, p.to_name) if is_direct_share \
                                else self.get_date_for_share_folder_record(share_events, next(iter(shared_record.sf_shares.keys())))
                            share_info.append(f'{p.get_target(show_team_users)} => {p.permissions_text}')
                            if share_date:
                                share_info.append(share_date)
                            if p.expiration > 0:
                                dt = datetime.datetime.fromtimestamp(p.expiration // 1000)
                                share_info.append('\t(expires on {0})'.format(str(dt)))

                        share_info = '\n'.join(share_info)

                    table.append([shared_record.owner, shared_record.uid, shared_record.name, share_info, folder_paths])
                if output_format != 'json':
                    headers = [field_to_title(x) for x in headers]
                return dump_report_data(
                    table, headers, fmt=output_format, filename=kwargs.get('output'),
                    sort_by=0, row_number=True)

    @staticmethod
    def get_record_share_activities(params: KeeperParams, record_uid: str):
        rq = {
            'command': 'get_audit_event_reports',
            'report_type': 'raw',
            'scope': 'enterprise',
            'limit': 1000,
            'order': 'ascending',
            'filter': {
                'audit_event_type': [
                    'share'
                    , 'record_share_outside_user'
                    , 'remove_share'

                    , 'folder_add_team'
                    , 'folder_remove_team'

                    , 'folder_add_record'
                    , 'folder_remove_record'

                    # ,'change_share'
                    # ,'transfer_owner'
                    # ,'accept_share'
                    # ,'cancel_share'
                ],
                'record_uid': record_uid
            }
        }

        try:
            rs = api.communicate(params, rq)

        except KeeperApiError as e:

            if e.result_code == 'not_an_enterprise_user':
                # logging.warning("In order to see shared time details, user must be part of the Keeper account.")
                return False
            elif e.result_code == 'access_denied':
                logging.debug("You do not have permissions to access report for your organization. In order to "
                                "allow user to access reports, ask administrator to grant permission \"Run Reports\" "
                                "permission.")
                return False

        rs = api.communicate(params, rq)

        if rs['result'] == 'success':
            audit_events = rs['audit_event_overview_report_rows']

            # sort list by creation date
            audit_events = sorted(audit_events, key=lambda i: i['created'])

        else:
            logging.warning("Error retrieving values")

            return None

        # Remove mutually exclusive records (ex. "share -> remove_share -> share -> remove_share -> share" will
        # become just "share")
        latest_record_share_events = {}
        latest_folder_share_events = {}

        for event in audit_events:

            if 'to_username' in event:  # INDIVIDUAL record sharing

                key = str(event['record_uid']) + '-' + str(event['to_username'])

                if event['audit_event_type'] in ['share', 'record_share_outside_user', 'remove_share']:
                    if key in latest_record_share_events and event['audit_event_type'] == 'remove_share':
                        del latest_record_share_events[key]
                    elif event['audit_event_type'] in ['share', 'record_share_outside_user']:
                        latest_record_share_events[key] = event
                    else:
                        pass

            elif 'shared_folder_uid' in event:  # FOLDER sharing

                key = str(event['record_uid']) + '-' + str(event['shared_folder_uid'])

                if event['audit_event_type'] in ['folder_add_record', 'folder_remove_record']:
                    if key in latest_folder_share_events and event['audit_event_type'] == 'folder_remove_record':
                        del latest_folder_share_events[key]
                    elif event['audit_event_type'] == 'folder_add_record':
                        latest_folder_share_events[key] = event
                    else:
                        pass

        return list(latest_record_share_events.values()) + list(latest_folder_share_events.values())

    @staticmethod
    def get_date_for_share(share_activity_list: list, user_name: str):
        if not share_activity_list or len(share_activity_list) == 0:
            return ""

        activity = next((s for s in share_activity_list if 'to_username' in s and s['to_username'] == user_name), None)

        if activity is None:
            return ""

        activity_created_ms = activity['created']
        dt = datetime.datetime.fromtimestamp(int(activity_created_ms//1000))
        date_formatted = str(dt)

        if activity['audit_event_type'] == 'record_share_outside_user':
            return '\t(externally shared on {0})'.format(date_formatted)
        else:
            return '\t(shared on {0})'.format(date_formatted)

    @staticmethod
    def get_date_for_share_folder_record(share_activity_list: list, shared_folder_uid: str):
        if not share_activity_list or len(share_activity_list) == 0:
            return ""

        activity = next((s for s in share_activity_list if ('folder' in s['audit_event_type'] and s["shared_folder_uid"] == shared_folder_uid)), None)

        if activity is None:
            return ""

        activity_created_ms = activity['created']
        date_formatted = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(activity_created_ms))

        return '\t(shared on {0})'.format(date_formatted)


class RecordPermissionCommand(Command):
    def get_parser(self):
        return record_permission_parser

    def execute(self, params, **kwargs):
        folder_name = kwargs['folder'] if 'folder' in kwargs else ''
        folder_uid = None
        if folder_name:
            if folder_name in params.folder_cache:
                folder_uid = folder_name
            else:
                rs = try_resolve_path(params, folder_name)
                if rs is not None:
                    folder, pattern = rs
                    if len(pattern) == 0:
                        folder_uid = folder.uid
                    else:
                        raise CommandError('record-permission', 'Folder {0} not found'.format(folder_name))

        if folder_uid:
            folder = params.folder_cache[folder_uid]  # type: BaseFolderNode or SharedFolderFolderNode
        else:
            folder = params.root_folder

        share_record = kwargs.get('share_record') or False
        share_folder = kwargs.get('share_folder') or False
        if not share_record and not share_folder:
            share_record = True
            share_folder = True

        flat_subfolders = [folder]
        if kwargs.get('recursive'):
            fols = set()
            fols.add(folder.uid)
            pos = 0
            while pos < len(flat_subfolders):
                subfolder = flat_subfolders[pos]
                if subfolder.subfolders:
                    for f_uid in subfolder.subfolders:
                        if f_uid not in fols:
                            f = params.folder_cache[f_uid]
                            if f:
                                flat_subfolders.append(f)
                            fols.add(f_uid)
                pos += 1
            logging.debug('Folder count: %s', len(flat_subfolders))

        should_have = True if kwargs['action'] == 'grant' else False
        change_share = kwargs['can_share'] or False
        change_edit = kwargs['can_edit'] or False

        if not change_share and not change_edit:
            raise CommandError('record-permission',
                               'Please choose at least one on the following options: can-edit, can-share')

        if not kwargs.get('force'):
            logging.info('\nRequest to {0} {1}{3}{2} permission(s) in "{4}" folder {5}'
                         .format('GRANT' if should_have else 'REVOKE',
                                 '"Can Edit"' if change_edit else '',
                                 '"Can Share"' if change_share else '',
                                 ' & ' if change_edit and change_share else '',
                                 folder.name,
                                 'recursively' if kwargs.get('recursive') else 'only'))

        uids = set()

        direct_shares_update = []
        direct_shares_skip = []

        # direct shares
        if share_record:
            uids.clear()
            for folder in flat_subfolders:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    uids.update(params.subfolder_record_cache[folder_uid])

            if len(uids) > 0:
                api.get_record_shares(params, uids)
                for record_uid in uids:
                    if record_uid in uids and record_uid in params.record_cache:
                        record = params.record_cache[record_uid]
                        has_record_share_permissions = False
                        if record_uid in params.meta_data_cache:
                            md = params.meta_data_cache[record_uid]
                            has_record_share_permissions = md['can_share']

                        if 'shares' in record:
                            if 'user_permissions' in record['shares']:
                                for up in record['shares']['user_permissions']:
                                    if up['owner']:  # exclude record owners
                                        continue
                                    username = up['username']
                                    if username == params.user:  # exclude self
                                        continue
                                    if (change_edit and should_have != up['editable']) or \
                                            (change_share and should_have != up['shareable']):
                                        cmd = {
                                            'to_username': up['username'],
                                            'record_uid': record_uid,
                                            'editable': up['editable'],
                                            'shareable': up['shareable']
                                        }
                                        if has_record_share_permissions:
                                            if change_edit:
                                                cmd['editable'] = should_have
                                            if change_share:
                                                cmd['shareable'] = should_have
                                            direct_shares_update.append(cmd)
                                        else:
                                            direct_shares_skip.append(cmd)

        # shared folder record permissions
        shared_folder_update = {}  # type: Dict[str, Dict[str, folder_pb2.SharedFolderUpdateRecord]]
        shared_folder_skip = {}    # type: Dict[str, Dict[str, folder_pb2.SharedFolderUpdateRecord]]

        if share_folder:
            share_admin_in_folders = set()   # type: Set[str]
            for folder in flat_subfolders:
                shared_folder_uid = None
                if folder.type == BaseFolderNode.SharedFolderType:
                    shared_folder_uid = folder.uid
                elif folder.type == BaseFolderNode.SharedFolderFolderType:
                    shared_folder_uid = folder.shared_folder_uid
                if shared_folder_uid:
                    if shared_folder_uid not in share_admin_in_folders and shared_folder_uid in params.shared_folder_cache:
                        share_admin_in_folders.add(shared_folder_uid)
            if len(share_admin_in_folders) > 0:
                rq = record_pb2.AmIShareAdmin()
                for shared_folder_uid in share_admin_in_folders:
                    osa = record_pb2.IsObjectShareAdmin()
                    osa.uid = utils.base64_url_decode(shared_folder_uid)
                    osa.objectType = record_pb2.CHECK_SA_ON_SF
                    rq.isObjectShareAdmin.append(osa)
                share_admin_in_folders.clear()
                try:
                    rs = api.communicate_rest(params, rq, 'vault/am_i_share_admin', rs_type=record_pb2.AmIShareAdmin)
                    for osa in rs.isObjectShareAdmin:
                        if osa.isAdmin:
                            share_admin_in_folders.add(utils.base64_url_encode(osa.uid))
                except:
                    pass

            for folder in flat_subfolders:
                if folder.type not in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    continue
                uids.clear()
                if folder.uid in params.subfolder_record_cache:
                    uids.update(params.subfolder_record_cache[folder.uid])

                shared_folder_uid = folder.uid
                if type(folder) == SharedFolderFolderNode:
                    shared_folder_uid = folder.shared_folder_uid

                account_uid = utils.base64_url_encode(params.account_uid_bytes)
                if shared_folder_uid in params.shared_folder_cache:
                    is_share_admin = shared_folder_uid in share_admin_in_folders
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    team_uid = None
                    has_manage_records_permission = is_share_admin
                    if not has_manage_records_permission:
                        if 'owner_account_uid' in shared_folder:
                            has_manage_records_permission = shared_folder['owner_account_uid'] == account_uid
                    if not has_manage_records_permission:
                        if 'users' in shared_folder:
                            user = next((x for x in shared_folder['users'] if x.get('username') == params.user), None)
                            if user and 'manage_records' in user:
                                has_manage_records_permission = user['manage_records'] is True
                    if not has_manage_records_permission:
                        if 'teams' in shared_folder:
                            for sft in shared_folder['teams']:
                                uid = sft['team_uid']
                                if sft.get('manage_records') and uid in params.team_cache:
                                    team_uid = uid
                                    has_manage_records_permission = True
                                    break

                    if 'records' in shared_folder:
                        for rp in shared_folder['records']:
                            record_uid = rp['record_uid']
                            if is_share_admin or has_manage_records_permission:
                                container = shared_folder_update
                            else:
                                container = shared_folder_skip

                            if shared_folder_uid not in container:
                                container[shared_folder_uid] = {}
                            record_permissions = container[shared_folder_uid]

                            if record_uid in uids and record_uid not in record_permissions:
                                if (change_edit and should_have != rp['can_edit']) or \
                                        (change_share and should_have != rp['can_share']):
                                    cmd = folder_pb2.SharedFolderUpdateRecord()
                                    cmd.recordUid = utils.base64_url_decode(record_uid)
                                    cmd.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
                                    if team_uid:
                                        cmd.teamUid = utils.base64_url_decode(team_uid)
                                    cmd.canEdit = (folder_pb2.BOOLEAN_TRUE if should_have else folder_pb2.BOOLEAN_FALSE) if change_edit else folder_pb2.BOOLEAN_NO_CHANGE
                                    cmd.canShare = (folder_pb2.BOOLEAN_TRUE if should_have else folder_pb2.BOOLEAN_FALSE) if change_share else folder_pb2.BOOLEAN_NO_CHANGE
                                    record_permissions[record_uid] = cmd

        if len(shared_folder_update) > 0:
            uids.clear()
            uids.update(shared_folder_update.keys())
            for shared_folder_uid in uids:
                if len(shared_folder_update[shared_folder_uid]) == 0:
                    del shared_folder_update[shared_folder_uid]

        if len(shared_folder_skip) > 0:
            uids.clear()
            uids.update(shared_folder_skip.keys())
            for shared_folder_uid in uids:
                if len(shared_folder_skip[shared_folder_uid]) == 0:
                    del shared_folder_skip[shared_folder_uid]

        if len(direct_shares_skip) > 0:
            if kwargs.get('dry_run'):
                table = []
                for cmd in direct_shares_skip:
                    record_uid = cmd['record_uid']
                    record = params.record_cache[record_uid]
                    record_owners = [x['username'] for x in record['shares']['user_permissions'] if x['owner']]
                    record_owner = record_owners[0] if len(record_owners) > 0 else ''
                    rec = api.get_record(params, record_uid)
                    row = [record_uid, rec.title[:32], record_owner, cmd['to_username']]
                    table.append(row)
                headers = ['Record UID', 'Title', 'Owner', 'Email']
                title = bcolors.FAIL + ' SKIP ' + bcolors.ENDC + 'Direct Record Share permission(s). Not permitted'
                dump_report_data(table, headers, title=title, row_number=True, group_by=0)
                logging.info('')
                logging.info('')

        if len(shared_folder_skip) > 0:
            if kwargs.get('dry_run'):
                table = []
                for shared_folder_uid in shared_folder_skip:
                    shared_folder = api.get_shared_folder(params, shared_folder_uid)
                    uid = shared_folder_uid
                    name = shared_folder.name[:32]
                    for record_uid in shared_folder_skip[shared_folder_uid]:
                        record = api.get_record(params, record_uid)
                        row = [uid, name, record_uid, record.title]
                        uid = ''
                        name = ''
                        table.append(row)
                if len(table) > 0:
                    headers = ['Shared Folder UID', 'Shared Folder Name', 'Record UID', 'Record Title']
                    title = (bcolors.FAIL + ' SKIP ' + bcolors.ENDC +
                             'Shared Folder Record Share permission(s). Not permitted')
                    dump_report_data(table, headers, title=title, row_number=True)
                    logging.info('')
                    logging.info('')

        if len(direct_shares_update) > 0:
            if not kwargs.get('force'):
                table = []
                for cmd in direct_shares_update:
                    record_uid = cmd['record_uid']
                    rec = api.get_record(params, record_uid)
                    row = [record_uid, rec.title[:32], cmd['to_username']]
                    if change_edit:
                        row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                   if 'editable' in cmd else '')
                    if change_share:
                        row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                   if 'shareable' in cmd else '')
                    table.append(row)

                headers = ['Record UID', 'Title', 'Email']
                if change_edit:
                    headers.append('Can Edit')
                if change_share:
                    headers.append('Can Share')

                title = (bcolors.OKGREEN + ' {0}' + bcolors.ENDC + ' Direct Record Share permission(s)') \
                    .format('GRANT' if should_have else 'REVOKE')
                dump_report_data(table, headers, title=title, row_number=True, group_by=0)
                logging.info('')
                logging.info('')

        if len(shared_folder_update) > 0:
            if not kwargs.get('force'):
                table = []
                for shared_folder_uid in shared_folder_update:
                    commands = shared_folder_update[shared_folder_uid]
                    shared_folder = api.get_shared_folder(params, shared_folder_uid)
                    uid = shared_folder_uid
                    name = shared_folder.name[:32]
                    for record_uid in commands:
                        cmd = commands[record_uid]
                        record = api.get_record(params, record_uid)
                        row = [uid, name, record_uid, record.title[:32]]
                        if change_edit:
                            row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                       if cmd.canEdit else '')
                        if change_share:
                            row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                       if cmd.canShare else '')
                        table.append(row)
                        uid = ''
                        name = ''

                if len(table) > 0:
                    headers = ['Shared Folder UID', 'Shared Folder Name', 'Record UID', 'Record Title']
                    if change_edit:
                        headers.append('Can Edit')
                    if change_share:
                        headers.append('Can Share')
                    title = (bcolors.OKGREEN + ' {0}' + bcolors.ENDC + ' Shared Folder Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title, row_number=True)
                    logging.info('')
                    logging.info('')

        if not kwargs.get('dry_run') and (len(shared_folder_update) > 0 or len(direct_shares_update) > 0):
            print('\n\n' + bcolors.WARNING + bcolors.BOLD + 'ALERT!!!' + bcolors.ENDC)
            answer = base.user_choice("Do you want to proceed with these permission changes?", 'yn', 'n') \
                if not kwargs.get('force') else 'Y'
            if answer.lower() == 'y':
                table = []
                while len(direct_shares_update) > 0:
                    batch = direct_shares_update[:80]
                    direct_shares_update = direct_shares_update[80:]
                    rq = {
                        'command': 'record_share_update',
                        'pt': 'Commander',
                        'update_shares': batch
                    }

                    rs = api.communicate(params, rq)
                    if 'update_statuses' in rs:
                        for status in rs['update_statuses']:
                            code = status['status']
                            if code != 'success':
                                record_uid = status['record_uid']
                                username = status.get('username') or status.get('to_username')
                                table.append([record_uid, username, code, status.get('message')])

                if len(table) > 0:
                    headers = ['Record UID', 'Email', 'Error Code', 'Message']
                    title = (bcolors.WARNING + 'Failed to {0}' + bcolors.ENDC + ' Direct Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title, row_number=True)
                    logging.info('')
                    logging.info('')

                table = []
                requests = []
                for shared_folder_uid in shared_folder_update:
                    updates = list(shared_folder_update[shared_folder_uid].values())
                    while len(updates) > 0:
                        batch = updates[:490]
                        updates = updates[490:]
                        rq = folder_pb2.SharedFolderUpdateV3Request()
                        rq.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
                        rq.forceUpdate = True
                        rq.sharedFolderUpdateRecord.extend(batch)
                        rq.fromTeamUid = batch[0].teamUid
                        requests.append(rq)

                chunks = []         # type: List[Dict[bytes, folder_pb2.SharedFolderUpdateV3Request]]
                current_rq = {}     # type: Dict[bytes, folder_pb2.SharedFolderUpdateV3Request]
                total_elements = 0
                for rq in requests:
                    if rq.sharedFolderUid in current_rq:
                        chunks.append(current_rq)
                        current_rq = {}
                        total_elements = 0
                    if total_elements + len(rq.sharedFolderUpdateRecord) > 500:
                        chunks.append(current_rq)
                        current_rq = {}
                        total_elements = 0

                    current_rq[rq.sharedFolderUid] = rq
                    total_elements += len(rq.sharedFolderUpdateRecord)
                if len(current_rq) > 0:
                    chunks.append(current_rq)

                for chunk in chunks:
                    rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                    rqs.sharedFoldersUpdateV3.extend(chunk.values())
                    rss = api.communicate_rest(params, rqs, 'vault/shared_folder_update_v3', payload_version=1,
                                               rs_type=folder_pb2.SharedFolderUpdateV3ResponseV2)
                    for rs in rss.sharedFoldersUpdateV3Response:
                        shared_folder_uid = utils.base64_url_encode(rs.sharedFolderUid)
                        for status in rs.sharedFolderUpdateRecordStatus:
                            record_uid = utils.base64_url_encode(status.recordUid)
                            code = status.status
                            if code != 'success':
                                table.append([shared_folder_uid, record_uid, code])

                if len(table) > 0:
                    headers = ['Shared Folder UID', 'Record UID', 'Error Code']
                    title = (
                                bcolors.WARNING + 'Failed to {0}' + bcolors.ENDC +
                                ' Shared Folder Record Share permission(s)').format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

                params.sync_data = True


class FindOwnerlessCommand(Command):
    def get_parser(self):
        return find_ownerless_parser

    def execute(self, params, **kwargs):
        def to_ownerless_record_rq_param(records):
            # type: (List[Dict[str, Any]]) -> List[APIRequest_pb2.OwnerlessRecord]
            rq_param = []
            for rec in records:
                rq_ownerless_record = APIRequest_pb2.OwnerlessRecord()
                rec_key = crypto.encrypt_aes_v1(rec.get('record_key_unencrypted'), params.data_key)
                rec_uid = utils.base64_url_decode(rec.get('record_uid'))
                rq_ownerless_record.recordUid = rec_uid
                rq_ownerless_record.recordKey = rec_key
                rq_param.append(rq_ownerless_record)
            return rq_param

        def claim_ownerless_records(records):
            chunk_size = 1000
            while records:
                rq = APIRequest_pb2.OwnerlessRecords()
                chunk = records[:chunk_size]
                records = records[chunk_size:]
                rq.ownerlessRecord.extend(to_ownerless_record_rq_param(chunk))
                api.communicate_rest(params, rq, 'ownerless_records/set_owner', rs_type=APIRequest_pb2.OwnerlessRecords)

        def fetch_ownerless_records():    # type: () -> List[Dict[str, Any]]
            rq = APIRequest_pb2.OwnerlessRecords()
            rs = api.communicate_rest(params, rq, 'ownerless_records/get_records',
                                      rs_type=APIRequest_pb2.OwnerlessRecords)
            rs_rec_uids = {utils.base64_url_encode(rec.recordUid) for rec in rs.ownerlessRecord if rec}
            records = [params.record_cache.get(uid) for uid in rs_rec_uids]
            return [rec for rec in records if rec and rec.get('record_key_unencrypted')]

        def dump_record_details(records, output, output_fmt):
            rec_uids = {r.get('record_uid') for r in records}
            shared_records = get_shared_records(params, rec_uids).values()
            headers = ['record_uid', 'title', 'shared_with', 'folder_path']
            table = []
            for shared_record in shared_records:
                row = [
                    shared_record.uid,
                    shared_record.name,
                    [f'{p.get_target(False)}' for p in shared_record.permissions.values()],
                    shared_record.folder_paths
                ]
                table.append(row)
            if fmt != 'json':
                headers = [field_to_title(x) for x in headers]
            return dump_report_data(table, headers, fmt=output_fmt, filename=output, row_number=True)

        ownerless_records = fetch_ownerless_records()

        # Filter records by containing folder(s)
        folders = kwargs.get('folder')
        if folders and ownerless_records:
            for f in folders:
                if not get_folder_uids(params, f):
                    logging.warning(f'Folder "{f}" not found')
            rec_uid_groups = [recs for f in folders for recs in get_contained_record_uids(params, f, False).values()]
            whitelist = set(itertools.chain.from_iterable(rec_uid_groups))
            ownerless_records = [r for r in ownerless_records if r.get('record_uid') in whitelist]

        claim_records = kwargs.get('claim')
        fmt = kwargs.get('format', 'table')
        out = kwargs.get('output')
        verbose = kwargs.get('verbose') or not claim_records or out
        records_dump = None
        if ownerless_records:
            logging.info(f'Found [{len(ownerless_records)}] ownerless record(s)')
            if verbose:
                records_dump = dump_record_details(ownerless_records, out, fmt)
            if claim_records:
                claim_ownerless_records(ownerless_records)
                SyncDownCommand().execute(params, force=True)
            else:
                logging.info('To claim the record(s) found above, re-run this command with the --claim flag.')
        else:
            logging.info('No ownerless records found')
        return records_dump


class FindDuplicateCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return find_duplicate_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any
        out_fmt = kwargs.get('format', 'table')
        out_dst = kwargs.get('output')

        def scan_enterprise_vaults():
            cmd = self.get_parser().prog
            if not params.enterprise:
                raise CommandError(cmd, 'This feature is available only to enterprise account administrators')
            from keepercommander import sox
            sox.validate_data_access(params, cmd)

            field_keys = ['title', 'url', 'record_type']
            refresh_data = kwargs.get('refresh_data')
            node_id = sox.get_node_id(params, None)
            enterprise_id = node_id >> 32
            now = datetime.datetime.now()
            update_floor_dt = now - datetime.timedelta(days=1)
            update_floor_ts = int(update_floor_dt.timestamp())

            sox_data = sox.get_compliance_data(params, node_id, enterprise_id, rebuild=refresh_data,
                                               min_updated=update_floor_ts)
            records = sox_data.get_records().values()
            recs_by_hash = {}

            for sd_rec in records:
                h_gen = hashlib.sha256()
                field_vals = [sd_rec.data.get(k) for k in field_keys]
                if not field_vals or not all(field_vals):
                    continue

                token_tuples = zip(field_keys, field_vals)
                for k, v in token_tuples:
                    h_gen.update(f'{k}={v};'.encode())

                hv = h_gen.hexdigest()
                grouped_records = recs_by_hash.get(hv, [])
                grouped_records.append(sd_rec)
                recs_by_hash[hv] = grouped_records

            dupe_groups = [recs for recs in recs_by_hash.values() if len(recs) > 1]  # type: List[List[Record]]
            if not dupe_groups:
                logging.info('No duplicates found.')
                return
            else:
                report_headers = ['group', 'record_uid', 'title', 'url', 'record_type', 'owner', 'shared',
                                  'shared_folder_uid']
                report_headers = fields_to_titles(report_headers) if out_fmt != 'json' else report_headers
                report_data = []
                for i, group in enumerate(dupe_groups):
                    for j, sd_rec in enumerate(group):
                        record_owner = sox_data.get_record_owner(sd_rec.record_uid).email
                        field_vals = [sd_rec.data.get(k) for k in field_keys]
                        sf_uids = sox_data.get_record_sfs(sd_rec.record_uid)
                        sf_uids = '\n'.join(sf_uids)
                        report_row = [i + 1, sd_rec.record_uid, *field_vals, record_owner, sd_rec.shared, sf_uids]
                        report_data.append(report_row)
                report_title = 'Duplicate Search Results (Enterprise Scope):'
                return dump_report_data(report_data, report_headers, fmt=out_fmt, filename=out_dst, title=report_title, group_by=0)

        scope = kwargs.get('scope', 'vault')
        if scope == 'enterprise':
            return scan_enterprise_vaults()

        quiet = kwargs.get('quiet', False)
        dry_run = kwargs.get('dry_run', False)
        quiet = quiet and not dry_run
        logging_fn = logging.info if not quiet else logging.debug

        def partition_by_shares(duplicate_sets, shared_recs_lookup):
            # type: (List[Set[str]], Dict[str, SharedRecord]) -> List[Set[str]]
            result = []
            for duplicates in duplicate_sets:
                recs_by_hash = {}
                for rec_uid in duplicates:
                    h = hashlib.sha256()
                    shared_rec = shared_recs_lookup.get(rec_uid)
                    permissions = shared_rec.permissions
                    tu_type = SharePermissions.SharePermissionsType.TEAM_USER
                    permissions = {k: p for k, p in permissions.items() if tu_type not in p.types or len(p.types) > 1}
                    permissions = {k: p for k, p in permissions.items() if p.to_name != shared_rec.owner}
                    permissions_keys = list(permissions.keys())
                    permissions_keys.sort()

                    to_hash = ';'.join(f'{k}={permissions.get(k).permissions_text}' for k in permissions_keys)
                    to_hash = to_hash or 'non-shared'
                    h.update(to_hash.encode())
                    h_val = h.hexdigest()
                    r_uids = recs_by_hash.get(h_val, set())
                    r_uids.add(rec_uid)
                    recs_by_hash[h_val] = r_uids
                result.extend([r for r in recs_by_hash.values() if len(r) > 1])
            return result

        def remove_duplicates(dupe_info, col_headers, dupe_uids):
            # type: (List[List[str]], List[str], Set[str]) -> None
            def confirm_removal(cols):
                prompt_title = f'\nThe following duplicate {"records have" if len(dupe_uids) > 1 else "record has"}' \
                        f' been marked for removal:\n'
                indices = (idx + 1 for idx in range(len(dupe_info)))
                prompt_report = prompt_title + '\n' + tabulate(dupe_info, col_headers, showindex=indices)
                prompt_msg = prompt_report + '\n\nDo you wish to proceed?'
                return confirm(prompt_msg)

            if kwargs.get('force') or confirm_removal(col_headers):
                logging_fn(f'Deleting {len(dupe_uids)} records...')
                if not dry_run:
                    rm_cmd = RecordRemoveCommand()
                    rm_cmd.execute(params, records=list(dupe_uids), force=True)
                else:
                    logging.info('In dry-run mode: no actual records removed (exclude --dry-run flag to disable)')
            else:
                print('Duplicate record removal aborted. No records removed.')

        by_title = kwargs.get('title', False)
        by_login = kwargs.get('login', False)
        by_password = kwargs.get('password', False)
        by_url = kwargs.get('url', False)
        by_custom = kwargs.get('full', False)
        by_shares = kwargs.get('shares', False)
        consolidate = kwargs.get('merge', False)

        by_custom = consolidate or by_custom

        if by_custom:
            by_title = True
            by_login = True
            by_password = True
            by_url = True
            by_shares = not kwargs.get('ignore_shares_on_merge') if consolidate else True
        elif not by_title and not by_login and not by_password and not by_url:
            by_title = True
            by_login = True
            by_password = True

        hashes = {}
        for record_uid in params.record_cache:
            rec = params.record_cache[record_uid]
            if rec.get('version', 0) not in {2, 3}:
                continue
            record = api.get_record(params, record_uid)
            tokens = []
            if by_title:
                tokens.append((record.title or '').lower())
            if by_login:
                tokens.append((record.login or '').lower())
            if by_password:
                tokens.append(record.password or '')
            if by_url:
                tokens.append(record.login_url or '')

            hasher = hashlib.sha256()
            non_empty = 0
            for token in tokens:
                if token:
                    non_empty += 1
                hasher.update(token.encode())

            if by_custom:
                customs = {}
                for x in record.custom_fields:
                    name = x.get('name')   # type: str
                    value = x.get('value')
                    if name and value:
                        if isinstance(value, list):
                            value = [str(x) for x in value]
                            value.sort()
                            value = '|'.join(value)
                        elif isinstance(value, int):
                            if value != 0:
                                value = str(value)
                            else:
                                value = None
                        elif isinstance(value, dict):
                            keys = list(value.keys())
                            keys.sort()
                            value = ';'.join((f'{x}:{value[x]}' for x in keys if value.get(x)))
                        elif not isinstance(value, str):
                            value = None
                        if value:
                            customs[name] = value
                if record.totp:
                    customs['totp'] = record.totp
                if record.record_type:
                    customs['type:'] = record.record_type
                keys = list(customs.keys())
                keys.sort()
                for key in keys:
                    non_empty += 1
                    for_hash = f'{key}={customs[key]}'
                    hasher.update(for_hash.encode('utf-8'))

            if non_empty > 0:
                hash_value = hasher.hexdigest()
                rec_uids = hashes.get(hash_value, set())
                rec_uids.add(record_uid)
                hashes[hash_value] = rec_uids

        fields = []
        if by_title:
            fields.append('Title')
        if by_login:
            fields.append('Login')
        if by_password:
            fields.append('Password')
        if by_url:
            fields.append('Website Address')
        if by_custom:
            fields.append('Custom Fields')
        if by_shares:
            fields.append('Shares')

        logging_fn('Find duplicated records by: %s', ', '.join(fields))
        partitions = [rec_uids for rec_uids in hashes.values() if len(rec_uids) > 1]

        r_uids = [rec_uid for duplicates in partitions for rec_uid in duplicates]
        shared_records_lookup = get_shared_records(params, r_uids, cache_only=True)  # type: Dict[str, SharedRecord]
        if by_shares:
            partitions = partition_by_shares(partitions, shared_records_lookup)
        if partitions:
            headers = ['group', 'title', 'login']
            if by_url:
                headers.append('url')
            headers.extend(['uid', 'record_owner', 'shared_to'])
            headers = fields_to_titles(headers) if out_fmt != 'json' else headers
            table_raw = []
            table = []
            to_remove = set()
            for i, partition in enumerate(partitions):
                for j, record_uid in enumerate(partition):
                    shared_record = shared_records_lookup.get(record_uid)
                    record = api.get_record(params, record_uid)
                    title = record.title or ''
                    login = record.login or ''
                    url = record.login_url or ''
                    url = urllib.parse.urlparse(url).hostname
                    url = url[:30] if url else ''
                    url = [url] if by_url else []
                    owner = shared_record.owner
                    if not owner:
                        owner = record_uid in params.record_owner_cache and params.record_owner_cache[record_uid].owner
                    team_user_type = SharePermissions.SharePermissionsType.TEAM_USER
                    perms = {k: p for k, p in shared_record.permissions.items()}
                    keys = list(perms.keys())
                    keys.sort()
                    perms = [perms.get(k) for k in keys]
                    perms = [p for p in perms if team_user_type not in p.types or len(p.types) > 1]
                    shares = '\n'.join([p.to_name for p in perms if owner != p.to_name])
                    row = [i + 1, title, login] + url + [record_uid, owner, shares]
                    table.append(row)

                    if j != 0:
                        to_remove.add(record_uid)
                        table_raw.append(row)
            if consolidate:
                uid_header = field_to_title('uid')
                record_uid_index = headers.index(uid_header) if uid_header in headers else None
                if not record_uid_index:
                    raise CommandError(self.get_parser().prog, 'Cannot find record UID for duplicate record')
                dup_info = [r for r in table_raw for rec_uid in to_remove if r[record_uid_index] == rec_uid]
                return remove_duplicates(dup_info, headers, to_remove)
            else:
                title = 'Duplicates Found:'
                return dump_report_data(table, headers, title=title, fmt=out_fmt, filename=out_dst, group_by=0)
        else:
            logging_fn('No duplicates found')


class OneTimeShareCommand(GroupCommand):
    def __init__(self):
        super(OneTimeShareCommand, self).__init__()
        self.register_command('list', OneTimeShareListCommand(), 'Displays a list of one-time shares for a records.')
        self.register_command('create', OneTimeShareCreateCommand(), 'Creates one-time share URL for a record.')
        self.register_command('remove', OneTimeShareRemoveCommand(), 'Removes one-time share URL for a record.')

    @staticmethod
    def resolve_record(params, name):
        record_uid = None
        if name in params.record_cache:
            record_uid = name
        else:
            rs = try_resolve_path(params, name)
            if rs is not None:
                folder, name = rs
                if folder is not None and name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == name.lower():
                                record_uid = uid
                                break

        if record_uid is None:
            raise CommandError('one-time-share', 'Enter name or uid of existing record')
        return record_uid

    @staticmethod
    def get_external_shares(params, record_uid):
        rq = APIRequest_pb2.GetAppInfoRequest()
        rq.appRecordUid.append(utils.base64_url_decode(record_uid))
        rs = api.communicate_rest(params, rq, 'vault/get_app_info', rs_type=APIRequest_pb2.GetAppInfoResponse)
        return rs.appInfo


class OneTimeShareRemoveCommand(Command):
    def get_parser(self):
        return one_time_share_remove_parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = OneTimeShareCommand.resolve_record(params, record_name)
        applications = OneTimeShareCommand.get_external_shares(params, record_uid)
        if len(applications) == 0:
            logging.info('There are no one-time shares for record \"%s\"', record_name)
            return

        share_name = kwargs.get('share')    # type: str
        if not share_name:
            self.get_parser().print_help()
            return
        if share_name.endswith('...'):
            share_name = share_name[:-3]

        client_id = None
        client_ids = []
        for app_info in applications:
            if client_id:
                break
            if not app_info.isExternalShare:
                continue
            for client in app_info.clients:
                if client.id.lower() == share_name.lower():
                    client_id = client.clientId
                    break
                enc_client_id = utils.base64_url_encode(client.clientId)
                if enc_client_id == share_name:
                    client_id = client.clientId
                    break
                if enc_client_id.startswith(share_name):
                    client_ids.append(client.clientId)

        if not client_id:
            if len(client_ids) == 1:
                client_id = client_ids[0]
                client_ids.clear()

        if not client_id:
            if len(client_ids) > 1:
                logging.warning('There are more than one one-time shares \"%s\"', share_name)
            else:
                logging.warning('There is no one-time share \"%s\"', share_name)
            return
        rq = APIRequest_pb2.RemoveAppClientsRequest()
        rq.appRecordUid = utils.base64_url_decode(record_uid)
        rq.clients.append(client_id)

        api.communicate_rest(params, rq, 'vault/external_share_remove')
        logging.info('One-time share \"%s\" is removed from record \"%s\"', share_name, record_name)


class OneTimeShareListCommand(Command):
    def get_parser(self):
        return one_time_share_list_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None
        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = OneTimeShareCommand.resolve_record(params, record_name)
        applications = OneTimeShareCommand.get_external_shares(params, record_uid)

        show_all = kwargs.get('show_all', False)
        verbose = kwargs.get('verbose', False)
        now = utils.current_milli_time()
        fields = ['record_uid', 'name', 'share_link_id', 'generated', 'opened', 'expires']
        if show_all:
            fields.append('status')
        table = []
        output_format = kwargs.get('format')
        for app_info in applications:
            if not app_info.isExternalShare:
                continue
            for client in app_info.clients:
                if not show_all and now > client.accessExpireOn:
                    continue
                link = {
                    'record_uid': record_uid,
                    'name': client.id,
                    'share_link_id': utils.base64_url_encode(client.clientId),
                    'generated': datetime.datetime.fromtimestamp(client.createdOn / 1000),
                    'expires': datetime.datetime.fromtimestamp(client.accessExpireOn / 1000),
                }
                if output_format == 'table' and not verbose:
                    link['share_link_id'] = utils.base64_url_encode(client.clientId)[:20] + '...'
                else:
                    link['share_link_id'] = utils.base64_url_encode(client.clientId)

                if client.firstAccess > 0:
                    link['opened'] = datetime.datetime.fromtimestamp(client.firstAccess / 1000)
                    link['accessed'] = datetime.datetime.fromtimestamp(client.lastAccess / 1000)

                link['status'] = 'Expired' if now > client.accessExpireOn else 'Opened' if client.firstAccess > 0 else 'Generated'

                table.append([link.get(x, '') for x in fields])
        if output_format == 'table':
            fields = [field_to_title(x) for x in fields]
        return dump_report_data(table, fields, fmt=output_format, filename=kwargs.get('output'))


class OneTimeShareCreateCommand(Command):
    def get_parser(self):
        return one_time_share_create_parser

    def execute(self, params, **kwargs):
        period_str = kwargs.get('expire')
        if not period_str:
            logging.warning('URL expiration period parameter \"--expire\" is required.')
            self.get_parser().print_help()
            return
        period = parse_timeout(period_str)
        if period.total_seconds() > 182 * 24 * 60 * 60:
            raise CommandError('one-time-share', 'URL expiration period cannot be greater than 6 months.')

        record_name = kwargs['record'] if 'record' in kwargs else None
        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = OneTimeShareCommand.resolve_record(params, record_name)
        record_key = params.record_cache[record_uid]['record_key_unencrypted']

        client_key = utils.generate_aes_key()
        client_id = crypto.hmac_sha512(client_key, 'KEEPER_SECRETS_MANAGER_CLIENT_ID'.encode())
        rq = APIRequest_pb2.AddExternalShareRequest()
        rq.recordUid = utils.base64_url_decode(record_uid)
        rq.encryptedRecordKey = crypto.encrypt_aes_v2(record_key, client_key)
        rq.clientId = client_id
        rq.accessExpireOn = utils.current_milli_time() + int(period.total_seconds() * 1000)
        share_name = kwargs.get('share_name')
        if share_name:
            rq.id = share_name

        api.communicate_rest(params, rq, 'vault/external_share_add', rs_type=APIRequest_pb2.Device)

        url = urlunparse(('https', params.server, '/vault/share', None, None, utils.base64_url_encode(client_key)))
        if params.batch_mode:
            return url
        else:
            output = kwargs.get('output') or ''
            if output == 'clipboard':
                import pyperclip
                pyperclip.copy(url)
                logging.info('One-Time record share URL is copied to clipboard')
            elif output == 'stdout':
                print('{0:>10s} : {1}'.format('URL', url))
            else:
                return url


class CreateRegularUserCommand(Command):
    def is_authorised(self):
        return False

    def get_parser(self):
        return create_account_parser

    def execute(self, params, **kwargs):
        email = kwargs.get('email')
        email_pattern = re.compile(constants.EMAIL_PATTERN)
        match = email_pattern.match(email)
        if not match:
            logging.warning('"%s" appears not a valid email address. Skipping.', email)
            return

        rules_rq = enterprise_pb2.DomainPasswordRulesRequest()
        rules_rq.username = email
        rules_rs = api.communicate_rest(params, rules_rq, 'authentication/get_domain_password_rules',
                                        rs_type=APIRequest_pb2.NewUserMinimumParams)
        iterations = max(rules_rs.minimumIterations, constants.PBKDF2_ITERATIONS)

        while True:
            password1 = getpass.getpass(prompt='  New User Password: ', stream=None)
            if not password1:
                return
            password2 = getpass.getpass(prompt='User Password Again: ', stream=None)
            if password1 == password2:
                password_ok = True
                for i in range(len(rules_rs.passwordMatchRegex)):
                    pattern = re.compile(rules_rs.passwordMatchRegex[i])
                    if not re.match(pattern, password1):
                        password_ok = False
                        logging.info('Your Master Password must follow this rule:')
                        logging.info(f'* {rules_rs.passwordMatchDescription[i]}')
                        break
                if password_ok:
                    break
            else:
                logging.warning('Passwords do not match.')
            answer = base.user_choice('Try again?', 'yn', 'n').lower()
            if answer not in ('y', 'yes'):
                return

        user_password = password1
        user_data_key = utils.generate_aes_key()
        rsa_private_key, rsa_public_key = crypto.generate_rsa_key()
        rsa_private = crypto.unload_rsa_private_key(rsa_private_key)
        rsa_public = crypto.unload_rsa_public_key(rsa_public_key)

        ec_private_key, ec_public_key = crypto.generate_ec_key()
        ec_private = crypto.unload_ec_private_key(ec_private_key)
        ec_public = crypto.unload_ec_public_key(ec_public_key)

        user_rq = APIRequest_pb2.CreateUserRequest()
        user_rq.username = email
        user_rq.authVerifier = utils.create_auth_verifier(
            user_password, crypto.get_random_bytes(16), iterations)
        user_rq.encryptionParams = utils.create_encryption_params(
            user_password, crypto.get_random_bytes(16), iterations, user_data_key)
        user_rq.rsaPublicKey = rsa_public
        user_rq.rsaEncryptedPrivateKey = crypto.encrypt_aes_v1(rsa_private, user_data_key)
        user_rq.eccPublicKey = ec_public
        user_rq.eccEncryptedPrivateKey = crypto.encrypt_aes_v2(ec_private, user_data_key)
        user_rq.encryptedDeviceToken = LoginV3API.get_device_id(params)
        user_rq.encryptedClientKey = crypto.encrypt_aes_v1(utils.generate_aes_key(), user_data_key)
        user_rq.clientVersion = rest_api.CLIENT_VERSION

        api.communicate_rest(params, user_rq, 'authentication/request_create_user')
        logging.info('Please check your email and enter the verification code below')
        logging.info('Press Enter to resume without code verification step.')
        while True:
            verification_code = getpass.getpass(prompt='Verification Code: ', stream=None)
            if not verification_code:
                break
            rq = APIRequest_pb2.ValidateCreateUserVerificationCodeRequest()
            rq.username = email
            rq.clientVersion = rest_api.CLIENT_VERSION
            rq.verificationCode = verification_code
            try:
                api.communicate_rest(params, rq, 'authentication/validate_create_user_verification_code')
                logging.info('Account \"%s\" has been created.', email)
                break
            except KeeperApiError as kae:
                if kae.result_code == 'link_or_code_expired':
                    logging.warning(kae.message)
                else:
                    raise kae
