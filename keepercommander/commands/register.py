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
import itertools
import re
import base64
import logging
import requests
import hashlib
import time
from tabulate import tabulate
from urllib.parse import urlparse, urlunparse

from Cryptodome.PublicKey import RSA
from typing import Optional, Dict, Any, Iterable

from .. import api, utils, crypto
from .base import dump_report_data, user_choice, field_to_title
from ..recordv3 import RecordV3
from ..params import KeeperParams
from ..proto import APIRequest_pb2
from ..subfolder import BaseFolderNode, SharedFolderFolderNode, try_resolve_path, find_folders, get_folder_path
from ..display import bcolors
from ..error import KeeperApiError, CommandError
from .base import raise_parse_exception, suppress_exit, Command, GroupCommand
from .helpers.timeout import parse_timeout


EMAIL_PATTERN = r"(?i)^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$"


def register_commands(commands):
    commands['share-record'] = ShareRecordCommand()
    commands['share-folder'] = ShareFolderCommand()
    commands['share-report'] = ShareReportCommand()
    commands['record-permission'] = RecordPermissionCommand()
    commands['find-duplicate'] = FindDuplicateCommand()
    commands['one-time-share'] = OneTimeShareCommand()
    # commands['file-report'] = FileReportCommand()


def register_command_info(aliases, command_info):
    aliases['sr'] = 'share-record'
    aliases['sf'] = 'share-folder'
    aliases['ots'] = 'one-time-share'

    for p in [share_record_parser, share_folder_parser, share_report_parser, record_permission_parser,
              find_duplicate_parser]:
        command_info[p.prog] = p.description

    command_info['one-time-share'] = 'Manage One-Time Shares'


share_record_parser = argparse.ArgumentParser(prog='share-record|sr', description='Change the sharing permissions of an individual record')
share_record_parser.add_argument('-e', '--email', dest='email', action='append', required=True, help='account email')
share_record_parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke', 'owner', 'cancel'],
                                 default='grant', action='store', help='user share action. \'grant\' if omitted')
share_record_parser.add_argument('-s', '--share', dest='can_share', action='store_true', help='can re-share record')
share_record_parser.add_argument('-w', '--write', dest='can_edit', action='store_true', help='can modify record')
share_record_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
share_record_parser.error = raise_parse_exception
share_record_parser.exit = suppress_exit

share_folder_parser = argparse.ArgumentParser(prog='share-folder|sf', description='Change a shared folders permissions.')
share_folder_parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke'], default='grant',
                                 action='store', help='shared folder action. \'grant\' if omitted')
share_folder_parser.add_argument('-e', '--email', dest='user', action='append',
                                 help='account email, team, or \'*\' as default folder permission')
share_folder_parser.add_argument('-r', '--record', dest='record', action='append',
                                 help='record name, record UID, or \'*\' as default folder permission')
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
share_folder_parser.add_argument('folder', nargs='?', type=str, action='store', help='shared folder path or UID')
share_folder_parser.error = raise_parse_exception
share_folder_parser.exit = suppress_exit

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
share_report_parser.error = raise_parse_exception
share_report_parser.exit = suppress_exit

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

file_report_parser = argparse.ArgumentParser(prog='file-report', description='List records with file attachments.')
file_report_parser.add_argument('-d', '--try-download', dest='try_download', action='store_true',
                                help='Try downloading every attachment you have access to.')
file_report_parser.error = raise_parse_exception
file_report_parser.exit = suppress_exit


find_duplicate_parser = argparse.ArgumentParser(prog='find-duplicate', description='List duplicated records.')
find_duplicate_parser.add_argument('--title', dest='title', action='store_true', help='Match duplicates by title.')
find_duplicate_parser.add_argument('--login', dest='login', action='store_true', help='Match duplicates by login.')
find_duplicate_parser.add_argument('--password', dest='password', action='store_true', help='Match duplicates by password.')
find_duplicate_parser.add_argument('--url', dest='url', action='store_true', help='Match duplicates by URL.')
find_duplicate_parser.add_argument('--full', dest='full', action='store_true', help='Match duplicates by all fields.')
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


class ShareFolderCommand(Command):
    def get_parser(self):
        return share_folder_parser

    def execute(self, params, **kwargs):
        folder = None
        name = kwargs.get('folder')
        if name:
            if name in params.folder_cache:
                folder = params.folder_cache[name]
            else:
                rs = try_resolve_path(params, name)
                if rs is not None:
                    folder, name = rs
                    if len(name or '') > 0:
                        folder = None
                    elif folder.type == BaseFolderNode.RootFolderType:
                        folder = None

        if folder is None:
            raise CommandError('share-folder', 'Enter name of the existing folder')

        if folder.type not in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            raise CommandError('share-folder', 'You can change permission of shared folders only')

        shared_folder_uid = folder.shared_folder_uid if folder.type == BaseFolderNode.SharedFolderFolderType else folder.uid
        if shared_folder_uid in params.shared_folder_cache:
            sh_fol = params.shared_folder_cache[shared_folder_uid]
            # TODO check permission to modify shared folder

            action = kwargs.get('action') or 'grant'

            as_users = set()
            as_teams = set()

            default_account = False
            if 'user' in kwargs:
                for u in (kwargs.get('user') or []):
                    if u == '*':
                        default_account = True
                    else:
                        em = re.match(EMAIL_PATTERN, u)
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

            record_uids = []
            default_record = False
            if 'record' in kwargs:
                records = kwargs.get('record') or []
                for r in records:
                    if r == '*':
                        default_record = True
                    elif r in params.record_cache:
                        record_uids.append(r)
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
                            record_uids.append(r_uid)
                        else:
                            logging.error('\'%s\' is not an existing record title or UID', r)

            request = {
                'command': 'shared_folder_update',
                'pt': 'Commander',
                'operation': 'update',
                'shared_folder_uid': sh_fol['shared_folder_uid'],
                'revision': sh_fol['revision']
            }

            if default_account:
                if kwargs.get('manage_records'):
                    request['default_manage_records'] = action == 'grant'
                if kwargs.get('manage_users'):
                    request['default_manage_users'] = action == 'grant'

            if default_record:
                if kwargs.get('can_edit'):
                    request['default_can_edit'] = action == 'grant'
                if kwargs.get('can_share'):
                    request['default_can_share'] = action == 'grant'

            if len(as_users) > 0:
                existing_users = {x['username'].lower(): x for x in sh_fol.get('users', [])}
                mr = kwargs.get('manage_records')
                mu = kwargs.get('manage_users')
                for email in as_users:
                    uo = {
                        'username': email
                    }
                    share_action = ''
                    if email in existing_users:
                        user = existing_users[email]
                        if action == 'grant':
                            uo['manage_records'] = True if mr else user.get('manage_records', False)
                            uo['manage_users'] = True if mu else user.get('manage_users', False)
                            share_action = 'update_users'
                        else:
                            if mr or mu:
                                uo['manage_records'] = False if mr else user.get('manage_records', False)
                                uo['manage_users'] = False if mu else user.get('manage_users', False)
                                share_action = 'update_users'
                            else:
                                share_action = 'remove_users'
                    elif action == 'grant':
                        api.load_user_public_keys(params, [email])
                        rsa_key = params.key_cache.get(email)
                        if rsa_key:
                            uo['manage_records'] = sh_fol.get('default_manage_records') or False
                            uo['manage_users'] = sh_fol.get('default_manage_users') or False
                            uo['shared_folder_key'] = api.encrypt_rsa(sh_fol['shared_folder_key_unencrypted'], rsa_key)
                            share_action = 'add_users'
                        else:
                            logging.warning('User %s not found', email)

                    if share_action:
                        if share_action not in request:
                            request[share_action] = []
                        request[share_action].append(uo)

            if len(as_teams) > 0:
                existing_teams = {x['team_uid']: x for x in sh_fol.get('teams', [])}
                mr = kwargs.get('manage_records')
                mu = kwargs.get('manage_users')
                for team_uid in as_teams:
                    to = {
                        'team_uid': team_uid
                    }
                    share_action = ''
                    if team_uid in existing_teams:
                        team = existing_teams[team_uid]
                        if action == 'grant':
                            to['manage_records'] = True if mr else team.get('manage_records', False)
                            to['manage_users'] = True if mu else team.get('manage_users', False)
                            share_action = 'update_teams'
                        else:
                            if mr or mu:
                                to['manage_records'] = False if mr else team.get('manage_records', False)
                                to['manage_users'] = False if mu else team.get('manage_users', False)
                                share_action = 'update_teams'
                            else:
                                share_action = 'remove_teams'
                    elif action == 'grant':
                        api.load_team_keys(params, [team_uid])
                        team_key = params.key_cache.get(team_uid)
                        if team_key:
                            if kwargs.get('force'):
                                to['manage_records'] = mr
                                to['manage_users'] = mu
                            else:
                                to['manage_records'] = sh_fol.get('default_manage_records') or False
                                to['manage_users'] = sh_fol.get('default_manage_users') or False
                            shared_folder_key = sh_fol['shared_folder_key_unencrypted']
                            if type(team_key) == bytes:
                                to['shared_folder_key'] = api.encrypt_aes(shared_folder_key, team_key)
                            else:
                                to['shared_folder_key'] = api.encrypt_rsa(shared_folder_key, team_key)
                            share_action = 'add_teams'

                    if share_action:
                        if share_action not in request:
                            request[share_action] = []
                        request[share_action].append(to)

            if len(record_uids) > 0:
                existing_records = {x['record_uid']: x for x in sh_fol.get('records', [])}
                team_uid = ''
                if 'key_type' not in sh_fol:
                    if 'teams' in sh_fol:
                        for team in sh_fol['teams']:
                            team_uid = team['team_uid']
                            if team.get('manage_records'):
                                break

                for record_uid in record_uids:
                    ro = {
                        'record_uid': record_uid
                    }
                    if team_uid:
                        ro['team_uid'] = team_uid
                        ro['shared_folder_uid'] = sh_fol['shared_folder_uid']

                    share_action = ''
                    ce = kwargs.get('can_edit')
                    cs = kwargs.get('can_share')
                    if record_uid in existing_records:
                        record = existing_records[record_uid]
                        if action == 'grant':
                            ro['can_edit'] = True if ce else record.get('can_edit', False)
                            ro['can_share'] = True if cs else record.get('can_share', False)
                            share_action = 'update_records'
                        else:
                            if ce or cs:
                                ro['can_edit'] = False if ce else record.get('can_edit', False)
                                ro['can_share'] = False if cs else record.get('can_share', False)
                                share_action = 'update_records'
                            else:
                                share_action = 'remove_records'
                    else:
                        if action == 'grant':
                            ro['can_edit'] = ce
                            ro['can_share'] = cs
                            rec = params.record_cache[record_uid]
                            ro['record_key'] = api.encrypt_aes(rec['record_key_unencrypted'],
                                                               sh_fol['shared_folder_key_unencrypted'])
                            share_action = 'add_records'

                    if share_action:
                        if share_action not in request:
                            request[share_action] = []
                        request[share_action].append(ro)

            try:
                response = api.communicate(params, request)
                params.sync_data = True

                for node in ['add_teams', 'update_teams', 'remove_teams']:
                    if node in response:
                        for t in response[node]:
                            team_uid = t['team_uid']
                            team = next((x for x in params.available_team_cache if x.get('team_uid') == team_uid), None)
                            if team:
                                if t['status'] == 'success':
                                    logging.info('Team share \'%s\' %s', team['team_name'],
                                                    'added' if node == 'add_teams' else
                                                    'updated' if node == 'update_teams' else
                                                    'removed')
                                else:
                                    logging.warning('Team share \'%s\' failed', team['team_name'])

                for node in ['add_users', 'update_users', 'remove_users']:
                    if node in response:
                        for s in response[node]:
                            if s['status'] == 'success':
                                logging.info('User share \'%s\' %s', s['username'],
                                                'added' if node == 'add_users' else
                                                'updated' if node == 'update_users' else
                                                'removed')
                            elif s['status'] == 'invited':
                                logging.info('User \'%s\' invited', s['username'])
                            else:
                                logging.warning('User share \'%s\' failed', s['username'])

                for node in ['add_records', 'update_records', 'remove_records']:
                    if node in response:
                        for r in response[node]:
                            rec = api.get_record(params, r['record_uid'])
                            if r['status'] == 'success':
                                logging.info('Record share \'%s\' %s', rec.title,
                                                'added' if node == 'add_records' else
                                                'updated' if node == 'update_records' else
                                                'removed')
                            else:
                                logging.warning('Record share \'%s\' failed', rec.title)

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
            answer = user_choice(bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                                 'This action cannot be undone.\n\n' +
                                 'Do you want to cancel all shares with user(s): ' + ', '.join(emails) + ' ?', 'yn',
                                 'n')
            if answer.lower() in {'y', 'yes'}:
                for email in emails:
                    rq = {
                        'command': 'cancel_share',
                        'to_email': email
                    }
                    try:
                        rs = api.communicate(params, rq)
                    except KeeperApiError as kae:
                        if kae.result_code == 'share_not_found':
                            logging.info('{0}: No shared records are found.'.format(email))
                        else:
                            logging.warning('{0}: {1}.'.format(email, kae.message))
                    except Exception as e:
                        logging.warning('{0}: {1}.'.format(email, e))
                params.sync_data = True
            return

        name = kwargs['record'] if 'record' in kwargs else None
        if not name:
            self.get_parser().print_help()
            return

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
            raise CommandError('share-record', 'Enter name or uid of existing record')

        RecordV3.validate_access(params, record_uid)
        public_keys = {}
        rq = {
            'command': 'public_keys',
            'key_owners': emails
        }
        rs = api.communicate(params, rq)
        if 'public_keys' in rs:
            for pk in rs['public_keys']:
                if 'public_key' in pk:
                    email = pk['key_owner'].lower()
                    if email != params.user.lower():
                        public_keys[email] = pk['public_key']
                else:
                    logging.error('\'%s\' is not a known Keeper account', pk['key_owner'])
        if len(public_keys) == 0:
            raise CommandError('share-record', 'No existing Keeper accounts provided.')

        record_path = api.resolve_record_share_path(params, record_uid)
        if record_path is None:
            raise CommandError('share-record', 'You do not have permissions to share this record.')

        rq = {
            'command': 'get_records',
            'include': ['shares'],
            'records': [record_path]
        }
        rs = api.communicate(params, rq)
        existing_shares = {}
        if 'records' in rs:
            if 'user_permissions' in rs['records'][0]:
                for po in rs['records'][0]['user_permissions']:
                    existing_shares[po['username'].lower()] = po

        can_edit = kwargs.get('can_edit') or False
        can_share = kwargs.get('can_share') or False

        record_key = params.record_cache[record_uid]['record_key_unencrypted']

        rq = {
            'command': 'record_share_update',
            'pt': 'Commander'
        }
        if action == 'owner':
            if len(public_keys) > 1:
                raise CommandError('share-record', 'You can transfer ownership to a single account only')

        for email in public_keys:
            current = existing_shares.get(email)
            ro = {
                'to_username': email
            }
            ro.update(record_path)
            share_action = ''
            if action == 'grant':
                if current is None:
                    rsa_key = RSA.importKey(base64.urlsafe_b64decode(public_keys[email] + '=='))
                    ro['record_key'] = api.encrypt_rsa(record_key, rsa_key)
                    ro['editable'] = can_edit,
                    ro['shareable'] = can_share
                else:
                    ro['editable'] = True if can_edit else current['editable']
                    ro['shareable'] = True if can_share else current['shareable']

                share_action = 'add_shares' if current is None else 'update_shares'
            elif action == 'revoke':
                if current:
                    if can_share or can_edit:
                        ro['editable'] = False if can_edit else current['editable']
                        ro['shareable'] = False if can_share else current['shareable']
                        share_action = 'update_shares'
                    else:
                        share_action = 'remove_shares'
            elif action == 'owner':
                if record_uid in params.meta_data_cache and params.meta_data_cache[record_uid].get('owner'):
                    ro['transfer'] = True
                    if current is None:
                        rsa_key = RSA.importKey(base64.urlsafe_b64decode(public_keys[email] + '=='))
                        ro['record_key'] = api.encrypt_rsa(record_key, rsa_key)
                        share_action = 'add_shares'
                    else:
                        share_action = 'update_shares'
                else:
                    logging.error('You should be a record owner to be able to transfer ownership')
                    return
            else:
                pass

            if share_action:
                if share_action not in rq:
                    rq[share_action] = []
                    rq[share_action].append(ro)

        rs = api.communicate(params, rq)

        if 'add_statuses' in rs:
            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] in ['success']]
            if emails:
                logging.info('Record is successfully shared with: %s', ', '.join(emails))

            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] in ['pending_accept']]
            if emails:
                logging.info('Recipient must accept request to complete sharing. Invitation sent to %s. ',
                             ', '.join(emails))

            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] not in ['success', 'pending_accept']]
            if emails:
                logging.info('Failed to share record with: %s', ', '.join(emails))

        if 'remove_statuses' in rs:
            emails = [x['to_username'] for x in rs['remove_statuses'] if x['status'] == 'success']
            if emails:
                logging.info('Stopped sharing record with: %s', ', '.join(emails))


class ShareReportCommand(Command):
    def get_parser(self):
        return share_report_parser

    @staticmethod
    def sf_report(params, out=None, fmt=None, show_team_users=False):
        def get_share_info(share_target, name_key):  # type: (Dict[str, Any], str) -> Dict[str, str]
            permissions_lookup = {'manage_users': 'Manage Users', 'manage_records': 'Manage Records'}
            share = {
                'name': share_target.get(name_key),
                'permissions': ', '.join([val for k, val in permissions_lookup.items() if share_target.get(k)])
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
        verbose = kwargs.get('verbose') or False
        output_format = kwargs.get('format', 'table')
        user_filter = set()
        record_filter = set()
        user_lookup = None   # type: Optional[Dict[int, str]]
        if isinstance(params.enterprise, dict) and 'users' in params.enterprise:
            user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise['users']}

        if kwargs.get('folders'):
            report = ShareReportCommand.sf_report(
                params,
                out=kwargs.get('output'),
                fmt=kwargs.get('format'),
                show_team_users=kwargs.get('show_team_users')
            )
            return report

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

            record_uids = [x for x in record_filter]
        elif kwargs.get('user'):
            for u in kwargs['user']:
                user_filter.add(u)

            record_uids = [x['record_uid'] for x in params.record_cache.values() if x['shared']]
        else:
            record_uids = [x['record_uid'] for x in params.record_cache.values() if x['shared']]

        api.get_record_shares(params, record_uids)

        if not kwargs.get('owner'):
            record_shares = {}
            sf_shares = {}
            record_owners = {}
            for uid in record_uids:
                record = params.record_cache[uid]
                if 'shares' in record:
                    if 'user_permissions' in record['shares']:
                        for up in record['shares']['user_permissions']:
                            user_name = up['username']
                            if up.get('owner'):
                                record_owners[uid] = user_name
                            if user_filter:
                                if user_name not in user_filter:
                                    continue
                            if user_name not in record_shares:
                                record_shares[user_name] = set()
                            if uid not in record_shares[user_name]:
                                record_shares[user_name].add(uid)
                    if 'shared_folder_permissions' in record['shares']:
                        names = set()
                        for sfp in record['shares']['shared_folder_permissions']:
                            shared_folder_uid = sfp['shared_folder_uid']
                            if shared_folder_uid in params.shared_folder_cache:
                                shared_folder = params.shared_folder_cache[sfp['shared_folder_uid']]
                                names.clear()
                                if 'users' in shared_folder:
                                    for u in shared_folder['users']:
                                        user_name = u['username']
                                        matches = user_name in user_filter if user_filter else True
                                        if matches:
                                            names.add(user_name)
                                if 'teams' in shared_folder:
                                    for t in shared_folder['teams']:
                                        user_name = t['name']
                                        matches = user_name in user_filter if user_filter else True
                                        if matches:
                                            names.add(user_name)
                                        if user_lookup:
                                            team_uid = t['team_uid']
                                            if 'team_users' in params.enterprise:
                                                for tu in params.enterprise['team_users']:
                                                    if tu.get('team_uid') != team_uid:
                                                        continue
                                                    if tu.get('user_type') == 2:
                                                        continue
                                                    user_name = user_lookup.get(tu.get('enterprise_user_id'))
                                                    if not user_name:
                                                        continue
                                                    matches = user_name in user_filter if user_filter else True
                                                    if matches:
                                                        names.add(user_name)

                                for user_name in names:
                                    if user_name not in sf_shares:
                                        sf_shares[user_name] = set()
                                    if shared_folder_uid not in sf_shares[user_name]:
                                        sf_shares[user_name].add(shared_folder_uid)

                                if 'records' in shared_folder:
                                    for sfr in shared_folder['records']:
                                        uid = sfr['record_uid']
                                        if record_filter:
                                            if uid not in record_filter:
                                                continue
                                        for user_name in names:
                                            if user_filter:
                                                if user_name not in user_filter:
                                                    continue
                                            if user_name not in record_shares:
                                                record_shares[user_name] = set()
                                            if uid not in record_shares[user_name]:
                                                record_shares[user_name].add(uid)

            if kwargs.get('record'):
                if len(record_shares) > 0:
                    users_shares = {}
                    for user in record_shares:
                        for uid in record_shares[user]:
                            if uid not in users_shares:
                                users_shares[uid] = set()
                            users_shares[uid].add(user)
                    for record_uid in users_shares:
                        record = api.get_record(params, record_uid)
                        print('')
                        print('{0:>20s}   {1}'.format('Record UID:', record.record_uid))
                        print('{0:>20s}   {1}'.format('Title:', record.title))
                        for i, user in enumerate(users_shares[record_uid]):
                            print('{0:>20s}   {1}'.format('Shared with:' if i == 0 else '', user))
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
                            rec = api.get_record(params, record_uid)
                            table.append([user, record_owners.get(rec.record_uid, ''), record_uid, rec.title if rec else ''])

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
            record_owners = {}
            record_shared_with = {}
            # To track if use is part of an enterprise. If not then call backend only once.
            is_an_enterprise_user_by_ref = [True]
            total_record = len(record_uids)
            count = 0
            for uid in record_uids:

                if include_share_date:

                    rem_count = total_record - count
                    percent = int(((rem_count/total_record)*100))
                    percent_indicator_left = int(50 - (percent/2))
                    percent_indicator_right = int(50 - percent_indicator_left)

                    print(
                          (bcolors.OKBLUE + 'Generating report: |' + bcolors.ENDC) +
                          ((bcolors.OKBLUE + '█' + bcolors.ENDC) * percent_indicator_left) +
                          ((bcolors.OKBLUE + '_' + bcolors.ENDC) * percent_indicator_right) +
                          (bcolors.OKBLUE + '|' + bcolors.ENDC),
                          (bcolors.OKBLUE + str(100-percent) + "%" + bcolors.ENDC), end='\x1b[1K\r')

                count = count + 1

                record = params.record_cache[uid]
                if 'shares' in record:
                    record_shared_with[uid] = []
                    record_share_details = self.get_record_share_activities(params, uid, is_an_enterprise_user_by_ref) if include_share_date else None
                    if 'user_permissions' in record['shares']:
                        for up in record['shares']['user_permissions']:
                            user_name = up['username']
                            if up.get('owner'):
                                record_owners[uid] = user_name
                            else:
                                can_edit = up.get('editable') or False
                                can_share = up.get('shareable') or False
                                permission = self.get_permission_text(can_edit, can_share)
                                date_shared = self.get_date_for_share(record_share_details, user_name)
                                record_shared_with[uid].append('{0} -> {1}{2}'.format(user_name, permission, date_shared))
                    if 'shared_folder_permissions' in record['shares']:
                        for sfp in record['shares']['shared_folder_permissions']:
                            shared_folder_uid = sfp['shared_folder_uid']
                            if shared_folder_uid in params.shared_folder_cache:
                                shared_folder = params.shared_folder_cache[sfp['shared_folder_uid']]
                                rp = None
                                if 'records' in shared_folder:
                                    for record in shared_folder['records']:
                                        if record.get('record_uid') == uid:
                                            rp = record
                                            break
                                if rp:
                                    can_edit = rp.get('can_edit')
                                    can_share = rp.get('can_share')
                                    permission = self.get_permission_text(can_edit, can_share)
                                    if 'users' in shared_folder:
                                        for u in shared_folder['users']:
                                            date_shared = self.get_date_for_share_folder_record(record_share_details, shared_folder_uid)
                                            user_name = u['username']
                                            record_shared_with[uid].append('{0} => {1}{2}'.format(user_name, permission, date_shared))
                                    if 'teams' in shared_folder:
                                        for t in shared_folder['teams']:
                                            date_shared = self.get_date_for_share_folder_record(record_share_details, shared_folder_uid)
                                            team_name = t['name']
                                            record_shared_with[uid].append('{0} => {1}{2}'.format(team_name, permission, date_shared))

            if len(record_owners) > 0:
                headers = ['record_owner', 'record_uid', 'record_title', 'shared_with', 'folder_path']
                table = []
                for uid, user_name in record_owners.items():
                    folder_paths = []
                    folders = list(find_folders(params, uid))
                    if len(folders) > 0:
                        for folder_uid in folders:
                            folder_paths.append(get_folder_path(params, folder_uid))
                    folder_paths = '\n'.join(folder_paths)

                    record = api.get_record(params, uid)
                    row = [user_name, uid, record.title[0:32] if record else '']
                    share_to = record_shared_with.get(uid)
                    if verbose:
                        share_to.sort()
                        row.append(share_to)
                    else:
                        row.append(len(share_to) if share_to else 0)
                    row.append(folder_paths)
                    table.append(row)

                if output_format == 'table':
                    headers = [field_to_title(x) for x in headers]
                return dump_report_data(
                    table, headers, fmt=output_format, filename=kwargs.get('output'),
                    group_by=0, row_number=True)

    @staticmethod
    def get_permission_text(can_edit, can_share, can_view=True):
        if can_edit or can_share:
            if can_edit and can_view:
                return 'Can Share & Edit'
            if can_share:
                return 'Can Share'
            return 'Can Edit'
        else:
            return 'Read Only' if can_view else 'Launch Only'

    @staticmethod
    def get_record_share_activities(params: KeeperParams, record_uid: str, is_an_enterprise_user_by_ref):

        if not is_an_enterprise_user_by_ref[0]:
            # no need to execute the query to get analytics data because we know that user is not part of the enterprise
            return None

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
                is_an_enterprise_user_by_ref[0] = False
                return None
            elif e.result_code == 'access_denied':
                logging.debug("You do not have permissions to access report for your organization. In order to "
                                "allow user to access reports, ask administrator to grant permission \"Run Reports\" "
                                "permission.")
                is_an_enterprise_user_by_ref[0] = False
                return None

        is_an_enterprise_user_by_ref[0] = True

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
        date_formatted = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(activity_created_ms))

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
                folder = flat_subfolders[pos]
                if folder.subfolders:
                    for f_uid in folder.subfolders:
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
        shared_folder_update = {}  # dict<shared_folder_uid, list[sf_record]>
        shared_folder_skip = {}

        if share_folder:
            for folder in flat_subfolders:
                if folder.type not in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    continue
                uids.clear()
                if folder.uid in params.subfolder_record_cache:
                    uids.update(params.subfolder_record_cache[folder.uid])

                shared_folder_uid = folder.uid
                if type(folder) == SharedFolderFolderNode:
                    shared_folder_uid = folder.shared_folder_uid
                if shared_folder_uid in params.shared_folder_cache:
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    team_uid = None
                    has_manage_records_permission = False
                    if 'shared_folder_key' in shared_folder:
                        has_manage_records_permission = shared_folder.get('manage_records') or False
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
                            has_record_share_permissions = False
                            has_record_edit_permissions = False
                            if record_uid in params.meta_data_cache:
                                md = params.meta_data_cache[record_uid]
                                has_record_share_permissions = md.get('can_share', False)
                                has_record_edit_permissions = md.get('can_edit', False)
                            if has_manage_records_permission:
                                if not has_record_share_permissions or not has_record_edit_permissions:
                                    if not has_record_edit_permissions:
                                        has_record_edit_permissions = rp.get('can_edit', False)
                                    if not has_record_share_permissions:
                                        has_record_share_permissions = rp.get('can_share', False)

                            if not has_manage_records_permission:
                                container = shared_folder_skip
                            elif change_edit and not has_record_edit_permissions:
                                container = shared_folder_skip
                            elif change_share and not has_record_share_permissions:
                                container = shared_folder_skip
                            else:
                                container = shared_folder_update

                            if shared_folder_uid not in container:
                                container[shared_folder_uid] = {}
                            record_permissions = container[shared_folder_uid]

                            if record_uid in uids and record_uid not in record_permissions:
                                if (change_edit and should_have != rp['can_edit']) or \
                                        (change_share and should_have != rp['can_share']):
                                    cmd = {
                                        'record_uid': record_uid,
                                        'shared_folder_uid': shared_folder_uid,
                                        'can_edit': rp['can_edit'],
                                        'can_share': rp['can_share']
                                    }
                                    if team_uid:
                                        cmd['team_uid'] = team_uid
                                    if change_edit:
                                        cmd['can_edit'] = should_have
                                    if change_share:
                                        cmd['can_share'] = should_have
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
                last_record_uid = ''
                table = []
                for i, cmd in enumerate(direct_shares_skip):
                    record_uid = cmd['record_uid']
                    row = [i + 1, '', '', '']
                    if record_uid != last_record_uid:
                        last_record_uid = record_uid
                        record = params.record_cache[record_uid]
                        record_owners = [x['username'] for x in record['shares']['user_permissions'] if x['owner']]
                        record_owner = record_owners[0] if len(record_owners) > 0 else ''
                        rec = api.get_record(params, record_uid)
                        row[1] = record_uid
                        row[2] = rec.title[:32]
                        row[3] = record_owner
                    row.append(cmd['to_username'])
                    table.append(row)
                headers = ['#', 'Record UID', 'Title', 'Owner', 'Email']
                title = bcolors.FAIL + ' SKIP ' + bcolors.ENDC + 'Direct Record Share permission(s). Not permitted'
                dump_report_data(table, headers, title=title)
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
                        row = [len(table) + 1, uid, name, record_uid, record.title]
                        uid = ''
                        name = ''
                        table.append(row)
                if len(table) > 0:
                    headers = ['#', 'Shared Folder UID', 'Shared Folder Name', 'Record UID', 'Record Title']
                    title = (bcolors.FAIL + ' SKIP ' + bcolors.ENDC +
                             'Shared Folder Record Share permission(s). Not permitted')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

        if len(direct_shares_update) > 0:
            if not kwargs.get('force'):
                last_record_uid = ''
                table = []
                for i, cmd in enumerate(direct_shares_update):
                    record_uid = cmd['record_uid']
                    row = [i + 1, '', '']
                    if record_uid != last_record_uid:
                        last_record_uid = record_uid
                        rec = api.get_record(params, record_uid)
                        row[1] = record_uid
                        row[2] = rec.title[:32]
                    row.append(cmd['to_username'])
                    if change_edit:
                        row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                   if 'editable' in cmd else '')
                    if change_share:
                        row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                   if 'shareable' in cmd else '')
                    table.append(row)

                headers = ['#', 'Record UID', 'Title', 'Email']
                if change_edit:
                    headers.append('Can Edit')
                if change_share:
                    headers.append('Can Share')

                title = (bcolors.OKGREEN + ' {0}' + bcolors.ENDC + ' Direct Record Share permission(s)') \
                    .format('GRANT' if should_have else 'REVOKE')
                dump_report_data(table, headers, title=title)
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
                        row = [len(table) + 1, uid, name, record_uid, record.title[:32]]
                        if change_edit:
                            row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                       if 'can_edit' in cmd else '')
                        if change_share:
                            row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                       if 'can_share' in cmd else '')
                        table.append(row)
                        uid = ''
                        name = ''

                if len(table) > 0:
                    headers = ['#', 'Shared Folder UID', 'Shared Folder Name', 'Record UID', 'Record Title']
                    if change_edit:
                        headers.append('Can Edit')
                    if change_share:
                        headers.append('Can Share')
                    title = (bcolors.OKGREEN + ' {0}' + bcolors.ENDC + ' Shared Folder Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

        if not kwargs.get('dry_run') and (len(shared_folder_update) > 0 or len(direct_shares_update) > 0):
            print('\n\n' + bcolors.WARNING + bcolors.BOLD + 'ALERT!!!' + bcolors.ENDC)
            answer = user_choice("Do you want to proceed with these permission changes?", 'yn', 'n') \
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
                        for i, status in enumerate(rs['update_statuses']):
                            code = status['status']
                            if code != 'success':
                                record_uid = status['record_uid']
                                username = status.get('username') or status.get('to_username')
                                table.append([len(table) + 1, record_uid, username, code, status.get('message')])

                if len(table) > 0:
                    headers = ['#', 'Record UID', 'Email', 'Error Code', 'Message']
                    title = (bcolors.WARNING + 'Failed to {0}' + bcolors.ENDC + ' Direct Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

                table = []
                for shared_folder_uid in shared_folder_update:
                    updates = list(shared_folder_update[shared_folder_uid].values())
                    while len(updates) > 0:
                        batch = updates[:80]
                        updates = updates[80:]
                        rq = {
                            'command': 'shared_folder_update',
                            'pt': 'Commander',
                            'operation': 'update',
                            'shared_folder_uid': shared_folder_uid,
                            'update_records': batch,
                            'force_update': True
                        }
                        if 'team_uid' in batch[0]:
                            rq['from_team_uid'] = batch[0]['team_uid']
                        rs = api.communicate(params, rq)
                        if 'update_records' in rs:
                            for status in rs['update_records']:
                                code = status['status']
                                if code != 'success':
                                    table.append([len(table) + 1, shared_folder_uid, status['record_uid'],
                                                  code, status.get('message')])

                if len(table) > 0:
                    headers = ['#', 'Shared Folder UID', 'Record UID', 'Error Code', 'Message']
                    title = (
                                bcolors.WARNING + 'Failed to {0}' + bcolors.ENDC + ' Shared Folder Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

                params.sync_data = True


class FileReportCommand(Command):
    def get_parser(self):
        return file_report_parser

    def execute(self, params, **kwargs):
        headers = ['#', 'Title', 'Record UID', 'File ID']
        if kwargs.get('try_download'):
            headers.append('Downloadable')
        table = []
        for record_uid in params.record_cache:
            r = api.get_record(params, record_uid)
            if not r.attachments:
                continue
            file_ids = {}
            for atta in r.attachments:
                file_id = atta.get('id')
                file_ids[file_id] = ''
            if kwargs.get('try_download'):
                ids = [x for x in file_ids]
                rq = {
                    'command': 'request_download',
                    'file_ids': ids,
                }
                api.resolve_record_access_path(params, r.record_uid, path=rq)
                logging.info('Downloading attachments for record %s', r.title)
                try:
                    rs = api.communicate(params, rq)
                    urls = {}
                    for file_id, dl in zip(ids, rs['downloads']):
                        if 'url' in dl:
                            urls[file_id] = dl['url']
                        elif 'error_code' in dl:
                            file_ids[file_id] = dl['error_code']
                    for file_id in urls:
                        url = urls[file_id]
                        opt_rs = requests.get(url, proxies=params.rest_context.proxies, headers={"Range": "bytes=0-1"})
                        file_ids[file_id] = 'OK' if opt_rs.status_code in {200, 206} else str(opt_rs.status_code)
                except Exception as e:
                    logging.debug(e)
            for file_id in file_ids:
                row = [len(table) + 1, r.title, r.record_uid, file_id]
                if kwargs.get('try_download'):
                    row.append(file_ids[file_id] or '-')
                table.append(row)

        dump_report_data(table, headers)


class FindDuplicateCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return find_duplicate_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any
        by_title = kwargs.get('title', False)
        by_login = kwargs.get('login', False)
        by_password = kwargs.get('password', False)
        by_url = kwargs.get('url', False)
        by_custom = kwargs.get('full', False)
        if by_custom:
            by_title = True
            by_login = True
            by_password = True
            by_url = True
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
                if hash_value in hashes:
                    hashes[hash_value].append(record_uid)
                else:
                    hashes[hash_value] = [record_uid]

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

        logging.info('Find duplicated records by: %s', ', '.join(fields))
        duplicates = [x for x in hashes.values() if len(x) > 1]
        if duplicates:
            record_uids = []
            for x in duplicates:
                record_uids.extend(x)
            api.get_record_shares(params, record_uids)

            headers = ['#', 'Title', 'Login']
            if by_url:
                headers.append('Website Address')
            headers.extend(['UID', 'Record Owner'])
            table = []
            for i in range(len(duplicates)):
                duplicate = duplicates[i]
                for j in range(len(duplicate)):
                    record_uid = duplicate[j]
                    record = api.get_record(params, record_uid)
                    row = [i+1 if j == 0 else None, record.title if j == 0 or not by_title else '', record.login if j == 0 or not by_login else '']
                    if by_url:
                        row.append(record.login_url if j == 0 else '')
                    row.append(record_uid)
                    rec = params.record_cache[record_uid]
                    owner = params.user if rec.get('shared') is False else ''
                    if 'shares' in rec:
                        shares = rec['shares']
                        if 'user_permissions' in shares:
                            user_permissions = shares['user_permissions']
                            un = next((x['username'] for x in user_permissions if x.get('owner')), None)
                            if un:
                                owner = un
                    row.append(owner)
                    table.append(row)
            print(tabulate(table, headers=headers))
        else:
            logging.info('No duplicates found.')


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

        api.communicate_rest(params, rq, 'vault/app_client_remove')
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

        comps = urlparse(params.rest_context.server_base)
        comps = comps._replace(path='/vault/share', fragment=utils.base64_url_encode(client_key), query='')
        url = urlunparse(comps)

        if params.batch_mode:
            return url
        else:
            if kwargs.get('output', '') == 'clipboard':
                import pyperclip
                pyperclip.copy(url)
                logging.info('One-Time record share URL is copied to clipboard')
            else:
                print('{0:>10s} : {1}'.format('URL', url))
