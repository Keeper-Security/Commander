#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


import argparse
import json
import getpass
import logging
import os
from typing import Optional, List

from . import imp_exp
from .importer import BaseFileImporter, SharedFolder, Permission, PathDelimiter, replace_email_domain
from .json.json import KeeperJsonImporter, KeeperJsonExporter
from .lastpass import fetcher
from .lastpass.vault import Vault
from .. import api
from ..commands.base import raise_parse_exception, suppress_exit, user_choice, Command
from ..params import KeeperParams


def register_commands(commands):
    commands['import'] = RecordImportCommand()
    commands['export'] = RecordExportCommand()
    commands['download-membership'] = DownloadMembershipCommand()
    commands['apply-membership'] = ApplyMembershipCommand()


def register_command_info(aliases, command_info):
    for p in [import_parser, export_parser, download_membership_parser, apply_membership_parser]:
        command_info[p.prog] = p.description


import_parser = argparse.ArgumentParser(prog='import', description='Import data from a local file into Keeper.')
import_parser.add_argument('--display-csv', '-dc', dest='display_csv', action='store_true',
                           help='display Keeper CSV import instructions')
import_parser.add_argument('--display-json', '-dj', dest='display_json', action='store_true',
                           help='display Keeper JSON import instructions')
import_parser.add_argument(
    '--format', choices=['json', 'csv', 'keepass', 'lastpass', 'myki', 'nordpass', 'manageengine', '1password', 'bitwarden'],
    required=True, help='file format'
)
import_parser.add_argument('--folder', dest='folder', action='store',
                           help='import into a separate folder.')
import_parser.add_argument('-s', '--shared', dest='shared', action='store_true',
                           help='import folders as Keeper shared folders')
import_parser.add_argument('-p', '--permissions', dest='permissions', action='store',
                           help='default shared folder permissions: manage (U)sers, manage (R)ecords, can (E)dit, can (S)hare, or (A)ll, (N)one')
import_parser.add_argument('--update',  dest='update',  action='store_true',
                           help='Update records with common login, url or title')
import_parser.add_argument('--users',  dest='users',  action='store_true',
                           help='Update shared folder user permissions only')
import_parser.add_argument('--record-type', dest='record_type', action='store',
                           help='Import legacy records as record type')
import_parser.add_argument('--login-type', '-l', dest='login_type', action='store_true',
                           help='Import legacy records as login record type')
import_parser.add_argument('--old-domain', '-od', dest='old_domain', action='store',
                           help='old domain for changing user emails in permissions')
import_parser.add_argument('--new-domain', '-nd', dest='new_domain', action='store',
                           help='new domain for changing user emails in permissions')
import_parser.add_argument('--file-cache', dest='tmpdir', action='store',
                           help='Temp directory used to cache encrypted attachment imports')
import_parser.add_argument(
    'name', type=str, help='file name (json, csv, keepass, 1password), account name (lastpass), or URL (ManageEngine)'
)
import_parser.error = raise_parse_exception
import_parser.exit = suppress_exit


export_parser = argparse.ArgumentParser(prog='export', description='Export data from Keeper to a local file.')
export_parser.add_argument('--format', dest='format', choices=['json', 'csv', 'keepass'], required=True, help='file format')
export_parser.add_argument('--max-size', dest='max_size', help='Maximum file attachment file. Example: 100K, 50M, 2G. Default: 10M')
export_parser.add_argument('-kp', '--keepass-file-password', dest='keepass_file_password', action='store', help='Password for the exported Keepass file')
export_parser.add_argument('--force', dest='force', action='store_true', help='Suppress user interaction. Assume "yes"')
export_parser.add_argument('--folder', dest='folder', action='store', help='Export data from the specific folder only.')
export_parser.add_argument('name', type=str, nargs='?', help='file name or console output if omitted (except keepass)')
export_parser.error = raise_parse_exception
export_parser.exit = suppress_exit


download_membership_parser = argparse.ArgumentParser(prog='download-membership', description='Unload shared folder membership to JSON file.')
download_membership_parser.add_argument('--source', dest='source', choices=['keeper', 'lastpass'], required=True, help='Shared folder membership source')
download_membership_parser.add_argument('--folder', dest='folder', action='store', help='import into a separate folder.')
download_membership_parser.add_argument('-p', '--permissions', dest='permissions', action='store', help='force shared folder permissions: manage (U)sers, manage (R)ecords')
download_membership_parser.add_argument('-r', '--restrictions', dest='restrictions', action='store', help='force shared folder restrictions: manage (U)sers, manage (R)ecords')
download_membership_parser.add_argument('--old-domain', '-od', dest='old_domain', action='store',  help='old domain for changing user emails in permissions')
download_membership_parser.add_argument('--new-domain', '-nd', dest='new_domain', action='store',  help='new domain for changing user emails in permissions')
download_membership_parser.add_argument('name', type=str, nargs='?', help='Output file name. "shared_folder_membership.json" if omitted.')
download_membership_parser.error = raise_parse_exception
download_membership_parser.exit = suppress_exit


apply_membership_parser = argparse.ArgumentParser(prog='apply-membership', description='Loads shared folder membership from JSON file into Keeper.')
apply_membership_parser.add_argument('name', type=str, nargs='?', help='Output file name. "shared_folder_membership.json" if omitted.')
apply_membership_parser.error = raise_parse_exception
apply_membership_parser.exit = suppress_exit

csv_instructions = '''CSV Import Instructions

File Format:
Folder,Title,Login,Password,Website Address,Notes,Shared Folder,Custom Fields

• To specify subfolders, use backslash "\\" between folder names
• To make a shared folder specify the name or path to it in the 7th field

Example 1: Create a regular folder at the root level with 2 custom fields
My Business Stuff,Twitter,marketing@company.com,123456,https://twitter.com,These are some notes,,API Key,5555,Date Created, 2018-04-02

Example 2: Create a shared subfolder inside another folder with edit and re-share permission
Personal,Twitter,craig@gmail.com,123456,https://twitter.com,,Social Media#edit#reshare

To load the sample data:
import --format=csv sample_data/import.csv
'''

json_instructions = '''JSON Import Instructions

Example JSON import file can be found in sample_data/import.json.txt.

The JSON file supports creating records, folders and shared folders.

Within shared folders, you can also automatically assign user or team permissions.

To load the sample file into your vault, run this command:
import --format=json sample_data/import.json.txt
'''


class ImporterCommand(Command):
    def execute_args(self, params, args, **kwargs):
        if args.find('--display-csv') >= 0 or args.find('-dc') >= 0:
            print(csv_instructions)
        elif args.find('--display-json') >= 0 or args.find('-dj') >= 0:
            print(json_instructions)
        else:
            Command.execute_args(self, params, args, **kwargs)


class RecordImportCommand(ImporterCommand):
    def get_parser(self):
        return import_parser

    def execute(self, params, **kwargs):
        if params.enforcements and 'booleans' in params.enforcements:
            restricted = next((x['value'] for x in params.enforcements['booleans'] if x['key'] == 'restrict_import'), False)
            if restricted:
                logging.warning('"import" is restricted by Keeper Administrator')
                return
        update_flag = kwargs['update'] if 'update' in kwargs else False
        import_format = kwargs['format'] if 'format' in kwargs else None
        import_name = kwargs['name'] if 'name' in kwargs else None
        shared = kwargs.get('shared') or False
        manage_users = False
        manage_records = False
        can_edit = False
        can_share = False
        if import_format and import_name:
            permissions = kwargs.get('permissions')
            if shared and not permissions:
                permissions = user_choice('Default shared folder permissions: manage (U)sers, manage (R)ecords, can (E)dit, can (S)hare, or (A)ll, (N)one', 'uresan', show_choice=False, multi_choice=True)
            if permissions:
                chars = set()
                chars.update([x for x in permissions.lower()])
                if 'a' in chars:
                    manage_users = True
                    manage_records = True
                    can_edit = True
                    can_share = True
                else:
                    if 'u' in chars:
                        manage_users = True
                    if 'r' in chars:
                        manage_records = True
                    if 'e' in chars:
                        can_edit = True
                    if 's' in chars:
                        can_share = True

            logging.info('Processing... please wait.')
            record_type = ''
            if kwargs.get('login_type'):
                record_type = 'login'
            rt = kwargs.get('record_type')
            if rt:
                if record_type and record_type != rt:
                    logging.warning('Options login-type and record-type are mutually exclusive.')
                    return
                record_type = rt
            if record_type:
                rti = None
                if params.record_type_cache:
                    for rts in params.record_type_cache.values():
                        try:
                            rto = json.loads(rts)
                            if rto.get('$id') == record_type:
                                rti = rto
                                break
                        except:
                            pass
                if rti is None:
                    logging.warning(f'Record type "{record_type}" not found.')
                    return

            imp_exp._import(params, import_format, import_name, shared=shared, import_into=kwargs.get('folder'),
                            manage_users=manage_users, manage_records=manage_records, users_only=kwargs.get('users') or False,
                            can_edit=can_edit, can_share=can_share, update_flag=update_flag, tmpdir=kwargs.get('tmpdir'),
                            old_domain=kwargs.get('old_domain'), new_domain=kwargs.get('new_domain'),
                            record_type=record_type)
        else:
            logging.error('Missing argument')


class RecordExportCommand(ImporterCommand):
    def get_parser(self):
        return export_parser

    def execute(self, params, **kwargs):

        if is_export_restricted(params):
            logging.warning('Permissions Required: `export` command is disabled. '
                            'Please contact your enterprise administrator.')
            return

        export_format = kwargs.pop('format', None)
        export_name = kwargs.pop('name', None)

        if format:
            msize = kwargs.pop('max_size', None)    # type: str
            if msize:
                multiplier = 1
                scale = msize[-1].upper()
                if scale == 'K':
                    multiplier = 1024
                elif scale == 'M':
                    multiplier = 1024 ** 2
                elif scale == 'G':
                    multiplier = 1024 ** 3

                if multiplier != 1:
                    msize = msize[:-1]
                try:
                    max_size = int(msize) * multiplier
                    kwargs['max_size'] = max_size
                except ValueError:
                    logging.error('Invalid maximum attachment file size parameter: %s', kwargs.get('max_size'))
                    return

            imp_exp.export(params, export_format, export_name, **kwargs)
        else:
            logging.error('Missing argument')


def is_export_restricted(params):
    is_export_restricted = False

    booleans = params.enforcements['booleans'] if params.enforcements and 'booleans' in params.enforcements else []

    if len(booleans) > 0:
        restrict_export_boolean = next((s for s in booleans if s['key'] == 'restrict_export'), None)

        if restrict_export_boolean:
            is_export_restricted = restrict_export_boolean['value']

    return is_export_restricted


def set_permission(perm, user, permit, restrict, perm_name):
    p = (user[perm_name] or permit[perm_name]) and not restrict[perm_name]
    setattr(perm, perm_name, p)


class DownloadMembershipCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return download_membership_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        source = kwargs.get('source') or 'keeper'
        file_name = kwargs.get('name') or 'shared_folder_membership.json'
        old_domain = kwargs.get('old_domain')
        new_domain = kwargs.get('new_domain')
        import_into = kwargs.get('folder')
        if import_into:
            import_into = import_into.replace(PathDelimiter, 2 * PathDelimiter)

        permissions = kwargs.get('permissions')
        permit = {'manage_users': False, 'manage_records': False}
        if permissions:
            if 'u' in permissions.lower():
                permit['manage_users'] = True
            if 'r' in permissions.lower():
                permit['manage_records'] = True

        restrictions = kwargs.get('restrictions')
        restrict = {'manage_users': False, 'manage_records': False}
        if restrictions:
            if 'u' in restrictions.lower():
                restrict['manage_users'] = True
            if 'r' in restrictions.lower():
                restrict['manage_records'] = True

        shared_folders = []  # type: List[SharedFolder]

        json_importer = KeeperJsonImporter()

        if os.path.exists(file_name):
            for sf in json_importer.do_import(file_name, users_only=True):
                if isinstance(sf, SharedFolder):
                    shared_folders.append(sf)

        json_shared_folders = set((x.uid for x in shared_folders))

        added_members = []  # type: List[SharedFolder]
        if source == 'keeper':
            if params.shared_folder_cache:
                for shared_folder_uid in params.shared_folder_cache:
                    if shared_folder_uid in json_shared_folders:
                        continue
                    shared_folder = api.get_shared_folder(params, shared_folder_uid)
                    sf = SharedFolder()
                    sf.uid = shared_folder.shared_folder_uid
                    sf.path = imp_exp.get_folder_path(params, shared_folder.shared_folder_uid)
                    sf.manage_users = shared_folder.default_manage_users
                    sf.manage_records = shared_folder.default_manage_records
                    sf.can_edit = shared_folder.default_can_edit
                    sf.can_share = shared_folder.default_can_share
                    sf.permissions = []
                    if shared_folder.teams:
                        for team in shared_folder.teams:
                            perm = Permission()
                            perm.uid = team['team_uid']
                            perm.name = team['name']
                            set_permission(perm, team, permit, restrict, 'manage_users')
                            set_permission(perm, team, permit, restrict, 'manage_records')
                            sf.permissions.append(perm)
                    if shared_folder.users:
                        for user in shared_folder.users:
                            perm = Permission()
                            perm.name = user['username']
                            set_permission(perm, user, permit, restrict, 'manage_users')
                            set_permission(perm, user, permit, restrict, 'manage_records')
                            sf.permissions.append(perm)
                    added_members.append(sf)

        elif source == 'lastpass':
            username = input('...' + 'LastPass Username'.rjust(30) + ': ')
            if not username:
                logging.warning('LastPass username is required')
                return
            password = getpass.getpass(prompt='...' + 'LastPass Password'.rjust(30) + ': ', stream=None)
            if not password:
                logging.warning('LastPass password is required')
                return

            print('Press <Enter> if account is not protected with Multifactor Authentication')
            twofa_code = getpass.getpass(prompt='...' + 'Multifactor Password'.rjust(30) + ': ', stream=None)
            if not twofa_code:
                twofa_code = None

            session = None
            try:
                session = fetcher.login(username, password, twofa_code, None)
                blob = fetcher.fetch(session)
                encryption_key = blob.encryption_key(username, password)
                vault = Vault(blob, encryption_key, session, shared_folder_details=False, get_attachments=False)

                lastpass_shared_folder = [x for x in vault.shared_folders]

                for lpsf in lastpass_shared_folder:
                    if lpsf.id in json_shared_folders:
                        continue

                    logging.info('Loading shared folder membership for "%s"', lpsf.name)

                    members, teams, error = fetcher.fetch_shared_folder_members(session, lpsf.id)
                    sf = SharedFolder()
                    sf.uid = lpsf.id
                    if import_into:
                        sf.path = f'{import_into}{PathDelimiter}{lpsf.name}'
                    else:
                        sf.path = lpsf.name
                    sf.permissions = []
                    if members:
                        sf.permissions.extend((
                            self._lastpass_permission(x, permit, restrict, old_host=old_domain, new_host=new_domain)
                            for x in members
                        ))
                    if teams:
                        sf.permissions.extend((
                            self._lastpass_permission(x, permit, restrict, team=True) for x in teams
                        ))
                    added_members.append(sf)
            except Exception as e:
                logging.warning(e)
            finally:
                if session:
                    fetcher.logout(session)

        if added_members:
            shared_folders.extend(added_members)
            json_exporter = KeeperJsonExporter()
            json_exporter.do_export(file_name, shared_folders)
            logging.info('%d shared folder memberships downloaded.', len(added_members))
        else:
            logging.info('No folder memberships downloaded.')

    @staticmethod
    def _lastpass_permission(lp_permission, permit, restrict, team=False, old_host=None, new_host=None):
        # type: (dict, dict, dict, Optional[bool], Optional[str], Optional[str]) -> Permission
        permission = Permission()
        if team:
            permission.name = lp_permission['name']
        else:
            permission.name = replace_email_domain(lp_permission['username'], old_host, new_host)
        manage_records = lp_permission['readonly'] == '0'
        permission.manage_records = (manage_records or permit['manage_records']) and not restrict['manage_records']
        manage_users = lp_permission['can_administer'] == '1'
        permission.manage_users = (manage_users or permit['manage_users']) and not restrict['manage_users']
        return permission


class ApplyMembershipCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return apply_membership_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        file_name = kwargs.get('name') or 'shared_folder_membership.json'
        if not os.path.exists(file_name):
            logging.warning('Shared folder membership file "%s" not found', file_name)
            return

        file_name = kwargs.get('name') or 'shared_folder_membership.json'

        shared_folders = []  # type: List[SharedFolder]

        if os.path.exists(file_name):
            json_importer = KeeperJsonImporter()
            for sf in json_importer.do_import(file_name, users_only=True):
                if isinstance(sf, SharedFolder):
                    shared_folders.append(sf)

        if len(shared_folders) > 0:
            imp_exp.import_user_permissions(params, shared_folders)
