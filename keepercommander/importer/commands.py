#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


import argparse
import importlib
import json
import logging
import os
from typing import Optional, List, Dict

from . import imp_exp
from .. import api, record_types
from .importer import SharedFolder, Team, Permission, PathDelimiter, replace_email_domain, BaseDownloadMembership, BaseDownloadRecordType, RecordType
from .json.json import KeeperJsonImporter, KeeperJsonExporter
from ..commands.base import raise_parse_exception, suppress_exit, user_choice, Command
from ..commands.enterprise_common import EnterpriseCommand
from ..params import KeeperParams
from ..proto import record_pb2


def register_commands(commands):
    commands['import'] = RecordImportCommand()
    commands['export'] = RecordExportCommand()
    commands['download-membership'] = DownloadMembershipCommand()
    commands['apply-membership'] = ApplyMembershipCommand()


def register_enterprise_commands(commands):
    commands['download-record-types'] = DownloadRecordTypeCommand()
    commands['load-record-types'] = LoadRecordTypeCommand()


def register_command_info(aliases, command_info):
    for p in [import_parser, export_parser, download_membership_parser, apply_membership_parser, download_record_type_parser]:
        command_info[p.prog] = p.description


import_parser = argparse.ArgumentParser(prog='import', description='Import data from a local file into Keeper.')
import_parser.add_argument('--display-csv', '-dc', dest='display_csv', action='store_true',
                           help='display Keeper CSV import instructions')
import_parser.add_argument('--display-json', '-dj', dest='display_json', action='store_true',
                           help='display Keeper JSON import instructions')
import_parser.add_argument(
    '--format', choices=['json', 'csv', 'keepass', 'lastpass', 'myki', 'nordpass', 'manageengine', '1password',
                         'bitwarden', 'thycotic', 'proton'],
    required=True, help='file format')
import_parser.add_argument('--folder', dest='import_into', action='store',
                           help='import into a separate folder.')
import_parser.add_argument('--filter-folder', dest='filter_folder', action='store',
                           help='import data from the specific folder only.')
import_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                           help='display records to be imported without importing them')
import_parser.add_argument('-s', '--shared', dest='shared', action='store_true',
                           help='import folders as Keeper shared folders')
import_parser.add_argument('-p', '--permissions', dest='permissions', action='store',
                           help='default shared folder permissions: manage (U)sers, manage (R)ecords, can (E)dit, can (S)hare, or (A)ll, (N)one')
import_parser.add_argument('--update',  dest='update_flag',  action='store_true',
                           help='update records with common login, url or title')
import_parser.add_argument('--users',  dest='users_only',  action='store_true',
                           help='update shared folder user permissions only')
import_parser.add_argument('--record-type', dest='record_type', action='store',
                           help='Import legacy records as record type')
import_parser.add_argument('--login-type', '-l', dest='login_type', action='store_true',
                           help='import legacy records as login record type')
import_parser.add_argument('--old-domain', '-od', dest='old_domain', action='store',
                           help='old domain for changing user emails in permissions')
import_parser.add_argument('--new-domain', '-nd', dest='new_domain', action='store',
                           help='new domain for changing user emails in permissions')
import_parser.add_argument('--file-cache', dest='tmpdir', action='store',
                           help='temp directory used to cache encrypted attachment imports')
import_parser.add_argument('--show-skipped', dest='show_skipped', action='store_true',
                           help='Display skipped records')
import_parser.add_argument(
    'name', type=str, help='file name (json, csv, keepass, 1password), account name (lastpass), or URL (ManageEngine, Thycotic)'
)
import_parser.error = raise_parse_exception
import_parser.exit = suppress_exit


export_parser = argparse.ArgumentParser(prog='export', description='Export data from Keeper to a local file.')
export_parser.add_argument('--format', dest='format', choices=['json', 'csv', 'keepass'], required=True,
                           help='file format')
export_parser.add_argument('--max-size', dest='max_size',
                           help='Maximum file attachment file. Example: 100K, 50M, 2G. Default: 10M')
export_parser.add_argument('-kp', '--keepass-file-password', dest='file_password', action='store',
                           help='Password for the exported file')
export_parser.add_argument('--zip', dest='zip_archive', action='store_true',
                           help='Create ZIP archive for file attachments. JSON only')
export_parser.add_argument('--save-in-vault', dest='save_in_vault', action='store_true',
                           help='Stores exports file as a record attachment. KeePass only')
export_parser.add_argument('--force', dest='force', action='store_true', help='Suppress user interaction. Assume "yes"')
export_parser.add_argument('--folder', dest='folder', action='store', help='Export data from the specific folder only.')
export_parser.add_argument('name', type=str, nargs='?', help='file name or console output if omitted (except keepass)')
export_parser.error = raise_parse_exception
export_parser.exit = suppress_exit


download_membership_parser = argparse.ArgumentParser(prog='download-membership', description='Unload shared folder membership to JSON file.')
download_membership_parser.add_argument('--source', dest='source', choices=['keeper', 'lastpass', 'thycotic'], required=True, help='Shared folder membership source')
download_membership_parser.add_argument('--folder', dest='folder', action='store', help='import into a separate folder.')
download_membership_parser.add_argument('-p', '--permissions', dest='permissions', action='store', help='force shared folder permissions: manage (U)sers, manage (R)ecords')
download_membership_parser.add_argument('-r', '--restrictions', dest='restrictions', action='store', help='force shared folder restrictions: manage (U)sers, manage (R)ecords')
download_membership_parser.add_argument('--folders-only', dest='folders_only', action='store_true', help='Unload shared folders only. Skip teams')
download_membership_parser.add_argument('--old-domain', '-od', dest='old_domain', action='store',  help='old domain for changing user emails in permissions')
download_membership_parser.add_argument('--new-domain', '-nd', dest='new_domain', action='store',  help='new domain for changing user emails in permissions')
download_membership_parser.add_argument('--sub-folder', '-sf', dest='sub_folder', action='store', choices=['ignore', 'flatten'],
                                        help='shared sub-folder handling')
download_membership_parser.add_argument('name', type=str, nargs='?', help='Output file name. "shared_folder_membership.json" if omitted.')
download_membership_parser.error = raise_parse_exception
download_membership_parser.exit = suppress_exit


apply_membership_parser = argparse.ArgumentParser(prog='apply-membership', description='Loads shared folder membership from JSON file into Keeper.')
apply_membership_parser.add_argument('--full-sync', dest='full_sync', action='store_true', help='Update and remove membership also.')
apply_membership_parser.add_argument('name', type=str, nargs='?', help='Input file name. "shared_folder_membership.json" if omitted.')
apply_membership_parser.error = raise_parse_exception
apply_membership_parser.exit = suppress_exit

download_record_type_parser = argparse.ArgumentParser(
    prog='download-record-types', description='Unload custom record types to JSON file.')
download_record_type_parser.add_argument(
    '--source', dest='source', choices=['keeper', 'thycotic'], required=True, help='Record type source')
download_record_type_parser.add_argument(
    '--ssh-key-as-file', dest='ssh_key_as_file', action="store_true", help='Prefer store SSH keys as file attachments rather than fields on a record')

download_record_type_parser.add_argument(
    'name', type=str, nargs='?', help='Output file name. "record_types.json" if omitted.')


load_record_type_parser = argparse.ArgumentParser(
    prog='load_record_types', description='Loads custom record types from JSON file into Keeper.')
load_record_type_parser.add_argument(
    'name', type=str, nargs='?', help='Input file name. "record_types.json" if omitted.')

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
        import_format = kwargs['format'] if 'format' in kwargs else None
        import_name = kwargs['name'] if 'name' in kwargs else None
        if not import_format:
            logging.error('"--format" parameter is mandatory')
            return
        if not import_name:
            logging.error('"name" parameter is mandatory')
            return

        manage_users = False
        manage_records = False
        can_edit = False
        can_share = False
        permissions = ''
        if 'permissions' in kwargs:
            permissions = kwargs.get('permissions') or ''
            del kwargs['permissions']

        if kwargs.get('shared') is True and not permissions:
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

        if 'login_type' in kwargs:
            if kwargs['login_type'] is True:
                if 'record_type' in kwargs and kwargs['record_type']:
                    logging.warning('Options login-type and record-type are mutually exclusive.')
                    return
                kwargs['record_type'] = 'login'
            del kwargs['login_type']

        record_type = kwargs.get('record_type') or ''
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

        logging.info('Processing... please wait.')
        imp_exp._import(params, import_format, import_name, manage_users=manage_users, manage_records=manage_records,
                        can_edit=can_edit, can_share=can_share, **kwargs)


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
        save_in_file = kwargs.pop('save_in_file', None)

        if export_format:
            msize = kwargs.pop('max_size', None)
            if isinstance(msize, str):
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
        folders_only = kwargs.get('folders_only') is True
        old_domain = kwargs.get('old_domain')
        new_domain = kwargs.get('new_domain')
        import_into = kwargs.get('folder')
        if import_into:
            import_into = import_into.strip()
            import_into = import_into.replace(PathDelimiter, 2 * PathDelimiter)

        override_users = None    # type: Optional[bool]
        override_records = None  # type: Optional[bool]
        permissions = kwargs.get('permissions')
        if permissions:
            permissions = permissions.lower()
            if 'u' in permissions:
                override_users = True
            if 'r' in permissions:
                override_records = True

        restrictions = kwargs.get('restrictions')
        if restrictions:
            restrictions = restrictions.lower()
            if 'u' in restrictions:
                override_users = False
            if 'r' in restrictions:
                override_records = False

        added_folders = []  # type: List[SharedFolder]
        added_teams = []    # type: List[Team]

        try:
            full_name = f'keepercommander.importer.{"json" if source == "keeper" else source}'
            module = importlib.import_module(full_name)
            if hasattr(module, 'MembershipDownload'):
                plugin = module.MembershipDownload()   # type:   Optional[BaseDownloadMembership]
            else:
                logging.warning('Membership plugin is missing: %s', source)
                return
        except:
            logging.warning('Error loading membership plugin: %s', source)
            return

        for obj in plugin.download_membership(params, folders_only=folders_only):
            if isinstance(obj, SharedFolder):
                obj.path = obj.path.strip()
                if import_into:
                    obj.path = f'{import_into}{PathDelimiter}{obj.path}'
                if isinstance(obj.permissions, list):
                    for p in obj.permissions:   # type: Permission
                        if old_domain and new_domain:
                            p.name = replace_email_domain(p.name, old_domain, new_domain)
                        if isinstance(override_users, bool):
                            p.manage_users = override_users
                        if isinstance(override_records, bool):
                            p.manage_records = override_records
                added_folders.append(obj)
            elif isinstance(obj, Team):
                if old_domain and new_domain and obj.members:
                    obj.members = [replace_email_domain(x, old_domain, new_domain) for x in obj.members]
                added_teams.append(obj)

        # process shared sub folders
        for f in added_folders:
            if f.path[0] == PathDelimiter or f.path[-1] == PathDelimiter:
                path = f.path.replace(2 * PathDelimiter, '\0')
                path = path.strip(PathDelimiter)
                f.path = path.replace('\0', PathDelimiter)
        sub_folder_action = kwargs.get('sub_folder') or 'ignore'
        sf = {x.path.lower(): x for x in added_folders if x.path}
        paths = list(sf.keys())
        paths.sort()
        pos = 0
        while pos < len(paths):
            next_pos = 1
            p1 = paths[pos]
            while pos + next_pos < len(paths):
                p2 = paths[pos + next_pos]
                if p2.startswith(p1 + PathDelimiter):
                    if sub_folder_action == 'flatten':
                        folder = sf[p2]
                        folder.path = folder.path[:len(p1)] + folder.path[len(p1):].replace(PathDelimiter, ' - ', )
                    else:
                        del sf[p2]
                    next_pos += 1
                else:
                    break
            pos += next_pos

        added_folders = list(sf.values())

        shared_folders = {}  # type: Dict[str, SharedFolder]
        teams = {}           # type: Dict[str, Team]

        json_importer = KeeperJsonImporter()
        if os.path.exists(file_name):
            try:
                for obj in json_importer.do_import(file_name, users_only=True):
                    if isinstance(obj, SharedFolder):
                        if obj.uid:
                            shared_folders[obj.uid] = obj
                    elif isinstance(obj, Team):
                        if obj.uid:
                            teams[obj.uid] = obj
            except:
                pass

        if added_folders or added_teams:
            for sf in added_folders:
                if sf.uid and sf.uid in shared_folders:
                    del shared_folders[sf.uid]
            for t in added_teams:
                if t.uid and t.uid in teams:
                    del teams[t.uid]

            memberships = []
            memberships.extend(shared_folders.values())
            memberships.extend(teams.values())
            memberships.extend(added_folders)
            memberships.extend(added_teams)
            json_exporter = KeeperJsonExporter()
            json_exporter.do_export(file_name, memberships)
            if len(added_folders) > 0:
                logging.info('%d shared folder memberships added.', len(added_folders))
            if len(added_teams) > 0:
                logging.info('%d team memberships added.', len(added_teams))
        else:
            logging.info('No folder memberships downloaded.')


class ApplyMembershipCommand(Command):
    def get_parser(self):
        return apply_membership_parser

    def execute(self, params, **kwargs):
        file_name = kwargs.get('name') or 'shared_folder_membership.json'
        if not os.path.exists(file_name):
            logging.warning('Shared folder membership file "%s" not found', file_name)
            return

        shared_folders = []  # type: List[SharedFolder]
        teams = []     # type: List[Team]

        json_importer = KeeperJsonImporter()
        for obj in json_importer.do_import(file_name, users_only=True):
            if isinstance(obj, SharedFolder):
                shared_folders.append(obj)
            if isinstance(obj, Team):
                teams.append(obj)

        full_sync = kwargs.get('full_sync') is True
        if len(shared_folders) > 0:
            imp_exp.import_user_permissions(params, shared_folders, full_sync)

        if len(teams) > 0:
            imp_exp.import_teams(params, teams, full_sync)


class DownloadRecordTypeCommand(EnterpriseCommand):
    def get_parser(self):
        return download_record_type_parser

    def execute(self, params, **kwargs):
        source = kwargs.get('source') or 'keeper'
        file_name = kwargs.get('name') or 'record_types.json'
        try:
            full_name = f'keepercommander.importer.{"json" if source == "keeper" else source}'
            module = importlib.import_module(full_name)
            if hasattr(module, 'RecordTypeDownload'):
                plugin = module.RecordTypeDownload()   # type:   Optional[BaseDownloadRecordType]
            else:
                logging.warning('Record Template plugin is missing: %s', source)
                return
        except:
            logging.warning('Error loading record template plugin: %s', source)
            return

        record_types = []
        ssh_key_as_file = kwargs.get('ssh_key_as_file')
        for rt in plugin.download_record_type(params):
            if not isinstance(rt, RecordType):
                continue
            need_file_ref = False
            rto = {
                'record_type_name': rt.name,
                'fields': []
            }
            if rt.description:
                rto['description'] = rt.description

            for f in rt.fields:
                if ssh_key_as_file is True and f.type == 'keyPair':
                    need_file_ref = True
                    continue
                fo = {'$type': f.type}
                if f.label:
                    fo['label'] = f.label
                if f.required is True:
                    fo['required'] = True
                rto['fields'].append(fo)

            if need_file_ref:
                has_ref = next((True for x in rto['fields'] if x['$type'] == 'fileRef'), False)
                if not has_ref:
                    rto['fields'].append({'$type': 'fileRef'})
            record_types.append(rto)

        if len(record_types) > 0:
            o = {
                'record_types': record_types
            }
            with open(file_name, 'wt') as f:
                json.dump(o, f, indent=2)
            logging.info('Downloaded %d record types to "%s"', len(record_types), os.path.abspath(file_name))
        else:
            logging.info('No record types are downloaded')


class LoadRecordTypeCommand(EnterpriseCommand):
    def get_parser(self):
        return load_record_type_parser

    def execute(self, params, **kwargs):
        file_name = kwargs.get('name') or 'record_types.json'
        if not os.path.exists(file_name):
            logging.warning('Custom record types file "%s" not found', file_name)
            return

        with open(file_name, 'rt') as f:
            j_obj = json.load(f)

        if not isinstance(j_obj, dict):
            logging.warning('Invalid custom record types file "%s"', file_name)
            return
        r_types = j_obj.get('record_types')
        if not isinstance(r_types, list):
            logging.warning('Invalid custom record types file "%s"', file_name)
            return

        loaded_record_types = set()
        if params.record_type_cache:
            for rts in params.record_type_cache.values():
                try:
                    rto = json.loads(rts)
                    if '$id' in rto:
                        loaded_record_types.add(rto['$id'].lower())
                except:
                    pass

        counter = 0
        for r_type in r_types:
            record_type_name = r_type.get('record_type_name')
            if not record_type_name:
                continue
            record_type_name = record_type_name[:30]
            if record_type_name.lower() in loaded_record_types:
                logging.warning('Custom record type "%s" already exists. Skipping.', record_type_name)
                continue
            fields = r_type.get('fields')
            if not isinstance(fields, list):
                continue

            is_valid = True
            for field in fields:
                field_type = field.get('$type')
                if field_type not in record_types.RecordFields:
                    logging.warning('Custom record type "%s": Invalid field \"%s\". Skipping.', record_type_name, field_type)
                    is_valid = False
                    break
            if not is_valid:
                continue

            content = {
                '$id': record_type_name,
                'description': r_type.get('description') or '',
                'fields': []
            }

            for field in fields:
                fo = {'$ref': field.get('$type')}
                field_label = field.get('label')
                if field_label:
                    fo['label'] = field_label
                if field.get('required') is True:
                    fo['required'] = True
                content['fields'].append(fo)

            rq = record_pb2.RecordType()
            rq.content = json.dumps(content)
            rq.scope = record_pb2.RT_ENTERPRISE
            rs = api.communicate_rest(params, rq, 'vault/record_type_add')

            counter += 1

        if counter > 0:
            logging.info('Added %d custom record types', counter)
            api.sync_down(params, record_types=True)
