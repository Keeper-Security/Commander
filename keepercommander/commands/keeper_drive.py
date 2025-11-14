#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
KeeperDrive CLI Commands

Commands for managing KeeperDrive folders and records using the v3 API.
"""

import argparse
import logging
import json
from typing import Optional

from .base import Command
from .. import keeper_drive, keeper_drive_records, api, utils
from ..error import CommandError


logger = logging.getLogger(__name__)


def raise_parse_exception(self, status=0, message=None):
    """Override parser error to raise exception instead of sys.exit"""
    from .base import ParseError
    raise ParseError(message)


def suppress_exit(self, status=0, message=None):
    """Suppress parser exit"""
    pass


# Parser for 'keeper-drive-mkdir' command
keeper_drive_mkdir_parser = argparse.ArgumentParser(
    prog='keeper-drive-mkdir',
    description='Create a new KeeperDrive folder using v3 API',
    allow_abbrev=False  # Disable prefix matching for flags
)
keeper_drive_mkdir_parser.add_argument(
    'folder',
    type=str,
    help='Folder name to create'
)
keeper_drive_mkdir_parser.add_argument(
    '--parent',
    dest='parent_uid',
    type=str,
    help='Parent folder UID (omit for root folder)'
)
keeper_drive_mkdir_parser.add_argument(
    '--color',
    type=str,
    choices=['none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray'],
    help='Folder color'
)
keeper_drive_mkdir_parser.add_argument(
    '--no-inherit',
    dest='no_inherit_permissions',
    action='store_true',
    help='Do not inherit parent folder permissions'
)
keeper_drive_mkdir_parser.error = raise_parse_exception
keeper_drive_mkdir_parser.exit = suppress_exit


# Parser for 'keeper-drive-mkdir-batch' command
keeper_drive_mkdir_batch_parser = argparse.ArgumentParser(
    prog='keeper-drive-mkdir-batch',
    description='Create multiple KeeperDrive folders in one API call',
    allow_abbrev=False  # Disable prefix matching for flags
)
keeper_drive_mkdir_batch_parser.add_argument(
    '--spec',
    dest='folder_specs',
    action='append',
    type=str,
    required=True,
    help='Folder specification in format: name[,parent=UID][,color=COLOR][,no-inherit]'
)
keeper_drive_mkdir_batch_parser.error = raise_parse_exception
keeper_drive_mkdir_batch_parser.exit = suppress_exit


# Parser for 'keeper-drive-add-record' command
keeper_drive_add_record_parser = argparse.ArgumentParser(
    prog='keeper-drive-add-record',
    description='Create a new KeeperDrive record using v3 API',
    allow_abbrev=False  # Disable prefix matching for flags
)
keeper_drive_add_record_parser.add_argument(
    '--syntax-help',
    dest='syntax_help',
    action='store_true',
    help='Display help on field parameters'
)
keeper_drive_add_record_parser.add_argument(
    '-f', '--force',
    dest='force',
    action='store_true',
    help='Ignore warnings'
)
keeper_drive_add_record_parser.add_argument(
    '-t', '--title',
    dest='title',
    type=str,
    required=True,
    help='Record title'
)
keeper_drive_add_record_parser.add_argument(
    '-rt', '--record-type',
    dest='record_type',
    type=str,
    default='login',
    help='Record type (default: login)'
)
keeper_drive_add_record_parser.add_argument(
    '-n', '--notes',
    dest='notes',
    type=str,
    help='Record notes'
)
keeper_drive_add_record_parser.add_argument(
    '--folder',
    dest='folder_uid',
    type=str,
    help='Folder UID, name, or path (omit for vault root)'
)
keeper_drive_add_record_parser.add_argument(
    'fields',
    nargs='*',
    type=str,
    help='Field specifications using dot notation (e.g., login=user@example.com password=secret123)'
)
keeper_drive_add_record_parser.error = raise_parse_exception
keeper_drive_add_record_parser.exit = suppress_exit


# Parser for 'keeper-drive-add-records-batch' command
keeper_drive_add_records_batch_parser = argparse.ArgumentParser(
    prog='keeper-drive-add-records-batch',
    description='Create multiple KeeperDrive records in one API call',
    allow_abbrev=False
)
keeper_drive_add_records_batch_parser.add_argument(
    '--spec',
    dest='record_specs',
    action='append',
    type=str,
    required=True,
    help='Record specification in JSON format'
)
keeper_drive_add_records_batch_parser.error = raise_parse_exception
keeper_drive_add_records_batch_parser.exit = suppress_exit


# Parser for 'keeper-drive-update-folder' command
keeper_drive_update_folder_parser = argparse.ArgumentParser(
    prog='keeper-drive-update-folder',
    description='Update a KeeperDrive folder using v3 API',
    allow_abbrev=False
)
keeper_drive_update_folder_parser.add_argument(
    'folder_uid',
    type=str,
    help='Folder UID, name, or path to update'
)
keeper_drive_update_folder_parser.add_argument(
    '--name',
    dest='folder_name',
    type=str,
    help='New folder name'
)
keeper_drive_update_folder_parser.add_argument(
    '--color',
    type=str,
    choices=['none', 'red', 'orange', 'yellow', 'green', 'blue', 'purple', 'pink', 'gray'],
    help='New folder color'
)
keeper_drive_update_folder_parser.add_argument(
    '--inherit',
    dest='inherit_permissions',
    action='store_true',
    help='Set folder to inherit parent permissions'
)
keeper_drive_update_folder_parser.add_argument(
    '--no-inherit',
    dest='no_inherit_permissions',
    action='store_true',
    help='Set folder to not inherit parent permissions'
)
keeper_drive_update_folder_parser.error = raise_parse_exception
keeper_drive_update_folder_parser.exit = suppress_exit


# Parser for 'keeper-drive-update-folders-batch' command
keeper_drive_update_folders_batch_parser = argparse.ArgumentParser(
    prog='keeper-drive-update-folders-batch',
    description='Update multiple KeeperDrive folders in one API call',
    allow_abbrev=False
)
keeper_drive_update_folders_batch_parser.add_argument(
    '--update',
    dest='folder_updates',
    action='append',
    type=str,
    required=True,
    help='Folder update specification in JSON format: {"folder_uid": "xxx", "name": "...", "color": "..."}'
)
keeper_drive_update_folders_batch_parser.error = raise_parse_exception
keeper_drive_update_folders_batch_parser.exit = suppress_exit


# Parser for 'keeper-drive-list' command  
keeper_drive_list_parser = argparse.ArgumentParser(
    prog='keeper-drive-list',
    description='List Keeper Drive folders and records',
    allow_abbrev=False
)
keeper_drive_list_parser.add_argument(
    '--folders',
    action='store_true',
    help='Show only folders'
)
keeper_drive_list_parser.add_argument(
    '--records',
    action='store_true',
    help='Show only records'
)
keeper_drive_list_parser.add_argument(
    '--verbose',
    '-v',
    action='store_true',
    help='Show detailed information'
)
keeper_drive_list_parser.add_argument(
    '--permissions',
    '-p',
    action='store_true',
    help='Show permissions and access information for records and folders'
)
keeper_drive_list_parser.error = raise_parse_exception
keeper_drive_list_parser.exit = suppress_exit


# Parser for 'keeper-drive-grant-access' command
keeper_drive_grant_access_parser = argparse.ArgumentParser(
    prog='keeper-drive-grant-access',
    description='Grant user access to a Keeper Drive folder',
    allow_abbrev=False
)
keeper_drive_grant_access_parser.add_argument(
    '--folder',
    type=str,
    required=True,
    help='Folder UID, name, or path'
)
keeper_drive_grant_access_parser.add_argument(
    '--user',
    type=str,
    required=True,
    help='User email address or UID to grant access to'
)
keeper_drive_grant_access_parser.add_argument(
    '--role',
    type=str,
    default='viewer',
    choices=['viewer', 'contributor', 'content_manager', 'manager'],
    help='Access role (default: viewer)'
)
keeper_drive_grant_access_parser.add_argument(
    '--expire',
    type=str,
    help='Expiration time: Unix timestamp in seconds or relative time (e.g., "30d" for 30 days, "24h" for 24 hours, "30mi" for 30 minutes)'
)
keeper_drive_grant_access_parser.error = raise_parse_exception
keeper_drive_grant_access_parser.exit = suppress_exit


# Parser for 'keeper-drive-update-access' command
keeper_drive_update_access_parser = argparse.ArgumentParser(
    prog='keeper-drive-update-access',
    description='Update user access to a Keeper Drive folder',
    allow_abbrev=False
)
keeper_drive_update_access_parser.add_argument(
    '--folder',
    type=str,
    required=True,
    help='Folder UID, name, or path'
)
keeper_drive_update_access_parser.add_argument(
    '--user',
    type=str,
    required=True,
    help='User email address or UID whose access to update'
)
keeper_drive_update_access_parser.add_argument(
    '--role',
    type=str,
    choices=['viewer', 'contributor', 'content_manager', 'manager'],
    help='New access role'
)
keeper_drive_update_access_parser.add_argument(
    '--hidden',
    type=bool,
    help='Hide the folder access (true/false)'
)
keeper_drive_update_access_parser.error = raise_parse_exception
keeper_drive_update_access_parser.exit = suppress_exit


# Parser for 'keeper-drive-revoke-access' command
keeper_drive_revoke_access_parser = argparse.ArgumentParser(
    prog='keeper-drive-revoke-access',
    description='Revoke user access from a Keeper Drive folder',
    allow_abbrev=False
)
keeper_drive_revoke_access_parser.add_argument(
    '--folder',
    type=str,
    required=True,
    help='Folder UID, name, or path'
)
keeper_drive_revoke_access_parser.add_argument(
    '--user',
    type=str,
    required=True,
    help='User email address or UID whose access to revoke'
)
keeper_drive_revoke_access_parser.error = raise_parse_exception
keeper_drive_revoke_access_parser.exit = suppress_exit


# Parser for 'keeper-drive-manage-access-batch' command
keeper_drive_manage_access_batch_parser = argparse.ArgumentParser(
    prog='keeper-drive-manage-access-batch',
    description='Batch manage folder access (grant, update, revoke)',
    allow_abbrev=False
)
keeper_drive_manage_access_batch_parser.add_argument(
    '--grants',
    type=str,
    help='JSON array of grant operations: [{"folder_uid":"xxx","user_uid":"yyy","role":"viewer"}]'
)
keeper_drive_manage_access_batch_parser.add_argument(
    '--updates',
    type=str,
    help='JSON array of update operations: [{"folder_uid":"xxx","user_uid":"yyy","role":"manager"}]'
)
keeper_drive_manage_access_batch_parser.add_argument(
    '--revokes',
    type=str,
    help='JSON array of revoke operations: [{"folder_uid":"xxx","user_uid":"yyy"}]'
)
keeper_drive_manage_access_batch_parser.error = raise_parse_exception
keeper_drive_manage_access_batch_parser.exit = suppress_exit


# Parser for 'keeper-drive-add-record-to-folder' command
keeper_drive_add_record_to_folder_parser = argparse.ArgumentParser(
    prog='keeper-drive-add-record-to-folder',
    description='Add an existing record to a Keeper Drive folder',
    allow_abbrev=False
)
keeper_drive_add_record_to_folder_parser.add_argument(
    '--folder',
    type=str,
    required=True,
    help='Folder UID, name, or path'
)
keeper_drive_add_record_to_folder_parser.add_argument(
    '--record',
    type=str,
    required=True,
    help='Record UID to add to the folder'
)
keeper_drive_add_record_to_folder_parser.error = raise_parse_exception
keeper_drive_add_record_to_folder_parser.exit = suppress_exit


# Parser for 'keeper-drive-remove-record-from-folder' command
keeper_drive_remove_record_from_folder_parser = argparse.ArgumentParser(
    prog='keeper-drive-remove-record-from-folder',
    description='Remove a record from a Keeper Drive folder',
    allow_abbrev=False
)
keeper_drive_remove_record_from_folder_parser.add_argument(
    '--folder',
    type=str,
    required=True,
    help='Folder UID, name, or path'
)
keeper_drive_remove_record_from_folder_parser.add_argument(
    '--record',
    type=str,
    required=True,
    help='Record UID to remove from the folder'
)
keeper_drive_remove_record_from_folder_parser.error = raise_parse_exception
keeper_drive_remove_record_from_folder_parser.exit = suppress_exit


# Parser for 'keeper-drive-move-record' command
keeper_drive_move_record_parser = argparse.ArgumentParser(
    prog='keeper-drive-move-record',
    description='Move a record between folders or to/from root',
    allow_abbrev=False
)
keeper_drive_move_record_parser.add_argument(
    'record',
    type=str,
    help='Record UID to move'
)
keeper_drive_move_record_parser.add_argument(
    '--from',
    dest='from_folder',
    type=str,
    help='Source folder UID, name, or path (omit for root)'
)
keeper_drive_move_record_parser.add_argument(
    '--to',
    dest='to_folder',
    type=str,
    help='Destination folder UID, name, or path (omit for root)'
)
keeper_drive_move_record_parser.error = raise_parse_exception
keeper_drive_move_record_parser.exit = suppress_exit


# Parser for 'keeper-drive-manage-folder-records-batch' command
keeper_drive_manage_folder_records_batch_parser = argparse.ArgumentParser(
    prog='keeper-drive-manage-folder-records-batch',
    description='Batch add or remove records from a folder',
    allow_abbrev=False
)
keeper_drive_manage_folder_records_batch_parser.add_argument(
    '--folder',
    type=str,
    required=True,
    help='Folder UID, name, or path'
)
keeper_drive_manage_folder_records_batch_parser.add_argument(
    '--add',
    type=str,
    help='JSON array of record UIDs to add: ["rec1_uid", "rec2_uid"]'
)
keeper_drive_manage_folder_records_batch_parser.add_argument(
    '--remove',
    type=str,
    help='JSON array of record UIDs to remove: ["rec3_uid", "rec4_uid"]'
)
keeper_drive_manage_folder_records_batch_parser.error = raise_parse_exception
keeper_drive_manage_folder_records_batch_parser.exit = suppress_exit


class KeeperDriveMkdirCommand(Command):
    """Command to create a KeeperDrive folder using v3 API"""
    
    def get_parser(self):
        return keeper_drive_mkdir_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-mkdir command.
        
        Creates a new folder in KeeperDrive using the v3 API endpoint.
        """
        folder_name = kwargs.get('folder')
        if not folder_name:
            raise CommandError('keeper-drive-mkdir', 'Folder name is required')
        
        parent_uid = kwargs.get('parent_uid')
        color = kwargs.get('color')
        inherit_permissions = not kwargs.get('no_inherit_permissions', False)
        
        try:
            result = keeper_drive.create_folder_v3(
                params=params,
                folder_name=folder_name,
                parent_uid=parent_uid,
                color=color,
                inherit_permissions=inherit_permissions
            )
            
            if result['success']:
                location = f"under parent {parent_uid}" if parent_uid else "at root"
                logging.info(f"✓ Folder '{folder_name}' created successfully {location}")
                logging.info(f"  Folder UID: {result['folder_uid']}")
                
                # Mark for sync
                params.sync_data = True
                
                return result['folder_uid']
            else:
                logging.error(f"✗ Failed to create folder: {result['message']}")
                raise CommandError('keeper-drive-mkdir', result['message'])
        
        except Exception as e:
            logging.error(f"Error creating folder: {str(e)}")
            raise


class KeeperDriveMkdirBatchCommand(Command):
    """Command to create multiple KeeperDrive folders in batch"""
    
    def get_parser(self):
        return keeper_drive_mkdir_batch_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-mkdir-batch command.
        
        Creates multiple folders in a single API call.
        """
        spec_strings = kwargs.get('folder_specs', [])
        if not spec_strings:
            raise CommandError('keeper-drive-mkdir-batch', 'At least one folder specification is required')
        
        # Parse folder specifications
        folder_specs = []
        for spec_str in spec_strings:
            spec = self._parse_folder_spec(spec_str)
            folder_specs.append(spec)
        
        try:
            results = keeper_drive.create_folders_batch_v3(
                params=params,
                folder_specs=folder_specs
            )
            
            # Display results
            success_count = 0
            failure_count = 0
            
            for result in results:
                if result['success']:
                    success_count += 1
                    logging.info(f"✓ {result['name']}: {result['folder_uid']}")
                else:
                    failure_count += 1
                    logging.error(f"✗ {result['name']}: {result['message']}")
            
            logging.info(f"\nCreated {success_count} folder(s) successfully, {failure_count} failed")
            
            if success_count > 0:
                params.sync_data = True
            
            return results
        
        except Exception as e:
            logging.error(f"Error creating folders: {str(e)}")
            raise
    
    @staticmethod
    def _parse_folder_spec(spec_str: str) -> dict:
        """
        Parse a folder specification string.
        
        Format: name[,parent=UID][,color=COLOR][,no-inherit]
        Example: "My Folder,parent=abc123,color=blue,no-inherit"
        """
        parts = [p.strip() for p in spec_str.split(',')]
        
        if not parts:
            raise CommandError('keeper-drive-mkdir-batch', 'Empty folder specification')
        
        spec = {
            'name': parts[0],
            'inherit_permissions': True
        }
        
        # Parse optional parameters
        for part in parts[1:]:
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'parent':
                    spec['parent_uid'] = value
                elif key == 'color':
                    spec['color'] = value
                else:
                    logging.warning(f"Unknown parameter '{key}' in folder spec")
            elif part.lower() == 'no-inherit':
                spec['inherit_permissions'] = False
            else:
                logging.warning(f"Unknown flag '{part}' in folder spec")
        
        return spec


class KeeperDriveAddRecordCommand(Command):
    """Command to create a KeeperDrive record using v3 API"""
    
    # Field descriptions for --syntax-help
    FIELD_SYNTAX_HELP = '''
KeeperDrive Record Add - Field Syntax

The keeper-drive-add-record command accepts field specifications using dot notation:
[<FIELD_TYPE>][<FIELD_LABEL>]=<FIELD_VALUE>

Examples:
  keeper-drive-add-record -t "My Login" -rt login login=user@example.com password=secret123
  keeper-drive-add-record -t "Web Account" -rt login login=admin url=https://example.com password=pass123
  keeper-drive-add-record -t "Server" -rt login --folder MyFolder login=root password=secure123 url=ssh://server.com

Common field types for 'login' records:
  - login        : Login/username
  - password     : Password
  - url          : URL
  - oneTimeCode  : TOTP secret

Field value with spaces:
  keeper-drive-add-record -t "Title" -rt login "login=user name" "password=pass word"

Multiple URLs or custom fields:
  keeper-drive-add-record -t "Title" -rt login login=user password=pass url=https://site1.com url.backup=https://site2.com

For detailed record type information, use: record-type-info (rti)
'''
    
    def get_parser(self):
        return keeper_drive_add_record_parser
    
    @staticmethod
    def parse_field(field):
        """Parse a field specification: field_type[.field_label]=value"""
        if not isinstance(field, str):
            raise ValueError('Incorrect field value')
        
        name, sep, value = field.partition('=')
        if not sep:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing `=`')
        if not name:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing <field>')
        
        # Handle escaped equals signs
        while value.startswith('='):
            name1, sel, value1 = value[1:].partition('=')
            if sel:
                name += sel + name1
                value = value1
            else:
                break
        
        if not name:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing field type or label')
        
        field_type, sep, field_label = name.partition('.')
        if not field_type:
            raise ValueError(f'Missing field type in: {field}')
        
        return {
            'type': field_type,
            'label': field_label if sep else '',
            'value': value.strip()
        }
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-add-record command.
        
        Creates a new record in KeeperDrive using the v3 API endpoint.
        """
        # Show syntax help if requested
        if kwargs.get('syntax_help'):
            print(self.FIELD_SYNTAX_HELP)
            return
        
        title = kwargs.get('title')
        if not title:
            raise CommandError('keeper-drive-add-record', 'Record title is required (use -t or --title)')
        
        record_type = kwargs.get('record_type', 'login')
        folder_uid = kwargs.get('folder_uid')
        notes = kwargs.get('notes')
        
        # Parse field specifications
        field_specs = kwargs.get('fields', [])
        field_specs = [f.strip() for f in field_specs if f.strip()]
        
        # Build fields dictionary from field specifications
        fields = {}
        for field_spec in field_specs:
            try:
                parsed = self.parse_field(field_spec)
                field_type = parsed['type']
                field_value = parsed['value']
                
                # For now, we use simple field_type as key
                # In future, could support labeled fields with field_type.label syntax
                if field_type in fields:
                    # If field already exists, convert to list or append to list
                    if not isinstance(fields[field_type], list):
                        fields[field_type] = [fields[field_type]]
                    fields[field_type].append(field_value)
                else:
                    fields[field_type] = field_value
                    
            except ValueError as e:
                raise CommandError('keeper-drive-add-record', f'Invalid field specification: {str(e)}')
        
        try:
            result = keeper_drive_records.create_record_v3(
                params=params,
                record_type=record_type,
                title=title,
                fields=fields,
                folder_uid=folder_uid,
                notes=notes
            )
            
            if result['success']:
                location = f"in folder {folder_uid}" if folder_uid else "at vault root"
                logging.info(f"✓ Record '{title}' created successfully {location}")
                logging.info(f"  Record UID: {result['record_uid']}")
                logging.info(f"  Revision: {result['revision']}")
                
                # Mark for sync
                params.sync_data = True
                
                return result['record_uid']
            else:
                logging.error(f"✗ Failed to create record: {result['message']}")
                raise CommandError('keeper-drive-add-record', result['message'])
        
        except Exception as e:
            logging.error(f"Error creating record: {str(e)}")
            raise


# Parser for 'keeper-drive-update-record' command
keeper_drive_update_record_parser = argparse.ArgumentParser(
    prog='keeper-drive-update-record',
    description='Update an existing KeeperDrive record using v3 API',
    allow_abbrev=False
)
keeper_drive_update_record_parser.add_argument(
    'record_uid',
    type=str,
    help='Record UID to update'
)
keeper_drive_update_record_parser.add_argument(
    '--title',
    dest='title',
    type=str,
    help='New title for the record'
)
keeper_drive_update_record_parser.add_argument(
    '--type',
    dest='record_type',
    type=str,
    help='New record type (e.g., login, passport)'
)
keeper_drive_update_record_parser.add_argument(
    '--login',
    dest='login',
    type=str,
    help='New login/username'
)
keeper_drive_update_record_parser.add_argument(
    '--password',
    dest='password',
    type=str,
    help='New password'
)
keeper_drive_update_record_parser.add_argument(
    '--url',
    dest='url',
    type=str,
    help='New URL'
)
keeper_drive_update_record_parser.add_argument(
    '--notes',
    dest='notes',
    type=str,
    help='New notes'
)
keeper_drive_update_record_parser.error = raise_parse_exception
keeper_drive_update_record_parser.exit = suppress_exit


class KeeperDriveUpdateRecordCommand(Command):
    """Command to update a KeeperDrive record"""
    
    def get_parser(self):
        return keeper_drive_update_record_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-update-record command.
        
        Updates an existing record with new values.
        """
        record_uid = kwargs.get('record_uid')
        title = kwargs.get('title')
        record_type = kwargs.get('record_type')
        
        if not record_uid:
            raise CommandError('keeper-drive-update-record', 'Record UID is required')
        
        # Build fields dictionary from provided options
        fields = {}
        if kwargs.get('login'):
            fields['login'] = kwargs.get('login')
        if kwargs.get('password'):
            fields['password'] = kwargs.get('password')
        if kwargs.get('url'):
            fields['url'] = kwargs.get('url')
        
        # Notes is a top-level property, not a field
        notes = kwargs.get('notes')
        
        try:
            result = keeper_drive_records.update_record_v3(
                params=params,
                record_uid=record_uid,
                title=title,
                record_type=record_type,
                fields=fields if fields else None,
                notes=notes,
            )
            
            if result['success']:
                logging.info(f"✓ Record '{record_uid}' updated successfully")
                logging.info(f"  Status: {result['status']}")
                logging.info(f"  Revision: {result['revision']}")
                
                # Mark for sync
                params.sync_data = True
                
                return record_uid
            else:
                logging.error(f"✗ Failed to update record: {result['message']}")
                raise CommandError('keeper-drive-update-record', result['message'])
        
        except ValueError as e:
            logging.error(f"Error: {str(e)}")
            raise CommandError('keeper-drive-update-record', str(e))
        except Exception as e:
            logging.error(f"Error updating record: {str(e)}")
            raise


class KeeperDriveAddRecordsBatchCommand(Command):
    """Command to create multiple KeeperDrive records in batch"""
    
    def get_parser(self):
        return keeper_drive_add_records_batch_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-add-records-batch command.
        
        Creates multiple records in a single API call.
        """
        spec_strings = kwargs.get('record_specs', [])
        if not spec_strings:
            raise CommandError('keeper-drive-add-records-batch', 'At least one record specification is required')
        
        # Parse record specifications
        record_specs = []
        for spec_str in spec_strings:
            try:
                spec = json.loads(spec_str)
                record_specs.append(spec)
            except json.JSONDecodeError as e:
                raise CommandError('keeper-drive-add-records-batch', f'Invalid JSON specification: {e}')
        
        try:
            results = keeper_drive_records.create_records_batch_v3(
                params=params,
                record_specs=record_specs
            )
            
            # Display results
            success_count = 0
            failure_count = 0
            
            for result in results:
                if result['success']:
                    success_count += 1
                    logging.info(f"✓ {result['title']}: {result['record_uid']}")
                else:
                    failure_count += 1
                    logging.error(f"✗ {result['title']}: {result['message']}")
            
            logging.info(f"\nCreated {success_count} record(s) successfully, {failure_count} failed")
            
            if success_count > 0:
                params.sync_data = True
            
            return results
        
        except Exception as e:
            logging.error(f"Error creating records: {str(e)}")
            raise


class KeeperDriveUpdateFolderCommand(Command):
    """Command to update a KeeperDrive folder using v3 API"""
    
    def get_parser(self):
        return keeper_drive_update_folder_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-update-folder command.
        
        Updates an existing folder in KeeperDrive using the v3 API endpoint.
        """
        folder_uid = kwargs.get('folder_uid')
        if not folder_uid:
            raise CommandError('keeper-drive-update-folder', 'Folder UID, name, or path is required')
        
        folder_name = kwargs.get('folder_name')
        color = kwargs.get('color')
        
        # Handle inherit permissions flags
        inherit_permissions = None
        if kwargs.get('inherit_permissions'):
            inherit_permissions = True
        elif kwargs.get('no_inherit_permissions'):
            inherit_permissions = False
        
        # Verify at least one field to update
        if folder_name is None and color is None and inherit_permissions is None:
            raise CommandError('keeper-drive-update-folder', 
                             'At least one update field (--name, --color, --inherit, or --no-inherit) must be provided')
        
        try:
            result = keeper_drive.update_folder_v3(
                params=params,
                folder_uid=folder_uid,
                folder_name=folder_name,
                color=color,
                inherit_permissions=inherit_permissions
            )
            
            if result['success']:
                logging.info(f"✓ Folder updated successfully")
                logging.info(f"  Folder UID: {result['folder_uid']}")
                if folder_name:
                    logging.info(f"  New name: {folder_name}")
                if color:
                    logging.info(f"  New color: {color}")
                if inherit_permissions is not None:
                    logging.info(f"  Inherit permissions: {inherit_permissions}")
                
                # Mark for sync
                params.sync_data = True
                
                return result['folder_uid']
            else:
                logging.error(f"✗ Failed to update folder: {result['message']}")
                raise CommandError('keeper-drive-update-folder', result['message'])
        
        except ValueError as e:
            error_msg = str(e)
            logging.error(f"✗ {error_msg}")
            
            # Provide helpful suggestions
            if "not found" in error_msg.lower():
                logging.info("\nTip: To find your folder UID:")
                logging.info("  1. Run 'ls' to see folders in the current directory")
                logging.info("  2. Run 'tree' to see the full folder hierarchy")
                logging.info("  3. Run 'sync-down' to refresh your local cache")
                logging.info("  4. Use the folder's full path instead of just the name")
            elif "key not found" in error_msg.lower():
                logging.info("\nTip: Try running 'sync-down' to refresh your local cache")
            
            raise CommandError('keeper-drive-update-folder', error_msg)
        
        except Exception as e:
            logging.error(f"Error updating folder: {str(e)}")
            raise


class KeeperDriveUpdateFoldersBatchCommand(Command):
    """Command to update multiple KeeperDrive folders in batch"""
    
    def get_parser(self):
        return keeper_drive_update_folders_batch_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-update-folders-batch command.
        
        Updates multiple folders in a single API call.
        """
        update_strings = kwargs.get('folder_updates', [])
        if not update_strings:
            raise CommandError('keeper-drive-update-folders-batch', 'At least one folder update specification is required')
        
        # Parse folder update specifications
        folder_updates = []
        for update_str in update_strings:
            try:
                update = json.loads(update_str)
                folder_updates.append(update)
            except json.JSONDecodeError as e:
                raise CommandError('keeper-drive-update-folders-batch', f'Invalid JSON specification: {e}')
        
        try:
            results = keeper_drive.update_folders_batch_v3(
                params=params,
                folder_updates=folder_updates
            )
            
            # Display results
            success_count = 0
            failure_count = 0
            
            for result in results:
                if result['success']:
                    success_count += 1
                    logging.info(f"✓ {result['folder_uid']}: Updated")
                else:
                    failure_count += 1
                    logging.error(f"✗ {result['folder_uid']}: {result['message']}")
            
            logging.info(f"\nUpdated {success_count} folder(s) successfully, {failure_count} failed")
            
            if success_count > 0:
                params.sync_data = True
            
            return results
        
        except Exception as e:
            logging.error(f"Error updating folders: {str(e)}")
            raise


class KeeperDriveListCommand(Command):
    """Command to list Keeper Drive folders and records"""
    
    def get_parser(self):
        return keeper_drive_list_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-list command.
        
        Lists Keeper Drive folders and records from the cache.
        """
        show_folders = kwargs.get('folders', False)
        show_records = kwargs.get('records', False)
        verbose = kwargs.get('verbose', False)
        show_permissions = kwargs.get('permissions', False)
        
        # If neither flag specified, show both
        if not show_folders and not show_records:
            show_folders = True
            show_records = True
        
        # Display Keeper Drive folders
        if show_folders and params.keeper_drive_folders:
            logging.info("\n=== Keeper Drive Folders ===")
            for folder_uid, folder_obj in params.keeper_drive_folders.items():
                name = folder_obj.get('name', 'Unnamed')
                color = folder_obj.get('color', 'none')
                parent_uid = folder_obj.get('parent_uid', 'root')
                has_key = 'folder_key_unencrypted' in folder_obj
                
                logging.info(f"\nFolder: {name}")
                logging.info(f"  UID: {folder_uid}")
                logging.info(f"  Parent: {parent_uid}")
                logging.info(f"  Color: {color}")
                logging.info(f"  Has Key: {'✓' if has_key else '✗'}")
                
                # Show owner info (always)
                owner_name = folder_obj.get('owner_username')
                if not owner_name:
                    owner_uid = folder_obj.get('owner_account_uid')
                    if owner_uid and hasattr(params, 'user_cache'):
                        owner_name = params.user_cache.get(owner_uid)
                
                # If still no owner name, try to get from folder access with AT_OWNER type
                if not owner_name and folder_uid in params.keeper_drive_folder_accesses:
                    for access in params.keeper_drive_folder_accesses[folder_uid]:
                        if access.get('access_type') == 1:  # AT_OWNER
                            owner_uid = access.get('access_type_uid')
                            if owner_uid and hasattr(params, 'user_cache'):
                                owner_name = params.user_cache.get(owner_uid)
                                break
                
                if owner_name:
                    logging.info(f"  Owner: {owner_name}")
                
                # Show permissions if requested
                if show_permissions or verbose:
                    # Check for folder access data
                    if folder_uid in params.keeper_drive_folder_accesses:
                        from keepercommander.proto import folder_pb2
                        
                        # Map enum values to names
                        access_type_names = {
                            0: "UNKNOWN",
                            1: "OWNER",
                            2: "USER",
                            3: "TEAM",
                            4: "ENTERPRISE",
                            5: "FOLDER",
                            6: "APPLICATION"
                        }
                        
                        role_type_names = {
                            0: "NO_ROLE",
                            1: "VIEWER",
                            2: "SHARED_MANAGER",
                            3: "CONTRIBUTOR",
                            4: "CONTENT_MANAGER",
                            5: "MANAGER"
                        }
                        
                        # Role descriptions for better UX
                        role_descriptions = {
                            0: "Custom permissions",
                            1: "Can view folder",
                            2: "Can manage sharing",
                            3: "Can view and edit folder",
                            4: "Can manage folder content",
                            5: "Full management permissions"
                        }
                        
                        accesses = params.keeper_drive_folder_accesses[folder_uid]
                        
                        # Separate owner access from shared accesses
                        owner_access = None
                        shared_accesses = []
                        
                        for access in accesses:
                            access_type = access.get('access_type', 0)
                            if access_type == 1:  # AT_OWNER
                                owner_access = access
                            else:
                                shared_accesses.append(access)
                        
                        # Show shared access info (owner already shown above)
                        if shared_accesses:
                            # Count shared users/teams
                            share_count = len(shared_accesses)
                            logging.info(f"  Shared With: {share_count} {'entity' if share_count == 1 else 'entities'}")
                            
                            for access in shared_accesses:
                                access_type_val = access.get('access_type', 0)
                                access_type_name = access_type_names.get(access_type_val, f"Unknown({access_type_val})")
                                
                                access_role_val = access.get('access_role_type', 0)
                                access_role_name = role_type_names.get(access_role_val, f"Unknown({access_role_val})")
                                role_desc = role_descriptions.get(access_role_val, "")
                                
                                inherited = access.get('inherited', False)
                                hidden = access.get('hidden', False)
                                
                                # Get user/team email/name from access_type_uid
                                access_uid = access.get('access_type_uid', '')
                                entity_name = None
                                if access_uid and hasattr(params, 'user_cache'):
                                    entity_name = params.user_cache.get(access_uid)
                                
                                # If not in user_cache, try enterprise users
                                if not entity_name and hasattr(params, 'enterprise') and params.enterprise:
                                    for user in params.enterprise.get('users', []):
                                        user_uid = user.get('enterprise_user_id')
                                        if isinstance(user_uid, int):
                                            user_uid_bytes = user_uid.to_bytes(16, byteorder='big', signed=False)
                                            user_uid_str = utils.base64_url_encode(user_uid_bytes)
                                        else:
                                            user_uid_str = str(user_uid)
                                        
                                        if user_uid_str == access_uid:
                                            entity_name = user.get('username')
                                            break
                                
                                # Build entity display (email or UID)
                                entity_display = entity_name if entity_name else access_uid[:8] + '...' if len(access_uid) > 8 else access_uid
                                
                                # Build display string
                                inherited_flag = " [inherited]" if inherited else ""
                                hidden_flag = " [hidden]" if hidden else ""
                                
                                # Show access type and role
                                if access_type_val == 2:  # AT_USER
                                    logging.info(f"    - User: {entity_display} - {access_role_name} ({role_desc}){inherited_flag}{hidden_flag}")
                                elif access_type_val == 3:  # AT_TEAM
                                    logging.info(f"    - Team: {entity_display} - {access_role_name} ({role_desc}){inherited_flag}{hidden_flag}")
                                else:
                                    logging.info(f"    - {access_type_name}: {entity_display} - {access_role_name} ({role_desc}){inherited_flag}{hidden_flag}")
                        else:
                            # Not shared with anyone
                            logging.info(f"  Shared: No")
                
                if verbose:
                    logging.info(f"  Type: {folder_obj.get('type', 'N/A')}")
                    logging.info(f"  Inherit Permissions: {folder_obj.get('inherit_permissions', 'N/A')}")
                    if folder_uid in params.keeper_drive_folder_records:
                        record_count = len(params.keeper_drive_folder_records[folder_uid])
                        logging.info(f"  Records: {record_count}")
                    
                    # Check if in subfolder_cache
                    in_subfolder = folder_uid in params.subfolder_cache
                    in_folder_cache = folder_uid in params.folder_cache
                    logging.info(f"  In subfolder_cache: {'✓' if in_subfolder else '✗'}")
                    logging.info(f"  In folder_cache: {'✓' if in_folder_cache else '✗'}")
                    
                    if in_folder_cache:
                        folder_node = params.folder_cache[folder_uid]
                        logging.info(f"  Node name: {folder_node.name}")
                        logging.info(f"  Subfolders: {len(folder_node.subfolders) if folder_node.subfolders else 0}")
            
            logging.info(f"\nTotal Keeper Drive folders: {len(params.keeper_drive_folders)}")
        elif show_folders:
            logging.info("No Keeper Drive folders found in cache.")
        
        # Display Keeper Drive records
        if show_records and params.keeper_drive_records:
            logging.info("\n=== Keeper Drive Records ===")
            for record_uid, record_obj in params.keeper_drive_records.items():
                version = record_obj.get('version', 'N/A')
                revision = record_obj.get('revision', 'N/A')
                has_key = 'record_key_unencrypted' in record_obj
                
                # Get title from record data if available
                title = 'Unknown'
                type = 'Unknown'
                if record_uid in params.keeper_drive_record_data:
                    data_obj = params.keeper_drive_record_data[record_uid]
                    if 'data_json' in data_obj:
                        title = data_obj['data_json'].get('title', 'Unknown')
                        type = data_obj['data_json'].get('type', 'Unknown')
                
                logging.info(f"\nRecord: {title}")
                logging.info(f"  UID: {record_uid}")
                logging.info(f"  Type: {type}")
                logging.info(f"  Version: {version}")
                logging.info(f"  Revision: {revision}")
                logging.info(f"  Has Key: {'✓' if has_key else '✗'}")
                
                # Show owner info
                owner_name = None
                
                # Try to get owner from record_data first (most accurate)
                if record_uid in params.keeper_drive_record_data:
                    rd_obj = params.keeper_drive_record_data[record_uid]
                    owner_name = rd_obj.get('user_username')
                    if not owner_name:
                        owner_uid = rd_obj.get('user_account_uid')
                        if owner_uid and hasattr(params, 'user_cache'):
                            owner_name = params.user_cache.get(owner_uid)
                
                # Fallback to meta_data_cache
                if not owner_name and record_uid in params.meta_data_cache:
                    md = params.meta_data_cache[record_uid]
                    owner_name = md.get('owner_username')
                    if not owner_name:
                        owner_uid = md.get('owner_account_uid')
                        if owner_uid and hasattr(params, 'user_cache'):
                            owner_name = params.user_cache.get(owner_uid)
                
                # Fallback to record_owner_cache
                if not owner_name and record_uid in params.record_owner_cache:
                    from keepercommander.params import RecordOwner
                    owner_info = params.record_owner_cache[record_uid]
                    if isinstance(owner_info, RecordOwner):
                        owner_uid = owner_info.account_uid
                        if owner_uid and hasattr(params, 'user_cache'):
                            owner_name = params.user_cache.get(owner_uid)
                
                if owner_name:
                    logging.info(f"  Owner: {owner_name}")
                
                # Show permissions if requested
                if show_permissions or verbose:
                    # Check for record access data
                    if record_uid in params.keeper_drive_record_accesses:
                        from keepercommander.proto import folder_pb2
                        
                        # Map enum values to names
                        access_type_names = {
                            0: "UNKNOWN",
                            1: "OWNER",
                            2: "USER",
                            3: "TEAM",
                            4: "ENTERPRISE",
                            5: "FOLDER",
                            6: "APPLICATION"
                        }
                        
                        role_type_names = {
                            0: "NO_ROLE",
                            1: "VIEWER",
                            2: "SHARED_MANAGER",
                            3: "CONTRIBUTOR",
                            4: "CONTENT_MANAGER",
                            5: "MANAGER"
                        }
                        
                        # Role descriptions for better UX
                        role_descriptions = {
                            0: "Custom permissions",
                            1: "Can view record",
                            2: "Can manage sharing",
                            3: "Can view and edit record",
                            4: "Can manage record content",
                            5: "Full management permissions"
                        }
                        
                        accesses = params.keeper_drive_record_accesses[record_uid]
                        
                        # Separate owner access from shared accesses
                        owner_access = None
                        shared_accesses = []
                        
                        for access in accesses:
                            if access.get('owner', False):
                                owner_access = access
                            else:
                                shared_accesses.append(access)
                        
                        # Only show sharing info if record is actually shared with others
                        if shared_accesses:
                            # Count shared users
                            share_count = len(shared_accesses)
                            logging.info(f"  Shared With: {share_count} {'user' if share_count == 1 else 'users'}")
                            
                            for access in shared_accesses:
                                access_role_val = access.get('access_role_type', 0)
                                access_role_name = role_type_names.get(access_role_val, f"Unknown({access_role_val})")
                                role_desc = role_descriptions.get(access_role_val, "")
                                
                                can_edit = access.get('can_edit', False)
                                can_view = access.get('can_view', False)
                                can_share = access.get('can_share', False)
                                can_delete = access.get('can_delete', False)
                                
                                # Get user email/name from access_uid
                                access_uid = access.get('access_uid', '')
                                user_name = None
                                if access_uid and hasattr(params, 'user_cache'):
                                    user_name = params.user_cache.get(access_uid)
                                
                                # If not in user_cache, try enterprise users
                                if not user_name and hasattr(params, 'enterprise') and params.enterprise:
                                    # Try to find user by matching account_uid
                                    for user in params.enterprise.get('users', []):
                                        if user.get('user_account_uid') == access_uid:
                                            user_name = user.get('username')
                                            break
                                
                                # Build user display (email or UID)
                                user_display = user_name if user_name else access_uid[:8] + '...' if len(access_uid) > 8 else access_uid
                                
                                # Show role
                                if access_role_val == 0:
                                    # NO_ROLE means custom permissions - just show permissions
                                    permissions = []
                                    if can_view:
                                        permissions.append("View")
                                    if can_edit:
                                        permissions.append("Edit")
                                    if can_share:
                                        permissions.append("Share")
                                    if can_delete:
                                        permissions.append("Delete")
                                    if permissions:
                                        logging.info(f"    - {user_display}: Custom ({', '.join(permissions)})")
                                else:
                                    # Show role with description
                                    logging.info(f"    - {user_display}: {access_role_name} ({role_desc})")
                        else:
                            # Not shared with anyone
                            logging.info(f"  Shared: No")
                    
                    # Check sharing state
                    from keepercommander.proto import record_sharing_pb2
                    if hasattr(params, 'keeper_drive_record_sharing_states'):
                        if record_uid in params.keeper_drive_record_sharing_states:
                            state = params.keeper_drive_record_sharing_states[record_uid]
                            logging.info(f"  Sharing State:")
                            logging.info(f"    Directly Shared: {'✓' if state.get('is_directly_shared') else '✗'}")
                            logging.info(f"    Indirectly Shared: {'✓' if state.get('is_indirectly_shared') else '✗'}")
                
                if verbose:
                    logging.info(f"  Shared: {record_obj.get('shared', False)}")
                    if 'file_size' in record_obj:
                        logging.info(f"  File Size: {record_obj['file_size']} bytes")
                    
                    # Check if in record_cache
                    in_record_cache = record_uid in params.record_cache
                    logging.info(f"  In record_cache: {'✓' if in_record_cache else '✗'}")
            
            logging.info(f"\nTotal Keeper Drive records: {len(params.keeper_drive_records)}")
        elif show_records:
            logging.info("No Keeper Drive records found in cache.")
        
        # Summary
        if not verbose:
            logging.info("\nSummary:")
            logging.info(f"  Keeper Drive folders: {len(params.keeper_drive_folders)}")
            logging.info(f"  Keeper Drive records: {len(params.keeper_drive_records)}")
            logging.info(f"  Total subfolder_cache entries: {len(params.subfolder_cache)}")
            logging.info(f"  Total folder_cache entries: {len(params.folder_cache)}")
            logging.info("\nTip: Use --verbose (-v) for detailed information")


class KeeperDriveGrantAccessCommand(Command):
    """Grant user access to a Keeper Drive folder"""
    
    def get_parser(self):
        return keeper_drive_grant_access_parser
    
    def execute(self, params, **kwargs):
        folder_uid = kwargs.get('folder')
        user_uid = kwargs.get('user')
        role = kwargs.get('role', 'viewer')
        expire_str = kwargs.get('expire')
        
        if not folder_uid:
            logging.error("Folder UID, name, or path is required")
            return
        
        if not user_uid:
            logging.error("User UID is required")
            return
        
        # Parse expiration time
        expiration_timestamp = None
        if expire_str:
            expiration_timestamp = self._parse_expiration(expire_str)
            if expiration_timestamp is None:
                logging.error(f"Invalid expiration format: {expire_str}")
                logging.error("Valid formats: Unix timestamp in seconds, or relative time like '30d', '24h', '30mi'")
                return
        
        try:
            result = keeper_drive.grant_folder_access_v3(
                params,
                folder_uid=folder_uid,
                user_uid=user_uid,
                role=role,
                expiration_timestamp=expiration_timestamp
            )
            
            if result['success']:
                logging.info(f"✓ Access granted successfully")
                logging.info(f"  Folder: {result['folder_uid']}")
                logging.info(f"  User: {result['user_uid']}")
                logging.info(f"  Role: {role}")
                if expiration_timestamp:
                    import datetime
                    expiration_date = datetime.datetime.fromtimestamp(expiration_timestamp / 1000)
                    logging.info(f"  Expiration: {expiration_date.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                logging.error(f"Failed to grant access: {result['message']}")
                logging.error(f"  Status: {result['status']}")
        
        except ValueError as e:
            logging.error(f"Validation error: {str(e)}")
        except Exception as e:
            logging.error(f"Error granting access: {str(e)}")
    
    @staticmethod
    def _parse_expiration(expiration_str):
        """
        Parse expiration time string.
        
        Args:
            expiration_str: Unix timestamp in seconds, or relative time (e.g., "30d", "24h", "30mi")
        
        Returns:
            Unix timestamp in milliseconds, or None if invalid
        """
        import time
        import re
        
        # Try to parse as Unix timestamp (seconds)
        try:
            timestamp = int(expiration_str)
            # Convert to milliseconds
            return timestamp * 1000
        except ValueError:
            pass
        
        # Try to parse as relative time (e.g., "30d", "24h", "30mi")
        # Support: mi (minutes), h (hours), d (days)
        match = re.match(r'^(\d+)(mi|h|d)$', expiration_str.lower())
        if match:
            value = int(match.group(1))
            unit = match.group(2)
            
            # Calculate seconds from now
            now = int(time.time())
            if unit == 'mi':  # minutes
                future = now + (value * 60)
            elif unit == 'h':  # hours
                future = now + (value * 3600)
            elif unit == 'd':  # days
                future = now + (value * 86400)
            else:
                return None
            
            # Convert to milliseconds
            return future * 1000
        
        return None


class KeeperDriveUpdateAccessCommand(Command):
    """Update user access to a Keeper Drive folder"""
    
    def get_parser(self):
        return keeper_drive_update_access_parser
    
    def execute(self, params, **kwargs):
        folder_uid = kwargs.get('folder')
        user_uid = kwargs.get('user')
        role = kwargs.get('role')
        hidden = kwargs.get('hidden')
        
        if not folder_uid:
            logging.error("Folder UID, name, or path is required")
            return
        
        if not user_uid:
            logging.error("User UID is required")
            return
        
        if role is None and hidden is None:
            logging.error("At least one of --role or --hidden must be specified")
            return
        
        try:
            result = keeper_drive.update_folder_access_v3(
                params,
                folder_uid=folder_uid,
                user_uid=user_uid,
                role=role,
                hidden=hidden
            )
            
            if result['success']:
                logging.info(f"✓ Access updated successfully")
                logging.info(f"  Folder: {result['folder_uid']}")
                logging.info(f"  User: {result['user_uid']}")
                if role:
                    logging.info(f"  New Role: {role}")
                if hidden is not None:
                    logging.info(f"  Hidden: {hidden}")
            else:
                logging.error(f"Failed to update access: {result['message']}")
                logging.error(f"  Status: {result['status']}")
        
        except ValueError as e:
            logging.error(f"Validation error: {str(e)}")
        except Exception as e:
            logging.error(f"Error updating access: {str(e)}")


class KeeperDriveRevokeAccessCommand(Command):
    """Revoke user access to a Keeper Drive folder"""
    
    def get_parser(self):
        return keeper_drive_revoke_access_parser
    
    def execute(self, params, **kwargs):
        folder_uid = kwargs.get('folder')
        user_uid = kwargs.get('user')
        
        if not folder_uid:
            logging.error("Folder UID, name, or path is required")
            return
        
        if not user_uid:
            logging.error("User UID is required")
            return
        
        try:
            result = keeper_drive.revoke_folder_access_v3(
                params,
                folder_uid=folder_uid,
                user_uid=user_uid
            )
            
            if result['success']:
                logging.info(f"✓ Access revoked successfully")
                logging.info(f"  Folder: {result['folder_uid']}")
                logging.info(f"  User: {result['user_uid']}")
            else:
                logging.error(f"Failed to revoke access: {result['message']}")
                logging.error(f"  Status: {result['status']}")
        
        except ValueError as e:
            logging.error(f"Validation error: {str(e)}")
        except Exception as e:
            logging.error(f"Error revoking access: {str(e)}")


class KeeperDriveManageAccessBatchCommand(Command):
    """Batch manage folder access (grant, update, revoke)"""
    
    def get_parser(self):
        return keeper_drive_manage_access_batch_parser
    
    def execute(self, params, **kwargs):
        grants_json = kwargs.get('grants')
        updates_json = kwargs.get('updates')
        revokes_json = kwargs.get('revokes')
        
        if not any([grants_json, updates_json, revokes_json]):
            logging.error("At least one of --grants, --updates, or --revokes must be specified")
            return
        
        try:
            # Parse JSON inputs
            access_grants = json.loads(grants_json) if grants_json else None
            access_updates = json.loads(updates_json) if updates_json else None
            access_revokes = json.loads(revokes_json) if revokes_json else None
            
            # Validate input types
            if access_grants and not isinstance(access_grants, list):
                logging.error("--grants must be a JSON array")
                return
            if access_updates and not isinstance(access_updates, list):
                logging.error("--updates must be a JSON array")
                return
            if access_revokes and not isinstance(access_revokes, list):
                logging.error("--revokes must be a JSON array")
                return
            
            # Execute batch operation
            results = keeper_drive.manage_folder_access_batch_v3(
                params,
                access_grants=access_grants,
                access_updates=access_updates,
                access_revokes=access_revokes
            )
            
            # Display results
            success_count = sum(1 for r in results if r['success'])
            fail_count = len(results) - success_count
            
            logging.info(f"\nBatch folder access management completed:")
            logging.info(f"  Total operations: {len(results)}")
            logging.info(f"  Successful: {success_count}")
            logging.info(f"  Failed: {fail_count}")
            
            # Show details for each operation
            for result in results:
                status_icon = "✓" if result['success'] else "✗"
                logging.info(f"\n{status_icon} {result['operation'].upper()}: {result['folder_uid']} / {result['user_uid']}")
                logging.info(f"  Status: {result['status']}")
                if result.get('message'):
                    logging.info(f"  Message: {result['message']}")
        
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON: {str(e)}")
        except ValueError as e:
            logging.error(f"Validation error: {str(e)}")
        except Exception as e:
            logging.error(f"Error in batch operation: {str(e)}")


# Parsers for record details commands
keeper_drive_get_record_details_parser = argparse.ArgumentParser(
    prog='keeper-drive-get-record-details',
    description='Get record metadata (title, color, etc.) using v3 API',
    allow_abbrev=False
)
keeper_drive_get_record_details_parser.add_argument(
    'record_uids',
    nargs='+',
    type=str,
    help='Record UIDs to get details for'
)
keeper_drive_get_record_details_parser.add_argument(
    '--format',
    dest='format',
    choices=['table', 'json'],
    default='table',
    help='Output format (default: table)'
)
keeper_drive_get_record_details_parser.error = raise_parse_exception
keeper_drive_get_record_details_parser.exit = suppress_exit


keeper_drive_get_record_access_parser = argparse.ArgumentParser(
    prog='keeper-drive-get-record-access',
    description='Get record access information (who has access and permissions) using v3 API',
    allow_abbrev=False
)
keeper_drive_get_record_access_parser.add_argument(
    'record_uids',
    nargs='+',
    type=str,
    help='Record UIDs to get access information for'
)
keeper_drive_get_record_access_parser.add_argument(
    '--format',
    dest='format',
    choices=['table', 'json'],
    default='table',
    help='Output format (default: table)'
)
keeper_drive_get_record_access_parser.error = raise_parse_exception
keeper_drive_get_record_access_parser.exit = suppress_exit


class KeeperDriveGetRecordDetailsCommand(Command):
    """Command to get record metadata details"""
    
    def get_parser(self):
        return keeper_drive_get_record_details_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-get-record-details command.
        
        Gets metadata details (title, color) for specified records.
        """
        record_uids = kwargs.get('record_uids', [])
        output_format = kwargs.get('format', 'table')
        
        if not record_uids:
            raise CommandError('keeper-drive-get-record-details', 'At least one record UID is required')
        
        try:
            result = keeper_drive_records.get_record_details_v3(params, record_uids)
            
            if output_format == 'json':
                # JSON output
                print(json.dumps(result, indent=2))
            else:
                # Table output
                if result['data']:
                    logging.info("\n=== Record Details ===\n")
                    for record in result['data']:
                        logging.info(f"Record UID: {record['record_uid']}")
                        logging.info(f"  Title: {record['title']}")
                        logging.info(f"  Type: {record.get('type', 'Unknown')}")
                        logging.info(f"  Version: {record.get('version', 0)}")
                        logging.info(f"  Revision: {record.get('revision', 0)}")
                        logging.info("")
                
                if result['forbidden_records']:
                    logging.warning(f"\nForbidden records: {len(result['forbidden_records'])}")
                    for uid in result['forbidden_records']:
                        logging.warning(f"  {uid}")
                
                logging.info(f"Total records retrieved: {len(result['data'])}")
        
        except Exception as e:
            logging.error(f"Error getting record details: {str(e)}")
            raise


# Parser for 'keeper-drive-share-record' command
keeper_drive_share_record_parser = argparse.ArgumentParser(
    prog='keeper-drive-share-record',
    description='Share a KeeperDrive record with a user using role-based permissions',
    allow_abbrev=False
)
keeper_drive_share_record_parser.add_argument(
    'record_uid',
    type=str,
    help='Record UID to share'
)
keeper_drive_share_record_parser.add_argument(
    'recipient_email',
    type=str,
    help='Email address of recipient user'
)

# Role-based permission flags (mutually exclusive)
role_group = keeper_drive_share_record_parser.add_mutually_exclusive_group(required=True)
role_group.add_argument(
    '--viewer',
    dest='role',
    action='store_const',
    const='viewer',
    help='Grant VIEWER role (can view record)'
)
role_group.add_argument(
    '--contributor',
    dest='role',
    action='store_const',
    const='contributor',
    help='Grant CONTRIBUTOR role (can view and edit record)'
)
role_group.add_argument(
    '--shared-manager',
    dest='role',
    action='store_const',
    const='shared_manager',
    help='Grant SHARED_MANAGER role (can manage sharing)'
)
role_group.add_argument(
    '--content-manager',
    dest='role',
    action='store_const',
    const='content_manager',
    help='Grant CONTENT_MANAGER role (can manage record content)'
)
role_group.add_argument(
    '--manager',
    dest='role',
    action='store_const',
    const='manager',
    help='Grant MANAGER role (full management permissions)'
)

keeper_drive_share_record_parser.add_argument(
    '--expiration',
    dest='expiration',
    type=int,
    help='Expiration timestamp in milliseconds'
)
keeper_drive_share_record_parser.error = raise_parse_exception
keeper_drive_share_record_parser.exit = suppress_exit


class KeeperDriveShareRecordCommand(Command):
    """Command to share a record with a user"""
    
    def get_parser(self):
        return keeper_drive_share_record_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-share-record command.
        
        Shares a record with a specific user using role-based permissions.
        """
        from keepercommander.proto import folder_pb2
        
        record_uid = kwargs.get('record_uid')
        recipient_email = kwargs.get('recipient_email')
        role = kwargs.get('role')
        
        if not record_uid or not recipient_email:
            raise CommandError('keeper-drive-share-record', 'Record UID and recipient email are required')
        
        if not role:
            raise CommandError('keeper-drive-share-record', 'A role must be specified (--viewer, --contributor, --shared-manager, --content-manager, or --manager)')
        
        # Map role strings to enum values
        role_map = {
            'viewer': folder_pb2.VIEWER,
            'contributor': folder_pb2.CONTRIBUTOR,
            'shared_manager': folder_pb2.SHARED_MANAGER,
            'content_manager': folder_pb2.CONTENT_MANAGER,
            'manager': folder_pb2.MANAGER
        }
        
        access_role_type = role_map.get(role)
        if access_role_type is None:
            raise CommandError('keeper-drive-share-record', f'Invalid role: {role}')
        
        expiration = kwargs.get('expiration')
        
        try:
            result = keeper_drive_records.share_record_v3(
                params=params,
                record_uid=record_uid,
                recipient_email=recipient_email,
                access_role_type=access_role_type,
                expiration_timestamp=expiration
            )
            
            if result['success']:
                for res in result['results']:
                    if res['success']:
                        logging.info(f"✓ Record '{res['record_uid']}' shared with {recipient_email}")
                        logging.info(f"  Status: {res['status']}")
                        logging.info(f"  Role: {role.upper()}")
                    else:
                        logging.error(f"✗ Failed to share: {res['message']}")
                
                return record_uid
            else:
                error_msg = result['results'][0]['message'] if result['results'] else 'Unknown error'
                logging.error(f"✗ Failed to share record: {error_msg}")
                raise CommandError('keeper-drive-share-record', error_msg)
        
        except ValueError as e:
            logging.error(f"Error: {str(e)}")
            raise CommandError('keeper-drive-share-record', str(e))
        except Exception as e:
            logging.error(f"Error sharing record: {str(e)}")
            raise


# Parser for 'keeper-drive-update-record-share' command
keeper_drive_update_record_share_parser = argparse.ArgumentParser(
    prog='keeper-drive-update-record-share',
    description='Update sharing permissions for a KeeperDrive record using role-based permissions',
    allow_abbrev=False
)
keeper_drive_update_record_share_parser.add_argument(
    'record_uid',
    type=str,
    help='Record UID'
)
keeper_drive_update_record_share_parser.add_argument(
    'recipient_email',
    type=str,
    help='Email address of recipient user'
)

# Role-based permission flags (mutually exclusive)
role_group = keeper_drive_update_record_share_parser.add_mutually_exclusive_group(required=True)
role_group.add_argument(
    '--viewer',
    dest='role',
    action='store_const',
    const='viewer',
    help='Update to VIEWER role (can view record)'
)
role_group.add_argument(
    '--contributor',
    dest='role',
    action='store_const',
    const='contributor',
    help='Update to CONTRIBUTOR role (can view and edit record)'
)
role_group.add_argument(
    '--shared-manager',
    dest='role',
    action='store_const',
    const='shared_manager',
    help='Update to SHARED_MANAGER role (can manage sharing)'
)
role_group.add_argument(
    '--content-manager',
    dest='role',
    action='store_const',
    const='content_manager',
    help='Update to CONTENT_MANAGER role (can manage record content)'
)
role_group.add_argument(
    '--manager',
    dest='role',
    action='store_const',
    const='manager',
    help='Update to MANAGER role (full management permissions)'
)

keeper_drive_update_record_share_parser.add_argument(
    '--expiration',
    dest='expiration',
    type=int,
    help='Update expiration timestamp in milliseconds'
)
keeper_drive_update_record_share_parser.error = raise_parse_exception
keeper_drive_update_record_share_parser.exit = suppress_exit


class KeeperDriveUpdateRecordShareCommand(Command):
    """Command to update record sharing permissions"""
    
    def get_parser(self):
        return keeper_drive_update_record_share_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-update-record-share command.
        
        Updates sharing permissions for a record using role-based permissions.
        """
        from keepercommander.proto import folder_pb2
        
        record_uid = kwargs.get('record_uid')
        recipient_email = kwargs.get('recipient_email')
        role = kwargs.get('role')
        
        if not record_uid or not recipient_email or not role:
            raise CommandError('keeper-drive-update-record-share', 'Record UID, recipient email, and role are required')
        
        # Map role string to access_role_type constant
        role_mapping = {
            'viewer': folder_pb2.VIEWER,
            'contributor': folder_pb2.CONTRIBUTOR,
            'shared_manager': folder_pb2.SHARED_MANAGER,
            'content_manager': folder_pb2.CONTENT_MANAGER,
            'manager': folder_pb2.MANAGER
        }
        
        access_role_type = role_mapping.get(role)
        if not access_role_type:
            raise CommandError('keeper-drive-update-record-share', f'Invalid role: {role}')
        
        expiration = kwargs.get('expiration')
        
        try:
            result = keeper_drive_records.update_record_share_v3(
                params=params,
                record_uid=record_uid,
                recipient_email=recipient_email,
                access_role_type=access_role_type,
                expiration_timestamp=expiration
            )
            
            if result['success']:
                for res in result['results']:
                    if res['success']:
                        logging.info(f"✓ Record '{res['record_uid']}' sharing permissions updated for {recipient_email}")
                        logging.info(f"  Status: {res['status']}")
                        logging.info(f"  New Role: {role.upper()}")
                    else:
                        logging.error(f"✗ Failed to update: {res['message']}")
                
                return record_uid
            else:
                error_msg = result['results'][0]['message'] if result['results'] else 'Unknown error'
                logging.error(f"✗ Failed to update permissions: {error_msg}")
                raise CommandError('keeper-drive-update-record-share', error_msg)
        
        except ValueError as e:
            logging.error(f"Error: {str(e)}")
            raise CommandError('keeper-drive-update-record-share', str(e))
        except Exception as e:
            logging.error(f"Error updating permissions: {str(e)}")
            raise


# Parser for 'keeper-drive-unshare-record' command
keeper_drive_unshare_record_parser = argparse.ArgumentParser(
    prog='keeper-drive-unshare-record',
    description='Unshare a KeeperDrive record from a user',
    allow_abbrev=False
)
keeper_drive_unshare_record_parser.add_argument(
    'record_uid',
    type=str,
    help='Record UID'
)
keeper_drive_unshare_record_parser.add_argument(
    'recipient_email',
    type=str,
    help='Email address of recipient user'
)
keeper_drive_unshare_record_parser.error = raise_parse_exception
keeper_drive_unshare_record_parser.exit = suppress_exit


class KeeperDriveUnshareRecordCommand(Command):
    """Command to unshare a record from a user"""
    
    def get_parser(self):
        return keeper_drive_unshare_record_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-unshare-record command.
        
        Revokes record sharing from a specific user.
        """
        record_uid = kwargs.get('record_uid')
        recipient_email = kwargs.get('recipient_email')
        
        if not record_uid or not recipient_email:
            raise CommandError('keeper-drive-unshare-record', 'Record UID and recipient email are required')
        
        try:
            result = keeper_drive_records.unshare_record_v3(
                params=params,
                record_uid=record_uid,
                recipient_email=recipient_email
            )
            
            if result['success']:
                for res in result['results']:
                    if res['success']:
                        logging.info(f"✓ Record '{res['record_uid']}' unshared from {recipient_email}")
                        logging.info(f"  Status: {res['status']}")
                    else:
                        logging.error(f"✗ Failed to unshare: {res['message']}")
                
                return record_uid
            else:
                error_msg = result['results'][0]['message'] if result['results'] else 'Unknown error'
                logging.error(f"✗ Failed to unshare record: {error_msg}")
                raise CommandError('keeper-drive-unshare-record', error_msg)
        
        except ValueError as e:
            logging.error(f"Error: {str(e)}")
            raise CommandError('keeper-drive-unshare-record', str(e))
        except Exception as e:
            logging.error(f"Error unsharing record: {str(e)}")
            raise


# Parser for 'keeper-drive-transfer-record' command
keeper_drive_transfer_record_parser = argparse.ArgumentParser(
    prog='keeper-drive-transfer-record',
    description='Transfer record ownership to another user',
    allow_abbrev=False
)
keeper_drive_transfer_record_parser.add_argument(
    'record_uid',
    type=str,
    help='Record UID to transfer'
)
keeper_drive_transfer_record_parser.add_argument(
    'new_owner_email',
    type=str,
    help='Email address of the new owner'
)
keeper_drive_transfer_record_parser.error = raise_parse_exception
keeper_drive_transfer_record_parser.exit = suppress_exit


class KeeperDriveTransferRecordCommand(Command):
    """Command to transfer record ownership"""
    
    def get_parser(self):
        return keeper_drive_transfer_record_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-transfer-record command.
        
        Transfers ownership of a record to a new user.
        """
        record_uid = kwargs.get('record_uid')
        new_owner_email = kwargs.get('new_owner_email')
        
        if not record_uid or not new_owner_email:
            raise CommandError('keeper-drive-transfer-record', 'Record UID and new owner email are required')
        
        try:
            result = keeper_drive_records.transfer_record_ownership_v3(
                params=params,
                record_uid=record_uid,
                new_owner_email=new_owner_email
            )
            
            if result['success']:
                for res in result['results']:
                    if res['success']:
                        logging.info(f"✓ Record '{res['record_uid']}' ownership transferred to {new_owner_email}")
                        logging.info(f"  Status: {res['status']}")
                        logging.warning(f"  ⚠️  You will no longer have access to this record!")
                    else:
                        logging.error(f"✗ Failed to transfer: {res['message']}")
                
                return record_uid
            else:
                error_msg = result['results'][0]['message'] if result['results'] else 'Unknown error'
                logging.error(f"✗ Failed to transfer ownership: {error_msg}")
                raise CommandError('keeper-drive-transfer-record', error_msg)
        
        except ValueError as e:
            logging.error(f"Error: {str(e)}")
            raise CommandError('keeper-drive-transfer-record', str(e))
        except Exception as e:
            logging.error(f"Error transferring record: {str(e)}")
            raise


# Parser for 'keeper-drive-transfer-records-batch' command
keeper_drive_transfer_records_batch_parser = argparse.ArgumentParser(
    prog='keeper-drive-transfer-records-batch',
    description='Transfer ownership of multiple records in batch',
    allow_abbrev=False
)
keeper_drive_transfer_records_batch_parser.add_argument(
    '--transfer',
    dest='transfers',
    action='append',
    required=True,
    help='Transfer specification: record_uid,new_owner_email'
)
keeper_drive_transfer_records_batch_parser.error = raise_parse_exception
keeper_drive_transfer_records_batch_parser.exit = suppress_exit


class KeeperDriveTransferRecordsBatchCommand(Command):
    """Command to transfer ownership of multiple records in batch"""
    
    def get_parser(self):
        return keeper_drive_transfer_records_batch_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-transfer-records-batch command.
        
        Transfers ownership of multiple records to different users.
        """
        transfer_specs = kwargs.get('transfers', [])
        
        if not transfer_specs:
            raise CommandError('keeper-drive-transfer-records-batch', 'At least one --transfer is required')
        
        # Parse transfer specifications
        transfers = []
        for spec in transfer_specs:
            try:
                parts = [p.strip() for p in spec.split(',')]
                if len(parts) != 2:
                    logging.warning(f"Invalid transfer spec (expected 'record_uid,new_owner_email'): {spec}")
                    continue
                
                transfers.append({
                    'record_uid': parts[0],
                    'new_owner_email': parts[1]
                })
            except Exception as e:
                logging.warning(f"Error parsing transfer spec '{spec}': {e}")
                continue
        
        if not transfers:
            raise CommandError('keeper-drive-transfer-records-batch', 'No valid transfer specifications provided')
        
        try:
            result = keeper_drive_records.transfer_records_ownership_batch_v3(
                params=params,
                transfers=transfers
            )
            
            if result['total'] > 0:
                logging.info(f"\nTransfer Summary:")
                logging.info(f"  Total: {result['total']}")
                logging.info(f"  ✓ Successful: {result['successful']}")
                logging.info(f"  ✗ Failed: {result['failed']}")
                logging.info("")
                
                # Show detailed results
                for res in result['results']:
                    if res['success']:
                        logging.info(f"✓ {res['record_uid']} → {res['username']}")
                    else:
                        logging.error(f"✗ {res['record_uid']} → {res['username']}: {res['message']}")
                
                if result['successful'] > 0:
                    logging.warning(f"\n⚠️  You will no longer have access to {result['successful']} record(s)!")
                
                return result['results']
            else:
                logging.warning("No records were transferred")
                return []
        
        except ValueError as e:
            logging.error(f"Error: {str(e)}")
            raise CommandError('keeper-drive-transfer-records-batch', str(e))
        except Exception as e:
            logging.error(f"Error transferring records: {str(e)}")
            raise


class KeeperDriveGetRecordAccessCommand(Command):
    """Command to get record access information"""
    
    def get_parser(self):
        return keeper_drive_get_record_access_parser
    
    def execute(self, params, **kwargs):
        """
        Execute the keeper-drive-get-record-access command.
        
        Gets access information for specified records (who has access and permissions).
        """
        record_uids = kwargs.get('record_uids', [])
        output_format = kwargs.get('format', 'table')
        
        if not record_uids:
            raise CommandError('keeper-drive-get-record-access', 'At least one record UID is required')
        
        try:
            result = keeper_drive_records.get_record_accesses_v3(params, record_uids)
            
            if output_format == 'json':
                # JSON output
                print(json.dumps(result, indent=2))
            else:
                # Table output
                if result['record_accesses']:
                    logging.info("\n=== Record Access Information ===\n")
                    
                    # Group by record UID
                    records_map = {}
                    for access in result['record_accesses']:
                        record_uid = access['record_uid']
                        if record_uid not in records_map:
                            records_map[record_uid] = []
                        records_map[record_uid].append(access)
                    
                    for record_uid, accesses in records_map.items():
                        logging.info(f"Record: {record_uid}")
                        for access in accesses:
                            logging.info(f"  Accessor: {access['accessor_name']}")
                            logging.info(f"    Type: {access['access_type']}")
                            logging.info(f"    Owner: {access['owner']}")
                            logging.info(f"    Can Edit: {access['can_edit']}")
                            logging.info(f"    Can View: {access['can_view']}")
                            logging.info(f"    Can Share: {access['can_share']}")
                            logging.info(f"    Can Delete: {access['can_delete']}")
                            logging.info("")
                        logging.info("")
                
                if result['forbidden_records']:
                    logging.warning(f"\nForbidden records: {len(result['forbidden_records'])}")
                    for uid in result['forbidden_records']:
                        logging.warning(f"  {uid}")
                
                logging.info(f"Total access entries retrieved: {len(result['record_accesses'])}")
        
        except Exception as e:
            logging.error(f"Error getting record access information: {str(e)}")
            raise


class KeeperDriveAddRecordToFolderCommand(Command):
    """Add an existing record to a folder"""
    
    def get_parser(self):
        return keeper_drive_add_record_to_folder_parser
    
    def execute(self, params, **kwargs):
        folder_uid = kwargs.get('folder')
        record_uid = kwargs.get('record')
        
        if not folder_uid:
            logging.error("Folder UID, name, or path is required")
            return
        
        if not record_uid:
            logging.error("Record UID is required")
            return
        
        try:
            result = keeper_drive_records.add_record_to_folder_v3(
                params,
                folder_uid=folder_uid,
                record_uid=record_uid
            )
            
            if result['success']:
                logging.info(f"✓ Record added to folder successfully")
                logging.info(f"  Folder: {result['folder_uid']}")
                logging.info(f"  Record: {result['record_uid']}")
            else:
                logging.error(f"Failed to add record to folder: {result['message']}")
                logging.error(f"  Status: {result['status']}")
        
        except ValueError as e:
            logging.error(f"Validation error: {str(e)}")
        except Exception as e:
            logging.error(f"Error adding record to folder: {str(e)}")


class KeeperDriveRemoveRecordFromFolderCommand(Command):
    """Remove a record from a folder"""
    
    def get_parser(self):
        return keeper_drive_remove_record_from_folder_parser
    
    def execute(self, params, **kwargs):
        folder_uid = kwargs.get('folder')
        record_uid = kwargs.get('record')
        
        if not folder_uid:
            logging.error("Folder UID, name, or path is required")
            return
        
        if not record_uid:
            logging.error("Record UID is required")
            return
        
        try:
            result = keeper_drive_records.remove_record_from_folder_v3(
                params,
                folder_uid=folder_uid,
                record_uid=record_uid
            )
            
            if result['success']:
                logging.info(f"✓ Record removed from folder successfully")
                logging.info(f"  Folder: {result['folder_uid']}")
                logging.info(f"  Record: {result['record_uid']}")
            else:
                logging.error(f"Failed to remove record from folder: {result['message']}")
                logging.error(f"  Status: {result['status']}")
        
        except ValueError as e:
            logging.error(f"Validation error: {str(e)}")
        except Exception as e:
            logging.error(f"Error removing record from folder: {str(e)}")


class KeeperDriveMoveRecordCommand(Command):
    """Move a record between folders or to/from root"""
    
    def get_parser(self):
        return keeper_drive_move_record_parser
    
    def execute(self, params, **kwargs):
        record_uid = kwargs.get('record')
        from_folder = kwargs.get('from_folder')
        to_folder = kwargs.get('to_folder')
        
        if not record_uid:
            logging.error("Record UID is required")
            return
        
        if not from_folder and not to_folder:
            logging.error("At least one of --from or --to must be specified")
            return
        
        try:
            result = keeper_drive_records.move_record_v3(
                params,
                record_uid=record_uid,
                from_folder_uid=from_folder,
                to_folder_uid=to_folder
            )
            
            if result['success']:
                logging.info(f"✓ Record moved successfully")
                logging.info(f"  Record: {result['record_uid']}")
                logging.info(f"  From: {result['from_folder']}")
                logging.info(f"  To: {result['to_folder']}")
            else:
                logging.error(f"Failed to move record: {result['message']}")
        
        except ValueError as e:
            logging.error(f"Validation error: {str(e)}")
        except Exception as e:
            logging.error(f"Error moving record: {str(e)}")


class KeeperDriveManageFolderRecordsBatchCommand(Command):
    """Batch add or remove records from a folder"""
    
    def get_parser(self):
        return keeper_drive_manage_folder_records_batch_parser
    
    def execute(self, params, **kwargs):
        folder_uid = kwargs.get('folder')
        add_json = kwargs.get('add')
        remove_json = kwargs.get('remove')
        
        if not folder_uid:
            logging.error("Folder UID, name, or path is required")
            return
        
        if not any([add_json, remove_json]):
            logging.error("At least one of --add or --remove must be specified")
            return
        
        try:
            # Parse JSON inputs
            records_to_add = json.loads(add_json) if add_json else None
            records_to_remove = json.loads(remove_json) if remove_json else None
            
            # Validate input types
            if records_to_add and not isinstance(records_to_add, list):
                logging.error("--add must be a JSON array")
                return
            if records_to_remove and not isinstance(records_to_remove, list):
                logging.error("--remove must be a JSON array")
                return
            
            # Execute batch operation
            results = keeper_drive_records.manage_folder_records_batch_v3(
                params,
                folder_uid=folder_uid,
                records_to_add=records_to_add,
                records_to_remove=records_to_remove
            )
            
            # Display results
            success_count = sum(1 for r in results if r['success'])
            fail_count = len(results) - success_count
            
            logging.info(f"\nBatch folder record management completed:")
            logging.info(f"  Folder: {folder_uid}")
            logging.info(f"  Total operations: {len(results)}")
            logging.info(f"  Successful: {success_count}")
            logging.info(f"  Failed: {fail_count}")
            
            # Show details for each operation
            for result in results:
                status_icon = "✓" if result['success'] else "✗"
                logging.info(f"\n{status_icon} {result['operation'].upper()}: {result['record_uid']}")
                logging.info(f"  Status: {result['status']}")
                if result.get('message'):
                    logging.info(f"  Message: {result['message']}")
        
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON: {str(e)}")
        except ValueError as e:
            logging.error(f"Validation error: {str(e)}")
        except Exception as e:
            logging.error(f"Error in batch operation: {str(e)}")


def register_commands(commands):
    """Register KeeperDrive commands"""
    commands['keeper-drive-mkdir'] = KeeperDriveMkdirCommand()
    commands['keeper-drive-mkdir-batch'] = KeeperDriveMkdirBatchCommand()
    commands['keeper-drive-add-record'] = KeeperDriveAddRecordCommand()
    commands['keeper-drive-add-records-batch'] = KeeperDriveAddRecordsBatchCommand()
    commands['keeper-drive-update-record'] = KeeperDriveUpdateRecordCommand()
    commands['keeper-drive-update-folder'] = KeeperDriveUpdateFolderCommand()
    commands['keeper-drive-update-folders-batch'] = KeeperDriveUpdateFoldersBatchCommand()
    commands['keeper-drive-list'] = KeeperDriveListCommand()
    commands['keeper-drive-grant-access'] = KeeperDriveGrantAccessCommand()
    commands['keeper-drive-update-access'] = KeeperDriveUpdateAccessCommand()
    commands['keeper-drive-revoke-access'] = KeeperDriveRevokeAccessCommand()
    commands['keeper-drive-manage-access-batch'] = KeeperDriveManageAccessBatchCommand()
    commands['keeper-drive-get-record-details'] = KeeperDriveGetRecordDetailsCommand()
    commands['keeper-drive-get-record-access'] = KeeperDriveGetRecordAccessCommand()
    commands['keeper-drive-share-record'] = KeeperDriveShareRecordCommand()
    commands['keeper-drive-update-record-share'] = KeeperDriveUpdateRecordShareCommand()
    commands['keeper-drive-unshare-record'] = KeeperDriveUnshareRecordCommand()
    commands['keeper-drive-transfer-record'] = KeeperDriveTransferRecordCommand()
    commands['keeper-drive-transfer-records-batch'] = KeeperDriveTransferRecordsBatchCommand()
    commands['keeper-drive-add-record-to-folder'] = KeeperDriveAddRecordToFolderCommand()
    commands['keeper-drive-remove-record-from-folder'] = KeeperDriveRemoveRecordFromFolderCommand()
    commands['keeper-drive-move-record'] = KeeperDriveMoveRecordCommand()
    commands['keeper-drive-manage-folder-records-batch'] = KeeperDriveManageFolderRecordsBatchCommand()


def register_command_info(aliases, command_info):
    """Register command information for help"""
    command_info['keeper-drive-mkdir'] = 'Create a KeeperDrive folder (v3 API)'
    command_info['keeper-drive-mkdir-batch'] = 'Create multiple KeeperDrive folders (v3 API)'
    command_info['keeper-drive-add-record'] = 'Create a KeeperDrive record (v3 API)'
    command_info['keeper-drive-add-records-batch'] = 'Create multiple KeeperDrive records (v3 API)'
    command_info['keeper-drive-update-record'] = 'Update a KeeperDrive record (v3 API)'
    command_info['keeper-drive-update-folder'] = 'Update a KeeperDrive folder (v3 API)'
    command_info['keeper-drive-update-folders-batch'] = 'Update multiple KeeperDrive folders (v3 API)'
    command_info['keeper-drive-list'] = 'List Keeper Drive folders and records'
    command_info['keeper-drive-grant-access'] = 'Grant user access to a folder (v3 API)'
    command_info['keeper-drive-update-access'] = 'Update user access to a folder (v3 API)'
    command_info['keeper-drive-revoke-access'] = 'Revoke user access from a folder (v3 API)'
    command_info['keeper-drive-manage-access-batch'] = 'Batch manage folder access (v3 API)'
    command_info['keeper-drive-get-record-details'] = 'Get record metadata (title, color) (v3 API)'
    command_info['keeper-drive-get-record-access'] = 'Get record access permissions (v3 API)'
    command_info['keeper-drive-share-record'] = 'Share a record with a user (v3 API)'
    command_info['keeper-drive-update-record-share'] = 'Update record sharing permissions (v3 API)'
    command_info['keeper-drive-unshare-record'] = 'Unshare a record from a user (v3 API)'
    command_info['keeper-drive-transfer-record'] = 'Transfer record ownership to another user (v3 API)'
    command_info['keeper-drive-transfer-records-batch'] = 'Transfer ownership of multiple records in batch (v3 API)'
    command_info['keeper-drive-add-record-to-folder'] = 'Add a record to a folder (v3 API)'
    command_info['keeper-drive-remove-record-from-folder'] = 'Remove a record from a folder (v3 API)'
    command_info['keeper-drive-move-record'] = 'Move a record between folders or to/from root (v3 API)'
    command_info['keeper-drive-manage-folder-records-batch'] = 'Batch manage records in a folder (v3 API)'

