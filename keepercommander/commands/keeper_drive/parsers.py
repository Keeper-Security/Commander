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
KeeperDrive — argument parser definitions.

Uses the **Factory Method** pattern (``_make_parser``) to eliminate
boilerplate across the 22 parsers in the module.
"""

import argparse
from .helpers import raise_parse_exception, suppress_exit


def _make_parser(prog, description):
    """Factory that creates a parser with shared defaults and error overrides."""
    p = argparse.ArgumentParser(prog=prog, description=description, allow_abbrev=False)
    p.error = raise_parse_exception
    p.exit = suppress_exit
    return p


# ══════════════════════════════════════════════════════════════════════════
# Folder parsers
# ══════════════════════════════════════════════════════════════════════════

keeper_drive_mkdir_parser = _make_parser(
    'kd-mkdir', 'Create a new KeeperDrive folder using v3 API')
keeper_drive_mkdir_parser.add_argument(
    'folder', type=str,
    help='Folder name or path to create (e.g., "Projects/Work" or "folder1/folder2/folder3")')
keeper_drive_mkdir_parser.add_argument(
    '-p', '--parents', dest='create_parents', action='store_true',
    help='Create parent folders as needed')
keeper_drive_mkdir_parser.add_argument(
    '--color', type=str,
    choices=['none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray'],
    help='Folder color')
keeper_drive_mkdir_parser.add_argument(
    '--no-inherit', dest='no_inherit_permissions', action='store_true',
    help='Do not inherit parent folder permissions')


keeper_drive_update_folder_parser = _make_parser(
    'kd-rndir', 'Rename a KeeperDrive folder.')
keeper_drive_update_folder_parser.add_argument(
    '-n', '--name', dest='folder_name', action='store', metavar='NAME',
    help='folder new name')
keeper_drive_update_folder_parser.add_argument(
    '--color', dest='color', action='store',
    choices=['none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray'],
    help='folder color')
keeper_drive_update_folder_parser.add_argument(
    '--inherit', dest='inherit_permissions', action='store_true',
    help='set folder to inherit parent permissions')
keeper_drive_update_folder_parser.add_argument(
    '--no-inherit', dest='no_inherit_permissions', action='store_true',
    help='set folder to not inherit parent permissions')
keeper_drive_update_folder_parser.add_argument(
    '-q', '--quiet', dest='quiet', action='store_true',
    help='rename folder without confirmation message')
keeper_drive_update_folder_parser.add_argument(
    'folder', nargs='?', type=str, help='folder path or UID')


keeper_drive_list_parser = _make_parser(
    'kd-list', 'List Keeper Drive folders and records')
keeper_drive_list_parser.add_argument(
    '--folders', action='store_true', help='Show only folders')
keeper_drive_list_parser.add_argument(
    '--records', action='store_true', help='Show only records')
keeper_drive_list_parser.add_argument(
    '--verbose', '-v', action='store_true', help='Show detailed information')
keeper_drive_list_parser.add_argument(
    '--permissions', '-p', action='store_true',
    help='Show permissions and access information for records and folders')
keeper_drive_list_parser.add_argument(
    '--format', dest='format', choices=['table', 'csv', 'json'], default='table',
    help='Output format (default: table)')
keeper_drive_list_parser.add_argument(
    '--output', dest='output', type=str,
    help='Path to output file (ignored for table format)')


keeper_drive_share_folder_parser = _make_parser(
    'kd-share-folder', 'Change the sharing permissions of a KeeperDrive folder')
keeper_drive_share_folder_parser.add_argument(
    '-a', '--action', dest='action',
    choices=['grant', 'remove'], default='grant', action='store',
    help="shared folder action: grant (default, also updates existing shares), remove")
keeper_drive_share_folder_parser.add_argument(
    '-e', '--email', dest='user', action='append', metavar='USER',
    help='account email or @existing for all users in the folder')
keeper_drive_share_folder_parser.add_argument(
    '-r', '--role', dest='role',
    choices=[
        'contributor', 'viewer', 'shared-manager',
        'content-manager', 'content-share-manager', 'manager',
    ],
    default='viewer',
    help='permission role (default: viewer). Required for grant action')
_sf_expire = keeper_drive_share_folder_parser.add_mutually_exclusive_group()
_sf_expire.add_argument(
    '--expire-at', dest='expire_at', action='store', metavar='TIMESTAMP',
    help='share expiration: never or ISO datetime (yyyy-MM-ddTHH:MM:SSZ)')
_sf_expire.add_argument(
    '--expire-in', dest='expire_in', action='store', metavar='PERIOD',
    help='share expiration: never or period (e.g. 30d, 6mo, 1y, 24h, 30mi)')
keeper_drive_share_folder_parser.add_argument(
    'folder', nargs='+', type=str, help='KeeperDrive folder path or UID')


keeper_drive_get_folder_access_parser = _make_parser(
    'kd-get-folder-access',
    'Retrieve accessors (users and teams) of Keeper Drive folders')
keeper_drive_get_folder_access_parser.add_argument(
    'folder_uids', nargs='+', type=str,
    help='Folder UIDs, names, or paths to query (max 100)')
keeper_drive_get_folder_access_parser.add_argument(
    '--verbose', '-v', action='store_true',
    help='Show detailed information including permissions')


kd_rmdir_parser = _make_parser(
    'kd-rmdir',
    'Remove a KeeperDrive folder and its entire contents. '
    'Always runs a preview first showing the impact before asking for confirmation.')
kd_rmdir_parser.add_argument(
    'folders', nargs='+', metavar='FOLDER',
    help='Folder UID(s) or name(s) to remove (max 100 per invocation)')
kd_rmdir_parser.add_argument(
    '--operation', '-o', dest='operation',
    choices=['folder-trash', 'delete-permanent'], default='folder-trash',
    help='Removal operation (default: folder-trash). '
         'folder-trash = recoverable; delete-permanent = IRREVERSIBLE.')
_kd_rmdir_confirm = kd_rmdir_parser.add_mutually_exclusive_group()
_kd_rmdir_confirm.add_argument(
    '--force', '-f', action='store_true',
    help='Skip the confirmation prompt and execute immediately after preview.')
_kd_rmdir_confirm.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='Run the preview step only; do not delete anything.')
kd_rmdir_parser.add_argument(
    '--quiet', '-q', action='store_true',
    help='Suppress per-folder detail; only show the summary.')


# ══════════════════════════════════════════════════════════════════════════
# Record parsers
# ══════════════════════════════════════════════════════════════════════════

keeper_drive_add_record_parser = _make_parser(
    'kd-record-add', 'Add a record to folder.')
keeper_drive_add_record_parser.add_argument(
    '--syntax-help', dest='syntax_help', action='store_true',
    help='Display help on field parameters.')
keeper_drive_add_record_parser.add_argument(
    '-f', '--force', dest='force', action='store_true', help='ignore warnings')
keeper_drive_add_record_parser.add_argument(
    '-t', '--title', dest='title', type=str, help='record title')
keeper_drive_add_record_parser.add_argument(
    '-rt', '--record-type', dest='record_type', type=str, help='record type')
keeper_drive_add_record_parser.add_argument(
    '-n', '--notes', dest='notes', type=str, help='record notes')
keeper_drive_add_record_parser.add_argument(
    '--folder', dest='folder_uid', metavar='FOLDER', type=str,
    help='folder name or UID to store record')
keeper_drive_add_record_parser.add_argument(
    'fields', nargs='*', type=str,
    help='load record type data from strings with dot notation')


keeper_drive_update_record_parser = _make_parser(
    'kd-record-update', 'Update a record.')
keeper_drive_update_record_parser.add_argument(
    '--syntax-help', dest='syntax_help', action='store_true',
    help='Display help on field parameters.')
keeper_drive_update_record_parser.add_argument(
    '-f', '--force', dest='force', action='store_true', help='ignore warnings')
keeper_drive_update_record_parser.add_argument(
    '-t', '--title', dest='title', type=str, help='modify record title')
keeper_drive_update_record_parser.add_argument(
    '-rt', '--record-type', dest='record_type', type=str, help='record type')
keeper_drive_update_record_parser.add_argument(
    '-n', '--notes', dest='notes', type=str, help='append/modify record notes')
keeper_drive_update_record_parser.add_argument(
    '-r', '--record', dest='record_uids', metavar='RECORD', type=str, action='append',
    help='record path or UID.')
keeper_drive_update_record_parser.add_argument(
    'fields', nargs='*', type=str,
    help='load record type data from strings with dot notation')


keeper_drive_add_record_to_folder_parser = _make_parser(
    'kd-add-record-to-folder',
    'Add an existing record to a Keeper Drive folder')
keeper_drive_add_record_to_folder_parser.add_argument(
    '--folder', type=str, required=True, help='Folder UID, name, or path')
keeper_drive_add_record_to_folder_parser.add_argument(
    '--record', type=str, required=True, help='Record UID to add to the folder')


keeper_drive_remove_record_from_folder_parser = _make_parser(
    'kd-remove-record-from-folder',
    'Remove a record from a Keeper Drive folder')
keeper_drive_remove_record_from_folder_parser.add_argument(
    '--folder', type=str, required=True, help='Folder UID, name, or path')
keeper_drive_remove_record_from_folder_parser.add_argument(
    '--record', type=str, required=True, help='Record UID to remove from the folder')


keeper_drive_ln_parser = _make_parser(
    'kd-ln', 'Link a record into a KeeperDrive folder (positional: RECORD FOLDER).')
keeper_drive_ln_parser.add_argument(
    'src', nargs='?', type=str, help='record UID, title, or path')
keeper_drive_ln_parser.add_argument(
    'dst', nargs='?', type=str, help='destination folder UID or name')


# ══════════════════════════════════════════════════════════════════════════
# Sharing / permission parsers
# ══════════════════════════════════════════════════════════════════════════

keeper_drive_share_record_parser = _make_parser(
    'kd-share-record', 'Change the sharing permissions of an individual record')
keeper_drive_share_record_parser.add_argument(
    'record', nargs='?', type=str, help='record path or UID')
keeper_drive_share_record_parser.add_argument(
    '-e', '--email', dest='email', metavar='EMAIL', action='append', required=True,
    help='account email. Repeatable: -e user1@example.com -e user2@example.com')
keeper_drive_share_record_parser.add_argument(
    '--contacts-only', dest='contacts_only', action='store_true',
    help='Share only to known targets')
keeper_drive_share_record_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Skip confirmation prompts')
keeper_drive_share_record_parser.add_argument(
    '-a', '--action', dest='action', choices=['grant', 'revoke', 'owner'],
    default='grant', help="sharing action. 'grant' if omitted (also updates existing shares); 'owner' transfers ownership")
keeper_drive_share_record_parser.add_argument(
    '-r', '--role', dest='role',
    choices=[
        'contributor', 'viewer', 'shared-manager',
        'content-manager', 'content-share-manager', 'manager',
    ],
    help='permission role. Required for grant/update actions')
keeper_drive_share_record_parser.add_argument(
    '-R', '--recursive', dest='recursive', action='store_true',
    help='apply command to all records within a folder and its sub-folders')
keeper_drive_share_record_parser.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='display permission changes without committing them')
_sr_expire = keeper_drive_share_record_parser.add_mutually_exclusive_group()
_sr_expire.add_argument(
    '--expire-at', dest='expire_at', metavar='EXPIRE_AT', type=str,
    help='share expiration: never or UTC datetime (e.g. 2027-01-01T00:00:00Z)')
_sr_expire.add_argument(
    '--expire-in', dest='expire_in',
    metavar='<NUMBER>[(mi)nutes|(h)ours|(d)ays|(mo)nths|(y)ears]', type=str,
    help='share expiration: never or period (e.g. 30d, 6mo, 1y)')


keeper_drive_record_permission_parser = _make_parser(
    'kd-record-permission', 'Modify the permissions of a record')
keeper_drive_record_permission_parser.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='Display the permissions changes without committing them')
keeper_drive_record_permission_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Apply permission changes without any confirmation')
keeper_drive_record_permission_parser.add_argument(
    '-R', '--recursive', dest='recursive', action='store_true',
    help='Apply permission changes to all sub-folders')
keeper_drive_record_permission_parser.add_argument(
    '-a', '--action', dest='action', choices=['grant', 'revoke'], required=True,
    help='The action being taken')
keeper_drive_record_permission_parser.add_argument(
    '-r', '--role', dest='role',
    choices=[
        'contributor', 'viewer', 'shared-manager',
        'content-manager', 'content-share-manager', 'manager',
    ],
    help='Permission role to grant, or filter for revoke')
keeper_drive_record_permission_parser.add_argument(
    'folder', nargs='?', type=str, help='folder path or folder UID')


keeper_drive_transfer_record_parser = _make_parser(
    'kd-transfer-record', 'Transfer record ownership to another user')
keeper_drive_transfer_record_parser.add_argument(
    'record_uids', nargs='+', type=str, help='Record UID(s) to transfer')
keeper_drive_transfer_record_parser.add_argument(
    'new_owner_email', type=str, help='Email address of the new owner')


# ══════════════════════════════════════════════════════════════════════════
# Detail / access parsers
# ══════════════════════════════════════════════════════════════════════════

keeper_drive_get_record_details_parser = _make_parser(
    'kd-get-record-details',
    'Get record metadata (title, color, etc.) using v3 API')
keeper_drive_get_record_details_parser.add_argument(
    'record_uids', nargs='+', type=str, help='Record UIDs to get details for')
keeper_drive_get_record_details_parser.add_argument(
    '--format', dest='format', choices=['table', 'json'], default='table',
    help='Output format (default: table)')


keeper_drive_get_record_access_parser = _make_parser(
    'kd-get-record-access',
    'Get record access information using v3 API')
keeper_drive_get_record_access_parser.add_argument(
    'record_uids', nargs='+', type=str,
    help='Record UIDs to get access information for')
keeper_drive_get_record_access_parser.add_argument(
    '--format', dest='format', choices=['table', 'json'], default='table',
    help='Output format (default: table)')
keeper_drive_get_record_access_parser.add_argument(
    '--verbose', '-v', dest='verbose', action='store_true', default=False,
    help='Show individual permission flags in addition to the role name')


# ══════════════════════════════════════════════════════════════════════════
# Shortcut parsers
# ══════════════════════════════════════════════════════════════════════════

kd_shortcut_list_parser = _make_parser(
    'kd-shortcut list',
    'List KeeperDrive records that appear in more than one folder.')
kd_shortcut_list_parser.add_argument(
    'target', nargs='?', type=str,
    help='Optional record UID/title or folder path/UID to filter results')
kd_shortcut_list_parser.add_argument(
    '--format', dest='format', choices=['table', 'csv', 'json'], default='table',
    help='Output format (default: table)')
kd_shortcut_list_parser.add_argument(
    '--output', dest='output', type=str,
    help='Path to output file (ignored for table format)')


kd_shortcut_keep_parser = _make_parser(
    'kd-shortcut keep',
    'Keep a record only in one KeeperDrive folder, removing it from all others.')
kd_shortcut_keep_parser.add_argument(
    'target', nargs='?', type=str, help='Record UID or title')
kd_shortcut_keep_parser.add_argument(
    'folder', nargs='?', type=str,
    help='Folder path or UID to keep the record in (defaults to current folder)')
kd_shortcut_keep_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Do not prompt before removing')


# ══════════════════════════════════════════════════════════════════════════
# Remove parsers
# ══════════════════════════════════════════════════════════════════════════

kd_rm_parser = _make_parser(
    'kd-rm',
    'Remove a KeeperDrive record. Supports owner-trash, folder-trash, or unlink.')
kd_rm_parser.add_argument(
    'records', nargs='+', metavar='RECORD',
    help='Record UID(s) or title(s) to remove (max 500 per invocation)')
kd_rm_parser.add_argument(
    '--folder', '-f', dest='folder_uid', metavar='FOLDER',
    help='Folder UID or name that provides context for the operation')
kd_rm_parser.add_argument(
    '--operation', '-o', dest='operation',
    choices=['owner-trash', 'folder-trash', 'unlink'], default='owner-trash',
    help='Removal operation (default: owner-trash)')
_kd_rm_confirm = kd_rm_parser.add_mutually_exclusive_group()
_kd_rm_confirm.add_argument(
    '--force', action='store_true',
    help='Skip the confirmation prompt and execute immediately after preview.')
_kd_rm_confirm.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='Run the preview step only; do not delete anything.')


# ══════════════════════════════════════════════════════════════════════════
# Get parser
# ══════════════════════════════════════════════════════════════════════════

kd_get_parser = _make_parser(
    'kd-get',
    'Get the details of a KeeperDrive record or folder by UID or title')
kd_get_parser.add_argument(
    'uid', type=str, help='Record UID, folder UID, or title to look up')
kd_get_parser.add_argument(
    '--format', dest='format', choices=['detail', 'json'], default='detail',
    help='Output format: detail (default) or json')
kd_get_parser.add_argument(
    '--verbose', '-v', dest='verbose', action='store_true', default=False,
    help='Show full permission breakdown for each accessor')
kd_get_parser.add_argument(
    '--unmask', dest='unmask', action='store_true', default=False,
    help='Reveal masked field values (passwords, secrets)')
