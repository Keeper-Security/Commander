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
Nested Share Folder — argument parser definitions.

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

nested_share_folder_mkdir_parser = _make_parser(
    'nsf-mkdir', 'Create a new Nested Share Folder using v3 API')
nested_share_folder_mkdir_parser.add_argument(
    'folder', type=str,
    help='Folder name or path using folder names only (e.g. "Parent/Child"). '
         'Intermediate folders are created automatically. '
         'UIDs are not allowed in paths. '
         'Use "//" to embed a literal "/" in a segment name.')
nested_share_folder_mkdir_parser.add_argument(
    '--color', type=str,
    choices=['none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray'],
    help='Folder color')
nested_share_folder_mkdir_parser.add_argument(
    '--no-inherit', dest='no_inherit_permissions', action='store_true',
    help='Do not inherit parent folder permissions')


nested_share_folder_update_parser = _make_parser(
    'nsf-rndir', 'Rename a Nested Share Folder.')
nested_share_folder_update_parser.add_argument(
    '-n', '--name', dest='folder_name', action='store', metavar='NAME',
    help='folder new name')
nested_share_folder_update_parser.add_argument(
    '--color', dest='color', action='store',
    choices=['none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray'],
    help='folder color')
nested_share_folder_update_parser.add_argument(
    '-q', '--quiet', dest='quiet', action='store_true',
    help='rename folder without confirmation message')
nested_share_folder_update_parser.add_argument(
    'folder', nargs='?', type=str, help='folder path or UID')


nested_share_folder_list_parser = _make_parser(
    'nsf-list', 'List Nested Share Folder folders and records')
nested_share_folder_list_parser.add_argument(
    '--folders', action='store_true', help='Show only folders')
nested_share_folder_list_parser.add_argument(
    '--records', action='store_true', help='Show only records')
nested_share_folder_list_parser.add_argument(
    '--format', dest='format', choices=['table', 'csv', 'json'], default='table',
    help='Output format (default: table)')
nested_share_folder_list_parser.add_argument(
    '--output', dest='output', type=str,
    help='Path to output file (ignored for table format)')


nested_share_folder_share_parser = _make_parser(
    'nsf-share-folder', 'Change the sharing permissions of a Nested Share Folder')
nested_share_folder_share_parser.add_argument(
    '-a', '--action', dest='action',
    choices=['grant', 'remove'], default='grant', action='store',
    help="shared folder action: grant (default, also updates existing shares), remove")
nested_share_folder_share_parser.add_argument(
    '-e', '--email', dest='user', action='append', metavar='USER',
    help='account email, team name/UID, or @existing for all users '
         'and teams in the folder')
nested_share_folder_share_parser.add_argument(
    '-r', '--role', dest='role',
    choices=[
        'viewer', 'share-manager',
        'content-manager', 'content-share-manager', 'full-manager',
    ],
    default='viewer',
    help='permission role (default: viewer). Required for grant action')
_sf_expire = nested_share_folder_share_parser.add_mutually_exclusive_group()
_sf_expire.add_argument(
    '--expire-at', dest='expire_at', action='store', metavar='TIMESTAMP',
    help='share expiration: never or ISO datetime (yyyy-MM-ddTHH:MM:SSZ)')
_sf_expire.add_argument(
    '--expire-in', dest='expire_in', action='store', metavar='PERIOD',
    help='share expiration: never or period (e.g. 30d, 6mo, 1y, 24h, 30mi)')
nested_share_folder_share_parser.add_argument(
    'folder', nargs='+', type=str, help='Nested Share Folder path or UID')


nested_share_folder_rmdir_parser = _make_parser(
    'nsf-rmdir',
    'Remove a Nested Share Folder and its entire contents. '
    'Always runs a preview first showing the impact before asking for confirmation.')
nested_share_folder_rmdir_parser.add_argument(
    'folders', nargs='+', metavar='FOLDER',
    help='Folder UID(s) or name(s) to remove (max 100 per invocation)')
nested_share_folder_rmdir_parser.add_argument(
    '--operation', '-o', dest='operation',
    choices=['folder-trash', 'delete-permanent'], default='folder-trash',
    help='Removal operation (default: folder-trash). '
         'folder-trash = recoverable; delete-permanent = IRREVERSIBLE.')
_nsf_rmdir_confirm = nested_share_folder_rmdir_parser.add_mutually_exclusive_group()
_nsf_rmdir_confirm.add_argument(
    '--force', '-f', action='store_true',
    help='Skip the confirmation prompt and execute immediately after preview.')
_nsf_rmdir_confirm.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='Run the preview step only; do not delete anything.')
nested_share_folder_rmdir_parser.add_argument(
    '--quiet', '-q', action='store_true',
    help='Suppress per-folder detail; only show the summary.')


# ══════════════════════════════════════════════════════════════════════════
# Record parsers
# ══════════════════════════════════════════════════════════════════════════

nested_share_record_add_parser = _make_parser(
    'nsf-record-add', 'Add a record to folder.')
nested_share_record_add_parser.add_argument(
    '--syntax-help', dest='syntax_help', action='store_true',
    help='Display help on field parameters.')
nested_share_record_add_parser.add_argument(
    '-f', '--force', dest='force', action='store_true', help='ignore warnings')
nested_share_record_add_parser.add_argument(
    '-t', '--title', dest='title', type=str, help='record title')
nested_share_record_add_parser.add_argument(
    '-rt', '--record-type', dest='record_type', type=str, help='record type')
nested_share_record_add_parser.add_argument(
    '-n', '--notes', dest='notes', type=str, help='record notes')
nested_share_record_add_parser.add_argument(
    '--folder', dest='folder_uid', metavar='FOLDER', type=str,
    help='folder name or UID to store record')
nested_share_record_add_parser.add_argument(
    'fields', nargs='*', type=str,
    help='load record type data from strings with dot notation')


nested_share_record_update_parser = _make_parser(
    'nsf-record-update', 'Update a record.')
nested_share_record_update_parser.add_argument(
    '--syntax-help', dest='syntax_help', action='store_true',
    help='Display help on field parameters.')
nested_share_record_update_parser.add_argument(
    '-f', '--force', dest='force', action='store_true', help='ignore warnings')
nested_share_record_update_parser.add_argument(
    '-t', '--title', dest='title', type=str, help='modify record title')
nested_share_record_update_parser.add_argument(
    '-rt', '--record-type', dest='record_type', type=str, help='record type')
nested_share_record_update_parser.add_argument(
    '-n', '--notes', dest='notes', type=str, help='append/modify record notes')
nested_share_record_update_parser.add_argument(
    '-r', '--record', dest='record_uids', metavar='RECORD', type=str, action='append',
    help='record path or UID.')
nested_share_record_update_parser.add_argument(
    'fields', nargs='*', type=str,
    help='load record type data from strings with dot notation')


nested_share_record_ln_parser = _make_parser(
    'nsf-ln', 'Link a record into a Nested Share Folder (positional: RECORD FOLDER).')
nested_share_record_ln_parser.add_argument(
    'src', nargs='?', type=str, help='record UID, title, or path')
nested_share_record_ln_parser.add_argument(
    'dst', nargs='?', type=str, help='destination folder UID or name')


# ══════════════════════════════════════════════════════════════════════════
# Sharing / permission parsers
# ══════════════════════════════════════════════════════════════════════════

nested_share_record_share_parser = _make_parser(
    'nsf-share-record', 'Change the sharing permissions of an individual record')
nested_share_record_share_parser.add_argument(
    'record', nargs='?', type=str, help='record path or UID')
nested_share_record_share_parser.add_argument(
    '-e', '--email', dest='email', metavar='EMAIL', action='append', required=True,
    help='account email. Repeatable: -e user1@example.com -e user2@example.com')
nested_share_record_share_parser.add_argument(
    '--contacts-only', dest='contacts_only', action='store_true',
    help='Share only to known targets')
nested_share_record_share_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Skip confirmation prompts')
nested_share_record_share_parser.add_argument(
    '-a', '--action', dest='action', choices=['grant', 'revoke', 'owner'],
    default='grant', help="sharing action. 'grant' if omitted (also updates existing shares); 'owner' transfers ownership")
nested_share_record_share_parser.add_argument(
    '-r', '--role', dest='role',
    choices=[
        'viewer', 'share-manager',
        'content-manager', 'content-share-manager', 'full-manager',
    ],
    help='permission role. Required for grant/update actions')
nested_share_record_share_parser.add_argument(
    '-R', '--recursive', dest='recursive', action='store_true',
    help='apply command to all records within a folder and its sub-folders')
nested_share_record_share_parser.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='display permission changes without committing them')
_sr_expire = nested_share_record_share_parser.add_mutually_exclusive_group()
_sr_expire.add_argument(
    '--expire-at', dest='expire_at', metavar='EXPIRE_AT', type=str,
    help='share expiration: never or UTC datetime (e.g. 2027-01-01T00:00:00Z)')
_sr_expire.add_argument(
    '--expire-in', dest='expire_in',
    metavar='<NUMBER>[(mi)nutes|(h)ours|(d)ays|(mo)nths|(y)ears]', type=str,
    help='share expiration: never or period (e.g. 30d, 6mo, 1y)')


nested_share_record_permission_parser = _make_parser(
    'nsf-record-permission', 'Modify the permissions of a record')
nested_share_record_permission_parser.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='Display the permissions changes without committing them')
nested_share_record_permission_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Apply permission changes without any confirmation')
nested_share_record_permission_parser.add_argument(
    '-R', '--recursive', dest='recursive', action='store_true',
    help='Apply permission changes to all sub-folders')
nested_share_record_permission_parser.add_argument(
    '-a', '--action', dest='action', choices=['grant', 'revoke'], required=True,
    help='The action being taken')
nested_share_record_permission_parser.add_argument(
    '-r', '--role', dest='role',
    choices=[
        'viewer', 'share-manager',
        'content-manager', 'content-share-manager', 'full-manager',
    ],
    help='Permission role to grant, or filter for revoke')
nested_share_record_permission_parser.add_argument(
    'folder', nargs='?', type=str, help='folder path or folder UID')


nested_share_record_transfer_parser = _make_parser(
    'nsf-transfer-record', 'Transfer record ownership to another user')
nested_share_record_transfer_parser.add_argument(
    'record_uids', nargs='+', type=str, help='Record UID(s) to transfer')
nested_share_record_transfer_parser.add_argument(
    'new_owner_email', type=str, help='Email address of the new owner')


# ══════════════════════════════════════════════════════════════════════════
# Detail / access parsers
# ══════════════════════════════════════════════════════════════════════════

nested_share_record_get_details_parser = _make_parser(
    'nsf-get-record-details',
    'Get record metadata (title, color, etc.) using v3 API')
nested_share_record_get_details_parser.add_argument(
    'record_uids', nargs='+', type=str, help='Record UIDs to get details for')
nested_share_record_get_details_parser.add_argument(
    '--format', dest='format', choices=['table', 'json'], default='table',
    help='Output format (default: table)')


# ══════════════════════════════════════════════════════════════════════════
# Shortcut parsers
# ══════════════════════════════════════════════════════════════════════════

nested_share_record_shortcut_list_parser = _make_parser(
    'nsf-shortcut list',
    'List Nested Share Records that appear in more than one folder.')
nested_share_record_shortcut_list_parser.add_argument(
    'target', nargs='?', type=str,
    help='Optional record UID/title or folder path/UID to filter results')
nested_share_record_shortcut_list_parser.add_argument(
    '--format', dest='format', choices=['table', 'csv', 'json'], default='table',
    help='Output format (default: table)')
nested_share_record_shortcut_list_parser.add_argument(
    '--output', dest='output', type=str,
    help='Path to output file (ignored for table format)')


nested_share_record_shortcut_keep_parser = _make_parser(
    'nsf-shortcut keep',
    'Keep a record only in one Nested Share Folder, removing it from all others.')
nested_share_record_shortcut_keep_parser.add_argument(
    'target', nargs='?', type=str, help='Record UID or title')
nested_share_record_shortcut_keep_parser.add_argument(
    'folder', nargs='?', type=str,
    help='Folder path or UID to keep the record in (defaults to current folder)')
nested_share_record_shortcut_keep_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Do not prompt before removing')


# ══════════════════════════════════════════════════════════════════════════
# Remove parsers
# ══════════════════════════════════════════════════════════════════════════

nested_share_record_rm_parser = _make_parser(
    'nsf-rm',
    'Remove a Nested Share Record. Supports owner-trash, folder-trash, or unlink.')
nested_share_record_rm_parser.add_argument(
    'records', nargs='+', metavar='RECORD',
    help='Record UID(s) or title(s) to remove (max 500 per invocation)')

nested_share_record_rm_parser.add_argument(
    '--folder', dest='folder_uid', metavar='FOLDER',
    help='Folder UID or name that provides context for the operation')
nested_share_record_rm_parser.add_argument(
    '--operation', '-o', dest='operation',
    choices=['owner-trash', 'folder-trash', 'unlink'], default='owner-trash',
    help='Removal operation (default: owner-trash)')
_nsf_rm_confirm = nested_share_record_rm_parser.add_mutually_exclusive_group()
_nsf_rm_confirm.add_argument(
    '--force', '-f', action='store_true',
    help='Skip the confirmation prompt and execute immediately after preview.')
_nsf_rm_confirm.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='Run the preview step only; do not delete anything.')


# ══════════════════════════════════════════════════════════════════════════
# Get parser
# ══════════════════════════════════════════════════════════════════════════

nested_share_get_parser = _make_parser(
    'nsf-get',
    'Get the details of a Nested Share Record or folder by UID or title')
nested_share_get_parser.add_argument(
    'uid', type=str, help='Record UID, folder UID, or title to look up')
nested_share_get_parser.add_argument(
    '--format', dest='format', choices=['detail', 'json'], default='detail',
    help='Output format: detail (default) or json')
nested_share_get_parser.add_argument(
    '--verbose', '-v', dest='verbose', action='store_true', default=False,
    help='Show full permission breakdown for each accessor')
nested_share_get_parser.add_argument(
    '--unmask', dest='unmask', action='store_true', default=False,
    help='Reveal masked field values (passwords, secrets)')
nested_share_get_parser.add_argument(
    '--include-dag', dest='include_dag', action='store_true', default=False,
    help='Include DAG/GraphSync information in json output (PAM record types only)')
