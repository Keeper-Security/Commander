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
import copy
import csv
import datetime
import io
import getpass
import json
import logging
import os
import re
import sys
import threading
import time
import warnings
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from urllib3.exceptions import InsecureRequestWarning

import xml.etree.ElementTree as ET

import requests
from tabulate import tabulate

from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from typing import Tuple, Optional, Iterable, Union, Dict, Callable, Any, List

from ..importer import (BaseImporter, BaseDownloadMembership, Record, SharedFolder, Folder, Attachment, Permission,
                        RecordField, RecordShare, BytesAttachment, Team, BaseDownloadRecordType, RecordType,
                        RecordTypeField)
from ...constants import EMAIL_PATTERN
from ...params import KeeperParams
from ... import record_types, vault, api

# Secret Server leaves restricted secrets out of /v1/secrets/lookup unless
# filter.includeRestricted=true. The API user needs this Delinea role permission
# or the lookup still omits them.
DELINEA_RESTRICTED_SECRET_PERMISSION = 'View Restricted Secret'

# Sent on GET /v1/secrets/{id} and /v1/secrets/{id}/fields/{slug} only when a
# plain read fails. For secrets that require checkout or a comment, they check
# the secret out, read it, check it back in, and supply the comment. Secrets
# that do not need them are read without a checkout or an audit comment.
SECRET_ACCESS_PARAMS = (
    ('autoCheckout', 'true'),
    ('autoCheckIn', 'true'),
    ('autoComment', 'Checking out'),
)


SECRET_ACCESS_PARAM_NAMES = frozenset(name for name, _ in SECRET_ACCESS_PARAMS)

# SSH key validation limits (in bytes when decoded)
SSH_KEY_MIN_LENGTH = 30
SSH_KEY_MAX_LENGTH = 5000


def _replace_query(endpoint, params):
    # type: (str, List[Tuple[str, str]]) -> str
    """Replace query string in endpoint with provided params, using proper URL encoding."""
    parts = urlparse(endpoint)
    return urlunparse(parts._replace(query=urlencode(params, quote_via=quote)))


def with_secret_access_params(endpoint):
    # type: (str) -> str
    """Add checkout and comment parameters to a secret read URL.

    Existing query parameters are kept. Any existing checkout or comment
    parameter is replaced, not duplicated.
    """
    query = parse_qsl(urlparse(endpoint).query, keep_blank_values=True)
    params = [(k, v) for k, v in query if k not in SECRET_ACCESS_PARAM_NAMES]
    params.extend(SECRET_ACCESS_PARAMS)
    return _replace_query(endpoint, params)



def build_secrets_lookup_query(folder_id=None, include_restricted=True):
    # type: (Optional[Union[int, str]], bool) -> str
    """Build the secrets lookup used by import.

    filter.includeRestricted is always on the endpoint and defaults to true.
    Secret Server treats it as a filter: the lookup still succeeds when the
    API user cannot see restricted secrets, and those IDs stay out of the list.
    Seeing them requires the Delinea role permission View Restricted Secret.
    """
    restricted = 'true' if include_restricted else 'false'
    if folder_id is None:
        return f'/v1/secrets/lookup?filter.includeRestricted={restricted}'
    return (
        f'/v1/secrets/lookup?filter.folderId={folder_id}'
        f'&filter.includeSubFolders=true&filter.includeRestricted={restricted}'
    )


def _ids_from_lookup_response(response):
    # type: (Any) -> List
    """Extract secret IDs from lookup response, handling non-list responses safely."""
    if not isinstance(response, list):
        return []
    return [item['id'] for item in response if isinstance(item, dict) and item.get('id') is not None]


def lookup_secret_ids(search, folder_ids=None, include_restricted=True):
    # type: (Callable[[str], Iterable[dict]], Optional[Iterable], bool) -> List
    """Return secret IDs from a tenant-wide or folder-filtered lookup."""
    if folder_ids:
        secret_ids = []
        for folder_id in dict.fromkeys(folder_ids):  # deduplicate folder IDs
            if folder_id is None:
                continue
            query = build_secrets_lookup_query(folder_id, include_restricted)
            secret_ids.extend(_ids_from_lookup_response(search(query)))
        # A secret can be returned by more than one folder lookup: a matched
        # folder may be a subfolder of another, and includeSubFolders=true
        # returns its secrets again. Keep the first occurrence of each ID.
        return list(dict.fromkeys(secret_ids))
    query = build_secrets_lookup_query(include_restricted=include_restricted)
    return _ids_from_lookup_response(search(query))


DEFAULT_SECRET_SHARE_WORKERS = 4
MAX_SECRET_SHARE_WORKERS = 16


class ThycoticMixin:
    @staticmethod
    def url_from_tenant(tenant):  # type: (Optional[str]) -> str
        """Build a Secret Server base URL from a shell variable. Nothing is printed."""
        tenant = (tenant or '').strip().rstrip('/')
        if not tenant:
            return ''
        if tenant.startswith('https://') or tenant.startswith('http://'):
            return tenant
        if '.' not in tenant:
            tenant = '{0}.secretservercloud.com'.format(tenant)
        return 'https://{0}/'.format(tenant)

    @staticmethod
    def expand_shell_value(value, envvars):  # type: (str, Optional[dict]) -> Optional[str]
        """Replace ${NAME} from the Commander shell. Do not print the result."""
        from keepercommander.commands.base import expand_cmd_args, parameter_pattern
        expanded = expand_cmd_args(value or '', envvars or {})
        missing = parameter_pattern.findall(expanded)
        if missing:
            logging.warning('Shell variable is not set: %s', ', '.join(missing))
            return None
        return expanded

    @staticmethod
    def connect_to_server(url=None, envvars=None):  # type: (Optional[str], Optional[dict]) -> ThycoticAuth
        if not url:
            url = input('...' + 'Thycotic Host or URL'.rjust(30) + ': ')
            if not url:
                logging.warning('Thycotic Host or URL is required')
                return

        url = ThycoticMixin.expand_shell_value(url, envvars)
        if not url:
            return
        url = ThycoticMixin.url_from_tenant(url)
        if not url.startswith('http'):
            url = f'https://{url}'
        username = input('...' + 'Thycotic Username'.rjust(30) + ': ')
        if not username:
            logging.warning('Thycotic username is required')
            return
        password = getpass.getpass(prompt='...' + 'Thycotic Password'.rjust(30) + ': ', stream=None)
        if not password:
            logging.warning('Thycotic password is required')
            return

        def request_totp():
            return input('...' + 'Enter TOTP Code'.rjust(30) + ': ')

        auth = ThycoticAuth(url)
        auth.authenticate(username, password, on_totp=request_totp)
        return auth

    @staticmethod
    def get_user_lookup(auth):  # type: (ThycoticAuth) -> Optional[Dict[int, Dict]]
        try:
            user_rs = auth.thycotic_search('/v1/users')
            return {x['id']: {
                'emailAddress': x.get('emailAddress', ''),
                'userName': x.get('userName', ''),
                'domainName': x.get('domainName', ''),
            } for x in user_rs}
        except:
            pass

    @staticmethod
    def get_group_lookup(auth, on_progress=None):
        # type: (ThycoticAuth, Optional[Callable[[int, int], None]]) -> Optional[Dict[int, Dict]]
        try:
            group_rs = auth.thycotic_search('/v1/groups')
            lookup = {}
            total = len(group_rs)
            for i in range(total):
                group = group_rs[i]
                group_id = group['id']
                g = {
                    'name': group['name'],
                    'users': [],   # type: List[int]
                    'groups': [],  # type: List[int]
                }
                if group.get('memberCount', 0) > 0:
                    member_rs = auth.thycotic_search(f'/v1/groups/{group_id}/users')
                    if on_progress:
                        on_progress(i, total)
                    g['users'].extend((x['userId'] for x in member_rs if 'userId' in x and x['userId'] > 0))
                    g['groups'].extend((x['groupId'] for x in member_rs if 'groupId' in x and x['groupId'] > 0))
                lookup[group_id] = g
            return lookup
        except:
            pass

    @staticmethod
    def _parse_choice(choice, count):
        if not isinstance(choice, str):
            return None
        choice = choice.strip()
        if not choice or any(c not in '0123456789,- ' for c in choice):
            return None
        selected = set()
        for part in choice.split(','):
            part = part.strip()
            if not part:
                return None
            if '-' in part:
                bounds = part.split('-')
                if len(bounds) != 2 or not all(b.strip().isdigit() for b in bounds):
                    return None
                start, end = int(bounds[0]), int(bounds[1])
                if start < 1 or end > count or start > end:
                    return None
                selected.update(range(start, end + 1))
            elif part.isdigit():
                number = int(part)
                if number < 1 or number > count:
                    return None
                selected.add(number)
            else:
                return None
        return selected or None

    @staticmethod
    def _compose_folder_path(folder, folders):
        # type: (Dict, Dict[int, Dict]) -> str
        folder_path = folder.get('folderName') or ''
        parent = folder
        seen = {folder.get('id')}
        while parent:
            parent_id = parent.get('parentFolderId')
            if isinstance(parent_id, int) and parent_id > 1 and parent_id in folders and parent_id not in seen:
                seen.add(parent_id)
                parent = folders[parent_id]
                folder_path = (parent.get('folderName') or '') + '\\' + folder_path
            else:
                parent = None
        return folder_path

    @staticmethod
    def _apply_folder_paths(folders):
        # type: (Dict[int, Dict]) -> None
        for folder in folders.values():
            folder['folderPath'] = ThycoticMixin._compose_folder_path(folder, folders)

    @staticmethod
    def interactive_folder_picker(folders):
        if not isinstance(folders, list):
            return None
        if not folders:
            return folders
        indexed = {}
        for folder in folders:
            if isinstance(folder, dict) and folder.get('id') is not None and 'folderName' in folder:
                indexed.setdefault(folder['id'], folder)
        if indexed:
            ThycoticMixin._apply_folder_paths(indexed)
        print('\nFolders Found:')
        print('─' * 50)
        for i, folder in enumerate(folders, start=1):
            if not isinstance(folder, dict):
                folder = {}
            name = folder.get('folderName') or ''
            folder_path = folder.get('folderPath')
            if isinstance(folder_path, str) and folder_path:
                path = folder_path.strip('\\').replace('\\', ' / ')
            else:
                path = name
            print(f"  [{i}] {name} - Path -> {path}")
        print()
        try:
            while True:
                print("Enter the folder numbers to import, separated by commas (e.g. 1-4,6,8-10).")
                print("Press Enter or 'A' to import all.")
                selected = ThycoticMixin._select_folders(folders, input('Enter your choice: '))
                if selected is None:
                    print('Invalid choice. Enter folder numbers, press Enter, or A to import all.')
                else:
                    return selected
        except EOFError:
            return folders
        except KeyboardInterrupt:
            raise Exception('Import canceled') from None

    @staticmethod
    def _select_folders(folders, choice):
        # type: (List[Dict], str) -> Optional[List[Dict]]
        choice = choice.strip() if isinstance(choice, str) else ''
        if choice == '' or choice.upper() == 'A':
            return folders
        selected = ThycoticMixin._parse_choice(choice, len(folders))
        if selected is None:
            return None
        return [folder for index, folder in enumerate(folders, start=1) if index in selected]

    @staticmethod
    def expand_folder_ids(folders, root_ids):
        # type: (Union[Dict[int, Dict], Iterable[Dict]], Iterable) -> set
        if not folders or not root_ids:
            return set()
        if isinstance(folders, dict):
            values = folders.values()
        else:
            values = folders
        children_by_parent = {}
        for folder in values:
            if not isinstance(folder, dict) or folder.get('id') is None:
                continue
            children_by_parent.setdefault(folder.get('parentFolderId'), []).append(folder.get('id'))
        seen = set()
        pending = []
        for root_id in root_ids:
            if root_id is not None and root_id not in seen:
                seen.add(root_id)
                pending.append(root_id)
        pos = 0
        while pos < len(pending):
            folder_id = pending[pos]
            pos += 1
            for child_id in children_by_parent.get(folder_id, ()):
                if child_id not in seen:
                    seen.add(child_id)
                    pending.append(child_id)
        return seen

    @staticmethod
    def get_secret_ids(auth, folder_ids, query=None):
        # type: (ThycoticAuth, Optional[Iterable], Optional[str]) -> List
        """Bridge function to get secret IDs for selected folders with restricted secret support.

        Args:
            auth: Thycotic authentication object
            folder_ids: Folder IDs to query
            query: Legacy parameter (ignored; use build_secrets_lookup_query instead)

        Returns:
            List of secret IDs from selected folders with includeRestricted=true
        """
        if query is not None:
            logging.warning('Legacy query parameter provided but is not used; using folder_ids instead')
        ids = [folder_id for folder_id in (folder_ids or ()) if folder_id is not None]
        if not ids:
            return []
        return lookup_secret_ids(auth.thycotic_search, ids, include_restricted=True)

    @staticmethod
    def _construct_folders(folder_rs):
        # type: (Any) -> Dict[int, Dict]
        if not isinstance(folder_rs, list):
            return {}
        folders = {}   # type: Dict[int, Dict[str, Any]]
        for x in folder_rs:
            if not isinstance(x, dict) or x.get('id') is None or x['id'] in folders:
                continue
            folders[x['id']] = {
                'id': x['id'],
                'folderName': x.get('folderName') or '',
                'inheritPermissions': x.get('inheritPermissions', True),
                'parentFolderId': x.get('parentFolderId'),
            }
        ThycoticMixin._apply_folder_paths(folders)
        return folders

    @staticmethod
    def _load_folders(auth):
        # type: (ThycoticAuth) -> Dict[int, Dict]
        folder_rs = auth.thycotic_search('/v1/folders')
        folders = ThycoticMixin._construct_folders(folder_rs)
        logging.debug('Loaded %d folders', len(folders))
        logging.debug('Folder path built')
        return folders

    @staticmethod
    def get_folders(auth, skip_permissions=False):
        # type: (ThycoticAuth, bool) -> Optional[Dict[int, Dict]]
        logging.debug('Enter get_folders')
        folders = ThycoticMixin._load_folders(auth)

        if 1 in folders:
            del folders[1]


        if not skip_permissions:        # load permissions for shared folders
            folder_ids = [x['id'] for x in folders.values() if (x.get('inheritPermissions') is False) and x['id'] != 1]
            for pos in range(len(folder_ids)):
                folder_id = folder_ids[pos]
                if pos % 10 == 0:
                    logging.debug('Permission check progress: %d of %d', pos, len(folder_ids))

                folder = folders.get(folder_id)
                if not folder:
                    continue

                permissions = auth.thycotic_search(f'/v1/folder-permissions?filter.folderId={folder_id}')
                if isinstance(permissions, list):
                    if len(permissions) == 1:
                        permission = permissions[0]
                        user_id = permission.get('userId') or 0
                        if user_id > 0:
                            permissions = []
                else:
                    permissions = []
                if len(permissions) > 0:
                    folder['permissions'] = permissions
                else:
                    folder['inheritPermissions'] = True

            # check permissions are really modified
            folder_ids = [x['id'] for x in folders.values() if (x.get('inheritPermissions') is False) and x['id'] != 1]
            folder_ids.sort(reverse=False)
            for folder_id in folder_ids:
                folder = folders.get(folder_id)
                if not folder:
                    continue
                permissions = folder.get('permissions')
                if not isinstance(permissions, list):
                    continue

                user_permissions = {x['userId']: (x['folderAccessRoleId'], x['secretAccessRoleId']) for x in permissions if (x.get('userId') or 0) > 0}
                group_permissions = {x['groupId']: (x['folderAccessRoleId'], x['secretAccessRoleId']) for x in permissions if (x.get('groupId') or 0) > 0}
                parent_folder_id = folder.get('parentFolderId') or 0
                while parent_folder_id in folders:
                    parent_folder = folders[parent_folder_id]
                    if parent_folder.get('inheritPermissions') is True:
                        parent_folder_id = parent_folder.get('parentFolderId') or 0
                    else:
                        break
                if parent_folder_id in folders:
                    parent_folder = folders[parent_folder_id]
                    parent_permissions = parent_folder.get('permissions')
                    if not isinstance(parent_permissions, list):
                        continue
                    if len(parent_permissions) != len(permissions):
                        continue
                    parent_user_permissions = {x['userId']: (x['folderAccessRoleId'], x['secretAccessRoleId'])
                                               for x in parent_permissions if (x.get('userId') or 0) > 0}
                    parent_group_permissions = {x['groupId']: (x['folderAccessRoleId'], x['secretAccessRoleId'])
                                                for x in parent_permissions if (x.get('groupId') or 0) > 0}
                    if len(user_permissions) != len(parent_user_permissions):
                        continue
                    if len(group_permissions) != len(parent_group_permissions):
                        continue

                    are_same = True
                    for user_id, user_permission in user_permissions.items():
                        if user_id not in parent_user_permissions:
                            are_same = False
                            break
                        if user_permission != parent_user_permissions[user_id]:
                            are_same = False
                            break
                    for group_id, group_permission in group_permissions.items():
                        if group_id not in parent_group_permissions:
                            are_same = False
                            break
                        if group_permission != parent_group_permissions[group_id]:
                            are_same = False
                            break
                    if are_same:
                        del folder['permissions']
                        folder['inheritPermissions'] = True
        return folders

  

    @staticmethod
    def _secret_role_flags(role):
        # type: (str) -> Optional[Tuple[bool, bool]]
        """Map a Secret Server secret role to Keeper can_edit, can_share.

        List and View are both read-only. Keeper direct shares have no
        title-only role, so List cannot be kept apart from View.
        """
        role = (role or '').strip().casefold()
        if role == 'owner':
            return True, True
        if role == 'edit':
            return True, False
        if role in ('view', 'list'):
            return False, False
        return None

    @staticmethod
    def _remember_email(emails, user_id, email):
        email = (email or '').strip()
        if not email or user_id in (None, ''):
            return
        emails[user_id] = email
        try:
            emails[int(user_id)] = email
        except (TypeError, ValueError):
            pass

    @staticmethod
    def provisioned_emails(auth):
        # type: (ThycoticAuth) -> Dict
        """Map a Delinea user id to an email. No users are created.

        Folder membership already resolves these ids through the user list.
        A failed detail fetch must not throw that map away.
        """
        emails = {}
        for user_id, user in (ThycoticMixin.get_user_lookup(auth) or {}).items():
            if not isinstance(user, dict):
                continue
            email = (user.get('emailAddress') or '').strip()
            if not email:
                username = (user.get('userName') or '').strip()
                if '@' in username:
                    email = username
            ThycoticMixin._remember_email(emails, user_id, email)
        try:
            users = ThycoticImporter()._prepare_thycotic_users(auth) or []
        except Exception as exc:
            logging.info('Delinea users for secret shares: %s', exc)
            users = []
        for user in users:
            ThycoticMixin._remember_email(emails, user.get('id'), user.get('email'))
        return emails

    @staticmethod
    def _email_for_user(emails, user_id):
        email = emails.get(user_id) or ''
        if email or user_id in (None, '', 0):
            return email
        try:
            return emails.get(int(user_id)) or ''
        except (TypeError, ValueError):
            return ''

    @staticmethod
    def shares_from_secret_permissions(rows, emails, groups=None):
        # type: (list, Dict, Optional[Dict]) -> List[RecordShare]
        """Map permission rows to record shares for provisioned emails.

        Group flattening: Keeper record shares are per user, so a group row
        becomes one direct share per member that has a provisioned email.
        - The group link is not kept. Users added to the Delinea group after
          the import get no access, and removing a member does not revoke it.
        - Only direct members are shared. Nested groups are not expanded.
        - A user reached through several rows (directly and via groups) gets
          one share with the highest role: Owner > Edit > View/List.

        Rows with a role outside Owner/Edit/View/List are skipped. This does
        not change the shared-folder membership.
        """
        if not isinstance(rows, list):
            return []
        groups = groups or {}
        grants = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            flags = ThycoticMixin._secret_role_flags(row.get('secretAccessRoleName') or '')
            if flags is None:
                continue
            user_ids = []
            user_id = row.get('userId') or 0
            group_id = row.get('groupId') or 0
            direct_email = ''
            for key in ('emailAddress', 'userName', 'knownAs'):
                candidate = (row.get(key) or '')
                if isinstance(candidate, str) and '@' in candidate:
                    direct_email = candidate.strip()
                    break
            if user_id:
                user_ids.append(user_id)
            elif direct_email:
                previous = grants.get(direct_email)
                if previous is None:
                    grants[direct_email] = flags
                else:
                    grants[direct_email] = (previous[0] or flags[0], previous[1] or flags[1])
                continue
            elif group_id:
                group = groups.get(group_id) or {}
                if not group:
                    try:
                        group = groups.get(int(group_id)) or {}
                    except (TypeError, ValueError):
                        group = {}
                user_ids.extend(group.get('users') or [])
            for member_id in user_ids:
                email = ThycoticMixin._email_for_user(emails, member_id)
                if not email and direct_email and member_id == user_id:
                    email = direct_email
                if not email:
                    continue
                previous = grants.get(email)
                if previous is None:
                    grants[email] = flags
                else:
                    grants[email] = (previous[0] or flags[0], previous[1] or flags[1])
        return [
            RecordShare(email, can_edit, can_share)
            for email, (can_edit, can_share) in sorted(grants.items())
        ]

    @staticmethod
    def folder_permission_rows(auth, folders, folder_id, cache=None):
        # type: (ThycoticAuth, Dict, int, Optional[Dict]) -> list
        """Permission rows for a secret that inherits, walking up to a folder that has them.

        cache maps a folder id to the rows it returned, so secrets in the same
        folder do not fetch it again. A failed fetch is not cached.
        """
        seen = set()
        current = folder_id
        while current and current not in seen:
            seen.add(current)
            if cache is not None and current in cache:
                rows = cache[current]
            else:
                try:
                    rows = auth.thycotic_search('/v1/folder-permissions?filter.folderId={0}'.format(current))
                    if cache is not None:
                        cache[current] = rows
                except Exception as exc:
                    logging.info('folder-permissions %s: %s', current, exc)
                    rows = []
            if isinstance(rows, list) and rows:
                return rows
            folder = folders.get(current) if isinstance(folders, dict) else None
            parent = folder.get('parentFolderId') if isinstance(folder, dict) else 0
            if not parent or parent == current:
                break
            current = parent
        return []

    @staticmethod
    def all_secret_permission_rows(auth):
        # type: (ThycoticAuth) -> Optional[Dict[Any, list]]
        """Every secret-permission row from one paged search, grouped by secretId.

        Returns None when the search fails or returns nothing, so callers fall
        back to one secret-permissions request per secret.
        """
        try:
            rows = auth.thycotic_search('/v1/secret-permissions')
        except Exception as exc:
            logging.warning('Bulk secret-permissions failed, loading them per secret: %s', exc)
            return None
        by_secret = {}  # type: Dict[Any, list]
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get('secretId'):
                by_secret.setdefault(row['secretId'], []).append(row)
        if not by_secret:
            logging.info('Bulk secret-permissions returned no rows, loading them per secret')
            return None
        return by_secret

    @staticmethod
    def permission_rows_for_secret(auth, folders, secret, folder_cache=None, secret_permissions=None):
        # type: (ThycoticAuth, Dict, dict, Optional[Dict], Optional[Dict[Any, list]]) -> list
        """Rows that name who can open this secret.

        Secret Server often omits inheritPermissions on the secret record.
        Some secrets then return their users from secret-permissions, and
        others only from the folder. Keep whichever list is non-empty. A
        secret that inherits prefers the folder's secret roles.

        secret_permissions is the result of all_secret_permission_rows. When
        given, it replaces the per-secret secret-permissions request.
        """
        folder_id = secret.get('folderId') if isinstance(secret, dict) else None
        secret_id = secret.get('id') if isinstance(secret, dict) else None
        inherits = isinstance(secret, dict) and secret.get('inheritPermissions') is True

        def secret_rows():
            if not secret_id:
                return []
            if secret_permissions is not None:
                return list(secret_permissions.get(secret_id) or [])
            try:
                rows = auth.thycotic_search(
                    '/v1/secret-permissions?filter.secretId={0}'.format(secret_id))
            except Exception as exc:
                logging.warning('secret-permissions %s: %s', secret_id, exc)
                return []
            return rows if isinstance(rows, list) else []

        if inherits:
            rows = ThycoticMixin.folder_permission_rows(auth, folders, folder_id, folder_cache)
            if rows:
                return rows
            return secret_rows()
        rows = secret_rows()
        if rows:
            return rows
        return ThycoticMixin.folder_permission_rows(auth, folders, folder_id, folder_cache)

    @staticmethod
    def _fetch_secret_permissions(auth, folders, secret_id, folder_cache, secret_permissions=None):
        # type: (ThycoticAuth, Dict, Any, Dict, Optional[Dict[Any, list]]) -> Tuple[Optional[dict], list]
        """Fetch one secret and its permission rows. Runs on a worker thread."""
        secret = auth.thycotic_entity('/v1/secrets/{0}'.format(secret_id)) or {}
        if not isinstance(secret, dict):
            return None, []
        secret['id'] = secret.get('id') or secret_id
        return secret, ThycoticMixin.permission_rows_for_secret(
            auth, folders, secret, folder_cache, secret_permissions)

    @staticmethod
    def secret_share_workers(value):
        # type: (Any) -> int
        """Worker count for loading secret permissions: default 4, clamped to 1..16."""
        if value is None:
            return DEFAULT_SECRET_SHARE_WORKERS
        try:
            return min(max(int(value), 1), MAX_SECRET_SHARE_WORKERS)
        except (TypeError, ValueError):
            return DEFAULT_SECRET_SHARE_WORKERS

    @staticmethod
    def _fetch_in_order(fetch, items, workers):
        # type: (Callable[[Any], Any], Iterable[Any], int) -> Iterable[Tuple[Any, Any]]
        """Yield (item, fetch(item)) in input order, with at most `workers` fetches running.

        fetch must not raise. At most workers * 2 fetches are queued, so memory
        stays bounded. With one worker everything runs on the calling thread.
        If the caller stops early, queued fetches are cancelled and only the
        running ones are waited for.
        """
        if workers <= 1:
            for item in items:
                yield item, fetch(item)
            return
        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='thycotic-shares')
        items = iter(items)
        pending = deque()
        try:
            for item in items:
                pending.append((item, executor.submit(fetch, item)))
                if len(pending) >= workers * 2:
                    break
            while pending:
                item, future = pending.popleft()
                result = future.result()
                for next_item in items:
                    pending.append((next_item, executor.submit(fetch, next_item)))
                    break
                yield item, result
        finally:
            for _item, future in pending:
                future.cancel()
            executor.shutdown(wait=True)

    @staticmethod
    def _warn_unmapped_roles(title, secret_id, rows):
        # type: (str, Any, list) -> bool
        """Log the roles on this secret that have no Keeper equivalent. True if any were found."""
        roles = sorted({
            (item.get('secretAccessRoleName') or '').strip() or '(unnamed)'
            for item in rows or []
            if isinstance(item, dict) and ThycoticMixin._secret_role_flags(item.get('secretAccessRoleName')) is None
        })
        if roles:
            logging.warning(
                'Secret "%s" (%s): role(s) %s cannot be mapped to Keeper permissions; '
                'those users and groups were not shared, share them manually',
                title, secret_id, ', '.join(roles))
        return bool(roles)

    @staticmethod
    def _secret_folder_path(folders, folder_id):
        # type: (Optional[Dict], Any) -> str
        """Delinea folder path for folder_id, whether the folder map is keyed by int or str."""
        if not isinstance(folders, dict):
            return ''
        folder = folders.get(folder_id)
        if not isinstance(folder, dict):
            try:
                folder = folders.get(int(folder_id))
            except (TypeError, ValueError):
                folder = None
        return (folder.get('folderPath') or '') if isinstance(folder, dict) else ''

    @staticmethod
    def _secret_share_record(title, folder_path, shares):
        # type: (str, str, List[RecordShare]) -> Record
        record = Record()
        record.title = title
        if folder_path:
            record_folder = Folder()
            record_folder.path = folder_path
            record.folders = [record_folder]
        record.shares = shares
        return record

    @staticmethod
    def iter_secret_shares(auth, folders, workers=None):
        # type: (ThycoticAuth, Optional[Dict], Optional[int]) -> Iterable[Record]
        """Yield one record per secret with the users who can open it.

        A secret that inherits uses its folder's secret roles. Any other
        secret uses GET /v1/secret-permissions, and falls back to the folder
        secret roles when that list is empty. apply-membership grants the
        resulting shares onto the Keeper record. Folder membership is not
        changed.

        Secret permissions come from one bulk search when the server allows
        it, otherwise one request per secret. Secret reads run on a small
        worker pool (`workers`, default 4, 1 = sequential); records are
        yielded in lookup order. Group lookup and record building stay on the
        calling thread.

        A secret whose fetch fails is logged and skipped. The rest still load.
        """
        emails = ThycoticMixin.provisioned_emails(auth)
        groups = None
        try:
            lookup = auth.thycotic_search('/v1/secrets/lookup') or []
        except Exception as exc:
            logging.warning('secret lookup for permissions: %s', exc)
            return
        if not isinstance(lookup, list):
            lookup = []
        folders = folders or {}
        entries = [(row, row.get('id')) for row in lookup if isinstance(row, dict) and row.get('id')]
        written = 0
        seen = 0
        unmapped = 0
        failed = 0
        custom_role_secrets = 0
        # Shared by workers. Entries are only added, never removed; two workers can at
        # worst fetch the same uncached folder once each.
        folder_cache = {}
        secret_permissions = ThycoticMixin.all_secret_permission_rows(auth) if entries else None
        workers = min(ThycoticMixin.secret_share_workers(workers), max(len(entries), 1))
        logging.info('Loading secret permissions for %d secrets (%d worker(s))', len(entries), workers)

        def fetch(entry):
            try:
                secret, rows = ThycoticMixin._fetch_secret_permissions(
                    auth, folders, entry[1], folder_cache, secret_permissions)
                return secret, rows, None
            except Exception as exc:
                return None, [], exc

        for (row, secret_id), (secret, perm_rows, error) in ThycoticMixin._fetch_in_order(fetch, entries, workers):
            if error is not None:
                logging.warning('Secret %s permissions skipped: %s', secret_id, error)
                failed += 1
                continue
            if secret is None:
                continue
            seen += 1
            title = secret.get('name') or row.get('name') or ''
            if not title:
                continue
            if ThycoticMixin._warn_unmapped_roles(title, secret_id, perm_rows):
                custom_role_secrets += 1
            if groups is None and any(isinstance(item, dict) and item.get('groupId') for item in perm_rows or []):
                groups = ThycoticMixin.get_group_lookup(auth) or {}
            shares = ThycoticMixin.shares_from_secret_permissions(perm_rows, emails, groups)
            if not shares:
                if perm_rows:
                    unmapped += 1
                continue
            written += 1
            yield ThycoticMixin._secret_share_record(
                title, ThycoticMixin._secret_folder_path(folders, secret.get('folderId')), shares)
        logging.info('Loaded secret permissions for %d secrets', written)
        if failed:
            logging.warning('%d secret(s) were skipped because their permissions could not be fetched.', failed)
        if custom_role_secrets:
            logging.warning('%d secret(s) have custom roles that were not shared; see the warnings above.',
                            custom_role_secrets)
        if written == 0:
            logging.warning(
                'No secret permission lists downloaded (%d secrets, %d had permission rows that matched '
                'no provisioned Keeper user).',
                seen, unmapped)


def parse_thycotic_import_target(filename):
    """Return (username, base_url) for an import --format=thycotic target.

    user@https://host/ must not be prefixed with another scheme. Doing so
    sends the token request to a host named https.
    """
    filename = (filename or '').strip()
    if filename.startswith('https://') or filename.startswith('http://'):
        return '', filename
    username, sep, host = filename.partition('@')
    if not sep or not host.strip():
        return None
    host = ThycoticMixin.url_from_tenant(host.strip())
    if not host:
        return None
    return username, host


class ThycoticImporter(BaseImporter, ThycoticMixin):
    # Same end-of-import terminal summary CyberArk prints (Import finished, skipped rows).
    verbose_import_summary = True

    def __init__(self):
        super().__init__()
        self._last_keep_alive = int(datetime.datetime.utcnow().timestamp())
        self._keep_alive_period = 30 * 60

    def support_folder_filter(self):
        return True
    
    def support_add_users(self):
        return True
    
    @staticmethod
    def pop_field(fields, key):  # type: (Dict[str, Dict[str, str]], str) -> Tuple[str, Optional[Dict[str, str]]]
        field = fields.pop(key, None)
        value = field.get('itemValue', '') if isinstance(field, dict) else ''
        return str(value), field

    @staticmethod
    def pop_field_value(fields, key):  # type: (Dict[str, Dict[str, str]], str) -> str
        return ThycoticImporter.pop_field(fields, key)[0]

    @staticmethod
    def request_totp():
        return input('Enter TOTP code: '.rjust(25))

    def _send_keep_alive_if_needed(self, params):   # type: (KeeperParams) -> None
        if isinstance(params, KeeperParams):
            now = int(datetime.datetime.utcnow().timestamp())
            if (now - self._last_keep_alive) > self._keep_alive_period:
                self._last_keep_alive = now
                try:
                    api.send_keepalive(params)
                except:
                    pass

    @staticmethod
    def _user_field(user, key):  # type: (dict, str) -> str
        return str(user.get(key) or '').strip()

    @staticmethod
    def _extract_user_email(user):
        """Return the user's emailAddress, or an empty string.

        The list payload uses emailAddress. Other casings of the key are
        accepted too. An empty value does not hide another key.
        """
        if not isinstance(user, dict):
            return ''
        value = user.get('emailAddress')
        if isinstance(value, str) and value.strip():
            return value.strip()
        for key, value in user.items():
            if str(key).casefold() == 'emailaddress' and isinstance(value, str) and value.strip():
                return value.strip()
        return ''

    def _prepare_thycotic_users(self, auth):  # type: (ThycoticAuth) -> List[dict]
        """Fetch Delinea users that have an email address, including inactive users.

        Application accounts are omitted.
        When the user list has no email, the user detail endpoint is tried once.
        """
        all_users = auth.thycotic_search('/v1/users?filter.includeInactive=true')
        result = []
        skipped_application = 0
        skipped_no_email = 0
        for user in all_users or []:
            if not isinstance(user, dict):
                continue
            if user.get('isApplicationAccount') is True:
                skipped_application += 1
                continue
            email = self._extract_user_email(user)
            user_id = user.get('id')
            source = user
            if not email and user_id not in (None, ''):
                try:
                    detail = auth.thycotic_entity('/v1/users/{0}'.format(user_id))
                except Exception as exc:
                    logging.warning('Thycotic user %s: %s', user_id, exc)
                    detail = None
                if isinstance(detail, dict):
                    if detail.get('isApplicationAccount') is True:
                        skipped_application += 1
                        continue
                    email = self._extract_user_email(detail)
                    source = detail
            if not email:
                skipped_no_email += 1
                continue
            username = str(source.get('userName') or user.get('userName') or '').strip()
            display = str(source.get('displayName') or user.get('displayName') or '').strip()
            result.append({
                'id': user_id,
                'username': username,
                'name': display or username or email,
                'email': email,
            })
        if skipped_application:
            logging.info('Skipped %d Thycotic application account(s)', skipped_application)
        if skipped_no_email:
            logging.info('Skipped %d Thycotic user(s) with no email address', skipped_no_email)
        logging.info('Found %d Thycotic user(s) with an email address', len(result))
        return result

    def _load_existing_keeper_users(self, params):  # type: (KeeperParams) -> list
        try:
            if not getattr(params, 'enterprise', None):
                api.query_enterprise(params)
            enterprise_data = getattr(params, 'enterprise', None)
            if not isinstance(enterprise_data, dict):
                raise ValueError('enterprise data is unavailable')
            return [
                {
                    'email': self._user_field(user, 'email') or self._user_field(user, 'username'),
                    'status': user.get('status') or 'active',
                }
                for user in enterprise_data.get('users') or []
                if isinstance(user, dict)
            ]
        except Exception as e:
            logging.warning('Failed to load existing Keeper users: %s', e)
            return []

    def _create_keeper_user(self, params, email, name):
        # type: (KeeperParams, str, str) -> Optional[str]
        """Pre-activate one Keeper user."""
        from ...commands.enterprise_create_user import CreateEnterpriseUserCommand
        try:
            creator = CreateEnterpriseUserCommand()
            return creator.execute(params, email=email, name=name)
        except Exception as e:
            logging.warning('Could not create enterprise user "%s": %s', email, e)
            return None

    def _create_enterprise_users(self, params, thycotic_users):
        # type: (KeeperParams, List[dict]) -> dict
        def row(user, flag, **extra):
            item = {
                'username': str(user.get('username') or ''),
                'email': self._user_field(user, 'email'),
                'flag': flag,
            }
            item.update(extra)
            return item

        seen = set()
        outcomes = []
        existing_users = self._load_existing_keeper_users(params)
        existing_by_email = {}
        for existing in existing_users:
            key = (existing.get('email') or '').strip().casefold()
            if key and key not in existing_by_email:
                existing_by_email[key] = existing
        is_valid_email = re.compile(EMAIL_PATTERN).match
        for user in thycotic_users or []:
            if not isinstance(user, dict):
                continue
            email = self._user_field(user, 'email')
            email_key = email.casefold()
            if email_key in seen:
                continue
            user_exist = existing_by_email.get(email_key)
            if user_exist:
                seen.add(email_key)
                status = user_exist.get('status') or 'active'
                outcomes.append(row(user, 'existing', status=status))
            elif is_valid_email(email):
                seen.add(email_key)
                name = self._user_field(user, 'name') or self._user_field(user, 'username') or email
                created = self._create_keeper_user(params, email, name)
                if created:
                    outcomes.append(row(user, 'created'))
                else:
                    outcomes.append(row(user, 'failed', reason='user was not created'))
            else:
                outcomes.append(row(user, 'skipped', reason='invalid email'))
        return {'users': outcomes}

    def _print_thycotic_user_report(self, report):  # type: (dict) -> None
        users = report.get('users') or []
        counts = {'created': 0, 'existing': 0, 'skipped': 0, 'failed': 0}
        for user in users:
            flag = str((user or {}).get('flag') or 'skipped')
            if flag in counts:
                counts[flag] += 1
        logging.info(
            'Thycotic users: created %d, existing %d, skipped %d, failed %d',
            counts['created'], counts['existing'], counts['skipped'], counts['failed'],
        )
        for user in users:
            if not isinstance(user, dict):
                continue
            flag = str(user.get('flag') or 'skipped')
            label = user.get('email') or user.get('username') or '(no email)'
            detail = user.get('reason') or ''
            if not detail and flag == 'existing' and user.get('status'):
                detail = str(user.get('status'))
            suffix = ' ({0})'.format(detail) if detail else ''
            logging.info('[%s] %s%s', flag, label, suffix)

    def _preview_thycotic_users(self, auth):
        # type: (ThycoticAuth) -> None
        """Fetch Delinea users and print them. Does not create Keeper users."""
        logging.info('Dry run: fetching Thycotic users (no Keeper users will be created)...')
        try:
            thycotic_users = self._prepare_thycotic_users(auth)
        except Exception as e:
            logging.warning('Failed to fetch Thycotic users: %s', e)
            return
        if not thycotic_users:
            logging.info('No Thycotic users are available to migrate.')
            return
        rows = [
            {
                'Username': user.get('username') or '',
                'Email': user.get('email') or '',
                'Name': user.get('name') or '',
            }
            for user in thycotic_users
        ]
        logging.info(f'Thycotic users available to migrate ({len(rows)}):')
        logging.info(tabulate(rows, headers='keys'))

    def _migrate_thycotic_users(self, auth, params):
        # type: (ThycoticAuth, KeeperParams) -> None
        """Provision Delinea users as pre-activated Keeper users, then continue the import.

        A user-fetch failure does not abort secret migration.
        """
        logging.info('Migrating Thycotic users to Keeper')
        try:
            thycotic_users = self._prepare_thycotic_users(auth)
        except Exception as e:
            logging.warning('Failed to fetch Thycotic users: %s', e)
            logging.warning('Continuing import without creating Keeper users.')
            return
        report = self._create_enterprise_users(params, thycotic_users)
        self._print_thycotic_user_report(report)

    def do_import(self, filename, **kwargs):
        # type: (ThycoticImporter, str, ...) -> Iterable[Union[Record, SharedFolder]]
        loaded_record_types = {}
        params = kwargs.get('params')
        if isinstance(params, KeeperParams):
            if params.record_type_cache:
                for rts in params.record_type_cache.values():
                    try:
                        rto = json.loads(rts)
                        if '$id' in rto and 'fields' in rto:
                            loaded_record_types[rto['$id']] = rto['fields']
                    except:
                        pass

        parsed = parse_thycotic_import_target(filename)
        if not parsed:
            logging.warning('Thycotic connection parameters:')
            logging.warning('  <Username>@<Secret server host>.')
            logging.warning('  https://<Secret server host>/<Endpoint>. Full URL')
            raise Exception('Import canceled')
        username, host = parsed

        username_prompt = 'Thycotic Username: '.rjust(25)
        if not username:
            username = input(username_prompt)
            if not username:
                raise Exception('Import canceled')
        else:
            print(username_prompt + username)

        password_prompt = 'Thycotic Password: '.rjust(25)
        password = getpass.getpass(prompt=password_prompt, stream=None)
        if not password:
            raise Exception('Import canceled')

        auth = ThycoticAuth(host)
        auth.proxy = params.rest_context.proxies if params else None
        auth.authenticate(username, password, ThycoticImporter.request_totp)

        # Pre-activate users before secrets are imported so later migration steps
        # can share data to accounts that already exist.
        if kwargs.get('add_users') is True:
            if kwargs.get('dry_run') is True:
                self._preview_thycotic_users(auth)
            else:
                self._migrate_thycotic_users(auth, params)

        totp_codes = {}
        csv_file = 'secrets-export.csv'
        if not os.path.isfile('secrets-export.csv'):
            home_dir = os.path.expanduser('~/')
            home_dir = os.path.join(home_dir, csv_file)
            if os.path.isfile(home_dir):
                csv_file = home_dir
        if os.path.isfile(csv_file):
            print('"secrets-export.csv" file is detected. ', flush=True, end='')

            try:
                totp_index = -1
                with open(csv_file, "r", encoding='utf-8-sig') as csvfile:
                    reader = csv.reader(csvfile)
                    for row in reader:
                        if row[0] == 'Secret Name':
                            try:
                                totp_index = row.index('TOTP Key')
                            except:
                                pass
                        elif totp_index > 0:
                            if totp_index < len(row) and row[totp_index]:
                                totp_codes[row[0]] = row[totp_index]
            except Exception:
                pass
            print(f'Loaded {len(totp_codes)} code(s)', flush=True)

        self._send_keep_alive_if_needed(params)
        filter_folder = kwargs.get('filter_folder')
        constructed_folders = ThycoticImporter._load_folders(auth)
        picked_folder_ids = None
        if not filter_folder and sys.stdin and sys.stdin.isatty():
            folder_choices = list(constructed_folders.values())
            picked_folders = ThycoticImporter.interactive_folder_picker(folder_choices)
            if picked_folders is not None and picked_folders is not folder_choices:
                picked_folder_ids = list(dict.fromkeys(folder['id'] for folder in picked_folders))

        # Delete the system folder (ID 1)
        if 1 in constructed_folders:
            del constructed_folders[1]
        folders = constructed_folders

        # Determine which folders to query
        matched_folder_ids = None
        if filter_folder:
            # Handle --filter-folder argument
            if filter_folder == 'Personal Folders':
                matched_folder_ids = [1]
            else:
                matched_folder_ids = [x['id'] for x in folders.values() if x['folderName'].lower() == filter_folder.lower()]
                if len(matched_folder_ids) == 0:
                    logging.warning('Folder \"%s\" not found', filter_folder)
                    return  # Fail closed: don't import if filter folder not found
        elif picked_folder_ids is not None:
            # Use interactively selected folders
            matched_folder_ids = picked_folder_ids

        # Query secrets with restricted secret support
        if matched_folder_ids:
            # Expand selected folder IDs to include subfolders
            folder_ids = ThycoticImporter.expand_folder_ids(folders, matched_folder_ids)
            folders = {i: x for i, x in folders.items() if i in folder_ids}
            # Use lookup_secret_ids for restricted secret support
            secrets_ids = lookup_secret_ids(auth.thycotic_search, matched_folder_ids, include_restricted=True)
        else:
            # Tenant-wide lookup with restricted secret support
            secrets_ids = lookup_secret_ids(auth.thycotic_search, include_restricted=True)
        # secret_ids arg
        debug_ids = kwargs.get('secret_ids')
        if debug_ids is not None:
          # Convert CLI string input into list
          if isinstance(debug_ids,str):
              debug_ids = debug_ids.replace(' ','').split(',')
          # Handle secret IDs list
          if isinstance(debug_ids,list):
              # Deduplicate
              debug_ids = list(set(debug_ids))
              # Check whether secrets were found in the lookup
              stringified_secrets_ids = [str(x) for x in secrets_ids]
              stringified_debug_ids = [str(x) for x in debug_ids]
              found_secrets = [x for x in stringified_debug_ids if x in stringified_secrets_ids]
              logging.info(f'From the specified {len(debug_ids)} secret IDs, {len(found_secrets)} were found in the secret server lookup.')
              logging.info(', '.join(found_secrets))
              
              # Replace import list with specified IDs
              secrets_ids = debug_ids
          else:
              # Quit if secret IDs != list
              logging.warning('Invalid input for secret IDs, exiting.')
              return

        self._send_keep_alive_if_needed(params)
        print(f'Loading {len(secrets_ids)} Records ', flush=True, end='')
        secrets = []
        skipped_secrets = []
        skipped_fields = []
        for secret_id in secrets_ids:
            secret, error = auth.thycotic_secret(f'/v1/secrets/{secret_id}')
            if secret is None:
                status, message = error or ('N/A', 'Empty response')
                skipped_secrets.append({'ID': secret_id, 'Status': status, 'Message': message})
                continue
            secrets.append(secret)
            if len(secrets) % 10 == 9:
                print('.', flush=True, end='')
            if len(secrets) % 100 == 99:
                self._send_keep_alive_if_needed(params)

        self._send_keep_alive_if_needed(params)
        for secret in secrets:
            record = Record()
            record.title = secret.get('name', '')
            items = {x['slug']: x for x in secret.get('items', [])}
            folder_id = secret.get('folderId')
            if folder_id in folders:
                folder = folders[folder_id]
                path = folder.get('folderPath', '')
                if path:
                    record.folders = []
                    record_folder = Folder()
                    record_folder.path = path
                    record.folders.append(record_folder)

            template_name = secret.get('secretTemplateName', '')
            template_name = template_name[:32]
            if template_name in loaded_record_types:
                record.type = template_name
            elif template_name in ('Pin', 'Security Alarm Code'):
                record.type = 'encryptedNotes'
            elif template_name == 'Contact':
                record.type = 'address'
            elif template_name == 'Credit Card':
                record.type = 'bankCard'
            elif 'private-key' in items:
                record.type = 'sshKeys'
            elif 'card-number' in items:
                record.type = 'bankCard'
            elif 'account-number' in items and 'routing-number' in items:
                record.type = 'bankAccount'
            elif 'ssn' in items:
                record.type = 'ssnCard'
            elif 'license-key' in items:
                record.type = 'softwareLicense'
            elif 'combination' in items:
                record.type = 'encryptedNotes'
            elif 'healthcare-provider-name' in items:
                record.type = 'healthInsurance'
            elif any(True for x in ('host', 'server', 'ip-address---host-name') if x in items):
                if 'database' in items:
                    record.type = 'databaseCredentials'
                else:
                    record.type = 'serverCredentials'
            else:
                record.type = 'login'

            rt = loaded_record_types.get(record.type, [])

            record.notes = ThycoticImporter.pop_field_value(items, 'notes')

            skip_ssh_key = True
            if record.type in loaded_record_types:
                if any((1 for x in loaded_record_types[record.type] if x['$ref'] == 'keyPair')):
                    skip_ssh_key = False

            secret_id = secret['id']
            if 'lastPasswordChangeAttempt' in secret:
                try:
                    lm = secret['lastPasswordChangeAttempt']
                    if isinstance(lm, str) and lm.endswith('Z'):
                        lm = lm[:-1]
                        dt = datetime.datetime.fromisoformat(lm)
                        record.last_modified = int(dt.timestamp())
                except:
                    pass
            file_items = [x for x in items.values() if x.get('isFile') is True]
            for item in file_items:
                slug = item['slug']
                item['itemValue'] = ''
                attachment_id = item.get('fileAttachmentId')
                if not attachment_id:
                    continue
                file_name = item.get('filename')
                if not file_name:
                    continue

                endpoint = f'/v1/secrets/{secret_id}/fields/{slug}'
                if slug in ('private-key', 'public-key') and skip_ssh_key is not True:
                    try:
                        with auth.thycotic_secret_get(endpoint) as rs:
                            if rs.status_code == 200:
                                try:
                                    key_text = rs.content.decode()
                                except:
                                    key_text = ''
                                is_key = SSH_KEY_MIN_LENGTH < len(key_text) < SSH_KEY_MAX_LENGTH
                                if is_key:
                                    item['itemValue'] = key_text
                                else:
                                    if not isinstance(record.attachments, list):
                                        record.attachments = []
                                    attachment = BytesAttachment(file_name, key_text.encode('utf-8'))
                                    record.attachments.append(attachment)
                            else:
                                status, message = ThycoticAuth.response_error(rs)
                                skipped_fields.append({'ID': secret_id, 'Secret': record.title, 'Field': slug,
                                                       'Status': status, 'Message': message})
                    except requests.exceptions.RequestException as e:
                        skipped_fields.append({'ID': secret_id, 'Secret': record.title, 'Field': slug,
                                               'Status': 'N/A', 'Message': str(e)})
                else:
                    if not isinstance(record.attachments, list):
                        record.attachments = []
                    attachment = ThycoticAttachment(auth, endpoint, file_name)
                    record.attachments.append(attachment)
                    del items[slug]

            if 'private-key' in items:
                key_pair_value = record_types.FieldTypes['privateKey'].value.copy()
                key_pair_value['privateKey'], pk_field = ThycoticImporter.pop_field(items, 'private-key')
                key_pair_value['publicKey'] = ThycoticImporter.pop_field_value(items, 'public-key')
                if any(True for x in key_pair_value.values() if x):
                    field_label = pk_field.get('fieldName') or ''
                    field_label = ThycoticImporter.adjust_field_label(record, 'keyPair', field_label, rt)
                    record.fields.append(RecordField('keyPair', field_label, key_pair_value))

            if 'private-key-passphrase' in items:
                passphrase, field = ThycoticImporter.pop_field(items, 'private-key-passphrase')
                if passphrase:
                    if record.type == 'sshKeys' and not record.password:
                        record.password = passphrase
                    else:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'secret', field_label, rt)
                        record.fields.append(RecordField('secret', field_label, passphrase))

            if 'account-number' in items and 'routing-number' in items:
                bank_account = record_types.FieldTypes['bankAccount'].value.copy()
                bank_account['accountType'] = ''
                bank_account['accountNumber'] = ThycoticImporter.pop_field_value(items, 'account-number')
                bank_account['routingNumber'] = ThycoticImporter.pop_field_value(items, 'routing-number')
                field_label = ThycoticImporter.adjust_field_label(record, 'bankAccount', '', rt)
                record.fields.append(RecordField(type='bankAccount', label=field_label, value=bank_account))

            if 'card-number' in items:
                bank_card = record_types.FieldTypes['paymentCard'].value.copy()
                bank_card['cardNumber'] = ThycoticImporter.pop_field_value(items, 'card-number')
                _ = ThycoticImporter.pop_field_value(items, 'card-type')
                exp = ThycoticImporter.pop_field_value(items, 'expiration-date')
                if len(exp) >= 4:
                    month, sep, year = exp.partition('/')
                    if not sep:
                        month = exp[:2]
                        year = exp[2:]
                    if len(month) == 2:
                        pass
                    elif len(month) == 1:
                        month = '0' + month
                    else:
                        month = ''
                    if len(year) == 4:
                        pass
                    elif len(year) == 2:
                        year = '20' + year
                    else:
                        year = ''
                    if month and year:
                        bank_card['cardExpirationDate'] = f'{month}/{year}'
                field_label = ThycoticImporter.adjust_field_label(record, 'paymentCard', '', rt)
                record.fields.append(RecordField(type='paymentCard', label=field_label, value=bank_card))
                name_on_card = ThycoticImporter.pop_field_value(items, 'full-name')
                if name_on_card:
                    record.fields.append(RecordField(type='text', label='cardholderName', value=name_on_card))

            for login_field in ('username', 'client-id'):
                if login_field in items:
                    username, field = ThycoticImporter.pop_field(items, login_field)
                    if username:
                        if record.login:
                            field_label = field.get('fieldName') or ''
                            field_label = ThycoticImporter.adjust_field_label(record, 'login', field_label, rt)
                            record.fields.append(RecordField(type='login', label=field_label, value=username))
                        else:
                            record.login = username

            for password_field in ('password', 'client-secret'):
                if password_field in items:
                    password, field = ThycoticImporter.pop_field(items, password_field)
                    if password:
                        if record.password:
                            field_label = field.get('fieldName') or ''
                            field_label = ThycoticImporter.adjust_field_label(record, 'password', field_label, rt)
                            record.fields.append(RecordField(type='password', label=field_label, value=password))
                        else:
                            record.password = password

            if 'address-1' in items:
                address = record_types.FieldTypes['address'].value.copy()
                address['street1'] = ThycoticImporter.pop_field_value(items, 'address-1')
                address['street2'] = ThycoticImporter.pop_field_value(items, 'address-2')
                addr = ThycoticImporter.pop_field_value(items, 'address-3')
                if addr:
                    city, sep, addr = addr.partition(',')
                    address['city'] = city
                    if sep:
                        addr = addr.strip()
                        state, sep, zip_code = addr.rpartition(',')
                        if not sep:
                            state, sep, zip_code = addr.rpartition(' ')
                        address['state'] = state
                        address['zip'] = zip_code
                field_label = ThycoticImporter.adjust_field_label(record, 'address', '', rt)
                record.fields.append(RecordField(type='address', label=field_label, value=address))

            if 'address1' in items:
                address = record_types.FieldTypes['address'].value.copy()    # type: dict
                address['street1'] = ThycoticImporter.pop_field_value(items, 'address1')
                a2 = ThycoticImporter.pop_field_value(items, 'address2')
                a3 = ThycoticImporter.pop_field_value(items, 'address3')
                if a3:
                    a2 += ' ' + a3
                a2 = a2.strip()
                address['street2'] = a2
                address['city'] = ThycoticImporter.pop_field_value(items, 'city')
                address['state'] = ThycoticImporter.pop_field_value(items, 'state')
                address['zip'] = ThycoticImporter.pop_field_value(items, 'zip')
                address['country'] = ThycoticImporter.pop_field_value(items, 'country')
                if any(True for x in address.values() if x):
                    field_label = ThycoticImporter.adjust_field_label(record, 'address', '', rt)
                    record.fields.append(RecordField(type='address', label=field_label, value=address))

            if 'last-name' in items:
                name = record_types.FieldTypes['name'].value.copy()
                name['last'] = ThycoticImporter.pop_field_value(items, 'last-name')
                name['first'] = ThycoticImporter.pop_field_value(items, 'first-name')
                if any(True for x in name.values() if x):
                    field_label = ThycoticImporter.adjust_field_label(record, 'name', '', rt)
                    record.fields.append(RecordField(type='name', label=field_label, value=name))

            for full_name_field in ('name', 'contact-person'):
                if full_name_field in items:
                    full_name, field = ThycoticImporter.pop_field(items, full_name_field)
                    if full_name:
                        name = vault.TypedField.import_name_field(full_name)
                        if name:
                            field_label = field.get('fieldName') or ''
                            field_label = ThycoticImporter.adjust_field_label(record, 'name', field_label, rt)
                            record.fields.append(RecordField(type='name', label=field_label, value=name))

            for ssn in ('social-security-number', 'ssn'):
                number = ThycoticImporter.pop_field_value(items, ssn)
                if number:
                    record.fields.append(RecordField(type='accountNumber', label='identityNumber', value=number))

            for pin_slug in ('pin', 'pin-code'):
                if pin_slug in items:
                    pin_code, field = ThycoticImporter.pop_field(items, pin_slug)
                    if pin_code:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'pinCode', field_label, rt)
                        record.fields.append(RecordField(type='pinCode', label=field_label, value=pin_code))

            if 'combination' in items and record.type == 'encryptedNotes':
                combination = ThycoticImporter.pop_field_value(items, 'combination')
                if combination:
                    record.fields.append(RecordField(type='note', label='', value=combination))

            for phone_slug in ('contact-number', 'contact-phone', 'work-phone', 'home-phone', 'mobile-phone', 'fax'):
                phone_number, field = ThycoticImporter.pop_field(items, phone_slug)
                if phone_number:
                    phone = vault.TypedField.import_phone_field(phone_number)
                    if phone:
                        if phone_slug.startswith('work'):
                            phone['type'] = 'Work'
                        elif phone_slug.startswith('mobile'):
                            phone['type'] = 'Mobile'
                        elif phone_slug.startswith('home'):
                            phone['type'] = 'Home'
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'phone', field_label, rt)
                        record.fields.append(RecordField(type='phone', label=field_label, value=phone))

            for url_slug in ('website', 'blog', 'resource', 'url', 'tenant'):
                url, field = ThycoticImporter.pop_field(items, url_slug)
                if url:
                    field_label = field.get('fieldName') or ''
                    field_label = ThycoticImporter.adjust_field_label(record, 'url', field_label, rt)
                    if not record.login_url and field_label == '':
                        record.login_url = url
                    else:
                        field_label = ThycoticImporter.adjust_field_label(record, 'url', field_label, rt)
                        record.fields.append(RecordField(type='url', label=field_label, value=url))
            for host_slug in ('server', 'host', 'ip-address---host-name'):
                host_address, field = ThycoticImporter.pop_field(items, host_slug)
                port = ThycoticImporter.pop_field_value(items, host_slug)
                if host_address:
                    host = vault.TypedField.import_host_field(host_address)
                    if port:
                        host['port'] = port
                    field_label = field.get('fieldName') or ''
                    field_label = ThycoticImporter.adjust_field_label(record, 'host', field_label, rt)
                    record.fields.append(RecordField(type='host', label=field_label, value=host))

            for num_slug in ('policy-number', 'group-number'):
                if num_slug in items:
                    number, field = ThycoticImporter.pop_field(items, num_slug)
                    if number:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'accountNumber', field_label, rt)
                        record.fields.append(RecordField(type='accountNumber', label=field_label, value=number))

            for email_slug in ('email', 'email-address'):
                if email_slug in items:
                    email, field = ThycoticImporter.pop_field(items, email_slug)
                    if email:
                        field_label = field.get('fieldName') or ''
                        field_label = ThycoticImporter.adjust_field_label(record, 'email', field_label, rt)
                        record.fields.append(RecordField(type='email', label=field_label, value=email))

            for slug in list(items.keys()):
                field_value, field = ThycoticImporter.pop_field(items, slug)
                if not field_value:
                    continue
                is_password = field.get('isPassword') or False
                is_url = field.get('isUrl') or False
                is_note = field.get('isNote') or False

                field_type = 'secret' if is_password else 'url' if is_url else 'note' if is_note else 'text'
                field_label = field.get('fieldName') or ''
                field_label = ThycoticImporter.adjust_field_label(record, field_type, field_label, rt)
                record.fields.append(RecordField(type=field_type, label=field_label, value=field_value))

            if record.title in totp_codes:
                field_value = f'otpauth://totp/?secret={totp_codes[record.title]}'
                field_label = ThycoticImporter.adjust_field_label(record, 'oneTimeCode', '', rt)
                record.fields.append(RecordField(type='oneTimeCode', label=field_label, value=field_value))

            yield record
        print(' Done', flush=True)
        ThycoticImporter.print_skipped(skipped_secrets, skipped_fields)


    @staticmethod
    def print_skipped(skipped_secrets, skipped_fields):  # type: (List[dict], List[dict]) -> None
        """Print the secrets and fields that could not be read, like the CyberArk import does."""
        if skipped_secrets:
            print(f'\nSkipped {len(skipped_secrets)} Secrets:')
            print(tabulate(skipped_secrets, headers='keys', maxcolwidths=[None, None, 80]), end='\n\n')
        if skipped_fields:
            print(f'\nSkipped {len(skipped_fields)} Fields:')
            print(tabulate(skipped_fields, headers='keys', maxcolwidths=[None, 40, None, None, 80]), end='\n\n')


class ThycoticAuth:
    max_throttle_retries = 3
    throttle_backoff_seconds = 5
    max_throttle_wait_seconds = 300

    def __init__(self, base_url):    # type: (str) -> None
        if not base_url.endswith('/'):
            base_url += '/'
        self.base_url = base_url
        self.access_token = ''
        self.expires_in = 0
        self.refresh_token = ''
        self.last_login = 0
        self.proxy = None
        self._token_lock = threading.Lock()
        warnings.simplefilter('ignore', InsecureRequestWarning)

    def authenticate(self, username, password, on_totp=None):  # type: (str, str, Optional[Callable[[], str]]) -> None
        if isinstance(username, str):
            username = username.strip()
        request_data = {
            'grant_type': 'password',
            'username': username,
            'password': password
        }
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        logging.debug(
            'Secret Server token request password_length=%d proxy=%s',
            len(password or ''), 'yes' if self.proxy else 'no')
        rs = requests.post(self.base_url + 'oauth2/token', data=request_data, headers=headers,
                           verify=False, proxies=self.proxy)
        if rs.status_code != 200:
            if rs.status_code == 400:
                error = self._json_message(rs, 'error')
                if 'totp' in error.lower() and callable(on_totp):
                    code = on_totp()
                    if code:
                        request_data['OTP'] = code
                        rs = requests.post(self.base_url + 'oauth2/token', data=request_data, headers=headers,
                                           verify=False, proxies=self.proxy)
        if rs.status_code == 200:
            auth_rs = rs.json()
            self.access_token = auth_rs['access_token']
            self.expires_in = auth_rs.get('expires_in')
            self.refresh_token = auth_rs.get('refresh_token')
            self.last_login = int(datetime.datetime.now().timestamp())
        else:
            raise Exception(self._error_message(rs, 'error'))

    def refresh_auth_token(self):
        if not self.refresh_token:
            raise Exception('Not logged in')
        request_data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token
        }
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        rs = requests.post(self.base_url + 'oauth2/token', data=request_data, headers=headers,
                           verify=False, proxies=self.proxy)
        if rs.status_code == 200:
            auth_rs = rs.json()
            self.access_token = auth_rs['access_token']
            self.expires_in = auth_rs.get('expires_in')
            self.refresh_token = auth_rs.get('refresh_token')
            self.last_login = int(datetime.datetime.now().timestamp())
        else:
            raise Exception(self._error_message(rs, 'error'))

    def ensure_auth_token(self):
        # Locked so parallel workers refresh once; a second refresh would reuse a rotated refresh token.
        with self._token_lock:
            if self.access_token:
                now = int(datetime.datetime.now().timestamp())
                now -= 10
                if self.last_login + self.expires_in < now:
                    self.refresh_auth_token()

    def _throttle_wait(self, rs, attempt):  # type: (requests.Response, int) -> int
        """Seconds to wait before retry `attempt`: the larger of Retry-After (capped) and exponential backoff."""
        try:
            hint = min(max(int(rs.headers.get('Retry-After')), 0), self.max_throttle_wait_seconds)
        except (TypeError, ValueError):
            hint = 0
        return max(hint, self.throttle_backoff_seconds * (2 ** (attempt - 1)))

    def _get(self, url, **kwargs):  # type: (str, ...) -> requests.Response
        """GET that waits and retries when Secret Server answers 429 Too Many Requests."""
        attempt = 0
        while True:
            rs = requests.get(url, verify=False, proxies=self.proxy, **kwargs)
            if rs.status_code != 429 or attempt >= self.max_throttle_retries:
                return rs
            attempt += 1
            wait = self._throttle_wait(rs, attempt)
            rs.close()
            logging.warning('Secret Server rate limit (attempt %d/%d), retrying in %d seconds',
                            attempt, self.max_throttle_retries, wait)
            time.sleep(wait)

    def thycotic_search(self, endpoint):  # type: (str) -> list
        self.ensure_auth_token()
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }

        urlp = urlparse(self.base_url + 'api' + endpoint)
        queries = tuple(x for x in urlp.query.split(sep='&') if x)
        result = []
        skip = 0
        while True:
            q = list(queries)
            q.append('take=1000')
            if skip > 0:
                q.append(f'skip={skip}')
            url = urlunparse((urlp.scheme or 'https', urlp.netloc, urlp.path, None, '&'.join(q), None))
            try:
                rs = self._get(url, headers=headers)
            except requests.exceptions.ConnectionError:
                time.sleep(10)
                rs = self._get(url, headers=headers)
            if rs.status_code != 200:
                raise Exception(self._error_message(rs))
            chunk_rs = rs.json()
            records = chunk_rs.get('records')
            if isinstance(records, list):
                result.extend(records)
            else:
                break
            if chunk_rs.get('hasNext') is True:
                skip = chunk_rs['nextSkip']
            else:
                break
        return result

    @staticmethod
    def _json_message(rs, key='message'):  # type: (Optional[requests.Response], str) -> str
        """Return the given field of a JSON error body, or '' if there is none."""
        if rs is None or not (getattr(rs, 'text', None) or '').strip():
            return ''
        try:
            payload = rs.json()
        except ValueError:
            return ''
        if isinstance(payload, dict):
            return str(payload.get(key) or '')
        return ''

    @classmethod
    def _error_message(cls, rs, key='message'):  # type: (requests.Response, str) -> str
        """Describe an error response, whether or not its body is JSON."""
        message = cls._json_message(rs, key)
        if message:
            return message
        body = (rs.text or '').strip().replace('\n', ' ')[:300]
        return f'HTTP {rs.status_code} {rs.reason or ""}: {body or "<empty>"}'

    def _log_thycotic_response(self, endpoint, rs, error):
        if rs is None:
            logging.info('"%s" error: %s (no response)', endpoint, error)
            return
        logging.info(
            '"%s" error: %s (HTTP %s %s)',
            endpoint,
            error,
            getattr(rs, 'status_code', ''),
            getattr(rs, 'reason', '') or '')

    @classmethod
    def response_error(cls, rs):  # type: (requests.Response) -> Tuple[Any, str]
        """Return (HTTP status, message) describing a failed response."""
        message = cls._json_message(rs)
        if not message:
            message = (rs.text or '').strip().replace('\n', ' ')[:300] or rs.reason or ''
        return rs.status_code, message

    def thycotic_secret(self, endpoint):  # type: (str) -> Tuple[Optional[dict], Optional[Tuple[Any, str]]]
        """Read a secret, adding checkout parameters only if the plain read fails.

        Returns (secret, None) on success, or (None, (status, message)) describing
        the last failed attempt.
        """
        secret = None
        first_error = None
        try:
            secret, first_error = self._read_entity(endpoint)
        except Exception as e:
            logging.info('"%s" error: %s', endpoint, str(e))
            first_error = ('N/A', str(e))
        if secret is not None:
            return secret, None
        checkout = with_secret_access_params(endpoint)
        logging.info('Reading "%s" with checkout parameters', checkout)
        try:
            secret, error = self._read_entity(checkout)
            if secret is not None:
                return secret, None
            return None, error or first_error
        except Exception as e:
            logging.info('"%s" error: %s', checkout, str(e))
            return None, ('N/A', str(e))

    def thycotic_entity(self, endpoint):  # type: (str) -> Optional[dict]
        return self._read_entity(endpoint)[0]

    def _read_entity(self, endpoint):  # type: (str) -> Tuple[Optional[dict], Optional[Tuple[Any, str]]]
        self.ensure_auth_token()
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }
        try:
            rs = self._get(self.base_url + 'api' + endpoint, headers=headers)
        except Exception as e:
            logging.warning('"%s" error: %s', endpoint, str(e))
            time.sleep(10)
            try:
                rs = self._get(self.base_url + 'api' + endpoint, headers=headers)
            except Exception as e:
                logging.warning('Another "%s" error: %s', endpoint, str(e))
                time.sleep(10)
                return None, ('N/A', str(e))
        if rs.status_code != 200:
            self._log_thycotic_response(endpoint, rs, f'returned {rs.status_code}')
            return None, self.response_error(rs)
        try:
            return rs.json(), None
        except ValueError as e:
            self._log_thycotic_response(endpoint, rs, f'invalid JSON: {e}')
            return None, (rs.status_code, 'Response is not valid JSON')

    def thycotic_get(self, endpoint):    # type: (str) -> requests.Response
        self.ensure_auth_token()
        headers = {
            'Authorization': f'Bearer {self.access_token}'
        }

        try:
            rs = self._get(self.base_url + 'api' + endpoint, headers=headers, stream=True)
        except requests.exceptions.ConnectionError:
            time.sleep(10)
            rs = self._get(self.base_url + 'api' + endpoint, headers=headers, stream=True)
        return rs

    def thycotic_secret_get(self, endpoint):    # type: (str) -> requests.Response
        """Read a secret field, adding checkout parameters only if the plain read fails.

        This handles restricted secrets that require checkout parameters.
        """
        try:
            rs = self.thycotic_get(endpoint)
            if rs.status_code == 200:
                return rs
            rs.close()
        except Exception as e:
            logging.info('"%s" error: %s', endpoint, str(e))
        checkout = with_secret_access_params(endpoint)
        logging.info('Reading "%s" with checkout parameters', checkout)
        return self.thycotic_get(checkout)


class ThycoticAttachment(Attachment):
    def __init__(self, auth, endpoint, name):     # type: (ThycoticAuth, str, str) -> None
        super().__init__()
        self.auth = auth
        self.endpoint = endpoint
        self.name = name
        self._file_content = b''

    @contextmanager
    def open(self):
        yield io.BytesIO(self._file_content)
        self._file_content = b''

    def prepare(self):
        # Runs during upload, after the import summary is printed, so failures
        # are reported here as warnings instead of in the skipped fields table.
        try:
            with self.auth.thycotic_secret_get(self.endpoint) as rs:
                if rs.status_code == 200:
                    length = rs.headers.get('Content-Length', 0)
                    try:
                        self.size = int(length)
                    except:
                        pass
                    self._file_content = rs.content
                else:
                    status, message = ThycoticAuth.response_error(rs)
                    logging.error('Attachment "%s" (%s) was not imported: HTTP %s %s',
                                  self.name, self.endpoint, status, message)
        except requests.exceptions.RequestException as e:
            logging.error('Attachment "%s" (%s) was not imported: %s', self.name, self.endpoint, str(e))


class ThycoticMembershipDownload(BaseDownloadMembership, ThycoticMixin):
    def download_membership(self, params, **kwargs):
        envvars = getattr(params, 'environment_variables', None) if params is not None else None
        auth = ThycoticMixin.connect_to_server(envvars=envvars)
        if not auth:
            return

        users = ThycoticMembershipDownload.get_user_lookup(auth)

        sf_groups = set()
        folders = ThycoticMembershipDownload.get_folders(auth, skip_permissions=False)
        for folder in folders.values():
            if folder.get('inheritPermissions', True):
                continue
            if 'permissions' not in folder:
                continue
            permissions = folder['permissions']
            if not isinstance(permissions, list):
                continue
            if len(permissions) == 0:
                continue

            shared_folder = SharedFolder()
            shared_folder.uid = folder['id']
            shared_folder.path = folder['folderPath']
            shared_folder.permissions = []
            for p in folder.get('permissions', []):
                folder_permission = p.get('folderAccessRoleName')
                manage_users = folder_permission in ('Owner', 'Edit')
                secret_permission = p.get('secretAccessRoleName')
                manage_records = secret_permission in ('Owner', 'Edit') or folder_permission == 'Add Secret'

                user_id = p.get('userId', -1)
                if user_id in users:
                    user = users[user_id]
                    email = user.get('emailAddress')
                    if email:
                        perm = Permission()
                        perm.name = email
                        perm.manage_users = manage_users
                        perm.manage_records = manage_records
                        shared_folder.permissions.append(perm)
                else:
                    team_name = p.get('groupName') or ''
                    if team_name:
                        perm = Permission()
                        perm.name = team_name
                        perm.manage_users = manage_users
                        perm.manage_records = manage_records
                        shared_folder.permissions.append(perm)
                        group_id = p.get('groupId', -1)
                        if group_id > 0:
                            sf_groups.add(group_id)
            yield shared_folder

        folders_only = kwargs.get('folders_only') is True
        if folders_only is True:
            return

        if len(sf_groups) > 0:
            shown = False

            def progress(position, total):
                nonlocal shown
                if not shown:
                    shown = True
                    print(f'Loading {total} groups ', end='', flush=True)
                if position % 10 == 9:
                    print('.', end='', flush=True)
            groups = ThycoticMembershipDownload.get_group_lookup(auth, on_progress=progress)
            print(' Done', flush=True)

            for group_id in list(sf_groups):
                if group_id in groups:
                    group = groups[group_id]
                    team = Team()
                    team.uid = group_id
                    team.name = group['name']
                    user_ids = set(group['users'])
                    for sub_group_id in group['groups']:
                        if sub_group_id in groups:
                            sub_group = groups[sub_group_id]
                            user_ids.update(sub_group['users'])
                    emails = set((users[x]['emailAddress'] for x in user_ids if x in users and 'emailAddress' in users[x] and users[x]['emailAddress']))
                    team.members = list(emails)

                    yield team

        yield from ThycoticMembershipDownload.iter_secret_shares(auth, folders, kwargs.get('workers'))


class ThycoticRecordTypeDownload(BaseDownloadRecordType, ThycoticMixin):
    def download_record_type(self, params, **kwargs):
        envvars = getattr(params, 'environment_variables', None) if params is not None else None
        auth = ThycoticMixin.connect_to_server(envvars=envvars)
        if not auth:
            return
        templates = auth.thycotic_search('/v1/secret-templates?filter.includeInactive=false&filter.includeSecretCount=true')
        logging.debug('Loaded %d secret templates', len(templates))
        for template in templates:
            secret_count = template['secretCount']
            if isinstance(secret_count, int) and secret_count == 0:
                continue

            template_id = template['id']
            if not isinstance(template_id, int):
                continue

            xml = auth.thycotic_entity(f'/v1/secret-templates/{template_id}/export')
            tree = ET.ElementTree(ET.fromstring(xml['exportFileText']))
            root = tree.getroot()
            e_fields = next(root.iter('fields'))
            template['fields'] = {}
            for e_field in e_fields.iter('field'):
                tf = {}
                slug_name = ''
                for el in e_field.iter():
                    if el.tag == 'displayname':
                        tf['name'] = el.text
                    elif el.tag == 'fieldslugname':
                        slug_name = el.text
                        tf['slugName'] = slug_name
                    elif el.tag == 'description':
                        tf['description'] = el.text
                    elif el.tag == 'isurl' and el.text == 'true':
                        tf['type'] = 'URL'
                    elif el.tag == 'ispassword' and el.text == 'true':
                        tf['type'] = 'Password'
                    elif el.tag == 'isnotes' and el.text == 'true':
                        tf['type'] = 'Notes'
                    elif el.tag == 'isfile' and el.text == 'true':
                        tf['type'] = 'File'
                    elif el.tag == 'required' and el.text == 'true':
                        tf['required'] = True
                if 'type' not in tf:
                    tf['type'] = 'Text'

                template['fields'][slug_name] = tf

        for template in templates:
            template_fields = template.get('fields')    # type: Dict[str, Dict[str, Any]]
            if not isinstance(template_fields, dict):
                continue

            fields = copy.copy(template_fields)
            rt = RecordType()
            rt.name = template['name']
            fields.pop('notes', None)

            for login_field in ('username', 'client-id'):
                if login_field in fields:
                    field = fields.pop(login_field)
                    field_name = field['name']
                    rf = RecordTypeField.create('login', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for password_field in ('password', 'client-secret'):
                if password_field in fields:
                    field = fields.pop(password_field)
                    field_name = field['name']
                    rf = RecordTypeField.create('password', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for host_slug in ('server', 'host', 'ip-address---host-name'):
                if host_slug in fields:
                    field = fields.pop(host_slug)
                    _ = fields.pop('port', None)
                    field_name = field['name']
                    rf = RecordTypeField.create('host', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            if 'account-number' in fields and 'routing-number' in fields:
                field = fields.pop('account-number', None)
                f2 = fields.pop('routing-number', None)
                rf = RecordTypeField.create('bankAccount', '')
                if field.get('required') is True and f2.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            if 'card-number' in fields:
                field = fields.pop('card-number', None)
                _ = fields.pop('card-type', None)
                _ = fields.pop('expiration-date', None)
                rf = RecordTypeField.create('paymentCard', '')
                if field.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            if 'address-1' in fields:
                _ = fields.pop('address-1')
                _ = fields.pop('address-2')
                _ = fields.pop('address-3')
                rf = RecordTypeField.create('address', '')
                rt.fields.append(rf)

            if 'address1' in fields:
                _ = fields.pop('address1')
                _ = fields.pop('address2')
                _ = fields.pop('address3')
                _ = fields.pop('city')
                _ = fields.pop('state')
                _ = fields.pop('zip')
                _ = fields.pop('country')
                rf = RecordTypeField.create('address', '')
                rt.fields.append(rf)

            if 'last-name' in fields:
                _ = fields.pop('first-name')
                _ = fields.pop('last-name')
                rf = RecordTypeField.create('name', '')
                rt.fields.append(rf)

            for full_name_field in ('name', 'contact-person'):
                if full_name_field in fields:
                    field = fields.pop(full_name_field)
                    field_name = field['name']
                    rf = RecordTypeField.create('name', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for ssn in ('social-security-number', 'ssn'):
                if ssn in fields:
                    _ = fields.pop(ssn)
                    rf = RecordTypeField.create('accountNumber', 'identityNumber')
                    rt.fields.append(rf)

            for pin_slug in ('pin', 'pin-code'):
                if pin_slug in fields:
                    field = fields.pop(pin_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('pinCode', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            if 'private-key' in fields or 'public-key' in fields:
                private_field = fields.pop('private-key', None)
                public_field = fields.pop('public-key', None)
                field_name = private_field['name'] if private_field else public_field['name'] if public_field else ''
                rt.fields.append(RecordTypeField.create('keyPair', field_name))

            if 'private-key-passphrase' in fields:
                field = fields.pop('private-key-passphrase')
                field_name = field['name']
                rf = RecordTypeField.create('secret', field_name)
                if field.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            if 'combination' in fields:
                field = fields.pop('combination')
                field_name = field['name']
                rf = RecordTypeField.create('secret', field_name)
                if field.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            for num_slug in ('policy-number', 'group-number'):
                if num_slug in fields:
                    field = fields.pop(num_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('accountNumber', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            if 'license-key' in fields:
                field = fields.pop('license-key')
                field_name = field['name']
                rf = RecordTypeField.create('licenseNumber', field_name)
                if field.get('required') is True:
                    rf.required = True
                rt.fields.append(rf)

            for email_slug in ('email', 'email-address'):
                if email_slug in fields:
                    field = fields.pop(email_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('email', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for url_slug in ('website', 'blog', 'resource', 'url', 'tenant'):
                if url_slug in fields:
                    field = fields.pop(url_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('url', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            for phone_slug in ('contact-number', 'contact-phone', 'work-phone', 'home-phone', 'mobile-phone', 'fax'):
                if phone_slug in fields:
                    field = fields.pop(phone_slug)
                    field_name = field['name']
                    rf = RecordTypeField.create('phone', field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)

            has_files = False
            for field in fields.values():
                field_name = field.get('name')
                field_type = field.get('type')
                if field_type == 'File':
                    has_files = True
                else:
                    ft = 'text'
                    if field_type == 'Notes':
                        ft = 'multiline'
                    elif field_type == 'Password':
                        ft = 'secret'
                    elif field_type == 'URL':
                        ft = 'url'
                    elif field_type in ('List', 'URL List'):
                        continue
                    rf = RecordTypeField.create(ft, field_name)
                    if field.get('required') is True:
                        rf.required = True
                    rt.fields.append(rf)
            if has_files:
                rf = RecordTypeField.create('fileRef', '')
                rt.fields.append(rf)

            yield rt