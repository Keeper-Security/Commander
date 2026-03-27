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

from __future__ import annotations

import argparse
import copy
import datetime
import getpass
import json
import logging
import os
import subprocess
import tempfile
import time

from typing import Dict, List, Tuple

from ..base import Command
from ...error import CommandError
from ... import vault, utils


TOTP_ACCOUNT = 'kcm-totp%40keepersecurity.com'

SQL_GROUPS = """
SELECT
    cg.connection_group_id,
    parent_id,
    connection_group_name,
    cga.attribute_value AS ksm_config
FROM
    guacamole_connection_group cg
LEFT JOIN
    guacamole_connection_group_attribute cga
ON
    cg.connection_group_id = cga.connection_group_id
    AND cga.attribute_name = 'ksm-config'
"""

SQL_CONNECTIONS = """
SELECT
    c.connection_id,
    c.connection_name AS name,
    c.protocol,
    c.max_connections,
    cp.parameter_name,
    cp.parameter_value,
    e.name AS entity_name,
    e.type AS entity_type,
    g.connection_group_id,
    g.parent_id,
    g.connection_group_name AS group_name,
    ca.attribute_name,
    ca.attribute_value
FROM
    guacamole_connection c
LEFT JOIN
    guacamole_connection_parameter cp ON c.connection_id = cp.connection_id
LEFT JOIN
    guacamole_connection_attribute ca ON c.connection_id = ca.connection_id
LEFT JOIN
    guacamole_connection_group g ON c.parent_id = g.connection_group_id
LEFT JOIN
    guacamole_connection_permission p ON c.connection_id = p.connection_id
LEFT JOIN
    guacamole_entity e ON p.entity_id = e.entity_id
"""

PROTOCOL_TYPE_MAP = {
    'http': 'pamRemoteBrowser',
    'mysql': 'pamDatabase',
    'postgres': 'pamDatabase',
    'sql-server': 'pamDatabase',
}


class KCMDatabaseConnector:
    """Connects to a KCM/Guacamole database and extracts connection data."""

    def __init__(self, db_type, host, port, user, password, database, ssl=False):
        self.db_type = db_type
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.ssl = ssl
        self.conn = None
        self.cursor = None

    def connect(self):
        if self.db_type == 'mysql':
            self._connect_mysql()
        else:
            self._connect_postgresql()

    def _connect_mysql(self):
        kwargs = dict(
            host=self.host, port=self.port, user=self.user,
            password=self.password, database=self.database
        )
        if self.ssl:
            kwargs['ssl'] = {'ssl': True}
        try:
            import pymysql
            self.conn = pymysql.connect(**kwargs)
            self.cursor = self.conn.cursor(pymysql.cursors.DictCursor)
        except ImportError:
            try:
                from mysql.connector import connect
                if self.ssl:
                    kwargs.pop('ssl', None)
                    kwargs['ssl_disabled'] = False
                self.conn = connect(**kwargs)
                self.cursor = self.conn.cursor(dictionary=True)
            except ImportError:
                raise CommandError('kcm-import',
                    'MySQL driver not found. Install pymysql: pip3 install pymysql')

    def _connect_postgresql(self):
        try:
            import psycopg2
            import psycopg2.extras
            kwargs = dict(
                host=self.host, port=self.port, user=self.user,
                password=self.password, database=self.database
            )
            if self.ssl:
                kwargs['sslmode'] = 'require'
            self.conn = psycopg2.connect(**kwargs)
            self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        except ImportError:
            raise CommandError('kcm-import',
                'PostgreSQL driver not found. Install psycopg2: pip3 install psycopg2-binary')

    def validate_schema(self):
        try:
            self.cursor.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_name = 'guacamole_connection'"
            )
            if not self.cursor.fetchone():
                raise CommandError('kcm-import',
                    'KCM schema not found: guacamole_connection table does not exist')
        except CommandError:
            raise
        except Exception as e:
            raise CommandError('kcm-import', f'Schema validation failed: {e}') from e

    def extract_groups(self):
        self.cursor.execute(SQL_GROUPS)
        rows = self.cursor.fetchall()
        return [dict(r) for r in rows]

    def extract_connections(self):
        self.cursor.execute(SQL_CONNECTIONS)
        rows = self.cursor.fetchall()
        return [dict(r) for r in rows]

    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


def _set_nested(d, dotted_path, value):
    """Set a value in a nested dict using a dotted key path."""
    keys = dotted_path.split('.')
    for key in keys[:-1]:
        d = d.setdefault(key, {})
    d[keys[-1]] = value


class KCMParameterMapper:
    """Applies kcm_mappings.json transformations to raw KCM connection data."""

    def __init__(self):
        mappings_path = os.path.join(os.path.dirname(__file__), 'kcm_mappings.json')
        with open(mappings_path, 'r') as f:
            self.mappings = json.load(f)

    def transform(self, connection_rows, include_disabled=False):
        # type: (List[Dict], bool) -> Tuple[List[Dict], List[Dict]]
        """Group rows by connection_id, apply mappings, return (resources, users)."""
        connections = {}  # type: Dict[int, Dict]
        users = {}  # type: Dict[int, Dict]
        disabled_ids = set()  # type: set

        # Pre-scan for disabled connections (max_connections == 0)
        if not include_disabled:
            for row in connection_rows:
                if row.get('max_connections') == 0:
                    disabled_ids.add(row['connection_id'])

        for row in connection_rows:
            cid = row['connection_id']
            if cid in disabled_ids:
                continue
            name = row['name'] or ''
            # Sanitize connection name — strip control chars, path separators, enforce length
            name = ''.join(c for c in name if c >= ' ' and c != '\x7f')
            name = name.replace('/', '_').replace('\\', '_').replace('..', '_')
            if len(name) > 200:
                name = name[:200]
            if not name:
                name = f'unnamed-{cid}'
            protocol = row['protocol']

            if cid not in connections:
                record_type = PROTOCOL_TYPE_MAP.get(protocol, 'pamMachine')
                conn_protocol = 'postgresql' if protocol == 'postgres' else protocol
                connections[cid] = {
                    'title': f'KCM Resource - {name}',
                    'type': record_type,
                    'host': '',
                    'pam_settings': {
                        'options': {
                            'rotation': 'off',
                            'connections': 'on',
                            'tunneling': 'off',
                            'graphical_session_recording': 'off'
                        },
                        'connection': {
                            'protocol': conn_protocol,
                            'launch_credentials': f'KCM User - {name}'
                        }
                    },
                    '_group_id': row.get('connection_group_id'),
                }

            if cid not in users:
                users[cid] = {
                    'title': f'KCM User - {name}',
                    'type': 'pamUser',
                    'rotation_settings': {},
                    '_group_id': row.get('connection_group_id'),
                }

            param_name = row.get('parameter_name')
            param_value = row.get('parameter_value') or ''
            attr_name = row.get('attribute_name')
            attr_value = row.get('attribute_value') or ''

            if param_name:
                self._apply_mapping(cid, param_name, param_value,
                                    connections, users)
            if attr_name:
                self._apply_mapping(cid, attr_name, attr_value,
                                    connections, users)

        return list(connections.values()), list(users.values())

    def _apply_mapping(self, cid, arg, value, connections, users):
        resource = connections[cid]
        user = users[cid]

        # Special cases first
        if arg == 'hostname':
            resource['host'] = value
            return
        if arg == 'port':
            resource['pam_settings']['connection']['port'] = value
            return
        if arg.startswith('totp-') and value:
            self._handle_totp(user, arg, value)
            return

        # User mappings
        if value and arg in self.mappings['users']:
            mapping = self.mappings['users'][arg]
            self._apply_single_mapping(mapping, value, user)
            return

        # Resource mappings
        if arg in self.mappings['resources']:
            mapping = self.mappings['resources'][arg]
            self._apply_single_mapping(mapping, value, resource)

    def _apply_single_mapping(self, mapping, value, target):
        if mapping == 'ignore':
            return
        if mapping == 'log':
            logging.debug('Unmapped KCM parameter: %s (value: %s)', mapping, value)
            return
        if mapping is None:
            return
        if '=' in mapping:
            mapping, value = mapping.split('=', 1)
        _set_nested(target, mapping, value)

    def _handle_totp(self, user, arg, value):
        if '_totp_parts' not in user:
            user['_totp_parts'] = {}
        user['_totp_parts'][arg] = value

    @staticmethod
    def finalize_totp(users):
        """Convert collected TOTP parts into otpauth:// URLs."""
        for user in users:
            parts = user.pop('_totp_parts', None)
            if not parts:
                continue
            alg = parts.get('totp-algorithm', '')
            digits = parts.get('totp-digits', '')
            period = parts.get('totp-period', '')
            secret = parts.get('totp-secret', '')
            stripped_secret = ''.join(c for c in secret if c.isalnum())
            user['otp'] = (
                f'otpauth://totp/{TOTP_ACCOUNT}'
                f'?secret={stripped_secret}&issuer=&algorithm={alg}'
                f'&digits={digits}&period={period}'
            )

    @staticmethod
    def map_protocol_to_type(protocol):
        return PROTOCOL_TYPE_MAP.get(protocol, 'pamMachine')


class KCMGroupResolver:
    """Builds folder hierarchy from KCM connection groups."""

    def __init__(self, groups, mode='ksm', strip_root=False, max_depth=0):
        self.groups = {g['connection_group_id']: g for g in groups}
        self.mode = mode
        self.strip_root = strip_root
        self.max_depth = max_depth
        self.paths = {}  # type: Dict[int, str]
        self._resolve_all()

    @staticmethod
    def _sanitize(name):
        if not name:
            return '_unnamed_'
        # Strip control characters (includes null bytes since \x00 < ' ')
        name = ''.join(c for c in name if c >= ' ' and c != '\x7f')
        # Path traversal prevention
        name = name.replace('/', '_').replace('\\', '_').replace('..', '_')
        name = name.strip('. ')
        if not name:
            return '_unnamed_'
        # Length limit — Keeper folder names max ~255 chars
        if len(name) > 200:
            name = name[:200]
        return name

    def _resolve_all(self):
        for gid in self.groups:
            if self.mode == 'flat':
                raw = self.groups[gid]['connection_group_name']
                self.paths[gid] = self._sanitize(raw)
            elif self.mode == 'qualified':
                self._resolve_qualified(gid)
            else:
                self._resolve_path(gid)
        # Apply depth limiting after full paths are built
        if self.max_depth > 0 and self.mode not in ('flat', 'qualified'):
            self._apply_depth_limit()

    def _get_depth(self, group_id, _seen=None):
        """Compute absolute tree depth (root children = 1)."""
        if _seen is None:
            _seen = set()
        if group_id is None or group_id in _seen:
            return 0
        _seen.add(group_id)
        group = self.groups.get(group_id)
        if not group:
            return 0
        pid = group.get('parent_id')
        if pid is None or pid not in self.groups:
            return 1
        return self._get_depth(pid, _seen) + 1

    def _find_ancestor_at_depth(self, group_id, target_depth, _seen=None):
        """Walk up the tree to find the ancestor at exactly target_depth."""
        if _seen is None:
            _seen = set()
        if group_id in _seen:
            return group_id
        _seen.add(group_id)
        group = self.groups.get(group_id)
        if not group:
            return group_id
        depth = self._get_depth(group_id)
        if depth <= target_depth:
            return group_id
        pid = group.get('parent_id')
        if pid is None or pid not in self.groups:
            return group_id
        return self._find_ancestor_at_depth(pid, target_depth, _seen)

    def _apply_depth_limit(self):
        """Collapse groups deeper than max_depth into their ancestor."""
        for gid in list(self.paths.keys()):
            depth = self._get_depth(gid)
            if depth > self.max_depth:
                ancestor_id = self._find_ancestor_at_depth(gid, self.max_depth)
                if ancestor_id in self.paths:
                    self.paths[gid] = self.paths[ancestor_id]

    def _resolve_path(self, group_id, _seen=None):
        if group_id is None:
            return '' if self.strip_root else 'ROOT'
        if group_id in self.paths:
            return self.paths[group_id]
        if _seen is None:
            _seen = set()
        if group_id in _seen:
            return '' if self.strip_root else 'ROOT'
        _seen.add(group_id)
        group = self.groups.get(group_id)
        if not group:
            return '' if self.strip_root else 'ROOT'
        safe_name = self._sanitize(group['connection_group_name'])
        if self.mode == 'ksm' and group.get('ksm_config'):
            self.paths[group_id] = safe_name
            return safe_name
        parent_path = self._resolve_path(group.get('parent_id'), _seen)
        if parent_path:
            full_path = f"{parent_path}/{safe_name}"
        else:
            full_path = safe_name
        self.paths[group_id] = full_path
        return full_path

    def _resolve_qualified(self, group_id):
        """Build parent-qualified flat name to avoid collisions."""
        if group_id in self.paths:
            return self.paths[group_id]
        group = self.groups.get(group_id)
        if not group:
            self.paths[group_id] = ''
            return ''
        safe_name = self._sanitize(group['connection_group_name'])
        parent_id = group.get('parent_id')
        parent = self.groups.get(parent_id) if parent_id else None
        if parent:
            parent_name = self._sanitize(parent['connection_group_name'])
            qualified = f"{parent_name} - {safe_name}"
        else:
            qualified = safe_name
        # Collision check — qualify further if needed
        existing_names = set(self.paths.values())
        if qualified in existing_names and parent:
            grandparent_id = parent.get('parent_id')
            grandparent = self.groups.get(grandparent_id) if grandparent_id else None
            if grandparent:
                gp_name = self._sanitize(grandparent['connection_group_name'])
                qualified = f"{gp_name} - {parent_name} - {safe_name}"
        # Final fallback: numeric suffix if still colliding
        if qualified in existing_names:
            base = qualified
            counter = 2
            while qualified in existing_names:
                qualified = f"{base} ({counter})"
                counter += 1
        self.paths[group_id] = qualified
        return qualified

    def resolve_path(self, group_id):
        if group_id is None:
            return '' if self.strip_root else 'ROOT'
        return self.paths.get(group_id, '' if self.strip_root else 'ROOT')

    def get_shared_folders(self):
        folders = set()
        for path in self.paths.values():
            if not path:
                continue
            root = path.split('/')[0]
            folders.add(root)
        return sorted(folders)


class PAMProjectKCMImportCommand(Command):
    parser = argparse.ArgumentParser(prog='pam project kcm-import')

    # Database options
    parser.add_argument('--db-host', dest='db_host', action='store',
                        help='KCM database hostname')
    parser.add_argument('--docker-detect', dest='docker_detect', action='store_true',
                        default=False,
                        help='Auto-detect credentials from Docker container')
    parser.add_argument('--docker-container', dest='docker_container',
                        action='store', default='guacamole',
                        help='Docker container name for --docker-detect (default: guacamole)')
    parser.add_argument('--db-port', dest='db_port', type=int, action='store',
                        help='Database port (default: 3306 mysql, 5432 postgresql)')
    parser.add_argument('--db-name', dest='db_name', action='store',
                        default=None, help='Database name (default: guacamole_db)')
    parser.add_argument('--db-type', dest='db_type', action='store',
                        choices=['mysql', 'postgresql'], default='mysql',
                        help='Database type')
    parser.add_argument('--db-user', dest='db_user', action='store',
                        default=None, help='Database username (default: guacamole_user)')
    parser.add_argument('--db-password-record', dest='db_password_record',
                        action='store',
                        help='Keeper record UID containing DB password')
    parser.add_argument('--db-ssl', dest='db_ssl', action='store_true',
                        default=False,
                        help='Require SSL/TLS for database connection')
    parser.add_argument('--allow-cleartext', dest='allow_cleartext',
                        action='store_true', default=False,
                        help='Allow unencrypted connection to remote database (not recommended)')

    # Import options
    parser.add_argument('--name', '-n', dest='project_name', action='store',
                        help='Project name')
    parser.add_argument('--config', '-c', dest='config', action='store',
                        help='Existing PAM config UID or title (extend mode)')
    parser.add_argument('--folder-mode', dest='folder_mode', action='store',
                        choices=['ksm', 'exact', 'flat', 'qualified'], default='ksm',
                        help='Connection group mapping mode')
    parser.add_argument('--output', '-o', dest='output', action='store',
                        help='Save JSON to file instead of importing')
    parser.add_argument('--strip-root', dest='strip_root', action='store_true',
                        default=False,
                        help='Remove ROOT/ prefix from folder paths (use with exact mode)')
    parser.add_argument('--preview-groups', dest='preview_groups', action='store_true',
                        default=False,
                        help='Show group-to-folder mapping tree and exit (no vault changes)')
    parser.add_argument('--exclude-groups', dest='exclude_groups', action='store',
                        default='',
                        help='Comma-separated group names or IDs to exclude from import')
    parser.add_argument('--group-depth', dest='group_depth', type=int, default=0,
                        help='Max folder nesting depth (0=unlimited)')

    # Gateway options
    parser.add_argument('--gateway', '-g', dest='gateway', action='store',
                        help='Existing gateway UID or name (skips gateway creation)')
    parser.add_argument('--max-instances', dest='max_instances', type=int,
                        default=0,
                        help='Set gateway pool size (0 = skip, requires new gateway)')
    parser.add_argument('--deploy-gateway', dest='deploy_gateway', action='store_true',
                        default=False,
                        help='Auto-deploy gateway via Docker after creation')
    parser.add_argument('--gateway-name', dest='gateway_docker_name', action='store',
                        default='keeper-gateway',
                        help='Docker container name for --deploy-gateway (default: keeper-gateway)')
    parser.add_argument('--gateway-image', dest='gateway_image', action='store',
                        default='keeper/gateway:latest',
                        help='Docker image for --deploy-gateway')

    # Flags
    parser.add_argument('--dry-run', '-d', dest='dry_run', action='store_true',
                        default=False, help='Preview without vault changes')
    parser.add_argument('--skip-users', dest='skip_users', action='store_true',
                        default=False, help='Import connections only, skip users')
    parser.add_argument('--include-disabled', dest='include_disabled',
                        action='store_true', default=False,
                        help='Include disabled KCM connections')

    def get_parser(self):
        return PAMProjectKCMImportCommand.parser

    def execute(self, params, **kwargs):
        t_start = time.monotonic()
        db_host = kwargs.get('db_host') or ''
        docker_detect = kwargs.get('docker_detect', False)

        if not db_host and not docker_detect:
            raise CommandError('kcm-import',
                'Either --db-host or --docker-detect is required')

        db_type = kwargs.get('db_type', 'mysql')
        db_port = kwargs.get('db_port') or (3306 if db_type == 'mysql' else 5432)
        db_name = kwargs.get('db_name')
        db_user = kwargs.get('db_user')
        folder_mode = kwargs.get('folder_mode', 'ksm')
        output_file = kwargs.get('output') or ''
        dry_run = kwargs.get('dry_run', False)
        skip_users = kwargs.get('skip_users', False)
        config_uid = kwargs.get('config') or ''
        project_name = kwargs.get('project_name') or ''
        include_disabled = kwargs.get('include_disabled', False)

        # Resolve DB credentials
        if docker_detect:
            container_name = kwargs.get('docker_container', 'guacamole')
            det_host, det_port, det_name, det_user, db_password = \
                self._detect_docker_credentials(db_type, container_name)
            # Explicit CLI flags override docker-detected values
            db_host = db_host or det_host
            db_port = kwargs.get('db_port') or det_port
            db_name = db_name or det_name or 'guacamole_db'
            db_user = db_user or det_user or 'guacamole_user'
        else:
            db_name = db_name or 'guacamole_db'
            db_user = db_user or 'guacamole_user'
            db_password = self._resolve_db_password(params, kwargs)

        # Connect and extract
        db_ssl = kwargs.get('db_ssl', False)
        allow_cleartext = kwargs.get('allow_cleartext', False)
        if not db_ssl and not self._is_local_host(db_host):
            if not allow_cleartext:
                raise CommandError('kcm-import',
                    f'Refusing to connect to remote host {db_host} without SSL/TLS. '
                    f'Credentials and data would transit in cleartext. '
                    f'Use --db-ssl to encrypt, or --allow-cleartext to override.')
            logging.warning(
                'WARNING: Connecting to remote database %s without SSL/TLS. '
                'Credentials and extracted data will transit in cleartext.', db_host)
        connector = KCMDatabaseConnector(
            db_type, db_host, db_port, db_user, db_password, db_name, ssl=db_ssl
        )
        try:
            logging.info('Connecting to KCM database at %s:%d...', db_host, db_port)
            connector.connect()
            connector.validate_schema()

            logging.info('Extracting connection groups...')
            groups = connector.extract_groups()

            logging.info('Extracting connections and parameters...')
            connection_rows = connector.extract_connections()
        except CommandError:
            raise
        except Exception as e:
            logging.debug('Database error details', exc_info=True)
            raise CommandError('kcm-import', f'Database connection failed: {e.__class__.__name__}: {e}') from e
        finally:
            connector.close()
            # Clear credentials from memory (best effort — Python strings are immutable)
            connector.password = None
            db_password = None  # noqa: F841

        t_extract = time.monotonic()
        logging.info('Extracted %d group(s), %d connection row(s) in %.1fs',
                     len(groups), len(connection_rows), t_extract - t_start)

        # Filter excluded groups
        exclude_groups = kwargs.get('exclude_groups') or ''
        if exclude_groups:
            groups, connection_rows = self._filter_excluded_groups(
                groups, connection_rows, exclude_groups)

        # Build group hierarchy
        strip_root = kwargs.get('strip_root', False)
        group_depth = kwargs.get('group_depth', 0)
        if group_depth < 0:
            raise CommandError('kcm-import', '--group-depth must be >= 0')
        resolver = KCMGroupResolver(groups, mode=folder_mode,
                                    strip_root=strip_root, max_depth=group_depth)

        # Resolve project name early (needed for folder_path naming and preview)
        if not project_name:
            ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            project_name = f'KCM-Import-{ts}'

        # Preview mode — show tree and exit
        preview_groups = kwargs.get('preview_groups', False)
        if preview_groups:
            self._preview_group_tree(groups, resolver, connection_rows, project_name)
            return

        # Transform parameters
        mapper = KCMParameterMapper()
        resources, users = mapper.transform(connection_rows,
                                            include_disabled=include_disabled)

        # Assign folder paths
        for item in resources:
            group_id = item.pop('_group_id', None)
            kcm_path = resolver.resolve_path(group_id)
            folder_path = f'{project_name} - Resources'
            if kcm_path:
                folder_path += '/' + kcm_path
            item['folder_path'] = folder_path

        for item in users:
            group_id = item.pop('_group_id', None)
            kcm_path = resolver.resolve_path(group_id)
            folder_path = f'{project_name} - Users'
            if kcm_path:
                folder_path += '/' + kcm_path
            item['folder_path'] = folder_path

        # Finalize TOTP
        KCMParameterMapper.finalize_totp(users)

        # Handle SFTP sub-resources
        # Use parent connection title to derive unique SFTP names,
        # stripping the "KCM Resource - " prefix for brevity.
        sftp_resources = []
        sftp_users = []
        for resource in resources:
            sftp = resource.get('pam_settings', {}).get('connection', {}).get('sftp')
            if sftp:
                res_label = resource['title'].replace('KCM Resource - ', '', 1)
                sftp_res_title = f'SFTP connection for {res_label}'
                sftp_usr_title = f'SFTP credentials for {res_label}'
                sftp_resource = {
                    'folder_path': resource['folder_path'] + '/SFTP Resources',
                    'title': sftp_res_title,
                    'type': 'pamMachine',
                    'host': sftp.get('host', ''),
                    'port': sftp.get('port', ''),
                    'pam_settings': {
                        'options': {
                            'rotation': 'off',
                            'connections': 'off',
                            'tunneling': 'off',
                            'graphical_session_recording': 'off'
                        },
                        'connection': {
                            'protocol': 'ssh',
                            'launch_credentials': sftp_usr_title
                        }
                    }
                }
                sftp_resources.append(sftp_resource)

                user_folder = resource['folder_path'].replace(
                    f'{project_name} - Resources', f'{project_name} - Users', 1)
                sftp_user = {
                    'folder_path': f'{user_folder}/SFTP Users',
                    'title': sftp_usr_title,
                    'type': 'pamUser',
                    'login': sftp.get('login', ''),
                    'password': sftp.get('password', ''),
                    'private_pem_key': sftp.get('private_key', ''),
                    'rotation_settings': {}
                }
                sftp_users.append(sftp_user)

                sftp['sftp_resource'] = sftp_res_title
                sftp['sftp_user_credentials'] = sftp_usr_title

        resources.extend(sftp_resources)
        if not skip_users:
            users.extend(sftp_users)

        # Build shared folder list
        sf_list = [f'{project_name} - Resources', f'{project_name} - Users']

        # Build PAM JSON
        pam_json = {
            'pam_data': {
                'shared_folders': sf_list,
                'resources': resources,
                'users': users if not skip_users else [],
            }
        }

        if not config_uid:
            pam_json['project'] = project_name

        num_resources = len(resources)
        num_users = len(users) if not skip_users else 0

        # Output or import
        if output_file:
            fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(pam_json, f, indent=2)
            logging.warning('JSON written to %s (%d resources, %d users)',
                            output_file, num_resources, num_users)
            logging.warning('WARNING: Output file contains plaintext credentials. '
                            'Secure or delete %s after use.', output_file)
            return

        if dry_run:
            redacted = self._redact_for_display(pam_json)
            print(json.dumps(redacted, indent=2))
            logging.warning('Dry run: %d resources, %d users (no vault changes)',
                            num_resources, num_users)
            return

        # Gateway handling — three modes:
        # 1. --gateway <name/uid>  → reuse existing gateway, skip Phase 1
        # 2. --config <uid>        → extend mode, no gateway creation
        # 3. (default)             → new project: Phase 1 + Phase 2
        gateway_arg = kwargs.get('gateway') or ''
        deploy_gateway = kwargs.get('deploy_gateway', False)
        gateway_token = None

        # Warn about flags that are ignored in reuse/extend mode
        if (gateway_arg or config_uid) and deploy_gateway:
            logging.warning('--deploy-gateway is ignored when --gateway or --config is specified')
        if (gateway_arg or config_uid) and kwargs.get('max_instances', 0) > 0:
            logging.warning('--max-instances is ignored when --gateway or --config is specified')

        if gateway_arg:
            # ── REUSE EXISTING GATEWAY ──
            pam_config_uid = self._resolve_gateway(params, gateway_arg)
            logging.info('Using existing gateway, PAM config: %s', pam_config_uid)
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            try:
                with os.fdopen(tmp_fd, 'w') as tmp:
                    json.dump(pam_json, tmp, indent=2)
                from .extend import PAMProjectExtendCommand
                cmd = PAMProjectExtendCommand()
                cmd.execute(params, config=pam_config_uid,
                            file_name=tmp_path, dry_run=False)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        elif config_uid:
            # ── EXTEND MODE (explicit --config) ──
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            try:
                with os.fdopen(tmp_fd, 'w') as tmp:
                    json.dump(pam_json, tmp, indent=2)
                from .extend import PAMProjectExtendCommand
                cmd = PAMProjectExtendCommand()
                cmd.execute(params, config=config_uid,
                            file_name=tmp_path, dry_run=False)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        else:
            # ── NEW PROJECT (Phase 1 + Phase 2) ──
            # Phase 1: Create infrastructure (shared folders, KSM app, gateway, PAM config)
            infra_json = {
                'pam_data': {
                    'shared_folders': sf_list,
                    'resources': [],
                    'users': [],
                },
                'project': project_name
            }
            tmp_fd1, tmp_path1 = tempfile.mkstemp(suffix='.json')
            try:
                with os.fdopen(tmp_fd1, 'w') as tmp:
                    json.dump(infra_json, tmp, indent=2)

                from .edit import PAMProjectImportCommand
                edit_cmd = PAMProjectImportCommand()
                project_result = edit_cmd.execute(params,
                                                  project_name=project_name,
                                                  file_name=tmp_path1,
                                                  dry_run=False)
            finally:
                if os.path.exists(tmp_path1):
                    os.unlink(tmp_path1)

            # Capture gateway token and PAM config UID from Phase 1
            pam_config_uid = None
            if project_result and isinstance(project_result, dict):
                gw_data = project_result.get('gateway') or {}
                gateway_token = gw_data.get('gateway_token', '')
                pam_config_uid = (project_result.get('pam_config') or {}).get('pam_config_uid', '')

            if not pam_config_uid:
                # Fallback: search for the config by title
                pam_config_uid = self._find_pam_config_by_title(params, project_name)

            if not pam_config_uid:
                raise CommandError('kcm-import',
                                   'Failed to retrieve PAM configuration UID after infrastructure creation')

            # Phase 2: Import records with proper subfolders via extend
            tmp_fd2, tmp_path2 = tempfile.mkstemp(suffix='.json')
            try:
                with os.fdopen(tmp_fd2, 'w') as tmp:
                    json.dump(pam_json, tmp, indent=2)

                from .extend import PAMProjectExtendCommand
                extend_cmd = PAMProjectExtendCommand()
                extend_cmd.execute(params,
                                   config=pam_config_uid,
                                   file_name=tmp_path2,
                                   dry_run=False)
            finally:
                if os.path.exists(tmp_path2):
                    os.unlink(tmp_path2)

        # Import statistics
        t_end = time.monotonic()
        elapsed = t_end - t_start
        total_records = num_resources + num_users
        rate = total_records / elapsed if elapsed > 0 else 0

        logging.warning('KCM import complete: %d resources, %d users',
                        num_resources, num_users)
        print(f'\n{"=" * 60}')
        print(f'Import Statistics')
        print(f'{"=" * 60}')
        print(f'  Project:      {project_name}')
        print(f'  Folder mode:  {folder_mode}')
        print(f'  Resources:    {num_resources}')
        print(f'  Users:        {num_users}')
        print(f'  Total:        {total_records} records')
        print(f'  Elapsed:      {elapsed:.1f}s')
        if total_records > 0:
            print(f'  Throughput:   {rate:.1f} records/s  ({elapsed/total_records:.1f}s per record)')
        print(f'{"=" * 60}')

        # Gateway post-import (only when we created a new gateway)
        if not config_uid and not gateway_arg:
            max_instances = kwargs.get('max_instances', 0)
            if max_instances > 0:
                self._set_gateway_pool_size(params, project_name, max_instances)

            if deploy_gateway and gateway_token:
                self._deploy_gateway_docker(
                    gateway_token,
                    kwargs.get('gateway_docker_name', 'keeper-gateway'),
                    kwargs.get('gateway_image', 'keeper/gateway:latest'))
            else:
                self._print_deploy_instructions(project_name, gateway_token)

    @staticmethod
    def _find_pam_config_by_title(params, project_name):
        """Find PAM configuration record UID by project name (fallback)."""
        from ... import api
        from ...vault_extensions import find_records as vault_find_records
        api.sync_down(params)
        expected_title = f'{project_name} PAM Configuration'
        for rec in vault_find_records(params, record_version=6):
            if rec.title and rec.title == expected_title:
                return rec.record_uid
        # Fallback: exact project name match
        for rec in vault_find_records(params, record_version=6):
            if rec.title and rec.title == project_name:
                return rec.record_uid
        return None

    @staticmethod
    def _set_gateway_pool_size(params, project_name, max_instances):
        """Set max instances for the newly created gateway."""
        from ..pam import gateway_helper
        gateways = gateway_helper.get_all_gateways(params)
        gw_name = f'{project_name} Gateway'
        match = next((g for g in gateways if g.controllerName.startswith(project_name)), None)
        if match:
            try:
                from ...proto import pam_pb2
                from ... import api
                rq = pam_pb2.PAMSetMaxInstanceCountRequest()
                rq.controllerUid = match.controllerUid
                rq.maxInstanceCount = max_instances
                api.communicate_rest(params, rq, 'pam/set_controller_max_instance_count')
                logging.warning('Gateway pool size set to %d instances.', max_instances)
            except Exception as e:
                logging.warning('Could not set pool size: %s: %s', type(e).__name__, e)
        else:
            logging.warning('Could not find gateway "%s" to set pool size.', gw_name)

    @staticmethod
    def _deploy_gateway_docker(token, container_name, image):
        """Deploy gateway via Docker using the access token."""
        try:
            # Check if container name already in use
            result = subprocess.run(
                ['docker', 'inspect', container_name],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logging.warning('Docker container "%s" already exists. '
                                'Remove it first or use --gateway-name to pick a different name.',
                                container_name)
                return False

            logging.info('Deploying gateway as Docker container "%s"...', container_name)
            result = subprocess.run(
                ['docker', 'run', '-d',
                 '--name', container_name,
                 '-e', f'GATEWAY_CONFIG={token}',
                 '-e', 'ACCEPT_EULA=Y',
                 '--shm-size=2g',
                 '--restart', 'unless-stopped',
                 image],
                capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                container_id = result.stdout.strip()[:12]
                print(f'\n{"=" * 60}')
                print(f'Gateway Deployed')
                print(f'{"=" * 60}')
                print(f'  Container:  {container_name} ({container_id})')
                print(f'  Image:      {image}')
                print(f'  Status:     Running')
                print(f'\n  Verify:  pam gateway list')
                print(f'{"=" * 60}')
                return True
            else:
                logging.warning('Docker deploy failed (exit %d): %s',
                                result.returncode, result.stderr.strip())
                return False
        except FileNotFoundError:
            logging.warning('Docker not found on this system. Deploy the gateway manually:')
            PAMProjectKCMImportCommand._print_deploy_instructions('', token)
            return False
        except subprocess.TimeoutExpired:
            logging.warning('Docker deploy timed out (120s). Check: docker ps')
            return False

    @staticmethod
    def _print_deploy_instructions(project_name, gateway_token=None):
        """Print Docker deployment one-liner after gateway creation."""
        token_display = gateway_token if gateway_token else '<access_token>'
        print('\n' + '=' * 60)
        print('Gateway Deployment')
        print('=' * 60)
        if gateway_token:
            print(f'\n  Gateway token captured. Deploy with:')
        else:
            print(f'\n  Copy the access_token from above and deploy:')
        print()
        print('  # Docker (single instance)')
        print(f'  docker run -d --name keeper-gateway \\')
        print(f'    -e GATEWAY_CONFIG="{token_display}" \\')
        print(f'    -e ACCEPT_EULA=Y \\')
        print(f'    --shm-size=2g \\')
        print(f'    --restart unless-stopped \\')
        print(f'    keeper/gateway:latest')
        print()
        print('  # Or auto-deploy next time with:')
        print(f'  # pam project kcm-import ... --deploy-gateway')
        print()
        print('  # Docker Compose (HA pool)')
        print('  # Set GATEWAY_CONFIG in .env, then:')
        print('  # docker compose up -d')
        print()
        print('  # Kubernetes')
        print('  # kubectl create secret generic gateway-config \\')
        print(f'  #   --from-literal=GATEWAY_CONFIG="{token_display}"')
        print()
        print(f'  # Verify (after deployment):')
        print(f'  pam gateway list  # should show "{project_name} Gateway" as ONLINE')
        print('=' * 60)

    @staticmethod
    def _resolve_gateway(params, gateway_arg):
        """Interactive gateway selection. Returns PAM config UID or None.

        Flow:
          --gateway <uid/name>  → find matching gateway, find its config, use extend mode
          (no flag, interactive) → list gateways, let user choose or create new
          'new' choice          → return None (import engine creates new gateway)
        """
        from ..pam import gateway_helper
        from ..pam.router_helper import router_get_connected_gateways

        gateways = gateway_helper.get_all_gateways(params)

        # Determine online status by cross-referencing with router
        online_uids = set()
        try:
            connected = router_get_connected_gateways(params)
            if connected and connected.controllers:
                online_uids = {c.controllerUid for c in connected.controllers}
        except Exception as e:
            logging.debug('Could not reach router to check online gateways: %s', e)

        online = [g for g in gateways if g.controllerUid in online_uids]

        # If --gateway flag provided, find it directly
        if gateway_arg:
            match = None
            for g in gateways:
                uid_str = utils.base64_url_encode(g.controllerUid)
                if uid_str == gateway_arg or g.controllerName == gateway_arg:
                    match = g
                    break
            if not match:
                raise CommandError('kcm-import',
                    f'Gateway "{gateway_arg}" not found. Use --dry-run to preview without a gateway.')
            if match.controllerUid not in online_uids:
                logging.warning('Gateway "%s" is OFFLINE — connections will not work until it is started.',
                                match.controllerName)
            return PAMProjectKCMImportCommand._find_config_for_gateway(params, match)

        # Interactive: show options
        print('\nGateway Selection')
        print('─' * 50)
        if online:
            print(f'  Found {len(online)} online gateway(s):\n')
            for i, g in enumerate(online, 1):
                uid_str = utils.base64_url_encode(g.controllerUid)
                print(f'  [{i}] {g.controllerName}  ({uid_str})')
            print(f'\n  [N] Create a new gateway')
            print()
            choice = input('  Select gateway [N]: ').strip()
            if choice and choice.upper() != 'N':
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(online):
                        selected = online[idx]
                        logging.info('Using existing gateway: %s', selected.controllerName)
                        return PAMProjectKCMImportCommand._find_config_for_gateway(params, selected)
                except ValueError:
                    pass
                logging.warning('Invalid selection — creating new gateway.')
        else:
            print('  No online gateways found.')
            print('  A new gateway will be created. Deploy it with the token shown after import.\n')

        # Return None = import engine creates new gateway
        return None

    @staticmethod
    def _find_config_for_gateway(params, gateway):
        """Find the PAM config UID associated with a gateway."""
        from ..pam.config_helper import configuration_controller_get

        gateway_uid_bytes = gateway.controllerUid

        # Search all PAM configs to find one linked to this gateway
        all_records = params.record_cache.values()
        for rec in all_records:
            if rec.get('version') != 6:
                continue
            try:
                rec_uid = rec.get('record_uid', '')
                if not rec_uid:
                    continue
                controller = configuration_controller_get(
                    params, utils.base64_url_decode(rec_uid))
                if controller and controller.controllerUid == gateway_uid_bytes:
                    logging.info('Found PAM config "%s" for gateway "%s"',
                                 rec_uid, gateway.controllerName)
                    return rec_uid
            except Exception as e:
                logging.debug('Skipping record %s during config scan: %s', rec_uid, e)
                continue

        raise CommandError('kcm-import',
            f'No PAM configuration found for gateway "{gateway.controllerName}". '
            f'Create one first with: pam config create')

    def _resolve_db_password(self, params, kwargs):
        record_uid = kwargs.get('db_password_record') or ''
        if record_uid:
            record = vault.KeeperRecord.load(params, record_uid)
            if not record:
                raise CommandError('kcm-import',
                    f'Record {record_uid} not found in vault')
            # PasswordRecord (v2) has .password directly
            if hasattr(record, 'password') and record.password:
                return record.password
            # TypedRecord (v3) stores password in typed fields
            if hasattr(record, 'get_typed_field'):
                field = record.get_typed_field('password')
                if field and field.value:
                    val = field.value
                    if isinstance(val, list) and val:
                        return str(val[0])
                    if isinstance(val, str) and val:
                        return val
            raise CommandError('kcm-import',
                f'Record {record_uid} has no password field')
        return getpass.getpass('KCM Database Password: ')

    @staticmethod
    def _is_local_host(host):
        """Check if host is a local/private address (no SSL warning needed)."""
        if host in ('localhost', '127.0.0.1', '::1', ''):
            return True
        # Docker bridge and private RFC1918 ranges
        for prefix in ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                        '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                        '172.30.', '172.31.', '192.168.'):
            if host.startswith(prefix):
                return True
        return False

    @staticmethod
    def _filter_excluded_groups(groups, connection_rows, exclude_str):
        """Remove excluded groups and their descendant connections."""
        excludes = {x.strip() for x in exclude_str.split(',') if x.strip()}
        # Track which exclude tokens were matched
        matched_excludes = set()
        excluded_ids = set()
        for g in groups:
            gid_str = str(g['connection_group_id'])
            gname = g['connection_group_name']
            if gid_str in excludes:
                excluded_ids.add(g['connection_group_id'])
                matched_excludes.add(gid_str)
            elif gname in excludes:
                excluded_ids.add(g['connection_group_id'])
                matched_excludes.add(gname)
        unmatched = excludes - matched_excludes
        if unmatched:
            logging.warning('--exclude-groups: no match found for: %s',
                            ', '.join(sorted(unmatched)))
        # Cascade to descendants
        changed = True
        while changed:
            changed = False
            for g in groups:
                if g['connection_group_id'] not in excluded_ids:
                    if g.get('parent_id') in excluded_ids:
                        excluded_ids.add(g['connection_group_id'])
                        changed = True
        filtered_groups = [g for g in groups
                           if g['connection_group_id'] not in excluded_ids]
        filtered_rows = [r for r in connection_rows
                         if r.get('connection_group_id') not in excluded_ids]
        excluded_count = len(groups) - len(filtered_groups)
        row_count = len(connection_rows) - len(filtered_rows)
        if excluded_count:
            logging.info('Excluded %d group(s) and %d connection row(s)',
                         excluded_count, row_count)
        return filtered_groups, filtered_rows

    @staticmethod
    def _preview_group_tree(groups, resolver, connection_rows, project_name):
        """Print group-to-folder mapping tree and exit."""
        # Count unique connections per group
        conn_per_group = {}
        for row in connection_rows:
            gid = row.get('connection_group_id')
            cid = row.get('connection_id')
            conn_per_group.setdefault(gid, set()).add(cid)
        counts = {gid: len(cids) for gid, cids in conn_per_group.items()}

        # Build parent->children map
        group_map = {g['connection_group_id']: g for g in groups}
        children = {}
        for g in groups:
            pid = g.get('parent_id')
            children.setdefault(pid, []).append(g)

        # Find top-level groups
        top_level = [g for g in groups
                     if g.get('parent_id') is None
                     or g.get('parent_id') not in group_map]

        def fmt_path(gid):
            p = resolver.resolve_path(gid)
            base = f'{project_name} - Resources'
            return f'{base}/{p}' if p else base

        visited = set()

        def print_node(group, indent=0):
            gid = group['connection_group_id']
            if gid in visited:
                return
            visited.add(gid)
            name = group['connection_group_name']
            count = counts.get(gid, 0)
            path = fmt_path(gid)
            pad = '    ' * indent
            cnt = f' [{count}]' if count else ''
            print(f'{pad}+-- {name}{cnt}')
            print(f'{pad}|   -> {path}')
            for child in sorted(children.get(gid, []),
                                key=lambda x: x['connection_group_name']):
                print_node(child, indent + 1)

        root_count = counts.get(None, 0)
        total = sum(counts.values())

        print(f'\n{"=" * 60}')
        print(f'KCM Connection Groups -> Vault Folder Mapping')
        print(f'Project: {project_name}   Mode: {resolver.mode}')
        print(f'{"=" * 60}')
        if root_count:
            rpath = fmt_path(None)
            print(f'ROOT [{root_count} ungrouped]')
            print(f'|   -> {rpath}')
        for g in sorted(top_level, key=lambda x: x['connection_group_name']):
            print_node(g, 0)
        print(f'{"=" * 60}')
        print(f'Groups: {len(groups)}   Connections: {total}')
        print(f'{"=" * 60}')

    @staticmethod
    def _detect_docker_credentials(db_type, container='guacamole'):
        env_prefix = 'MYSQL' if db_type == 'mysql' else 'POSTGRES'
        default_port = 3306 if db_type == 'mysql' else 5432

        # Single docker inspect call, parse all env vars at once
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format',
                 '{{range .Config.Env}}{{println .}}{{end}}', container],
                capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise CommandError('kcm-import',
                f'Docker inspect failed: {e}')

        if result.returncode != 0:
            logging.debug('Docker stderr: %s', result.stderr.strip())
            raise CommandError('kcm-import',
                f'Docker inspect failed for container "{container}" (exit code {result.returncode})')

        env_vars = {}
        try:
            for line in result.stdout.strip().splitlines():
                if '=' in line:
                    k, v = line.split('=', 1)
                    env_vars[k] = v

            password = env_vars.get(f'{env_prefix}_PASSWORD')
            if not password:
                raise CommandError('kcm-import',
                    f'Could not detect {env_prefix}_PASSWORD from Docker container "{container}"')

            host = env_vars.get(f'{env_prefix}_HOSTNAME', '127.0.0.1')
            user = env_vars.get(f'{env_prefix}_USER') or env_vars.get(
                f'{env_prefix}_USERNAME', 'guacamole_user')
            database = env_vars.get(f'{env_prefix}_DATABASE', 'guacamole_db')
            port_str = env_vars.get(f'{env_prefix}_PORT')
            try:
                port = int(port_str) if port_str else default_port
            except ValueError:
                raise CommandError('kcm-import',
                    f'Invalid port value from Docker: {port_str}')

            logging.info('Docker auto-detected: host=%s, port=%d, db=%s',
                         host, port, database)
            return host, port, database, user, password
        finally:
            # Always clear secrets from memory regardless of success/failure
            result = None  # noqa: F841
            env_vars.clear()

    @staticmethod
    def _redact_for_display(pam_json):
        """Deep-copy JSON and replace password values with [REDACTED]."""
        redacted = copy.deepcopy(pam_json)
        sensitive_keys = {'password', 'private_pem_key', 'private_key',
                          'sftp-password', 'otp'}
        def _walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in sensitive_keys and isinstance(v, str) and v:
                        obj[k] = '[REDACTED]'
                    else:
                        _walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item)
        _walk(redacted)
        return redacted
