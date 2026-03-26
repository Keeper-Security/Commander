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
        except Exception as e:
            if isinstance(e, CommandError):
                raise
            raise CommandError('kcm-import', f'Schema validation failed: {e}')

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
            name = row['name']
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

    def __init__(self, groups, mode='ksm'):
        self.groups = {g['connection_group_id']: g for g in groups}
        self.mode = mode
        self.paths = {}  # type: Dict[int, str]
        self._resolve_all()

    def _resolve_all(self):
        for gid in self.groups:
            if self.mode == 'flat':
                raw = self.groups[gid]['connection_group_name']
                self.paths[gid] = raw.replace('/', '_').replace('\\', '_').replace('..', '_')
            else:
                self._resolve_path(gid)

    def _resolve_path(self, group_id, _seen=None):
        if group_id is None:
            return 'ROOT'
        if group_id in self.paths:
            return self.paths[group_id]
        if _seen is None:
            _seen = set()
        if group_id in _seen:
            return 'ROOT'
        _seen.add(group_id)
        group = self.groups.get(group_id)
        if not group:
            return 'ROOT'
        # Sanitize group name: strip path separators to prevent traversal
        safe_name = group['connection_group_name'].replace('/', '_').replace('\\', '_').replace('..', '_')
        if self.mode == 'ksm' and group.get('ksm_config'):
            self.paths[group_id] = safe_name
            return safe_name
        parent_path = self._resolve_path(group.get('parent_id'), _seen)
        full_path = f"{parent_path}/{safe_name}"
        self.paths[group_id] = full_path
        return full_path

    def resolve_path(self, group_id):
        if group_id is None:
            return 'ROOT'
        return self.paths.get(group_id, 'ROOT')

    def get_shared_folders(self):
        folders = set()
        for path in self.paths.values():
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
                        default='guacamole_db', help='Database name')
    parser.add_argument('--db-type', dest='db_type', action='store',
                        choices=['mysql', 'postgresql'], default='mysql',
                        help='Database type')
    parser.add_argument('--db-user', dest='db_user', action='store',
                        default='guacamole_user', help='Database username')
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
                        choices=['ksm', 'exact', 'flat'], default='ksm',
                        help='Connection group mapping mode')
    parser.add_argument('--output', '-o', dest='output', action='store',
                        help='Save JSON to file instead of importing')

    # Gateway options
    parser.add_argument('--gateway', '-g', dest='gateway', action='store',
                        help='Existing gateway UID or name (skips gateway creation)')
    parser.add_argument('--max-instances', dest='max_instances', type=int,
                        default=0,
                        help='Set gateway pool size (0 = skip, requires new gateway)')

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
        db_host = kwargs.get('db_host') or ''
        docker_detect = kwargs.get('docker_detect', False)

        if not db_host and not docker_detect:
            raise CommandError('kcm-import',
                'Either --db-host or --docker-detect is required')

        db_type = kwargs.get('db_type', 'mysql')
        db_port = kwargs.get('db_port') or (3306 if db_type == 'mysql' else 5432)
        db_name = kwargs.get('db_name', 'guacamole_db')
        db_user = kwargs.get('db_user', 'guacamole_user')
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
            db_host, db_port, db_name, db_user, db_password = \
                self._detect_docker_credentials(db_type, container_name)
        else:
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
            logging.debug('Database error details: %s', e)
            raise CommandError('kcm-import', f'Database connection failed: {e.__class__.__name__}')
        finally:
            connector.close()
            # Clear credentials from memory (best effort — Python strings are immutable)
            connector.password = None
            db_password = None  # noqa: F841

        logging.info('Extracted %d group(s), %d connection row(s)',
                     len(groups), len(connection_rows))

        # Build group hierarchy
        resolver = KCMGroupResolver(groups, mode=folder_mode)

        # Transform parameters
        mapper = KCMParameterMapper()
        resources, users = mapper.transform(connection_rows,
                                            include_disabled=include_disabled)

        # Assign folder paths
        shared_folders = set()
        for item in resources:
            group_id = item.pop('_group_id', None)
            kcm_path = resolver.resolve_path(group_id)
            folder_array = kcm_path.split('/')
            shared_folders.add(folder_array[0])
            folder_path = f'KCM Resources - {folder_array[0]}'
            if len(folder_array) > 1:
                folder_path += '/' + '/'.join(folder_array[1:])
            item['folder_path'] = folder_path

        for item in users:
            group_id = item.pop('_group_id', None)
            kcm_path = resolver.resolve_path(group_id)
            folder_array = kcm_path.split('/')
            folder_path = f'KCM Users - {folder_array[0]}'
            if len(folder_array) > 1:
                folder_path += '/' + '/'.join(folder_array[1:])
            item['folder_path'] = folder_path

        # Finalize TOTP
        KCMParameterMapper.finalize_totp(users)

        # Handle SFTP sub-resources
        sftp_resources = []
        sftp_users = []
        for resource in resources:
            sftp = resource.get('pam_settings', {}).get('connection', {}).get('sftp')
            if sftp:
                sftp_resource = {
                    'folder_path': resource['folder_path'] + '/SFTP Resources',
                    'title': f'SFTP connection for resource {resource["host"]}',
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
                            'launch_credentials': f'SFTP credentials for resource {resource["host"]}'
                        }
                    }
                }
                sftp_resources.append(sftp_resource)

                user_folder = resource['folder_path'].replace(
                    'KCM Resources - ', 'KCM Users - ', 1)
                sftp_user = {
                    'folder_path': f'{user_folder}/SFTP Users',
                    'title': f'SFTP credentials for resource {resource["host"]}',
                    'type': 'pamUser',
                    'login': sftp.get('login', ''),
                    'password': sftp.get('password', ''),
                    'private_pem_key': sftp.get('private_key', ''),
                    'rotation_settings': {}
                }
                sftp_users.append(sftp_user)

                sftp['sftp_resource'] = f'SFTP connection for resource {resource["host"]}'
                sftp['sftp_user_credentials'] = f'SFTP credentials for resource {resource["host"]}'

        resources.extend(sftp_resources)
        if not skip_users:
            users.extend(sftp_users)

        # Build shared folder list
        sf_list = []
        for folder in sorted(shared_folders):
            sf_list.extend([f'KCM Users - {folder}', f'KCM Resources - {folder}'])

        # Build PAM JSON
        pam_json = {
            'pam_data': {
                'shared_folders': sf_list,
                'resources': resources,
                'users': users if not skip_users else [],
            }
        }

        if not project_name:
            ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            project_name = f'KCM-Import-{ts}'

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
            return

        if dry_run:
            redacted = self._redact_for_display(pam_json)
            print(json.dumps(redacted, indent=2))
            logging.warning('Dry run: %d resources, %d users (no vault changes)',
                            num_resources, num_users)
            return

        # Gateway selection (only for new project imports, not extend mode)
        gateway_arg = kwargs.get('gateway') or ''
        if not config_uid:
            resolved_config = self._resolve_gateway(params, gateway_arg)
            if resolved_config:
                config_uid = resolved_config

        # Write to temp file and delegate to import/extend
        tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(tmp_fd, 'w') as tmp:
                json.dump(pam_json, tmp, indent=2)

            if config_uid:
                from .extend import PAMProjectExtendCommand
                cmd = PAMProjectExtendCommand()
                cmd.execute(params,
                            config=config_uid,
                            file_name=tmp_path,
                            dry_run=False)
            else:
                from .edit import PAMProjectImportCommand
                cmd = PAMProjectImportCommand()
                cmd.execute(params,
                            project_name=project_name,
                            file_name=tmp_path,
                            dry_run=False)

            logging.warning('KCM import complete: %d resources, %d users',
                            num_resources, num_users)

            # Set max instances for gateway pooling
            max_instances = kwargs.get('max_instances', 0)
            if max_instances > 0 and not config_uid:
                self._set_gateway_pool_size(params, project_name, max_instances)

            # Print deployment instructions for new gateways
            if not config_uid:
                self._print_deploy_instructions(project_name)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

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
                logging.warning('Could not set pool size: %s', type(e).__name__)
        else:
            logging.warning('Could not find gateway "%s" to set pool size.', gw_name)

    @staticmethod
    def _print_deploy_instructions(project_name):
        """Print Docker deployment one-liner after gateway creation."""
        print('\n' + '─' * 60)
        print('Gateway Deployment')
        print('─' * 60)
        print()
        print('Copy the access_token from above and deploy:')
        print()
        print('  # Docker (single instance)')
        print('  docker run -d --name keeper-gateway \\')
        print('    -e GATEWAY_CONFIG="<access_token>" \\')
        print('    -e ACCEPT_EULA=Y \\')
        print('    --shm-size=2g \\')
        print('    --restart unless-stopped \\')
        print('    keeper/gateway:latest')
        print()
        print('  # Docker Compose (HA pool)')
        print('  # Set GATEWAY_CONFIG in .env, then:')
        print('  # docker compose up -d')
        print()
        print('  # Kubernetes')
        print('  # Use the base64 config as a Secret:')
        print('  # kubectl create secret generic gateway-config \\')
        print('  #   --from-literal=GATEWAY_CONFIG="<access_token>"')
        print()
        print(f'  # Verify (after deployment):')
        print(f'  pam gateway list  # should show "{project_name} Gateway" as ONLINE')
        print('─' * 60)

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
        except Exception:
            logging.debug('Could not reach router to check online gateways')

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
                except (ValueError, IndexError):
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
            except Exception:
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
        for line in result.stdout.strip().splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                env_vars[k] = v
        # Clear raw docker output — contains all container env vars including secrets
        result = None

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
        # Clear parsed env vars — only keep what we need
        env_vars.clear()
        return host, port, database, user, password

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
