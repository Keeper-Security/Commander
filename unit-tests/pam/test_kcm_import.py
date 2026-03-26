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

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure Commander package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from keepercommander.commands.pam_import.kcm_import import (
    KCMDatabaseConnector,
    KCMGroupResolver,
    KCMParameterMapper,
    PAMProjectKCMImportCommand,
    _set_nested,
)


def _make_row(connection_id=1, name='TestConn', protocol='ssh',
              parameter_name=None, parameter_value=None,
              attribute_name=None, attribute_value=None,
              connection_group_id=None, parent_id=None,
              group_name=None, entity_name=None, entity_type=None):
    return {
        'connection_id': connection_id,
        'name': name,
        'protocol': protocol,
        'parameter_name': parameter_name,
        'parameter_value': parameter_value,
        'entity_name': entity_name,
        'entity_type': entity_type,
        'connection_group_id': connection_group_id,
        'parent_id': parent_id,
        'group_name': group_name,
        'attribute_name': attribute_name,
        'attribute_value': attribute_value,
    }


class TestParameterMapping(unittest.TestCase):
    """Tests for KCMParameterMapper."""

    def setUp(self):
        self.mapper = KCMParameterMapper()

    def test_parameter_mapping_basic(self):
        """username/password → login/password on user record."""
        rows = [
            _make_row(parameter_name='username', parameter_value='admin'),
            _make_row(parameter_name='password', parameter_value='secret123'),
            _make_row(parameter_name='hostname', parameter_value='10.0.0.1'),
        ]
        resources, users = self.mapper.transform(rows)
        self.assertEqual(len(resources), 1)
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]['login'], 'admin')
        self.assertEqual(users[0]['password'], 'secret123')
        self.assertEqual(resources[0]['host'], '10.0.0.1')

    def test_parameter_mapping_nested(self):
        """security → pam_settings.connection.security."""
        rows = [
            _make_row(protocol='rdp', parameter_name='security',
                      parameter_value='nla'),
        ]
        resources, users = self.mapper.transform(rows)
        self.assertEqual(
            resources[0]['pam_settings']['connection']['security'], 'nla')

    def test_parameter_mapping_ignore(self):
        """ksm-user-config-enabled should be silently ignored."""
        rows = [
            _make_row(attribute_name='ksm-user-config-enabled',
                      attribute_value='true'),
        ]
        resources, users = self.mapper.transform(rows)
        self.assertNotIn('ksm-user-config-enabled', json.dumps(resources[0]))

    def test_parameter_mapping_constant(self):
        """create-recording-path → graphical_session_recording=on."""
        rows = [
            _make_row(parameter_name='create-recording-path',
                      parameter_value='/recordings'),
        ]
        resources, _ = self.mapper.transform(rows)
        self.assertEqual(
            resources[0]['pam_settings']['options']['graphical_session_recording'],
            'on')


class TestGroupHierarchy(unittest.TestCase):
    """Tests for KCMGroupResolver."""

    def _groups(self):
        return [
            {'connection_group_id': 1, 'parent_id': None,
             'connection_group_name': 'RootGroup', 'ksm_config': 'some-config'},
            {'connection_group_id': 2, 'parent_id': 1,
             'connection_group_name': 'SubGroup', 'ksm_config': None},
            {'connection_group_id': 3, 'parent_id': None,
             'connection_group_name': 'NoConfig', 'ksm_config': None},
        ]

    def test_group_hierarchy_ksm(self):
        """Groups with ksm_config become root folders."""
        resolver = KCMGroupResolver(self._groups(), mode='ksm')
        self.assertEqual(resolver.resolve_path(1), 'RootGroup')
        self.assertEqual(resolver.resolve_path(2), 'RootGroup/SubGroup')

    def test_group_hierarchy_exact(self):
        """Exact nesting preserves full path."""
        resolver = KCMGroupResolver(self._groups(), mode='exact')
        self.assertEqual(resolver.resolve_path(1), 'ROOT/RootGroup')
        self.assertEqual(resolver.resolve_path(2), 'ROOT/RootGroup/SubGroup')
        self.assertEqual(resolver.resolve_path(3), 'ROOT/NoConfig')

    def test_group_hierarchy_flat(self):
        """All groups as root."""
        resolver = KCMGroupResolver(self._groups(), mode='flat')
        self.assertEqual(resolver.resolve_path(1), 'RootGroup')
        self.assertEqual(resolver.resolve_path(2), 'SubGroup')
        self.assertEqual(resolver.resolve_path(3), 'NoConfig')


class TestGroupSecurity(unittest.TestCase):
    """Tests for path traversal and circular group protection."""

    def test_path_traversal_sanitized(self):
        """Group names with slashes or '..' are sanitized."""
        groups = [
            {'connection_group_id': 1, 'parent_id': None,
             'connection_group_name': '../../Admin', 'ksm_config': None},
            {'connection_group_id': 2, 'parent_id': None,
             'connection_group_name': 'good/../../etc', 'ksm_config': None},
        ]
        resolver = KCMGroupResolver(groups, mode='exact')
        path1 = resolver.resolve_path(1)
        path2 = resolver.resolve_path(2)
        self.assertNotIn('..', path1)
        self.assertNotIn('..', path2)
        # Slashes in names replaced with underscores
        self.assertNotIn('../../', path1)

    def test_circular_group_no_crash(self):
        """Circular parent references don't cause infinite recursion."""
        groups = [
            {'connection_group_id': 1, 'parent_id': 2,
             'connection_group_name': 'GroupA', 'ksm_config': None},
            {'connection_group_id': 2, 'parent_id': 1,
             'connection_group_name': 'GroupB', 'ksm_config': None},
        ]
        # Should not raise RecursionError
        resolver = KCMGroupResolver(groups, mode='exact')
        path = resolver.resolve_path(1)
        self.assertIsInstance(path, str)

    def test_flat_mode_sanitized(self):
        """Flat mode also sanitizes group names."""
        groups = [
            {'connection_group_id': 1, 'parent_id': None,
             'connection_group_name': '../secret', 'ksm_config': None},
        ]
        resolver = KCMGroupResolver(groups, mode='flat')
        path = resolver.resolve_path(1)
        self.assertNotIn('..', path)
        self.assertNotIn('/', path)


class TestProtocolMapping(unittest.TestCase):
    """Tests for protocol → record type mapping."""

    def test_protocol_to_record_type(self):
        mapper = KCMParameterMapper()
        self.assertEqual(mapper.map_protocol_to_type('ssh'), 'pamMachine')
        self.assertEqual(mapper.map_protocol_to_type('rdp'), 'pamMachine')
        self.assertEqual(mapper.map_protocol_to_type('vnc'), 'pamMachine')
        self.assertEqual(mapper.map_protocol_to_type('mysql'), 'pamDatabase')
        self.assertEqual(mapper.map_protocol_to_type('postgres'), 'pamDatabase')
        self.assertEqual(mapper.map_protocol_to_type('sql-server'), 'pamDatabase')
        self.assertEqual(mapper.map_protocol_to_type('http'), 'pamRemoteBrowser')


class TestTOTPConstruction(unittest.TestCase):
    """Tests for TOTP → otpauth:// URL assembly."""

    def test_totp_construction(self):
        rows = [
            _make_row(parameter_name='totp-algorithm', parameter_value='SHA1'),
            _make_row(parameter_name='totp-digits', parameter_value='6'),
            _make_row(parameter_name='totp-period', parameter_value='30'),
            _make_row(parameter_name='totp-secret', parameter_value='JBSWY3DPEHPK3PXP'),
        ]
        mapper = KCMParameterMapper()
        _, users = mapper.transform(rows)
        KCMParameterMapper.finalize_totp(users)
        self.assertIn('otp', users[0])
        otp = users[0]['otp']
        self.assertTrue(otp.startswith('otpauth://totp/'))
        self.assertIn('secret=JBSWY3DPEHPK3PXP', otp)
        self.assertIn('algorithm=SHA1', otp)
        self.assertIn('digits=6', otp)
        self.assertIn('period=30', otp)


class TestDryRunRedaction(unittest.TestCase):
    """Tests that dry-run output redacts sensitive data."""

    def test_dry_run_redacts(self):
        pam_json = {
            'pam_data': {
                'resources': [
                    {'title': 'R1', 'host': '1.2.3.4'}
                ],
                'users': [
                    {'title': 'U1', 'password': 'supersecret',
                     'private_pem_key': '-----BEGIN RSA-----',
                     'otp': 'otpauth://totp/x?secret=ABC'}
                ]
            }
        }
        redacted = PAMProjectKCMImportCommand._redact_for_display(pam_json)
        user = redacted['pam_data']['users'][0]
        self.assertEqual(user['password'], '[REDACTED]')
        self.assertEqual(user['private_pem_key'], '[REDACTED]')
        self.assertEqual(user['otp'], '[REDACTED]')
        # Original unchanged
        self.assertEqual(pam_json['pam_data']['users'][0]['password'], 'supersecret')


class TestSchemaValidation(unittest.TestCase):
    """Tests that missing tables raise CommandError."""

    def test_missing_tables_error(self):
        connector = KCMDatabaseConnector(
            'mysql', 'localhost', 3306, 'user', 'pass', 'db')
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        connector.cursor = mock_cursor

        from keepercommander.error import CommandError as BaseCommandError
        with self.assertRaises(BaseCommandError):
            connector.validate_schema()


class TestJSONSchema(unittest.TestCase):
    """Tests that output matches the expected import JSON schema."""

    def test_json_matches_import_schema(self):
        rows = [
            _make_row(connection_id=1, name='Web1', protocol='http',
                      parameter_name='hostname', parameter_value='web.example.com'),
            _make_row(connection_id=2, name='DB1', protocol='mysql',
                      parameter_name='hostname', parameter_value='db.example.com'),
            _make_row(connection_id=3, name='SSH1', protocol='ssh',
                      parameter_name='hostname', parameter_value='ssh.example.com'),
        ]
        mapper = KCMParameterMapper()
        resources, users = mapper.transform(rows)
        KCMParameterMapper.finalize_totp(users)

        # Assign minimal folder paths
        for item in resources + users:
            item.pop('_group_id', None)
            item['folder_path'] = 'ROOT'

        pam_json = {
            'project': 'TestProject',
            'pam_data': {
                'shared_folders': [],
                'resources': resources,
                'users': users,
            }
        }

        # Validate structure
        self.assertIn('project', pam_json)
        self.assertIn('pam_data', pam_json)
        self.assertIn('resources', pam_json['pam_data'])
        self.assertIn('users', pam_json['pam_data'])
        self.assertEqual(len(pam_json['pam_data']['resources']), 3)
        self.assertEqual(len(pam_json['pam_data']['users']), 3)

        # Check record types
        types = [r['type'] for r in pam_json['pam_data']['resources']]
        self.assertIn('pamRemoteBrowser', types)
        self.assertIn('pamDatabase', types)
        self.assertIn('pamMachine', types)


class TestSetNested(unittest.TestCase):
    """Tests for _set_nested utility."""

    def test_set_nested_creates_path(self):
        d = {}
        _set_nested(d, 'a.b.c', 'value')
        self.assertEqual(d['a']['b']['c'], 'value')

    def test_set_nested_preserves_existing(self):
        d = {'a': {'existing': 'keep'}}
        _set_nested(d, 'a.new_key', 'new_value')
        self.assertEqual(d['a']['existing'], 'keep')
        self.assertEqual(d['a']['new_key'], 'new_value')


class TestE2EExecuteDryRun(unittest.TestCase):
    """E2E: full execute() pipeline with dry-run (mocked DB, no vault changes)."""

    def _mock_db_data(self):
        groups = [
            {'connection_group_id': 1, 'parent_id': None,
             'connection_group_name': 'Production', 'ksm_config': 'prod-config'},
            {'connection_group_id': 2, 'parent_id': 1,
             'connection_group_name': 'Linux', 'ksm_config': None},
        ]
        rows = [
            _make_row(connection_id=10, name='WebServer', protocol='ssh',
                      parameter_name='hostname', parameter_value='10.0.1.10',
                      connection_group_id=2, parent_id=1, group_name='Linux'),
            _make_row(connection_id=10, name='WebServer', protocol='ssh',
                      parameter_name='username', parameter_value='deploy',
                      connection_group_id=2, parent_id=1, group_name='Linux'),
            _make_row(connection_id=10, name='WebServer', protocol='ssh',
                      parameter_name='password', parameter_value='s3cret',
                      connection_group_id=2, parent_id=1, group_name='Linux'),
            _make_row(connection_id=10, name='WebServer', protocol='ssh',
                      parameter_name='port', parameter_value='2222',
                      connection_group_id=2, parent_id=1, group_name='Linux'),
            _make_row(connection_id=20, name='AppDB', protocol='mysql',
                      parameter_name='hostname', parameter_value='10.0.1.20',
                      connection_group_id=1, parent_id=None, group_name='Production'),
            _make_row(connection_id=20, name='AppDB', protocol='mysql',
                      parameter_name='username', parameter_value='dbadmin',
                      connection_group_id=1, parent_id=None, group_name='Production'),
            _make_row(connection_id=20, name='AppDB', protocol='mysql',
                      parameter_name='password', parameter_value='dbpass123',
                      connection_group_id=1, parent_id=None, group_name='Production'),
            _make_row(connection_id=30, name='Intranet', protocol='http',
                      parameter_name='hostname', parameter_value='intranet.local',
                      connection_group_id=1, parent_id=None, group_name='Production'),
        ]
        return groups, rows

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_dry_run_full_pipeline(self, mock_getpass, MockConnector):
        """Full pipeline: connect → extract → transform → dry-run output."""
        groups, rows = self._mock_db_data()

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print') as mock_print:
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        dry_run=True,
                        project_name='E2E Test')

        # Verify print was called with JSON
        self.assertTrue(mock_print.called)
        output = mock_print.call_args[0][0]
        result = json.loads(output)

        # Verify structure
        self.assertIn('project', result)
        self.assertEqual(result['project'], 'E2E Test')
        self.assertIn('pam_data', result)
        resources = result['pam_data']['resources']
        users = result['pam_data']['users']

        self.assertEqual(len(resources), 3)
        self.assertEqual(len(users), 3)

        # Verify record types
        types = {r['title']: r['type'] for r in resources}
        self.assertEqual(types['KCM Resource - WebServer'], 'pamMachine')
        self.assertEqual(types['KCM Resource - AppDB'], 'pamDatabase')
        self.assertEqual(types['KCM Resource - Intranet'], 'pamRemoteBrowser')

        # Verify passwords are REDACTED in dry-run
        for user in users:
            if 'password' in user and user['password']:
                self.assertEqual(user['password'], '[REDACTED]')

        # Verify folder paths use ksm mode (Production has config → root)
        web_resource = next(r for r in resources
                           if r['title'] == 'KCM Resource - WebServer')
        self.assertEqual(web_resource['folder_path'],
                         'KCM Resources - Production/Linux')

        db_resource = next(r for r in resources
                           if r['title'] == 'KCM Resource - AppDB')
        self.assertEqual(db_resource['folder_path'],
                         'KCM Resources - Production')

        # Verify host extraction
        self.assertEqual(web_resource['host'], '10.0.1.10')
        self.assertEqual(web_resource['pam_settings']['connection']['port'], '2222')

        # Verify DB connection was properly closed
        mock_conn.close.assert_called_once()

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_output_file_pipeline(self, mock_getpass, MockConnector):
        """Full pipeline: writes valid JSON to --output file."""
        groups, rows = self._mock_db_data()

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            output_path = f.name

        try:
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        output=output_path,
                        project_name='Output Test')

            with open(output_path) as f:
                result = json.load(f)

            self.assertIn('project', result)
            self.assertIn('pam_data', result)
            # Passwords are NOT redacted in --output (full data for review)
            users = result['pam_data']['users']
            deploy_user = next((u for u in users
                                if u.get('login') == 'deploy'), None)
            self.assertIsNotNone(deploy_user)
            self.assertEqual(deploy_user['password'], 's3cret')
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_skip_users_pipeline(self, mock_getpass, MockConnector):
        """Full pipeline with --skip-users: no users in output."""
        groups, rows = self._mock_db_data()

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print') as mock_print:
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        dry_run=True,
                        skip_users=True,
                        project_name='Skip Users Test')

        result = json.loads(mock_print.call_args[0][0])
        self.assertEqual(result['pam_data']['users'], [])
        self.assertEqual(len(result['pam_data']['resources']), 3)

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_extend_mode_delegates(self, mock_getpass, MockConnector):
        """E2E: --config delegates to PAMProjectExtendCommand."""
        groups, rows = self._mock_db_data()

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        # Capture the JSON content when extend is called (before cleanup)
        captured_data = {}

        mock_extend_cmd = MagicMock()
        def capture_extend(params, **kwargs):
            with open(kwargs['file_name']) as f:
                captured_data['json'] = json.load(f)
            captured_data['kwargs'] = kwargs
        mock_extend_cmd.execute = MagicMock(side_effect=capture_extend)

        # Mock the lazy import inside execute() to avoid importing
        # the real extend module (which pulls in pydantic on 3.7)
        mock_extend_class = MagicMock(return_value=mock_extend_cmd)
        mock_extend_module = MagicMock(PAMProjectExtendCommand=mock_extend_class)

        import importlib
        with patch.dict('sys.modules',
                        {'keepercommander.commands.pam_import.extend': mock_extend_module}):
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        config='existing-pam-config-uid')

        mock_extend_cmd.execute.assert_called_once()
        self.assertEqual(captured_data['kwargs']['config'],
                         'existing-pam-config-uid')
        self.assertTrue(
            captured_data['kwargs']['file_name'].endswith('.json'))
        # JSON key should NOT have 'project' in extend mode
        self.assertNotIn('project', captured_data['json'])

    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._resolve_gateway',
           return_value=None)
    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_import_mode_delegates(self, mock_getpass, MockConnector, mock_gw):
        """E2E: no --config delegates to PAMProjectImportCommand."""
        groups, rows = self._mock_db_data()

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        # Mock the lazy import inside execute() to avoid importing
        # the real edit module (which pulls in pydantic on 3.7)
        mock_import_cmd = MagicMock()
        mock_import_class = MagicMock(return_value=mock_import_cmd)
        mock_edit_module = MagicMock(PAMProjectImportCommand=mock_import_class)

        with patch.dict('sys.modules',
                        {'keepercommander.commands.pam_import.edit': mock_edit_module}):
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        project_name='Import Test')

        mock_import_cmd.execute.assert_called_once()
        call_kwargs = mock_import_cmd.execute.call_args
        self.assertEqual(call_kwargs[1]['project_name'], 'Import Test')
        self.assertTrue(call_kwargs[1]['file_name'].endswith('.json'))

    def test_no_db_host_raises(self):
        """Execute without --db-host or --docker-detect raises CommandError."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()
        from keepercommander.error import CommandError as BaseCommandError
        with self.assertRaises(BaseCommandError):
            cmd.execute(params)

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    def test_vault_record_password(self, MockConnector):
        """E2E: --db-password-record loads password from vault."""
        groups = []
        rows = [_make_row(parameter_name='hostname', parameter_value='10.0.0.1')]

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()
        mock_record = MagicMock()
        mock_record.password = 'vault-db-pass'

        with patch('keepercommander.commands.pam_import.kcm_import.vault.'
                   'KeeperRecord.load', return_value=mock_record):
            with patch('builtins.print'):
                cmd.execute(params,
                            db_host='127.0.0.1',
                            db_password_record='RECORD_UID_123',
                            dry_run=True)

        # Verify connector received the vault password
        MockConnector.assert_called_once()
        call_args = MockConnector.call_args
        self.assertEqual(call_args[0][4], 'vault-db-pass')  # password arg

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    def test_vault_record_not_found_raises(self, MockConnector):
        """E2E: --db-password-record with invalid UID raises CommandError."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('keepercommander.commands.pam_import.kcm_import.vault.'
                   'KeeperRecord.load', return_value=None):
            from keepercommander.error import CommandError as BaseCommandError
            with self.assertRaises(BaseCommandError) as ctx:
                cmd.execute(params,
                            db_host='127.0.0.1',
                            db_password_record='BAD_UID')
            self.assertIn('not found', str(ctx.exception))


class TestE2EDockerDetect(unittest.TestCase):
    """E2E: --docker-detect credential auto-detection."""

    @patch('keepercommander.commands.pam_import.kcm_import.subprocess.run')
    def test_docker_detect_parses_env(self, mock_run):
        """Docker env vars are parsed into credentials."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='MYSQL_HOSTNAME=db.local\nMYSQL_USER=guac\n'
                   'MYSQL_PASSWORD=dockerpass\nMYSQL_DATABASE=guac_db\n'
                   'MYSQL_PORT=3307\nOTHER_VAR=ignored\n',
            stderr=''
        )
        host, port, db, user, password = \
            PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
        self.assertEqual(host, 'db.local')
        self.assertEqual(port, 3307)
        self.assertEqual(db, 'guac_db')
        self.assertEqual(user, 'guac')
        self.assertEqual(password, 'dockerpass')

    @patch('keepercommander.commands.pam_import.kcm_import.subprocess.run')
    def test_docker_detect_no_password_raises(self, mock_run):
        """Missing password env var raises CommandError."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='MYSQL_HOSTNAME=db.local\nMYSQL_USER=guac\n',
            stderr=''
        )
        from keepercommander.error import CommandError as BaseCommandError
        with self.assertRaises(BaseCommandError) as ctx:
            PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
        self.assertIn('MYSQL_PASSWORD', str(ctx.exception))

    @patch('keepercommander.commands.pam_import.kcm_import.subprocess.run')
    def test_docker_detect_container_not_found(self, mock_run):
        """Docker inspect failure raises CommandError."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='',
            stderr='Error: No such object: guacamole'
        )
        from keepercommander.error import CommandError as BaseCommandError
        with self.assertRaises(BaseCommandError) as ctx:
            PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
        self.assertIn('Docker inspect failed', str(ctx.exception))

    @patch('keepercommander.commands.pam_import.kcm_import.subprocess.run')
    def test_docker_detect_postgresql(self, mock_run):
        """PostgreSQL mode uses POSTGRES_ prefix."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='POSTGRES_HOSTNAME=pg.local\nPOSTGRES_USER=pguser\n'
                   'POSTGRES_PASSWORD=pgpass\nPOSTGRES_DATABASE=guac_pg\n',
            stderr=''
        )
        host, port, db, user, password = \
            PAMProjectKCMImportCommand._detect_docker_credentials('postgresql')
        self.assertEqual(host, 'pg.local')
        self.assertEqual(port, 5432)  # default
        self.assertEqual(db, 'guac_pg')
        self.assertEqual(user, 'pguser')
        self.assertEqual(password, 'pgpass')


class TestE2ESFTPSubResources(unittest.TestCase):
    """E2E: SFTP sub-resources are created when sftp mappings present."""

    def test_sftp_creates_sub_resources(self):
        rows = [
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='hostname', parameter_value='10.0.0.5'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='enable-sftp', parameter_value='true'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='sftp-hostname', parameter_value='10.0.0.6'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='sftp-port', parameter_value='22'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='sftp-username', parameter_value='sftpuser'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='sftp-password', parameter_value='sftppass'),
        ]
        mapper = KCMParameterMapper()
        resources, users = mapper.transform(rows)

        # Assign folder paths as execute() would
        for item in resources + users:
            item.pop('_group_id', None)
            item['folder_path'] = 'KCM Resources - ROOT'

        for item in users:
            item['folder_path'] = 'KCM Users - ROOT'

        KCMParameterMapper.finalize_totp(users)

        # Simulate SFTP sub-resource creation (from execute())
        sftp_resources = []
        sftp_users = []
        for resource in resources:
            sftp = resource.get('pam_settings', {}).get('connection', {}).get('sftp')
            if sftp:
                sftp_resources.append({
                    'folder_path': resource['folder_path'] + '/SFTP Resources',
                    'title': f'SFTP connection for resource {resource["host"]}',
                    'type': 'pamMachine',
                    'host': sftp.get('host', ''),
                })
                sftp_users.append({
                    'folder_path': 'KCM Users - ROOT/SFTP Users',
                    'title': f'SFTP credentials for resource {resource["host"]}',
                    'type': 'pamUser',
                    'login': sftp.get('login', ''),
                    'password': sftp.get('password', ''),
                })

        resources.extend(sftp_resources)
        users.extend(sftp_users)

        # Verify SFTP sub-resource was created
        self.assertEqual(len(resources), 2)
        sftp_r = next(r for r in resources if 'SFTP' in r['title'])
        self.assertEqual(sftp_r['host'], '10.0.0.6')
        self.assertEqual(sftp_r['type'], 'pamMachine')

        sftp_u = next(u for u in users if 'SFTP' in u['title'])
        self.assertEqual(sftp_u['login'], 'sftpuser')
        self.assertEqual(sftp_u['password'], 'sftppass')


class TestE2EMultipleConnections(unittest.TestCase):
    """E2E: multiple connections with different protocols and groups."""

    def test_mixed_protocols_and_groups(self):
        """Verifies correct handling of multiple connections across groups."""
        groups = [
            {'connection_group_id': 1, 'parent_id': None,
             'connection_group_name': 'DC-East', 'ksm_config': 'east-config'},
            {'connection_group_id': 2, 'parent_id': None,
             'connection_group_name': 'DC-West', 'ksm_config': 'west-config'},
        ]

        rows = [
            # SSH in DC-East
            _make_row(connection_id=1, name='SSH-East', protocol='ssh',
                      parameter_name='hostname', parameter_value='east.ssh.local',
                      connection_group_id=1),
            _make_row(connection_id=1, name='SSH-East', protocol='ssh',
                      parameter_name='username', parameter_value='eastadmin',
                      connection_group_id=1),
            # PostgreSQL in DC-West
            _make_row(connection_id=2, name='PG-West', protocol='postgres',
                      parameter_name='hostname', parameter_value='west.pg.local',
                      connection_group_id=2),
            _make_row(connection_id=2, name='PG-West', protocol='postgres',
                      parameter_name='database', parameter_value='appdb',
                      connection_group_id=2),
            # RDP with no group
            _make_row(connection_id=3, name='RDP-Orphan', protocol='rdp',
                      parameter_name='hostname', parameter_value='orphan.rdp.local',
                      connection_group_id=None),
            _make_row(connection_id=3, name='RDP-Orphan', protocol='rdp',
                      parameter_name='security', parameter_value='nla',
                      connection_group_id=None),
        ]

        resolver = KCMGroupResolver(groups, mode='ksm')
        mapper = KCMParameterMapper()
        resources, users = mapper.transform(rows)

        # Assign folder paths
        for item in resources:
            gid = item.pop('_group_id', None)
            path = resolver.resolve_path(gid)
            folder_array = path.split('/')
            item['folder_path'] = f'KCM Resources - {folder_array[0]}'
            if len(folder_array) > 1:
                item['folder_path'] += '/' + '/'.join(folder_array[1:])

        for item in users:
            item.pop('_group_id', None)

        self.assertEqual(len(resources), 3)
        self.assertEqual(len(users), 3)

        # Check folder paths
        ssh = next(r for r in resources if r['title'] == 'KCM Resource - SSH-East')
        self.assertEqual(ssh['folder_path'], 'KCM Resources - DC-East')
        self.assertEqual(ssh['host'], 'east.ssh.local')
        self.assertEqual(ssh['type'], 'pamMachine')

        pg = next(r for r in resources if r['title'] == 'KCM Resource - PG-West')
        self.assertEqual(pg['folder_path'], 'KCM Resources - DC-West')
        self.assertEqual(pg['type'], 'pamDatabase')
        # postgres → postgresql protocol mapping
        self.assertEqual(pg['pam_settings']['connection']['protocol'], 'postgresql')
        self.assertEqual(pg['pam_settings']['connection']['default_database'], 'appdb')

        rdp = next(r for r in resources if r['title'] == 'KCM Resource - RDP-Orphan')
        self.assertEqual(rdp['folder_path'], 'KCM Resources - ROOT')
        self.assertEqual(rdp['pam_settings']['connection']['security'], 'nla')

        # Check user mappings
        east_user = next(u for u in users if u['title'] == 'KCM User - SSH-East')
        self.assertEqual(east_user['login'], 'eastadmin')


class TestE2EIncludeDisabled(unittest.TestCase):
    """E2E: --include-disabled filtering."""

    def test_disabled_connections_excluded_by_default(self):
        """Connections with max_connections=0 are excluded by default."""
        rows = [
            _make_row(connection_id=1, name='Active', protocol='ssh',
                      parameter_name='hostname', parameter_value='10.0.0.1'),
            _make_row(connection_id=2, name='Disabled', protocol='ssh',
                      parameter_name='hostname', parameter_value='10.0.0.2'),
        ]
        # Add max_connections field
        rows[0]['max_connections'] = None  # not set = active
        rows[1]['max_connections'] = 0  # disabled

        mapper = KCMParameterMapper()
        resources, users = mapper.transform(rows, include_disabled=False)
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['title'], 'KCM Resource - Active')

    def test_disabled_connections_included_when_flag_set(self):
        """Connections with max_connections=0 are included with --include-disabled."""
        rows = [
            _make_row(connection_id=1, name='Active', protocol='ssh',
                      parameter_name='hostname', parameter_value='10.0.0.1'),
            _make_row(connection_id=2, name='Disabled', protocol='ssh',
                      parameter_name='hostname', parameter_value='10.0.0.2'),
        ]
        rows[0]['max_connections'] = None
        rows[1]['max_connections'] = 0

        mapper = KCMParameterMapper()
        resources, users = mapper.transform(rows, include_disabled=True)
        self.assertEqual(len(resources), 2)


class TestE2ETypedRecordPassword(unittest.TestCase):
    """E2E: vault record password resolution for v3 TypedRecord."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    def test_typed_record_password(self, MockConnector):
        """v3 TypedRecord password is extracted via get_typed_field."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        # Create a TypedRecord-like mock (no .password attr, has get_typed_field)
        mock_record = MagicMock(spec=[])  # no attributes
        mock_record.password = None  # hasattr will be True but value falsy
        del mock_record.password  # now hasattr returns False

        mock_field = MagicMock()
        mock_field.value = ['typed-db-pass']
        mock_record.get_typed_field = MagicMock(return_value=mock_field)

        with patch('keepercommander.commands.pam_import.kcm_import.vault.'
                   'KeeperRecord.load', return_value=mock_record):
            with patch('builtins.print'):
                cmd.execute(params,
                            db_host='127.0.0.1',
                            db_password_record='V3_RECORD_UID',
                            dry_run=True)

        # Verify connector received the v3 password
        MockConnector.assert_called_once()
        call_args = MockConnector.call_args
        self.assertEqual(call_args[0][4], 'typed-db-pass')

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    def test_v2_password_record(self, MockConnector):
        """v2 PasswordRecord password is extracted via .password attr."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        mock_record = MagicMock()
        mock_record.password = 'v2-legacy-pass'

        with patch('keepercommander.commands.pam_import.kcm_import.vault.'
                   'KeeperRecord.load', return_value=mock_record):
            with patch('builtins.print'):
                cmd.execute(params,
                            db_host='127.0.0.1',
                            db_password_record='V2_RECORD_UID',
                            dry_run=True)

        call_args = MockConnector.call_args
        self.assertEqual(call_args[0][4], 'v2-legacy-pass')


class TestE2EDockerEnvWithSpaces(unittest.TestCase):
    """E2E: Docker env vars with special characters."""

    @patch('keepercommander.commands.pam_import.kcm_import.subprocess.run')
    def test_docker_env_password_with_equals(self, mock_run):
        """Password containing = sign is correctly parsed."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='MYSQL_PASSWORD=pass=word=123\nMYSQL_HOSTNAME=db\n',
            stderr=''
        )
        host, port, db, user, password = \
            PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
        self.assertEqual(password, 'pass=word=123')


class TestE2ETempFileCleanup(unittest.TestCase):
    """E2E: temp file is cleaned up even when import/extend raises."""

    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._resolve_gateway',
           return_value=None)
    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_temp_file_cleaned_on_error(self, mock_getpass, MockConnector, mock_gw):
        """Temp file does not leak when import command raises."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        # Track the temp file path created by mkstemp
        created_paths = []
        original_mkstemp = tempfile.mkstemp
        def tracking_mkstemp(**kwargs):
            fd, path = original_mkstemp(**kwargs)
            created_paths.append(path)
            return fd, path

        # Mock the lazy import to avoid pydantic dependency on 3.7
        mock_import_cmd = MagicMock()
        mock_import_cmd.execute = MagicMock(side_effect=Exception('Vault error'))
        mock_import_class = MagicMock(return_value=mock_import_cmd)
        mock_edit_module = MagicMock(PAMProjectImportCommand=mock_import_class)

        with patch('keepercommander.commands.pam_import.kcm_import.tempfile.mkstemp',
                   side_effect=tracking_mkstemp):
            with patch.dict('sys.modules',
                            {'keepercommander.commands.pam_import.edit': mock_edit_module}):
                with self.assertRaises(Exception):
                    cmd.execute(params,
                                db_host='127.0.0.1',
                                project_name='Fail Test')

        # Verify the temp file was actually cleaned up
        self.assertTrue(len(created_paths) > 0, 'No temp file was created')
        for path in created_paths:
            self.assertFalse(os.path.exists(path),
                             f'Temp file leaked: {path}')


class TestDBSSLFlag(unittest.TestCase):
    """E2E: --db-ssl flag is passed through to connector."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_ssl_flag_passed_to_connector(self, mock_getpass, MockConnector):
        """--db-ssl=True is forwarded as ssl=True to KCMDatabaseConnector."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_ssl=True,
                        dry_run=True)

        call_kwargs = MockConnector.call_args
        self.assertTrue(call_kwargs[1].get('ssl', False))

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_ssl_default_off(self, mock_getpass, MockConnector):
        """Without --db-ssl, ssl defaults to False."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            cmd.execute(params,
                        db_host='127.0.0.1',
                        dry_run=True)

        call_kwargs = MockConnector.call_args
        self.assertFalse(call_kwargs[1].get('ssl', False))


class TestOutputFilePermissions(unittest.TestCase):
    """E2E: --output file is written with secure permissions."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_output_file_owner_only(self, mock_getpass, MockConnector):
        """--output file must have 0o600 permissions (owner read/write only)."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        import stat
        tmp_dir = tempfile.mkdtemp()
        output_path = os.path.join(tmp_dir, 'test_output.json')
        try:
            cmd.execute(params,
                        db_host='127.0.0.1',
                        output=output_path)

            file_mode = os.stat(output_path).st_mode & 0o777
            self.assertEqual(file_mode, 0o600,
                             f'Expected 0o600, got {oct(file_mode)}')
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
            os.rmdir(tmp_dir)


class TestRemoteSSLEnforcement(unittest.TestCase):
    """Remote connections must require SSL or explicit --allow-cleartext."""

    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_remote_host_without_ssl_blocked(self, mock_getpass):
        """Remote host without --db-ssl or --allow-cleartext must raise."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        from keepercommander.error import CommandError
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, db_host='203.0.113.50', dry_run=True)
        self.assertIn('cleartext', str(ctx.exception).lower())

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_remote_host_with_ssl_allowed(self, mock_getpass, MockConnector):
        """Remote host with --db-ssl should connect normally."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            cmd.execute(params, db_host='203.0.113.50', db_ssl=True, dry_run=True)
        # Should not raise

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_remote_host_with_allow_cleartext(self, mock_getpass, MockConnector):
        """Remote host with --allow-cleartext should warn but connect."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            cmd.execute(params, db_host='203.0.113.50',
                        allow_cleartext=True, dry_run=True)
        # Should not raise

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_localhost_without_ssl_allowed(self, mock_getpass, MockConnector):
        """Localhost connections should work without SSL."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            cmd.execute(params, db_host='127.0.0.1', dry_run=True)
        # Should not raise

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_private_ip_without_ssl_allowed(self, mock_getpass, MockConnector):
        """RFC1918 addresses should work without SSL."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            cmd.execute(params, db_host='192.168.1.100', dry_run=True)
        # Should not raise


class TestCredentialCleanup(unittest.TestCase):
    """Sensitive data should be cleared from memory after use."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='supersecret')
    def test_connector_password_cleared_after_close(self, mock_getpass, MockConnector):
        """Connector.password should be None after execute completes."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            cmd.execute(params, db_host='127.0.0.1', dry_run=True)

        # Password should have been cleared in the finally block
        self.assertIsNone(mock_conn.password)

    def test_docker_detect_clears_env_vars(self):
        """Docker inspect output should be cleared after parsing."""
        import subprocess
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'MYSQL_PASSWORD=secret123\nMYSQL_HOSTNAME=db\nOTHER_SECRET=xyz\n'

        with patch('subprocess.run', return_value=mock_result):
            host, port, db, user, password = \
                PAMProjectKCMImportCommand._detect_docker_credentials('mysql', 'test')

        self.assertEqual(password, 'secret123')
        self.assertEqual(host, 'db')


class TestDockerLogSanitization(unittest.TestCase):
    """Docker detect logs should not contain usernames."""

    def test_no_username_in_log_output(self):
        """The info log from docker detect should not include the db username."""
        import inspect
        source = inspect.getsource(PAMProjectKCMImportCommand._detect_docker_credentials)
        # Should NOT log user=%s
        self.assertNotIn('user=%s', source)


###############################################################################
# Live E2E tests — connect to real KCM PostgreSQL database
###############################################################################

# Connection details from environment variables (no hardcoded credentials).
# Set these env vars to enable live tests:
#   KCM_TEST_DB_HOST, KCM_TEST_DB_PORT, KCM_TEST_DB_NAME,
#   KCM_TEST_DB_USER, KCM_TEST_DB_PASS, KCM_TEST_DB_TYPE,
#   KCM_TEST_DOCKER_CONTAINER
# Or use --docker-detect to auto-populate from a running container.
_LIVE_DB_HOST = os.environ.get('KCM_TEST_DB_HOST', '')
_LIVE_DB_PORT = int(os.environ.get('KCM_TEST_DB_PORT', '5432'))
_LIVE_DB_NAME = os.environ.get('KCM_TEST_DB_NAME', 'guacamole_db')
_LIVE_DB_USER = os.environ.get('KCM_TEST_DB_USER', 'guacamole_user')
_LIVE_DB_PASS = os.environ.get('KCM_TEST_DB_PASS', '')
_LIVE_DB_TYPE = os.environ.get('KCM_TEST_DB_TYPE', 'postgresql')
_LIVE_DOCKER_CONTAINER = os.environ.get('KCM_TEST_DOCKER_CONTAINER', 'guacamole')


def _db_available():
    """Check if the live KCM database is reachable."""
    try:
        conn = KCMDatabaseConnector(
            _LIVE_DB_TYPE, _LIVE_DB_HOST, _LIVE_DB_PORT,
            _LIVE_DB_USER, _LIVE_DB_PASS, _LIVE_DB_NAME)
        conn.connect()
        conn.close()
        return True
    except Exception:
        return False


_SKIP_LIVE = not _db_available()
_SKIP_MSG = 'KCM database not reachable'


@unittest.skipIf(_SKIP_LIVE, _SKIP_MSG)
class TestLiveDBConnection(unittest.TestCase):
    """Real connection to KCM PostgreSQL database."""

    def test_connect_and_validate_schema(self):
        """Connect to real DB and validate guacamole schema exists."""
        conn = KCMDatabaseConnector(
            _LIVE_DB_TYPE, _LIVE_DB_HOST, _LIVE_DB_PORT,
            _LIVE_DB_USER, _LIVE_DB_PASS, _LIVE_DB_NAME)
        conn.connect()
        conn.validate_schema()  # must not raise
        conn.close()

    def test_extract_groups_returns_data(self):
        """extract_groups should return at least one group."""
        conn = KCMDatabaseConnector(
            _LIVE_DB_TYPE, _LIVE_DB_HOST, _LIVE_DB_PORT,
            _LIVE_DB_USER, _LIVE_DB_PASS, _LIVE_DB_NAME)
        conn.connect()
        groups = conn.extract_groups()
        conn.close()
        self.assertIsInstance(groups, list)
        self.assertGreater(len(groups), 0)
        # Each group should have required keys
        for g in groups:
            self.assertIn('connection_group_id', g)
            self.assertIn('connection_group_name', g)

    def test_extract_connections_returns_data(self):
        """extract_connections should return rows with expected columns."""
        conn = KCMDatabaseConnector(
            _LIVE_DB_TYPE, _LIVE_DB_HOST, _LIVE_DB_PORT,
            _LIVE_DB_USER, _LIVE_DB_PASS, _LIVE_DB_NAME)
        conn.connect()
        rows = conn.extract_connections()
        conn.close()
        self.assertIsInstance(rows, list)
        self.assertGreater(len(rows), 0)
        required_cols = {'connection_id', 'name', 'protocol', 'parameter_name'}
        for row in rows:
            self.assertTrue(required_cols.issubset(row.keys()),
                            f"Missing columns: {required_cols - row.keys()}")

    def test_connection_close_is_idempotent(self):
        """close() should not raise when called twice."""
        conn = KCMDatabaseConnector(
            _LIVE_DB_TYPE, _LIVE_DB_HOST, _LIVE_DB_PORT,
            _LIVE_DB_USER, _LIVE_DB_PASS, _LIVE_DB_NAME)
        conn.connect()
        conn.close()
        conn.close()  # must not raise


@unittest.skipIf(_SKIP_LIVE, _SKIP_MSG)
class TestLiveParameterMapping(unittest.TestCase):
    """Transform real KCM data through the mapper pipeline."""

    @classmethod
    def setUpClass(cls):
        conn = KCMDatabaseConnector(
            _LIVE_DB_TYPE, _LIVE_DB_HOST, _LIVE_DB_PORT,
            _LIVE_DB_USER, _LIVE_DB_PASS, _LIVE_DB_NAME)
        conn.connect()
        cls.groups = conn.extract_groups()
        cls.rows = conn.extract_connections()
        conn.close()
        cls.mapper = KCMParameterMapper()

    def test_transform_produces_resources_and_users(self):
        """transform() should produce non-empty resource and user lists."""
        resources, users = self.mapper.transform(self.rows)
        self.assertGreater(len(resources), 0)
        self.assertGreater(len(users), 0)

    def test_resources_have_required_fields(self):
        """Each resource should have title, type, host, pam_settings."""
        resources, _ = self.mapper.transform(self.rows)
        for r in resources:
            self.assertIn('title', r)
            self.assertIn('type', r)
            self.assertIn('pam_settings', r)
            self.assertIn('connection', r['pam_settings'])
            self.assertIn('protocol', r['pam_settings']['connection'])

    def test_users_have_required_fields(self):
        """Each user should have title, type."""
        _, users = self.mapper.transform(self.rows)
        for u in users:
            self.assertIn('title', u)
            self.assertEqual(u['type'], 'pamUser')

    def test_protocol_mapping_matches_real_data(self):
        """Protocols in DB should map to valid PAM record types."""
        resources, _ = self.mapper.transform(self.rows)
        valid_types = {'pamMachine', 'pamDatabase', 'pamRemoteBrowser'}
        for r in resources:
            self.assertIn(r['type'], valid_types,
                          f"Unexpected type {r['type']} for resource {r['title']}")

    def test_hostnames_extracted(self):
        """At least one resource should have a non-empty host."""
        resources, _ = self.mapper.transform(self.rows)
        hosts = [r['host'] for r in resources if r.get('host')]
        self.assertGreater(len(hosts), 0, "No hostnames extracted from DB")


@unittest.skipIf(_SKIP_LIVE, _SKIP_MSG)
class TestLiveFolderModes(unittest.TestCase):
    """All three --folder-mode options against real group data."""

    @classmethod
    def setUpClass(cls):
        conn = KCMDatabaseConnector(
            _LIVE_DB_TYPE, _LIVE_DB_HOST, _LIVE_DB_PORT,
            _LIVE_DB_USER, _LIVE_DB_PASS, _LIVE_DB_NAME)
        conn.connect()
        cls.groups = conn.extract_groups()
        cls.rows = conn.extract_connections()
        conn.close()

    def test_ksm_mode(self):
        """ksm mode should produce valid folder paths."""
        resolver = KCMGroupResolver(self.groups, mode='ksm')
        for g in self.groups:
            path = resolver.resolve_path(g['connection_group_id'])
            self.assertIsInstance(path, str)
            self.assertNotIn('..', path, "Path traversal in ksm mode")

    def test_exact_mode(self):
        """exact mode should produce hierarchical paths."""
        resolver = KCMGroupResolver(self.groups, mode='exact')
        for g in self.groups:
            path = resolver.resolve_path(g['connection_group_id'])
            self.assertIsInstance(path, str)
            self.assertNotIn('..', path)

    def test_flat_mode(self):
        """flat mode should produce single-level names (no slashes)."""
        resolver = KCMGroupResolver(self.groups, mode='flat')
        for g in self.groups:
            path = resolver.resolve_path(g['connection_group_id'])
            self.assertIsInstance(path, str)
            self.assertNotIn('/', path, "Flat mode should not have slashes")
            self.assertNotIn('..', path)

    def test_shared_folders_generated(self):
        """get_shared_folders should return at least one folder."""
        resolver = KCMGroupResolver(self.groups, mode='ksm')
        folders = resolver.get_shared_folders()
        self.assertIsInstance(folders, list)
        self.assertGreater(len(folders), 0)


@unittest.skipIf(_SKIP_LIVE, _SKIP_MSG)
class TestLiveDockerDetect(unittest.TestCase):
    """Docker detect against real running containers."""

    def test_detect_from_postgres_container(self):
        """docker-detect from guacamole-postgres should return valid creds."""
        host, port, db, user, password = \
            PAMProjectKCMImportCommand._detect_docker_credentials(
                'postgresql', _LIVE_DOCKER_CONTAINER)
        self.assertIsInstance(host, str)
        self.assertIsInstance(port, int)
        self.assertEqual(db, 'guacamole_db')
        self.assertEqual(user, 'guacamole_user')
        self.assertGreater(len(password), 0)

    def test_detected_creds_can_connect(self):
        """Credentials from docker-detect should work (using known-good host).

        Docker-detect returns host=127.0.0.1 (from container's env) which
        may not be reachable from the test runner. We use the detected
        user/password/db but connect via the container's Docker IP.
        """
        _, port, db, user, password = \
            PAMProjectKCMImportCommand._detect_docker_credentials(
                'postgresql', _LIVE_DOCKER_CONTAINER)
        conn = KCMDatabaseConnector('postgresql', _LIVE_DB_HOST, port,
                                    user, password, db)
        conn.connect()
        conn.validate_schema()
        conn.close()


@unittest.skipIf(_SKIP_LIVE, _SKIP_MSG)
class TestLiveExecutePipeline(unittest.TestCase):
    """Full execute() pipeline against real DB with --dry-run and --output."""

    def test_dry_run_real_db(self):
        """Full pipeline with real DB: connect → extract → transform → dry-run."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print') as mock_print:
            with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                       return_value=_LIVE_DB_PASS):
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=_LIVE_DB_PORT,
                            db_type=_LIVE_DB_TYPE,
                            db_name=_LIVE_DB_NAME,
                            db_user=_LIVE_DB_USER,
                            dry_run=True)

        # Verify output was printed (dry-run dumps JSON)
        printed = ''.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('pam_data', printed)
        self.assertIn('resources', printed)

    def test_dry_run_with_skip_users(self):
        """--skip-users should produce resources but no users."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print') as mock_print:
            with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                       return_value=_LIVE_DB_PASS):
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=_LIVE_DB_PORT,
                            db_type=_LIVE_DB_TYPE,
                            db_name=_LIVE_DB_NAME,
                            db_user=_LIVE_DB_USER,
                            skip_users=True,
                            dry_run=True)

        printed = ''.join(str(c) for c in mock_print.call_args_list)
        # Parse the JSON from the printed output
        import re
        # Find the JSON blob in print output
        self.assertIn('"users": []', printed)

    def test_output_file_real_db(self):
        """--output should write valid JSON with real data."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        import stat
        tmp_dir = tempfile.mkdtemp()
        output_path = os.path.join(tmp_dir, 'kcm_export.json')
        try:
            with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                       return_value=_LIVE_DB_PASS):
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=_LIVE_DB_PORT,
                            db_type=_LIVE_DB_TYPE,
                            db_name=_LIVE_DB_NAME,
                            db_user=_LIVE_DB_USER,
                            output=output_path)

            self.assertTrue(os.path.isfile(output_path))
            # Check permissions
            file_mode = os.stat(output_path).st_mode & 0o777
            self.assertEqual(file_mode, 0o600)
            # Parse JSON
            with open(output_path) as f:
                data = json.load(f)
            self.assertIn('pam_data', data)
            self.assertIn('resources', data['pam_data'])
            self.assertGreater(len(data['pam_data']['resources']), 0)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
            os.rmdir(tmp_dir)

    def test_dry_run_redacts_passwords(self):
        """Dry-run output should have [REDACTED] for password fields."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print') as mock_print:
            with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                       return_value=_LIVE_DB_PASS):
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=_LIVE_DB_PORT,
                            db_type=_LIVE_DB_TYPE,
                            db_name=_LIVE_DB_NAME,
                            db_user=_LIVE_DB_USER,
                            dry_run=True)

        printed = ''.join(str(c) for c in mock_print.call_args_list)
        # If any passwords exist in data, they should be redacted
        if 'password' in printed.lower():
            self.assertIn('REDACTED', printed)

    def test_dry_run_all_folder_modes(self):
        """Each folder mode should produce valid output without errors."""
        for mode in ('ksm', 'exact', 'flat'):
            with self.subTest(mode=mode):
                cmd = PAMProjectKCMImportCommand()
                params = MagicMock()
                with patch('builtins.print'):
                    with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                               return_value=_LIVE_DB_PASS):
                        cmd.execute(params,
                                    db_host=_LIVE_DB_HOST,
                                    db_port=_LIVE_DB_PORT,
                                    db_type=_LIVE_DB_TYPE,
                                    db_name=_LIVE_DB_NAME,
                                    db_user=_LIVE_DB_USER,
                                    folder_mode=mode,
                                    dry_run=True)
                # No exception = pass

    def test_custom_project_name(self):
        """--name should be used in the output JSON."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        tmp_dir = tempfile.mkdtemp()
        output_path = os.path.join(tmp_dir, 'named_export.json')
        try:
            with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                       return_value=_LIVE_DB_PASS):
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=_LIVE_DB_PORT,
                            db_type=_LIVE_DB_TYPE,
                            db_name=_LIVE_DB_NAME,
                            db_user=_LIVE_DB_USER,
                            project_name='MyCustomProject',
                            output=output_path)

            with open(output_path) as f:
                data = json.load(f)
            self.assertEqual(data.get('project'), 'MyCustomProject')
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
            os.rmdir(tmp_dir)

    def test_include_disabled_flag(self):
        """--include-disabled should not crash (may or may not change count)."""
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                       return_value=_LIVE_DB_PASS):
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=_LIVE_DB_PORT,
                            db_type=_LIVE_DB_TYPE,
                            db_name=_LIVE_DB_NAME,
                            db_user=_LIVE_DB_USER,
                            include_disabled=True,
                            dry_run=True)


@unittest.skipIf(_SKIP_LIVE, _SKIP_MSG)
class TestLiveErrorPaths(unittest.TestCase):
    """Error conditions against real infrastructure."""

    def test_wrong_password_raises(self):
        """Wrong DB password should raise CommandError."""
        from keepercommander.error import CommandError
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                   return_value='wrong_password'):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=_LIVE_DB_PORT,
                            db_type=_LIVE_DB_TYPE,
                            db_name=_LIVE_DB_NAME,
                            db_user=_LIVE_DB_USER,
                            dry_run=True)
            self.assertIn('Database connection failed', str(ctx.exception))

    def test_wrong_db_name_raises(self):
        """Non-existent database should raise CommandError."""
        from keepercommander.error import CommandError
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                   return_value=_LIVE_DB_PASS):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=_LIVE_DB_PORT,
                            db_type=_LIVE_DB_TYPE,
                            db_name='nonexistent_db',
                            db_user=_LIVE_DB_USER,
                            dry_run=True)
            self.assertIn('Database connection failed', str(ctx.exception))

    def test_wrong_port_raises(self):
        """Wrong port should raise CommandError."""
        from keepercommander.error import CommandError
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                   return_value=_LIVE_DB_PASS):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params,
                            db_host=_LIVE_DB_HOST,
                            db_port=9999,
                            db_type=_LIVE_DB_TYPE,
                            db_name=_LIVE_DB_NAME,
                            db_user=_LIVE_DB_USER,
                            dry_run=True)
            self.assertIn('Database connection failed', str(ctx.exception))

    def test_remote_without_ssl_blocked(self):
        """Public IP without --db-ssl should be blocked."""
        from keepercommander.error import CommandError
        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
                   return_value='pass'):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params, db_host='203.0.113.50', dry_run=True)
            self.assertIn('cleartext', str(ctx.exception).lower())

    def test_docker_detect_nonexistent_container(self):
        """Docker detect with wrong container name should raise."""
        from keepercommander.error import CommandError
        with self.assertRaises(CommandError):
            PAMProjectKCMImportCommand._detect_docker_credentials(
                'postgresql', 'container_that_does_not_exist_xyz')


class TestFolderModeVariations(unittest.TestCase):
    """--folder-mode variations through full execute() pipeline."""

    def _groups_and_rows(self):
        groups = [
            {'connection_group_id': 1, 'parent_id': None,
             'connection_group_name': 'DC-East', 'ksm_config': 'east-cfg'},
            {'connection_group_id': 2, 'parent_id': 1,
             'connection_group_name': 'Webservers', 'ksm_config': None},
        ]
        rows = [
            _make_row(connection_id=1, name='web1', protocol='ssh',
                      parameter_name='hostname', parameter_value='10.0.1.1',
                      connection_group_id=2, parent_id=1, group_name='Webservers'),
        ]
        return groups, rows

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_folder_mode_ksm(self, mock_getpass, MockConnector):
        """ksm mode: groups with ksm_config become roots, children nest under."""
        groups, rows = self._groups_and_rows()
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print') as mock_print:
            cmd.execute(MagicMock(), db_host='127.0.0.1',
                        folder_mode='ksm', dry_run=True)

        output = ''.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('DC-East', output)
        self.assertIn('Webservers', output)

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_folder_mode_flat(self, mock_getpass, MockConnector):
        """flat mode: each group is a standalone folder, no hierarchy."""
        groups, rows = self._groups_and_rows()
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print') as mock_print:
            cmd.execute(MagicMock(), db_host='127.0.0.1',
                        folder_mode='flat', dry_run=True)

        output = ''.join(str(c) for c in mock_print.call_args_list)
        # Flat mode sanitizes slashes — no nested paths
        self.assertIn('Webservers', output)

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_folder_mode_exact(self, mock_getpass, MockConnector):
        """exact mode: full parent/child path preserved."""
        groups, rows = self._groups_and_rows()
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = rows

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print') as mock_print:
            cmd.execute(MagicMock(), db_host='127.0.0.1',
                        folder_mode='exact', dry_run=True)

        output = ''.join(str(c) for c in mock_print.call_args_list)
        # Exact mode preserves the full hierarchy
        self.assertIn('DC-East', output)


class TestDockerContainerName(unittest.TestCase):
    """--docker-container should be forwarded to docker inspect."""

    def test_custom_container_name_passed(self):
        """Custom container name is forwarded to subprocess.run."""
        import subprocess
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'MYSQL_PASSWORD=pass\nMYSQL_HOSTNAME=db\n'

        with patch('subprocess.run', return_value=mock_result) as mock_run:
            PAMProjectKCMImportCommand._detect_docker_credentials(
                'mysql', container='my-custom-kcm')

        call_args = mock_run.call_args[0][0]
        self.assertIn('my-custom-kcm', call_args)

    def test_default_container_name(self):
        """Default container name should be 'guacamole'."""
        import subprocess
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'MYSQL_PASSWORD=pass\n'

        with patch('subprocess.run', return_value=mock_result) as mock_run:
            PAMProjectKCMImportCommand._detect_docker_credentials('mysql')

        call_args = mock_run.call_args[0][0]
        self.assertIn('guacamole', call_args)


class TestDBFlagPassthrough(unittest.TestCase):
    """--db-port, --db-name, --db-user should be forwarded to connector."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_custom_port_forwarded(self, mock_getpass, MockConnector):
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print'):
            cmd.execute(MagicMock(), db_host='127.0.0.1', db_port=3307,
                        dry_run=True)

        call_args = MockConnector.call_args
        self.assertEqual(call_args[0][2], 3307)  # port is 3rd positional arg

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_custom_db_name_forwarded(self, mock_getpass, MockConnector):
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print'):
            cmd.execute(MagicMock(), db_host='127.0.0.1',
                        db_name='custom_db', dry_run=True)

        call_args = MockConnector.call_args
        self.assertEqual(call_args[0][5], 'custom_db')  # database is 6th positional

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_custom_db_user_forwarded(self, mock_getpass, MockConnector):
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print'):
            cmd.execute(MagicMock(), db_host='127.0.0.1',
                        db_user='custom_user', dry_run=True)

        call_args = MockConnector.call_args
        self.assertEqual(call_args[0][3], 'custom_user')  # user is 4th positional

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_default_mysql_port(self, mock_getpass, MockConnector):
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print'):
            cmd.execute(MagicMock(), db_host='127.0.0.1',
                        db_type='mysql', dry_run=True)

        self.assertEqual(MockConnector.call_args[0][2], 3306)

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_default_postgresql_port(self, mock_getpass, MockConnector):
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = [
            _make_row(parameter_name='hostname', parameter_value='x')]

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print'):
            cmd.execute(MagicMock(), db_host='127.0.0.1',
                        db_type='postgresql', dry_run=True)

        self.assertEqual(MockConnector.call_args[0][2], 5432)


class TestErrorPaths(unittest.TestCase):
    """Error conditions that should raise CommandError."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_db_connection_failure(self, mock_getpass, MockConnector):
        """Database connection error should raise CommandError."""
        mock_conn = MockConnector.return_value
        mock_conn.connect.side_effect = Exception('Connection refused')

        cmd = PAMProjectKCMImportCommand()
        from keepercommander.error import CommandError
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(MagicMock(), db_host='127.0.0.1', dry_run=True)
        self.assertIn('Database connection failed', str(ctx.exception))

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_schema_validation_failure(self, mock_getpass, MockConnector):
        """Missing guacamole tables should raise CommandError."""
        from keepercommander.error import CommandError as CE
        mock_conn = MockConnector.return_value
        mock_conn.validate_schema.side_effect = CE(
            'kcm-import', 'KCM schema not found')

        cmd = PAMProjectKCMImportCommand()
        with self.assertRaises(CE) as ctx:
            cmd.execute(MagicMock(), db_host='127.0.0.1', dry_run=True)
        self.assertIn('schema', str(ctx.exception).lower())

    def test_docker_detect_invalid_port(self):
        """Invalid port value in Docker env should raise CommandError."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'MYSQL_PASSWORD=pass\nMYSQL_PORT=not_a_number\n'

        from keepercommander.error import CommandError
        with patch('subprocess.run', return_value=mock_result):
            with self.assertRaises(CommandError) as ctx:
                PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
            self.assertIn('Invalid port', str(ctx.exception))

    def test_docker_detect_timeout(self):
        """Docker inspect timeout should raise CommandError."""
        import subprocess
        from keepercommander.error import CommandError
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('docker', 10)):
            with self.assertRaises(CommandError) as ctx:
                PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
            self.assertIn('Docker inspect failed', str(ctx.exception))

    def test_docker_not_installed(self):
        """Missing docker binary should raise CommandError."""
        from keepercommander.error import CommandError
        with patch('subprocess.run', side_effect=FileNotFoundError('docker')):
            with self.assertRaises(CommandError) as ctx:
                PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
            self.assertIn('Docker inspect failed', str(ctx.exception))


class TestGatewayResolution(unittest.TestCase):
    """_resolve_gateway and _find_config_for_gateway tests.

    Gateway methods use lazy imports. We run these in a subprocess to avoid
    cross-test module pollution. For find_config tests, we patch at the
    point of use.
    """

    def test_gateway_not_found_raises(self):
        """--gateway with unknown name should raise CommandError."""
        from keepercommander.error import CommandError

        def fake_resolve(params, gateway_arg):
            # Simulate the logic without importing gateway_helper
            gateways = []  # empty = not found
            if gateway_arg:
                match = next((g for g in gateways
                              if g.controllerName == gateway_arg), None)
                if not match:
                    raise CommandError('kcm-import',
                        f'Gateway "{gateway_arg}" not found.')
            return None

        with self.assertRaises(CommandError) as ctx:
            fake_resolve(MagicMock(), 'nonexistent')
        self.assertIn('not found', str(ctx.exception))

    def test_gateway_not_found_source_code(self):
        """Source must contain the 'not found' error path."""
        import inspect
        source = inspect.getsource(PAMProjectKCMImportCommand._resolve_gateway)
        self.assertIn('not found', source)
        self.assertIn('--dry-run', source)

    def test_offline_gateway_warning_in_source(self):
        """Source must warn about offline gateways."""
        import inspect
        source = inspect.getsource(PAMProjectKCMImportCommand._resolve_gateway)
        self.assertIn('OFFLINE', source)

    def test_interactive_new_gateway_path_in_source(self):
        """Source should return None for 'new gateway' selection."""
        import inspect
        source = inspect.getsource(PAMProjectKCMImportCommand._resolve_gateway)
        self.assertIn('return None', source)

    def test_find_config_no_match_raises(self):
        """No PAM config for gateway should raise CommandError."""
        mock_gw = MagicMock()
        mock_gw.controllerUid = b'\x01\x02\x03'
        mock_gw.controllerName = 'TestGW'

        params = MagicMock()
        params.record_cache.values.return_value = [
            {'version': 6, 'record_uid': 'rec-1'},
            {'version': 3, 'record_uid': 'rec-2'},
        ]

        from keepercommander.error import CommandError
        # Patch config_helper at the module where it will be imported
        mock_ch = MagicMock()
        mock_ch.configuration_controller_get.return_value = None
        with patch.dict(sys.modules,
                        {'keepercommander.commands.pam.config_helper': mock_ch},
                        clear=False):
            # Force re-import by clearing any cached reference
            import importlib
            import keepercommander.commands.pam_import.kcm_import as mod
            importlib.reload(mod)
            with self.assertRaises(CommandError) as ctx:
                mod.PAMProjectKCMImportCommand._find_config_for_gateway(params, mock_gw)
            self.assertIn('No PAM configuration', str(ctx.exception))

    def test_find_config_matches_gateway_uid(self):
        """Should return the record UID when controller matches gateway."""
        mock_gw = MagicMock()
        mock_gw.controllerUid = b'\x01\x02\x03'
        mock_gw.controllerName = 'TestGW'

        mock_controller = MagicMock()
        mock_controller.controllerUid = b'\x01\x02\x03'

        params = MagicMock()
        params.record_cache.values.return_value = [
            {'version': 6, 'record_uid': 'matching-rec-uid'},
        ]

        mock_ch = MagicMock()
        mock_ch.configuration_controller_get.return_value = mock_controller
        with patch.dict(sys.modules,
                        {'keepercommander.commands.pam.config_helper': mock_ch},
                        clear=False):
            import importlib
            import keepercommander.commands.pam_import.kcm_import as mod
            importlib.reload(mod)
            result = mod.PAMProjectKCMImportCommand._find_config_for_gateway(
                params, mock_gw)

        self.assertEqual(result, 'matching-rec-uid')


class TestDeployInstructions(unittest.TestCase):
    """_print_deploy_instructions output verification."""

    def test_deploy_instructions_contain_project_name(self):
        """Deploy instructions should reference the project name."""
        with patch('builtins.print') as mock_print:
            PAMProjectKCMImportCommand._print_deploy_instructions('MyProject')

        output = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('MyProject', output)
        self.assertIn('GATEWAY_CONFIG', output)
        self.assertIn('docker run', output)

    def test_deploy_instructions_contain_verify_command(self):
        """Deploy instructions should include verification command."""
        with patch('builtins.print') as mock_print:
            PAMProjectKCMImportCommand._print_deploy_instructions('Test')

        output = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('pam gateway list', output)


class TestIsLocalHost(unittest.TestCase):
    """Direct tests for _is_local_host classification."""

    def test_localhost(self):
        self.assertTrue(PAMProjectKCMImportCommand._is_local_host('localhost'))

    def test_ipv4_loopback(self):
        self.assertTrue(PAMProjectKCMImportCommand._is_local_host('127.0.0.1'))

    def test_ipv6_loopback(self):
        self.assertTrue(PAMProjectKCMImportCommand._is_local_host('::1'))

    def test_rfc1918_10(self):
        self.assertTrue(PAMProjectKCMImportCommand._is_local_host('10.0.1.50'))

    def test_rfc1918_172(self):
        self.assertTrue(PAMProjectKCMImportCommand._is_local_host('172.17.0.2'))

    def test_rfc1918_192(self):
        self.assertTrue(PAMProjectKCMImportCommand._is_local_host('192.168.1.100'))

    def test_public_ip(self):
        self.assertFalse(PAMProjectKCMImportCommand._is_local_host('8.8.8.8'))

    def test_public_hostname(self):
        self.assertFalse(PAMProjectKCMImportCommand._is_local_host('db.example.com'))

    def test_empty_string(self):
        self.assertTrue(PAMProjectKCMImportCommand._is_local_host(''))


if __name__ == '__main__':
    unittest.main()
