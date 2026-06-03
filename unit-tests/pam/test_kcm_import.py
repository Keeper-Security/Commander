#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
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

from keepercommander.error import CommandError
from keepercommander.commands.pam_import.kcm_import import (
    KCMDatabaseConnector,
    KCMGroupResolver,
    KCMParameterMapper,
    PAMProjectKCMImportCommand,
    PAMProjectKCMCleanupCommand,
    _set_nested,
)


def _make_row(connection_id=1, name='TestConn', protocol='ssh',
              parameter_name=None, parameter_value=None,
              attribute_name=None, attribute_value=None,
              connection_group_id=None, parent_id=None,
              group_name=None, max_connections=None):
    return {
        'connection_id': connection_id,
        'name': name,
        'protocol': protocol,
        'max_connections': max_connections,
        'parameter_name': parameter_name,
        'parameter_value': parameter_value,
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

    def test_attr_map_applied_separately(self):
        """Attributes via attr_map should be applied without cartesian product."""
        rows = [_make_row(parameter_name='hostname', parameter_value='db.example.com')]
        attr_map = {1: [('ksm-user-config-enabled', 'true'),
                        ('disable-copy', 'true')]}
        resources, _ = self.mapper.transform(rows, attr_map=attr_map)
        # ksm-user-config-enabled is mapped to 'ignore', should not appear
        self.assertNotIn('ksm-user-config-enabled', json.dumps(resources[0]))
        # disable-copy should be mapped
        self.assertEqual(
            resources[0]['pam_settings']['connection']['disable_copy'], 'true')
        # hostname from params should still be set
        self.assertEqual(resources[0]['host'], 'db.example.com')

    def test_attr_map_skips_disabled_connections(self):
        """Attributes for disabled connections should be skipped."""
        rows = [_make_row(max_connections=0,
                          parameter_name='hostname', parameter_value='x')]
        attr_map = {1: [('disable-copy', 'true')]}
        resources, _ = self.mapper.transform(rows, include_disabled=False,
                                              attr_map=attr_map)
        self.assertEqual(len(resources), 0)

    def test_default_port_ssh(self):
        """SSH connections without explicit port get default 22."""
        rows = [_make_row(protocol='ssh',
                          parameter_name='hostname', parameter_value='server1')]
        resources, _ = self.mapper.transform(rows)
        self.assertEqual(resources[0]['pam_settings']['connection']['port'], '22')

    def test_default_port_rdp(self):
        """RDP connections without explicit port get default 3389."""
        rows = [_make_row(protocol='rdp',
                          parameter_name='hostname', parameter_value='win1')]
        resources, _ = self.mapper.transform(rows)
        self.assertEqual(resources[0]['pam_settings']['connection']['port'], '3389')

    def test_default_port_vnc(self):
        """VNC connections without explicit port get default 5900."""
        rows = [_make_row(protocol='vnc',
                          parameter_name='hostname', parameter_value='vnc1')]
        resources, _ = self.mapper.transform(rows)
        self.assertEqual(resources[0]['pam_settings']['connection']['port'], '5900')

    def test_default_port_not_applied_when_explicit(self):
        """Explicit port from KCM should NOT be overwritten by default."""
        rows = [_make_row(protocol='ssh',
                          parameter_name='port', parameter_value='2222')]
        resources, _ = self.mapper.transform(rows)
        self.assertEqual(resources[0]['pam_settings']['connection']['port'], '2222')

    def test_default_port_http_no_port(self):
        """HTTP/RBI connections should NOT get a default port."""
        rows = [_make_row(protocol='http',
                          parameter_name='url', parameter_value='https://example.com')]
        resources, _ = self.mapper.transform(rows)
        self.assertNotIn('port', resources[0]['pam_settings']['connection'])

    def test_default_port_database(self):
        """Database protocols get correct default ports."""
        # Note: 'postgres' is the Guacamole protocol name in the DB row;
        # transform() converts it to 'postgresql' internally.
        for proto, expected_port in [('mysql', '3306'), ('postgres', '5432'),
                                     ('sql-server', '1433')]:
            rows = [_make_row(protocol=proto,
                              parameter_name='hostname', parameter_value='db')]
            resources, _ = self.mapper.transform(rows)
            self.assertEqual(
                resources[0]['pam_settings']['connection']['port'], expected_port,
                f'{proto} should default to port {expected_port}')

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
        mock_conn.extract_connections.return_value = (rows, {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print') as mock_print:
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        dry_run=True,
                        project_name='E2E Test')

        # Verify print was called with JSON (first call is the JSON dump)
        self.assertTrue(mock_print.called)
        output = mock_print.call_args_list[0][0][0]
        result = json.loads(output)

        # Verify structure
        self.assertIn('project', result)
        self.assertEqual(result['project'], 'E2E Test')
        self.assertIn('pam_data', result)
        resources = result['pam_data']['resources']
        users = result['pam_data']['users']

        self.assertEqual(len(resources), 3)
        # pamMachine and pamDatabase users nested; pamRemoteBrowser stays top-level
        self.assertEqual(len(users), 1)  # RBI user is top-level
        self.assertEqual(users[0]['type'], 'login')

        # Verify record types
        types = {r['title']: r['type'] for r in resources}
        self.assertEqual(types['KCM Resource - WebServer'], 'pamMachine')
        self.assertEqual(types['KCM Resource - AppDB'], 'pamDatabase')
        self.assertEqual(types['KCM Resource - Intranet'], 'pamRemoteBrowser')

        # Non-RBI resources have nested users; RBI does not
        for r in resources:
            if r['type'] == 'pamRemoteBrowser':
                self.assertEqual(len(r.get('users', [])), 0)
                # RBI uses autofill_credentials instead of launch_credentials
                conn = r['pam_settings']['connection']
                self.assertIn('autofill_credentials', conn)
            else:
                self.assertEqual(len(r.get('users', [])), 1)

        # Verify passwords are REDACTED in dry-run (nested users)
        for r in resources:
            for user in r.get('users', []):
                if 'password' in user and user['password']:
                    self.assertEqual(user['password'], '[REDACTED]')

        # Verify folder paths use project-named shared folders with KSM group hierarchy
        web_resource = next(r for r in resources
                           if r['title'] == 'KCM Resource - WebServer')
        self.assertEqual(web_resource['folder_path'],
                         'E2E Test - Resources/Production/Linux')

        db_resource = next(r for r in resources
                           if r['title'] == 'KCM Resource - AppDB')
        self.assertEqual(db_resource['folder_path'],
                         'E2E Test - Resources/Production')

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
        mock_conn.extract_connections.return_value = (rows, {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            output_path = f.name

        try:
            # With --include-credentials, passwords are preserved
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        output=output_path,
                        include_credentials=True,
                        project_name='Output Test')

            with open(output_path) as f:
                result = json.load(f)

            self.assertIn('project', result)
            self.assertIn('pam_data', result)
            # Passwords preserved with --include-credentials
            # Users are nested inside resources
            deploy_user = None
            for r in result['pam_data']['resources']:
                for u in r.get('users', []):
                    if u.get('login') == 'deploy':
                        deploy_user = u
                        break
            self.assertIsNotNone(deploy_user)
            self.assertEqual(deploy_user['password'], 's3cret')
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_output_file_redacted_by_default(self, mock_getpass, MockConnector):
        """Default --output should redact passwords."""
        groups, rows = self._mock_db_data()

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = (rows, {})

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
                        project_name='Redact Test')

            with open(output_path) as f:
                result = json.load(f)

            # Password should be redacted by default
            deploy_user = None
            for r in result['pam_data']['resources']:
                for u in r.get('users', []):
                    if u.get('login') == 'deploy':
                        deploy_user = u
                        break
            self.assertIsNotNone(deploy_user)
            self.assertEqual(deploy_user['password'], '[REDACTED]')
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
        mock_conn.extract_connections.return_value = (rows, {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print') as mock_print:
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        dry_run=True,
                        skip_users=True,
                        project_name='Skip Users Test')

        result = json.loads(mock_print.call_args_list[0][0][0])
        self.assertEqual(result['pam_data']['users'], [])
        self.assertEqual(len(result['pam_data']['resources']), 3)

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._create_summary_record')
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._get_project_assets',
           return_value={})
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._discover_shared_folder_names',
           return_value=(None, None))
    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_extend_mode_delegates(self, mock_getpass, MockConnector,
                                   mock_discover, mock_assets,
                                   mock_summary, mock_sync):
        """E2E: --config delegates to PAMProjectExtendCommand."""
        groups, rows = self._mock_db_data()

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = (rows, {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()
        # Simulate record_cache growing after extend creates records
        fake_cache = {}
        params.record_cache = fake_cache

        # Capture the JSON content when extend is called (before cleanup)
        captured_data = {}

        mock_extend_cmd = MagicMock()
        def capture_extend(params, **kwargs):
            with open(kwargs['file_name']) as f:
                captured_data['json'] = json.load(f)
            captured_data['kwargs'] = kwargs
            # Simulate records being created
            fake_cache['rec1'] = {}
            fake_cache['rec2'] = {}
        mock_extend_cmd.execute = MagicMock(side_effect=capture_extend)

        # Mock the lazy import inside execute() to avoid importing
        # the real extend module (which pulls in pydantic on 3.7)
        mock_extend_class = MagicMock(return_value=mock_extend_cmd)
        mock_extend_module = MagicMock(PAMProjectExtendCommand=mock_extend_class)

        with patch.dict('sys.modules',
                        {'keepercommander.commands.pam_import.extend': mock_extend_module}):
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        config='existing-pam-config-uid',
                        auto_confirm=True,
                        auto_throttle=False)

        # Phase 2a (users) + 2b (resources) = multiple extend calls
        self.assertGreaterEqual(mock_extend_cmd.execute.call_count, 2)
        self.assertEqual(captured_data['kwargs']['config'],
                         'existing-pam-config-uid')
        self.assertTrue(
            captured_data['kwargs']['file_name'].endswith('.json'))
        # JSON key should NOT have 'project' in extend mode
        self.assertNotIn('project', captured_data['json'])

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._create_summary_record')
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._get_project_assets',
           return_value={})
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._discover_shared_folder_names',
           return_value=(None, None))
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._create_project_skeleton',
           return_value=('skeleton-config-uid', ''))
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._resolve_gateway',
           return_value=None)
    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_import_mode_delegates(self, mock_getpass, MockConnector, mock_gw,
                                   mock_skeleton, mock_discover,
                                   mock_assets, mock_summary, mock_sync):
        """E2E: no --config uses 2-phase (skeleton + extend)."""
        groups, rows = self._mock_db_data()

        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = (rows, {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()
        # Simulate record_cache growing after extend creates records
        fake_cache = {}
        params.record_cache = fake_cache

        # Capture the JSON content when extend is called (before cleanup)
        captured_data = {}

        mock_extend_cmd = MagicMock()
        def capture_extend(params, **kwargs):
            with open(kwargs['file_name']) as f:
                captured_data['json'] = json.load(f)
            captured_data['kwargs'] = kwargs
            # Simulate records being created
            fake_cache['rec1'] = {}
            fake_cache['rec2'] = {}
        mock_extend_cmd.execute = MagicMock(side_effect=capture_extend)

        mock_extend_class = MagicMock(return_value=mock_extend_cmd)
        mock_extend_module = MagicMock(PAMProjectExtendCommand=mock_extend_class)

        with patch.dict('sys.modules',
                        {'keepercommander.commands.pam_import.extend': mock_extend_module}):
            cmd.execute(params,
                        db_host='127.0.0.1',
                        db_type='mysql',
                        project_name='Import Test',
                        auto_confirm=True,
                        auto_throttle=False)

        # Phase 1: skeleton was created
        mock_skeleton.assert_called_once()
        skeleton_args = mock_skeleton.call_args
        self.assertEqual(skeleton_args[0][1], 'Import Test')  # project_name

        # Phase 2a (users) + 2b (resources) = multiple extend calls
        self.assertGreaterEqual(mock_extend_cmd.execute.call_count, 2)
        self.assertEqual(captured_data['kwargs']['config'],
                         'skeleton-config-uid')
        self.assertTrue(
            captured_data['kwargs']['file_name'].endswith('.json'))

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
        mock_conn.extract_connections.return_value = (rows, {})

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
        (host, port, db, user), password = \
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
        """PostgreSQL mode uses POSTGRESQL_ prefix."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='POSTGRESQL_HOSTNAME=pg.local\nPOSTGRESQL_USER=pguser\n'
                   'POSTGRESQL_PASSWORD=pgpass\nPOSTGRESQL_DATABASE=guac_pg\n',
            stderr=''
        )
        (host, port, db, user), password = \
            PAMProjectKCMImportCommand._detect_docker_credentials('postgresql')
        self.assertEqual(host, 'pg.local')
        self.assertEqual(port, 5432)  # default
        self.assertEqual(db, 'guac_pg')
        self.assertEqual(user, 'pguser')
        self.assertEqual(password, 'pgpass')


class TestE2ESFTPConnectionSettings(unittest.TestCase):
    """E2E: SFTP settings stay as connection settings, never separate records."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_rdp_sftp_stays_as_connection_setting(self, mock_getpass, MockConnector):
        """RDP with SFTP should keep SFTP as connection settings, not separate records."""
        groups = [{'connection_group_id': 1, 'parent_id': None,
                   'connection_group_name': 'Prod', 'ksm_config': None}]
        rows = [
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='hostname', parameter_value='10.0.0.5',
                      connection_group_id=1, parent_id=None, group_name='Prod'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='enable-sftp', parameter_value='true',
                      connection_group_id=1, parent_id=None, group_name='Prod'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='sftp-hostname', parameter_value='10.0.0.6',
                      connection_group_id=1, parent_id=None, group_name='Prod'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='sftp-port', parameter_value='22',
                      connection_group_id=1, parent_id=None, group_name='Prod'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='sftp-username', parameter_value='sftpuser',
                      connection_group_id=1, parent_id=None, group_name='Prod'),
            _make_row(connection_id=1, name='RDPBox', protocol='rdp',
                      parameter_name='sftp-password', parameter_value='sftppass',
                      connection_group_id=1, parent_id=None, group_name='Prod'),
        ]
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = (rows, {})

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print') as mock_print:
            cmd.execute(MagicMock(), db_host='127.0.0.1', db_type='mysql',
                        dry_run=True, project_name='SFTP Test')

        result = json.loads(mock_print.call_args_list[0][0][0])
        resources = result['pam_data']['resources']

        # Only 1 resource — NO separate SFTP resource created
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['title'], 'KCM Resource - RDPBox')
        self.assertEqual(resources[0]['host'], '10.0.0.5')

        # SFTP settings preserved as connection settings on the RDP record
        # (dry-run output redacts passwords, so check non-sensitive fields)
        sftp = resources[0]['pam_settings']['connection']['sftp']
        self.assertEqual(sftp['enable_sftp'], 'true')
        self.assertEqual(sftp['host'], '10.0.0.6')
        self.assertEqual(sftp['port'], '22')
        self.assertEqual(sftp['login'], 'sftpuser')
        # Password is redacted in dry-run output
        self.assertIn('password', sftp)

        # No SFTP-titled resources anywhere
        sftp_titles = [r for r in resources if 'SFTP' in r.get('title', '')]
        self.assertEqual(len(sftp_titles), 0)


class TestE2ESSHSFTPNativeSettings(unittest.TestCase):
    """SSH SFTP is a native setting, not a separate resource."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='testdbpass')
    def test_ssh_sftp_no_separate_records(self, mock_getpass, MockConnector):
        """SSH with enable-sftp should NOT create separate SFTP records."""
        groups = [{'connection_group_id': 1, 'parent_id': None,
                   'connection_group_name': 'Servers', 'ksm_config': None}]
        rows = [
            _make_row(connection_id=1, name='LinuxBox', protocol='ssh',
                      parameter_name='hostname', parameter_value='10.0.0.1',
                      connection_group_id=1, parent_id=None, group_name='Servers'),
            _make_row(connection_id=1, name='LinuxBox', protocol='ssh',
                      parameter_name='username', parameter_value='admin',
                      connection_group_id=1, parent_id=None, group_name='Servers'),
            _make_row(connection_id=1, name='LinuxBox', protocol='ssh',
                      parameter_name='enable-sftp', parameter_value='true',
                      connection_group_id=1, parent_id=None, group_name='Servers'),
            _make_row(connection_id=1, name='LinuxBox', protocol='ssh',
                      parameter_name='sftp-root-directory', parameter_value='/tmp',
                      connection_group_id=1, parent_id=None, group_name='Servers'),
            # These SSH-SFTP fields should be stripped (SSH reuses its own creds)
            _make_row(connection_id=1, name='LinuxBox', protocol='ssh',
                      parameter_name='sftp-hostname', parameter_value='10.0.0.1',
                      connection_group_id=1, parent_id=None, group_name='Servers'),
            _make_row(connection_id=1, name='LinuxBox', protocol='ssh',
                      parameter_name='sftp-username', parameter_value='admin',
                      connection_group_id=1, parent_id=None, group_name='Servers'),
        ]
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = groups
        mock_conn.extract_connections.return_value = (rows, {})

        cmd = PAMProjectKCMImportCommand()
        with patch('builtins.print') as mock_print:
            cmd.execute(MagicMock(), db_host='127.0.0.1', db_type='mysql',
                        dry_run=True, project_name='SSH SFTP Test')

        result = json.loads(mock_print.call_args_list[0][0][0])
        resources = result['pam_data']['resources']

        # Only 1 resource — NO separate SFTP resource created
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['title'], 'KCM Resource - LinuxBox')

        # SFTP settings should be cleaned to just enable_sftp + sftp_root_directory
        sftp = resources[0]['pam_settings']['connection'].get('sftp', {})
        self.assertEqual(sftp.get('enable_sftp'), 'true')
        self.assertEqual(sftp.get('sftp_root_directory'), '/tmp')
        # Extra fields stripped
        self.assertNotIn('host', sftp)
        self.assertNotIn('login', sftp)
        self.assertNotIn('sftp_resource', sftp)


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

        # Assign folder paths (mirroring kcm_import.py logic)
        project_name = 'TestProject'
        res_root = f'{project_name} - Resources'
        for item in resources:
            gid = item.pop('_group_id', None)
            kcm_path = resolver.resolve_path(gid)
            if kcm_path == 'ROOT':
                item['folder_path'] = res_root
            elif kcm_path.startswith('ROOT/'):
                item['folder_path'] = f'{res_root}/{kcm_path[5:]}'
            else:
                item['folder_path'] = f'{res_root}/{kcm_path}'

        for item in users:
            item.pop('_group_id', None)

        self.assertEqual(len(resources), 3)
        self.assertEqual(len(users), 3)

        # Check folder paths
        ssh = next(r for r in resources if r['title'] == 'KCM Resource - SSH-East')
        self.assertEqual(ssh['folder_path'], 'TestProject - Resources/DC-East')
        self.assertEqual(ssh['host'], 'east.ssh.local')
        self.assertEqual(ssh['type'], 'pamMachine')

        pg = next(r for r in resources if r['title'] == 'KCM Resource - PG-West')
        self.assertEqual(pg['folder_path'], 'TestProject - Resources/DC-West')
        self.assertEqual(pg['type'], 'pamDatabase')
        # postgres → postgresql protocol mapping
        self.assertEqual(pg['pam_settings']['connection']['protocol'], 'postgresql')
        self.assertEqual(pg['pam_settings']['connection']['default_database'], 'appdb')

        rdp = next(r for r in resources if r['title'] == 'KCM Resource - RDP-Orphan')
        self.assertEqual(rdp['folder_path'], 'TestProject - Resources')
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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        (host, port, db, user), password = \
            PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
        self.assertEqual(password, 'pass=word=123')


class TestE2ETempFileCleanup(unittest.TestCase):
    """E2E: temp file is cleaned up even when import/extend raises."""

    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._discover_shared_folder_names',
           return_value=(None, None))
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._create_project_skeleton',
           return_value=('skeleton-cfg-uid', ''))
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._resolve_gateway',
           return_value=None)
    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_temp_file_cleaned_on_error(self, mock_getpass, MockConnector,
                                        mock_gw, mock_skeleton, mock_discover):
        """Temp file does not leak when extend command raises."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        # Track the temp file path created by mkstemp
        created_paths = []
        original_mkstemp = tempfile.mkstemp
        def tracking_mkstemp(**kwargs):
            fd, path = original_mkstemp(**kwargs)
            created_paths.append(path)
            return fd, path

        # Mock extend module to raise
        mock_extend_cmd = MagicMock()
        mock_extend_cmd.execute = MagicMock(side_effect=Exception('Vault error'))
        mock_extend_class = MagicMock(return_value=mock_extend_cmd)
        mock_extend_module = MagicMock(PAMProjectExtendCommand=mock_extend_class)

        with patch('keepercommander.commands.pam_import.kcm_import.tempfile.mkstemp',
                   side_effect=tracking_mkstemp):
            with patch.dict('sys.modules',
                            {'keepercommander.commands.pam_import.extend': mock_extend_module}):
                with self.assertRaises(Exception):
                    cmd.execute(params,
                                db_host='127.0.0.1',
                                project_name='Fail Test',
                                auto_confirm=True)

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.print'):
            cmd.execute(params, db_host='127.0.0.1', dry_run=True)

        # Password should have been cleared in the finally block
        self.assertIsNone(mock_conn.password)

    def test_docker_detect_parses_env_vars(self):
        """Docker inspect output should be parsed into credentials."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'MYSQL_PASSWORD=secret123\nMYSQL_HOSTNAME=db\nOTHER_SECRET=xyz\n'

        with patch('keepercommander.commands.pam_import.kcm_import.subprocess.run', return_value=mock_result):
            (host, port, db, user), password = \
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
# Estimate feature tests
###############################################################################

class TestEstimate(unittest.TestCase):
    """Tests for --estimate pre-scan output."""

    @staticmethod
    def _make_groups(n=3):
        return [{'connection_group_id': i, 'connection_group_name': f'Group {i}',
                 'parent_id': None, 'type': 'ORGANIZATIONAL'} for i in range(1, n + 1)]

    @staticmethod
    def _make_resources(types=None):
        types = types or ['pamMachine', 'pamMachine', 'pamDatabase']
        resources = []
        for i, rtype in enumerate(types):
            r = {'title': f'Resource {i}', 'type': rtype, 'host': f'host{i}',
                 'pam_settings': {'options': {}, 'connection': {'protocol': 'ssh'}}}
            resources.append(r)
        return resources

    @staticmethod
    def _make_users(n=2):
        return [{'title': f'User {i}', 'type': 'pamUser',
                 'rotation_settings': {}} for i in range(n)]

    def test_estimate_prints_summary(self):
        """--estimate should print resource counts and API estimates."""
        from io import StringIO
        import sys
        groups = self._make_groups(2)
        resources = self._make_resources(['pamMachine', 'pamDatabase', 'pamMachine'])
        users = self._make_users(3)
        captured = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            PAMProjectKCMImportCommand._print_estimate(
                groups, resources, users,
                skip_users=False, include_disabled=False, total_connections=3)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        self.assertIn('KCM Migration Estimate', output)
        self.assertIn('Connection groups:', output)
        self.assertIn('Estimated API calls:', output)
        self.assertIn('Conservative', output)
        self.assertIn('Enterprise', output)

    def test_estimate_counts_by_type(self):
        """Estimate should break down resources by record type."""
        from io import StringIO
        import sys
        resources = self._make_resources(
            ['pamMachine', 'pamMachine', 'pamDatabase', 'pamRemoteBrowser'])
        captured = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            PAMProjectKCMImportCommand._print_estimate(
                [], resources, [], skip_users=True,
                include_disabled=False, total_connections=4)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        self.assertIn('SSH/RDP/VNC', output)
        self.assertIn('Database', output)
        self.assertIn('RemoteBrowser', output)
        self.assertIn('(skipped)', output)

    def test_estimate_api_call_calculation(self):
        """Verify API call estimate math."""
        resources = self._make_resources(['pamMachine'] * 10)
        users = self._make_users(5)
        # Expected: 20 (setup) + 10*20 (resources) + 5*8 (users) = 260
        from io import StringIO
        import sys
        captured = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            PAMProjectKCMImportCommand._print_estimate(
                [], resources, users, skip_users=False,
                include_disabled=False, total_connections=10)
        finally:
            sys.stdout = old_stdout
        self.assertIn('~  260', captured.getvalue())

    def test_estimate_sftp_no_extra_api_calls(self):
        """SFTP connection settings should NOT add extra API calls (not separate records)."""
        resources = [
            {'title': 'R1', 'type': 'pamMachine', 'host': 'h1',
             'pam_settings': {'connection': {'sftp': {'host': 'sftp1'}}}},
            {'title': 'R2', 'type': 'pamMachine', 'host': 'h2',
             'pam_settings': {'connection': {}}},
        ]
        from io import StringIO
        import sys
        captured = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            PAMProjectKCMImportCommand._print_estimate(
                [], resources, [], skip_users=True,
                include_disabled=False, total_connections=2)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        # SFTP is a connection setting, not separate records — no extra line
        self.assertNotIn('SFTP sub-resources', output)
        # 20 (setup) + 2*20 (resources) + 0 (users) = 60
        self.assertIn('~   60', output)

    def test_estimate_duration_formatting(self):
        """Duration formatter should handle seconds, minutes, and hours."""
        # Test via the output with a large number of resources
        resources = self._make_resources(['pamMachine'] * 200)
        users = self._make_users(100)
        from io import StringIO
        import sys
        captured = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            PAMProjectKCMImportCommand._print_estimate(
                [], resources, users, skip_users=False,
                include_disabled=False, total_connections=200)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        # At 5 req/s with 7420 calls = 1484s = 24m 44s
        self.assertIn('m', output)


###############################################################################
# Pre-import validation and confirmation tests
###############################################################################

class TestValidateImportData(unittest.TestCase):
    """Tests for _validate_import_data pre-import checks."""

    def test_rotation_settings_on_user_warns(self):
        """Users with rotation_settings should trigger a warning."""
        resources = [{'title': 'R1', 'host': '10.0.0.1'}]
        users = [{'title': 'U1', 'rotation_settings': {'period': 30}}]
        warnings = PAMProjectKCMImportCommand._validate_import_data(
            resources, users, skip_users=False)
        self.assertTrue(any('rotation_settings' in w for w in warnings))

    def test_no_rotation_settings_no_warning(self):
        """Clean data should produce no rotation warnings."""
        resources = [{'title': 'R1', 'host': '10.0.0.1'}]
        users = [{'title': 'U1', 'password': ''}]
        warnings = PAMProjectKCMImportCommand._validate_import_data(
            resources, users, skip_users=False)
        self.assertFalse(any('rotation_settings' in w for w in warnings))

    def test_unnested_users_warn(self):
        """Top-level users (not nested in resources) should warn."""
        resources = [{'title': 'R1', 'host': '10.0.0.1'}]
        users = [{'title': 'U1'}, {'title': 'U2'}]
        warnings = PAMProjectKCMImportCommand._validate_import_data(
            resources, users, skip_users=False)
        self.assertTrue(any('2 user(s) not linked' in w for w in warnings))

    def test_no_users_no_unlinked_warning(self):
        """All users nested = no unlinked warning."""
        resources = [{'title': 'R1', 'host': '10.0.0.1',
                      'users': [{'title': 'U1'}]}]
        users = []
        warnings = PAMProjectKCMImportCommand._validate_import_data(
            resources, users, skip_users=False)
        self.assertFalse(any('not linked' in w for w in warnings))

    def test_missing_host_warns(self):
        """Resources without host should trigger a warning."""
        resources = [{'title': 'R1', 'host': ''}, {'title': 'R2'}]
        warnings = PAMProjectKCMImportCommand._validate_import_data(
            resources, [], skip_users=True)
        host_warnings = [w for w in warnings if 'no host' in w]
        self.assertEqual(len(host_warnings), 2)

    def test_skip_users_skips_user_checks(self):
        """With skip_users=True, user checks should be skipped."""
        resources = [{'title': 'R1', 'host': '10.0.0.1'}]
        users = [{'title': 'U1', 'rotation_settings': {'bad': True}}]
        warnings = PAMProjectKCMImportCommand._validate_import_data(
            resources, users, skip_users=True)
        self.assertFalse(any('rotation_settings' in w for w in warnings))


class TestImportConfirmation(unittest.TestCase):
    """Tests for interactive confirmation prompt."""

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._discover_shared_folder_names',
           return_value=(None, None))
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._create_project_skeleton',
           return_value=('skeleton-cfg', ''))
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._resolve_gateway',
           return_value=None)
    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_user_cancel_aborts_import(self, mock_getpass, MockConnector,
                                       mock_gw, mock_skeleton, mock_discover,
                                       mock_sync):
        """Answering 'n' to confirmation should abort the import."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()

        with patch('builtins.input', return_value='n'), \
             patch('builtins.print'):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params, db_host='127.0.0.1',
                            project_name='Cancel Test')
            self.assertIn('cancelled', str(ctx.exception))

        # Skeleton should NOT have been called (cancelled before phase 1)
        mock_skeleton.assert_not_called()

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._create_summary_record')
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._get_project_assets',
           return_value={})
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._discover_shared_folder_names',
           return_value=(None, None))
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._create_project_skeleton',
           return_value=('skeleton-cfg', ''))
    @patch('keepercommander.commands.pam_import.kcm_import.PAMProjectKCMImportCommand._resolve_gateway',
           return_value=None)
    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_yes_flag_skips_prompt(self, mock_getpass, MockConnector,
                                   mock_gw, mock_skeleton, mock_discover,
                                   mock_assets, mock_summary, mock_sync):
        """--yes flag should skip the confirmation prompt entirely."""
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

        cmd = PAMProjectKCMImportCommand()
        params = MagicMock()
        fake_cache = {}
        params.record_cache = fake_cache

        mock_extend_cmd = MagicMock()
        def fake_extend(params, **kwargs):
            fake_cache['r1'] = {}
        mock_extend_cmd.execute = MagicMock(side_effect=fake_extend)
        mock_extend_class = MagicMock(return_value=mock_extend_cmd)
        mock_extend_module = MagicMock(PAMProjectExtendCommand=mock_extend_class)

        with patch.dict('sys.modules',
                        {'keepercommander.commands.pam_import.extend': mock_extend_module}), \
             patch('builtins.input') as mock_input:
            cmd.execute(params, db_host='127.0.0.1',
                        project_name='Auto Test',
                        auto_confirm=True,
                        auto_throttle=False)

        # input() should NOT have been called
        mock_input.assert_not_called()
        # Skeleton and extend should have been called
        mock_skeleton.assert_called_once()
        mock_extend_cmd.execute.assert_called_once()


class TestConvertKcmAutofill(unittest.TestCase):
    """_convert_kcm_autofill cleans KCM JSON for Keeper RBI."""

    def test_single_page_login(self):
        """Compact JSON with single step."""
        original = [{"page": "login.example.com", "username-field": "#user",
                      "password-field": "#pass", "submit": "button.login"}]
        # KCM DB often has extra whitespace
        kcm_raw = json.dumps(original, indent=4)
        resource = {'pam_settings': {'connection': {}}}
        KCMParameterMapper._convert_kcm_autofill(resource, kcm_raw)
        result = resource['pam_settings']['connection']['autofill_targets']
        self.assertEqual(json.loads(result), original)
        # Compact (no indent whitespace)
        self.assertNotIn('\n', result)

    def test_multi_step_preserved(self):
        """Multi-step flow preserved as JSON array."""
        original = [
            {"page": "*.example.com", "username-field": "#u",
             "submit": "input[type='submit']"},
            {"page": "*.example.com", "password-field": "#p",
             "submit": "button[type='submit']"},
            {"page": "*.example.com", "totp-code-field": "#otp",
             "submit": "button[type='submit']"},
        ]
        kcm_raw = json.dumps(original, indent=6)
        resource = {'pam_settings': {'connection': {}}}
        KCMParameterMapper._convert_kcm_autofill(resource, kcm_raw)
        result = resource['pam_settings']['connection']['autofill_targets']
        self.assertEqual(json.loads(result), original)
        self.assertEqual(len(json.loads(result)), 3)

    def test_yaml_fallback(self):
        """Non-JSON input stored as-is."""
        yaml_val = '- page: "https://example.com"\n  username-field: "#u"'
        resource = {'pam_settings': {'connection': {}}}
        KCMParameterMapper._convert_kcm_autofill(resource, yaml_val)
        result = resource['pam_settings']['connection']['autofill_targets']
        self.assertEqual(result, yaml_val.strip())

    def test_non_array_json_stored_as_is(self):
        """JSON object (not array) stored as-is."""
        kcm_raw = json.dumps({"page": "x.com"})
        resource = {'pam_settings': {'connection': {}}}
        KCMParameterMapper._convert_kcm_autofill(resource, kcm_raw)
        result = resource['pam_settings']['connection']['autofill_targets']
        self.assertEqual(result, kcm_raw.strip())

    def test_literal_backslash_n_from_kcm_db(self):
        """KCM DB extraction produces literal \\n — must parse correctly."""
        # Simulate what PostgreSQL extraction produces: literal \n characters
        # instead of real newlines in the JSON
        kcm_raw = (
            '[\\n'
            '          {\\n'
            '            "page": "*.microsoftonline.com",\\n'
            '            "username-field": "#i0116",\\n'
            '            "password-field": "#i0118",\\n'
            '            "submit": "input[type=\'submit\']"\\n'
            '          }\\n'
            '        ]'
        )
        resource = {'pam_settings': {'connection': {}}}
        KCMParameterMapper._convert_kcm_autofill(resource, kcm_raw)
        result = resource['pam_settings']['connection']['autofill_targets']
        parsed = json.loads(result)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]['page'], '*.microsoftonline.com')
        self.assertEqual(parsed[0]['username-field'], '#i0116')
        # Must be compact JSON
        self.assertNotIn('\\n', result)
        self.assertNotIn('\n', result)

    def test_literal_backslash_n_multi_step(self):
        """Multi-step autofill with literal \\n parses correctly."""
        kcm_raw = (
            '[\\n'
            '  {\\n'
            '    "page": "*.example.com",\\n'
            '    "username-field": "#user",\\n'
            '    "submit": "button.next"\\n'
            '  },\\n'
            '  {\\n'
            '    "page": "*.example.com",\\n'
            '    "password-field": "#pass",\\n'
            '    "submit": "button.login"\\n'
            '  }\\n'
            ']'
        )
        resource = {'pam_settings': {'connection': {}}}
        KCMParameterMapper._convert_kcm_autofill(resource, kcm_raw)
        result = resource['pam_settings']['connection']['autofill_targets']
        parsed = json.loads(result)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]['username-field'], '#user')
        self.assertEqual(parsed[1]['password-field'], '#pass')

    def test_double_escaped_quotes_in_css_selector(self):
        """KCM DB with double-escaped quotes: \\\\" → \\" in CSS selectors."""
        # Azure Portal / Lineleader style: submit has button[type=\"submit\"]
        # but extraction double-escapes to button[type=\\"submit\\"]
        # Reconstructed from actual dry-run output repr:
        kcm_raw = '[\\n  {\\n    "page": "login.microsoftonline.com",\\n    "username-field": "#i0116",\\n    "password-field": "#i0118",\\n    "submit": "button[type=\\\\"submit\\\\"]",\\n    "cannot-submit": "div[data-testid=\\\\"challenge-widget-container\\\\"]"\\n  }\\n]'
        resource = {'pam_settings': {'connection': {}}}
        KCMParameterMapper._convert_kcm_autofill(resource, kcm_raw)
        result = resource['pam_settings']['connection']['autofill_targets']
        parsed = json.loads(result)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]['page'], 'login.microsoftonline.com')
        self.assertEqual(parsed[0]['submit'], 'button[type="submit"]')
        self.assertEqual(parsed[0]['cannot-submit'],
                         'div[data-testid="challenge-widget-container"]')
        # Must be compact JSON
        self.assertNotIn('\n', result)

    def test_legacy_autofill_produces_json(self):
        """Legacy username-field/password-field → JSON array."""
        resource = {'pam_settings': {'connection': {}}}
        KCMParameterMapper._append_legacy_autofill(resource, 'username-field', 'u')
        KCMParameterMapper._append_legacy_autofill(resource, 'password-field', 'passwd')
        result = resource['pam_settings']['connection']['autofill_targets']
        parsed = json.loads(result)
        self.assertEqual(parsed, [{"username-field": "u", "password-field": "passwd"}])


class TestFlagIncompleteRecords(unittest.TestCase):
    """Tests for _flag_incomplete_records — moves bad data to special folder."""

    def _make_resource(self, title, protocol, host='10.0.0.1', **extra):
        r = {
            'title': title,
            'host': host,
            'type': 'pamMachine',
            'folder_path': 'Proj - Resources/GroupA',
            'pam_settings': {
                'connection': {
                    'protocol': protocol,
                    'launch_credentials': f'User - {title}',
                }
            }
        }
        r.update(extra)
        return r

    def _make_user(self, resource_title, login='admin'):
        return {
            'title': f'User - {resource_title}',
            'login': login,
            'type': 'pamUser',
            'folder_path': 'Proj - Users/GroupA',
        }

    def test_complete_records_unchanged(self):
        """Records with all required fields stay in their original folder."""
        r = self._make_resource('SSHBox', 'ssh')
        u = self._make_user('SSHBox')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'], 'Proj - Resources/GroupA')
        self.assertNotIn('notes', r)

    def test_missing_host_ssh_flagged(self):
        """SSH resource without host is moved to Incomplete folder."""
        r = self._make_resource('NoHost', 'ssh', host='')
        u = self._make_user('NoHost')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'],
                         'Proj - Resources/Incomplete (KCM Source)')
        self.assertIn('Missing host/IP', r['notes'])
        self.assertIn('INCOMPLETE DATA AT KCM SOURCE', r['notes'])

    def test_missing_host_vnc_flagged(self):
        """VNC resource without host is flagged."""
        r = self._make_resource('NoHostVNC', 'vnc', host='')
        u = self._make_user('NoHostVNC')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'],
                         'Proj - Resources/Incomplete (KCM Source)')

    def test_http_missing_url_flagged(self):
        """HTTP resource without host and without url is flagged."""
        r = self._make_resource('NoURL', 'http', host='')
        r['type'] = 'pamRemoteBrowser'
        u = self._make_user('NoURL')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'],
                         'Proj - Resources/Incomplete (KCM Source)')
        self.assertIn('Missing URL', r['notes'])

    def test_http_with_url_not_flagged(self):
        """HTTP resource with url but no host is NOT flagged."""
        r = self._make_resource('WebApp', 'http', host='')
        r['type'] = 'pamRemoteBrowser'
        r['url'] = 'https://example.com'
        u = self._make_user('WebApp')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'], 'Proj - Resources/GroupA')
        self.assertNotIn('notes', r)

    def test_rdp_sftp_missing_fields_flagged(self):
        """RDP with SFTP enabled but missing host/port/login is flagged."""
        r = self._make_resource('RDPBox', 'rdp')
        r['pam_settings']['connection']['sftp'] = {
            'enable_sftp': 'true',
            'sftp_root_directory': '/tmp',
            # Missing: host, port, login, password
        }
        u = self._make_user('RDPBox')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'],
                         'Proj - Resources/Incomplete (KCM Source)')
        self.assertIn('SFTP enabled but missing', r['notes'])
        self.assertIn('host', r['notes'])
        self.assertIn('login', r['notes'])

    def test_rdp_sftp_complete_not_flagged(self):
        """RDP with complete SFTP settings is NOT flagged."""
        r = self._make_resource('RDPGood', 'rdp')
        r['pam_settings']['connection']['sftp'] = {
            'enable_sftp': 'true',
            'host': '10.0.0.2', 'port': '22',
            'login': 'admin', 'password': 'pass',
        }
        u = self._make_user('RDPGood')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'], 'Proj - Resources/GroupA')

    def test_user_missing_login_flagged(self):
        """Resource with user missing login for login-required protocol."""
        r = self._make_resource('RDPNoLogin', 'rdp')
        u = self._make_user('RDPNoLogin', login='')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'],
                         'Proj - Resources/Incomplete (KCM Source)')
        self.assertIn('no login', r['notes'])
        # User also moved to incomplete folder
        self.assertEqual(u['folder_path'],
                         'Proj - Users/Incomplete (KCM Source)')

    def test_vnc_user_no_login_not_flagged(self):
        """VNC user without login is NOT flagged (VNC uses password only)."""
        r = self._make_resource('VNCBox', 'vnc')
        u = self._make_user('VNCBox', login='')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertEqual(r['folder_path'], 'Proj - Resources/GroupA')

    def test_notes_contain_original_folder(self):
        """Notes should mention the original folder path."""
        r = self._make_resource('BadHost', 'ssh', host='')
        u = self._make_user('BadHost')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertIn('Proj - Resources/GroupA', r['notes'])

    def test_multiple_issues_all_listed(self):
        """Resource with multiple issues lists all of them in notes."""
        r = self._make_resource('RDPBad', 'rdp', host='')
        r['pam_settings']['connection']['sftp'] = {
            'enable_sftp': 'true',
        }
        u = self._make_user('RDPBad', login='')
        PAMProjectKCMImportCommand._flag_incomplete_records(
            [r], [u], 'Proj - Resources', 'Proj - Users')
        self.assertIn('Missing host/IP', r['notes'])
        self.assertIn('SFTP enabled but missing', r['notes'])
        self.assertIn('no login', r['notes'])


class TestPrintImportSummary(unittest.TestCase):
    """Tests for _print_import_summary output."""

    def test_summary_shows_project_and_mode(self):
        """Summary should display project name and mode."""
        from io import StringIO
        import sys
        resources = [
            {'title': 'R1', 'folder_path': 'Proj - Resources/Group1',
             'users': [{'title': 'U1', 'folder_path': 'Proj - Users/Group1'}]},
        ]
        captured = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            PAMProjectKCMImportCommand._print_import_summary(
                'Proj', '', 1, 1, resources, [], False)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        self.assertIn('Proj', output)
        self.assertIn('New project', output)
        self.assertIn('Resources:  1', output)
        self.assertIn('Users:      1', output)
        self.assertIn('Folders to create:', output)
        self.assertIn('Proj - Resources/Group1', output)

    def test_summary_extend_mode(self):
        """Extend mode should show 'Extend existing project'."""
        from io import StringIO
        import sys
        captured = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            PAMProjectKCMImportCommand._print_import_summary(
                'Proj', 'existing-uid', 0, 0, [], [], True)
        finally:
            sys.stdout = old_stdout
        self.assertIn('Extend existing project', captured.getvalue())


###############################################################################
# Live E2E tests — connect to real KCM PostgreSQL database
###############################################################################

# Connection details (from guacamole-postgres container)
# Credentials loaded from environment to avoid committing secrets.
_LIVE_DB_HOST = os.environ.get('KCM_TEST_DB_HOST', '127.0.0.1')
_LIVE_DB_PORT = int(os.environ.get('KCM_TEST_DB_PORT', '5432'))
_LIVE_DB_NAME = os.environ.get('KCM_TEST_DB_NAME', 'guacamole_db')
_LIVE_DB_USER = os.environ.get('KCM_TEST_DB_USER', 'guacamole_user')
_LIVE_DB_PASS = os.environ.get('KCM_TEST_DB_PASS', '')
_LIVE_DB_TYPE = os.environ.get('KCM_TEST_DB_TYPE', 'postgresql')
_LIVE_DOCKER_CONTAINER = os.environ.get('KCM_TEST_DOCKER', 'guacamole-postgres')


_SKIP_LIVE = not os.environ.get('KCM_TEST_DB_HOST')
_SKIP_MSG = 'Set KCM_TEST_DB_HOST to enable live DB tests'


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
        """extract_connections should return (rows, attr_map) tuple."""
        conn = KCMDatabaseConnector(
            _LIVE_DB_TYPE, _LIVE_DB_HOST, _LIVE_DB_PORT,
            _LIVE_DB_USER, _LIVE_DB_PASS, _LIVE_DB_NAME)
        conn.connect()
        rows, attr_map = conn.extract_connections()
        conn.close()
        self.assertIsInstance(rows, list)
        self.assertIsInstance(attr_map, dict)
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
        cls.rows, cls.attr_map = conn.extract_connections()
        conn.close()
        cls.mapper = KCMParameterMapper()

    def test_transform_produces_resources_and_users(self):
        """transform() should produce non-empty resource and user lists."""
        resources, users = self.mapper.transform(self.rows, attr_map=self.attr_map)
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
        cls.rows, cls.attr_map = conn.extract_connections()
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
        (host, port, db, user), password = \
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
        (_, port, db, user), password = \
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
        mock_conn.extract_connections.return_value = (rows, {})

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
        mock_conn.extract_connections.return_value = (rows, {})

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
        mock_conn.extract_connections.return_value = (rows, {})

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
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'MYSQL_PASSWORD=pass\nMYSQL_HOSTNAME=db\n'

        with patch('keepercommander.commands.pam_import.kcm_import.subprocess.run', return_value=mock_result) as mock_run:
            PAMProjectKCMImportCommand._detect_docker_credentials(
                'mysql', container='my-custom-kcm')

        # First call is docker inspect with the container name
        call_args = mock_run.call_args_list[0][0][0]
        self.assertIn('my-custom-kcm', call_args)

    def test_default_container_name(self):
        """Default container name should be 'guacamole'."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'MYSQL_PASSWORD=pass\n'

        with patch('keepercommander.commands.pam_import.kcm_import.subprocess.run', return_value=mock_result) as mock_run:
            PAMProjectKCMImportCommand._detect_docker_credentials('mysql')

        # First call is docker inspect with the container name
        call_args = mock_run.call_args_list[0][0][0]
        self.assertIn('guacamole', call_args)


class TestDBFlagPassthrough(unittest.TestCase):
    """--db-port, --db-name, --db-user should be forwarded to connector."""

    @patch('keepercommander.commands.pam_import.kcm_import.KCMDatabaseConnector')
    @patch('keepercommander.commands.pam_import.kcm_import.getpass.getpass',
           return_value='pass')
    def test_custom_port_forwarded(self, mock_getpass, MockConnector):
        mock_conn = MockConnector.return_value
        mock_conn.extract_groups.return_value = []
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        mock_conn.extract_connections.return_value = ([
            _make_row(parameter_name='hostname', parameter_value='x')], {})

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
        with patch('keepercommander.commands.pam_import.kcm_import.subprocess.run', return_value=mock_result):
            with self.assertRaises(CommandError) as ctx:
                PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
            self.assertIn('Invalid port', str(ctx.exception))

    def test_docker_detect_timeout(self):
        """Docker inspect timeout should raise CommandError."""
        import subprocess
        from keepercommander.error import CommandError
        with patch('keepercommander.commands.pam_import.kcm_import.subprocess.run', side_effect=subprocess.TimeoutExpired('docker', 10)):
            with self.assertRaises(CommandError) as ctx:
                PAMProjectKCMImportCommand._detect_docker_credentials('mysql')
            self.assertIn('Docker inspect failed', str(ctx.exception))

    def test_docker_not_installed(self):
        """Missing docker binary should raise CommandError."""
        from keepercommander.error import CommandError
        with patch('keepercommander.commands.pam_import.kcm_import.subprocess.run', side_effect=FileNotFoundError('docker')):
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

        mock_gw_helper = MagicMock()
        mock_gw_helper.get_all_gateways.return_value = []

        mock_router_fn = MagicMock(return_value=MagicMock(controllers=[]))

        with patch('keepercommander.commands.pam.gateway_helper.get_all_gateways',
                   mock_gw_helper.get_all_gateways):
            with patch('keepercommander.commands.pam.router_helper.router_get_connected_gateways',
                       mock_router_fn):
                with self.assertRaises(CommandError) as ctx:
                    PAMProjectKCMImportCommand._resolve_gateway(
                        MagicMock(), 'nonexistent')
        self.assertIn('not found', str(ctx.exception))
        self.assertIn('--dry-run', str(ctx.exception))

    def test_offline_gateway_warns(self):
        """Selecting an offline gateway should log a warning."""
        from keepercommander import utils
        gw = MagicMock()
        gw.controllerName = 'MyGW'
        gw.controllerUid = b'\x01\x02\x03'

        with patch('keepercommander.commands.pam.gateway_helper.get_all_gateways',
                   return_value=[gw]):
            with patch('keepercommander.commands.pam.router_helper.router_get_connected_gateways',
                       return_value=MagicMock(controllers=[])):
                with patch.object(PAMProjectKCMImportCommand,
                                  '_find_config_for_gateway',
                                  return_value='config-uid-123'):
                    uid_str = utils.base64_url_encode(gw.controllerUid)
                    with self.assertLogs(level='WARNING') as cm:
                        result = PAMProjectKCMImportCommand._resolve_gateway(
                            MagicMock(), uid_str)
        self.assertTrue(any('OFFLINE' in msg for msg in cm.output))
        self.assertEqual(result, 'config-uid-123')

    def test_interactive_new_gateway_returns_none(self):
        """Choosing 'N' (new gateway) in interactive mode returns None."""
        with patch('keepercommander.commands.pam.gateway_helper.get_all_gateways',
                   return_value=[]):
            with patch('keepercommander.commands.pam.router_helper.router_get_connected_gateways',
                       return_value=MagicMock(controllers=[])):
                with patch('builtins.print'):
                    result = PAMProjectKCMImportCommand._resolve_gateway(
                        MagicMock(), None)
        self.assertIsNone(result)

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
        with patch('keepercommander.commands.pam.config_helper.configuration_controller_get',
                   return_value=None):
            with self.assertRaises(CommandError) as ctx:
                PAMProjectKCMImportCommand._find_config_for_gateway(params, mock_gw)
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

        with patch('keepercommander.commands.pam.config_helper.configuration_controller_get',
                   return_value=mock_controller):
            result = PAMProjectKCMImportCommand._find_config_for_gateway(
                params, mock_gw)

        self.assertEqual(result, 'matching-rec-uid')


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
        self.assertFalse(PAMProjectKCMImportCommand._is_local_host(''))


class TestComputeBatchParams(unittest.TestCase):
    """_compute_batch_params auto-scales batch sizes by import volume."""

    def test_small_import(self):
        res, usr, delay = PAMProjectKCMImportCommand._compute_batch_params(
            20, 10, None, None)
        self.assertEqual(res, 2)
        self.assertEqual(usr, 8)
        self.assertEqual(delay, 12.0)

    def test_medium_import(self):
        res, usr, delay = PAMProjectKCMImportCommand._compute_batch_params(
            200, 60, None, None)
        self.assertEqual(res, 2)
        self.assertEqual(usr, 8)
        self.assertEqual(delay, 15.0)

    def test_large_import(self):
        res, usr, delay = PAMProjectKCMImportCommand._compute_batch_params(
            3000, 500, None, None)
        self.assertEqual(res, 1)
        self.assertEqual(usr, 6)
        self.assertEqual(delay, 15.0)

    def test_override_batch_size(self):
        res, usr, delay = PAMProjectKCMImportCommand._compute_batch_params(
            200, 60, override_size=10, override_delay=None)
        self.assertEqual(res, 10)
        # user batch and delay use auto-computed defaults
        self.assertEqual(usr, 8)
        self.assertEqual(delay, 15.0)

    def test_override_delay(self):
        res, usr, delay = PAMProjectKCMImportCommand._compute_batch_params(
            200, 60, override_size=None, override_delay=5.0)
        self.assertEqual(res, 2)
        self.assertEqual(delay, 5.0)


class TestAdaptiveThrottler(unittest.TestCase):
    """AdaptiveThrottler: probe-based adaptive batch parameter management."""

    def test_defaults(self):
        """Default state: enabled, standard batch params."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        self.assertTrue(t.enabled)
        self.assertEqual(t.res_batch_size, 2)
        self.assertEqual(t.usr_batch_size, 8)
        self.assertEqual(t.res_delay, 15.0)
        self.assertEqual(t.usr_delay, 15.0)
        self.assertEqual(t.throttle_count, 0)

    def test_disabled_skips_adaptation(self):
        """When disabled, record_batch does nothing."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler(enabled=False)
        result = t.record_batch(100.0, 2, is_resource=True)
        self.assertFalse(result['adapted'])
        self.assertEqual(t.res_batch_size, 2)  # unchanged

    def test_compute_optimal_no_throttle(self):
        """No throttle: budget-based batch, call-proportional delays."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 3.0  # fast server
        t._compute_optimal_params(probe_throttled=False)
        # budget = 50 * 0.7 = 35
        # res_batch = 35/20 = 1, usr_batch = 35/8 = 4
        self.assertEqual(t._optimal_res_batch, 1)
        self.assertEqual(t._optimal_usr_batch, 4)
        # res_delay = max(3.0, 1 * 20 * 0.6) = 12.0
        self.assertAlmostEqual(t._optimal_res_delay, 12.0, places=1)
        # usr_delay = max(3.0, 4 * 8 * 0.6) = 19.2
        self.assertAlmostEqual(t._optimal_usr_delay, 19.2, places=1)

    def test_compute_optimal_with_throttle(self):
        """Probe throttle: conservative params."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 5.0
        t._compute_optimal_params(probe_throttled=True)
        self.assertEqual(t._optimal_res_batch, 1)
        # delay = max(15.0, 5.0 * 3) = 15.0
        self.assertEqual(t._optimal_res_delay, 15.0)
        self.assertEqual(t._optimal_usr_delay, 15.0)

    def test_adapt_down_on_slow_batch(self):
        """Throttle detected: only offending type's batch halved, delay doubled."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 2.0
        t.res_batch_size = 4
        t.usr_batch_size = 8
        t.res_delay = 10.0
        t.usr_delay = 5.0
        # Simulate a very slow resource batch (triggers throttle detection)
        result = t.record_batch(200.0, 4, is_resource=True)
        self.assertTrue(result['adapted'])
        self.assertEqual(result['direction'], 'down')
        self.assertEqual(t.res_batch_size, 2)   # halved
        self.assertEqual(t.usr_batch_size, 8)    # untouched
        self.assertEqual(t.res_delay, 20.0)      # doubled
        self.assertEqual(t.usr_delay, 5.0)       # untouched
        self.assertEqual(t.throttle_count, 1)

    def test_adapt_up_after_clean_batches(self):
        """Recovery: batch_size increases after N clean batches (type-specific)."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 2.0
        t._optimal_res_batch = 3
        t._optimal_usr_batch = 8
        t._optimal_res_delay = 5.0
        t._optimal_usr_delay = 5.0
        t.res_batch_size = 1    # currently below optimal
        t.res_delay = 20.0      # currently above optimal
        t.usr_delay = 5.0
        # Need CLEAN_BATCHES_TO_RECOVER (3) clean batches
        for i in range(2):
            result = t.record_batch(3.0, 1, is_resource=True)
            self.assertFalse(result['adapted'])
        # 3rd clean batch triggers recovery
        result = t.record_batch(3.0, 1, is_resource=True)
        self.assertTrue(result['adapted'])
        self.assertEqual(result['direction'], 'up')
        self.assertEqual(t.res_batch_size, 2)    # 1 → 2
        self.assertLess(t.res_delay, 20.0)       # decreased
        self.assertEqual(t.usr_delay, 5.0)        # untouched

    def test_no_recover_above_optimal(self):
        """Don't speed up beyond optimal params."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 2.0
        t._optimal_res_batch = 2
        t._optimal_usr_batch = 8
        t._optimal_res_delay = 5.0
        t._optimal_usr_delay = 5.0
        t.res_batch_size = 2  # already at optimal
        t.usr_batch_size = 8
        t.res_delay = 5.0     # already at optimal
        for _ in range(5):
            result = t.record_batch(3.0, 2, is_resource=True)
            self.assertFalse(result['adapted'])
        # Params unchanged
        self.assertEqual(t.res_batch_size, 2)
        self.assertEqual(t.res_delay, 5.0)

    def test_adapt_down_min_batch_size(self):
        """batch_size never goes below 1."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 2.0
        t.res_batch_size = 1
        t.res_delay = 10.0
        # Simulate throttle
        t.record_batch(200.0, 1, is_resource=True)
        self.assertEqual(t.res_batch_size, 1)  # floor
        self.assertEqual(t.res_delay, 20.0)

    def test_adapt_down_max_delay(self):
        """delay never exceeds MAX_DELAY."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 2.0
        t.res_delay = 40.0
        t.record_batch(200.0, 1, is_resource=True)  # throttle
        self.assertEqual(t.res_delay, 60.0)  # MAX_DELAY
        t.record_batch(200.0, 1, is_resource=True)  # throttle again
        self.assertEqual(t.res_delay, 60.0)  # capped

    def test_summary(self):
        """get_summary returns all fields."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 2.5
        t.probe_rtts = [2.0, 2.5, 3.0]
        t.record_batch(3.0, 1, is_resource=True)
        s = t.get_summary()
        self.assertEqual(s['base_rtt'], 2.5)
        self.assertEqual(s['probe_rtts'], [2.0, 2.5, 3.0])
        self.assertEqual(s['total_batches'], 1)
        self.assertIn('final_res_batch', s)
        self.assertIn('final_res_delay', s)
        self.assertIn('final_usr_delay', s)

    def test_probe_skipped_when_disabled(self):
        """Probe skipped when auto_throttle=False."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler(enabled=False)
        result = t.run_probe(None, None, {'pam_data': {'resources': [], 'users': []}}, None)
        self.assertTrue(result['skipped'])

    def test_probe_skipped_no_records(self):
        """Probe skipped when no records to probe with."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        result = t.run_probe(None, 'cfg', {'pam_data': {'resources': [], 'users': []}}, None)
        self.assertTrue(result['skipped'])

    def test_user_batch_adaptation_independent(self):
        """User throttle only affects user params, not resource params."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 1.0
        t.usr_batch_size = 6
        t.res_batch_size = 2
        t.usr_delay = 10.0
        t.res_delay = 8.0
        # Throttle on user batch
        t.record_batch(200.0, 6, is_resource=False)
        self.assertEqual(t.usr_batch_size, 3)     # halved
        self.assertEqual(t.res_batch_size, 2)     # untouched
        self.assertEqual(t.usr_delay, 20.0)       # doubled
        self.assertEqual(t.res_delay, 8.0)        # untouched

    def test_consecutive_clean_resets_on_throttle(self):
        """Throttle resets the clean batch counter."""
        from keepercommander.commands.pam_import.kcm_import import AdaptiveThrottler
        t = AdaptiveThrottler()
        t.base_rtt = 2.0
        t._optimal_res_batch = 5
        t.res_batch_size = 1
        t.res_delay = 15.0
        # 2 clean batches
        t.record_batch(3.0, 1, is_resource=True)
        t.record_batch(3.0, 1, is_resource=True)
        self.assertEqual(t.consecutive_clean, 2)
        # Throttle resets counter
        t.record_batch(200.0, 1, is_resource=True)
        self.assertEqual(t.consecutive_clean, 0)


class TestRewriteFolderPaths(unittest.TestCase):
    """_rewrite_folder_paths should fix roots when edit.py adds #N suffix."""

    def test_rewrite_resources_and_users(self):
        """Should replace project_name prefix with actual folder names."""
        pam_json = {
            'pam_data': {
                'resources': [
                    {'folder_path': 'Proj - Resources/GroupA/Sub1', 'title': 'r1'},
                    {'folder_path': 'Proj - Resources', 'title': 'r2'},
                ],
                'users': [
                    {'folder_path': 'Proj - Users/GroupA/Sub1', 'title': 'u1'},
                    {'folder_path': 'Proj - Users', 'title': 'u2'},
                ],
            }
        }
        PAMProjectKCMImportCommand._rewrite_folder_paths(
            pam_json, 'Proj #2 - Resources', 'Proj #2 - Users', 'Proj')

        self.assertEqual(pam_json['pam_data']['resources'][0]['folder_path'],
                         'Proj #2 - Resources/GroupA/Sub1')
        self.assertEqual(pam_json['pam_data']['resources'][1]['folder_path'],
                         'Proj #2 - Resources')
        self.assertEqual(pam_json['pam_data']['users'][0]['folder_path'],
                         'Proj #2 - Users/GroupA/Sub1')
        self.assertEqual(pam_json['pam_data']['users'][1]['folder_path'],
                         'Proj #2 - Users')

    def test_noop_when_names_match(self):
        """No rewriting when actual names match computed names."""
        pam_json = {
            'pam_data': {
                'resources': [
                    {'folder_path': 'Proj - Resources/A', 'title': 'r1'},
                ],
                'users': [],
            }
        }
        PAMProjectKCMImportCommand._rewrite_folder_paths(
            pam_json, 'Proj - Resources', 'Proj - Users', 'Proj')

        self.assertEqual(pam_json['pam_data']['resources'][0]['folder_path'],
                         'Proj - Resources/A')

    def test_sftp_subpaths_rewritten(self):
        """SFTP sub-paths under resources should also be rewritten."""
        pam_json = {
            'pam_data': {
                'resources': [
                    {'folder_path': 'P - Resources/G/SFTP Resources', 'title': 'sftp1'},
                ],
                'users': [
                    {'folder_path': 'P - Users/G/SFTP Users', 'title': 'sftp_u1'},
                ],
            }
        }
        PAMProjectKCMImportCommand._rewrite_folder_paths(
            pam_json, 'P #3 - Resources', 'P #3 - Users', 'P')

        self.assertEqual(pam_json['pam_data']['resources'][0]['folder_path'],
                         'P #3 - Resources/G/SFTP Resources')
        self.assertEqual(pam_json['pam_data']['users'][0]['folder_path'],
                         'P #3 - Users/G/SFTP Users')

    def test_empty_pam_data(self):
        """Should handle empty resources/users gracefully."""
        pam_json = {'pam_data': {'resources': [], 'users': []}}
        PAMProjectKCMImportCommand._rewrite_folder_paths(
            pam_json, 'X - Resources', 'X - Users', 'X')
        # No exception = pass


class TestDiscoverSharedFolderNames(unittest.TestCase):
    """_discover_shared_folder_names should find Resources/Users from KSM app."""

    def test_discovers_by_convention(self):
        """Should match folder names ending with '- Resources' and '- Users'."""
        mock_controller = MagicMock()
        mock_controller.controllerUid = b'\x01\x02'

        mock_gw = MagicMock()
        mock_gw.controllerUid = b'\x01\x02'
        mock_gw.applicationUid = b'\x03\x04'

        mock_extend_instance = MagicMock()
        mock_extend_instance.get_app_shared_folders.return_value = [
            {'name': 'MyProject - Resources', 'uid': 'sf-1'},
            {'name': 'MyProject - Users', 'uid': 'sf-2'},
        ]
        mock_extend_module = MagicMock()
        mock_extend_module.PAMProjectExtendCommand.return_value = mock_extend_instance

        mock_rec = MagicMock()
        # Must be valid base64url for CommonHelperMethods.url_safe_str_to_bytes
        mock_rec.record_uid = 'AQIDBA'

        params = MagicMock()

        # Mock extend module via sys.modules to avoid importing pydantic
        # (not available in all CI environments). Use direct patch for others.
        with patch.dict('sys.modules',
                        {'keepercommander.commands.pam_import.extend': mock_extend_module}):
            with patch('keepercommander.api.sync_down'):
                with patch('keepercommander.commands.pam_import.kcm_import.vault.KeeperRecord.load',
                           return_value=mock_rec):
                    with patch('keepercommander.commands.pam.config_helper.configuration_controller_get',
                               return_value=mock_controller):
                        with patch('keepercommander.commands.pam.gateway_helper.get_all_gateways',
                                   return_value=[mock_gw]):
                            res, usr = PAMProjectKCMImportCommand._discover_shared_folder_names(
                                params, 'AQIDBA')

        self.assertEqual(res, 'MyProject - Resources')
        self.assertEqual(usr, 'MyProject - Users')

    def test_returns_none_for_missing_config(self):
        """Should return (None, None) if config UID not found."""
        params = MagicMock()

        with patch('keepercommander.api.sync_down'):
            with patch('keepercommander.commands.pam_import.kcm_import.vault.KeeperRecord.load',
                       return_value=None):
                res, usr = PAMProjectKCMImportCommand._discover_shared_folder_names(
                    params, 'nonexistent')

        self.assertIsNone(res)
        self.assertIsNone(usr)


class TestKCMCleanupCommand(unittest.TestCase):
    """Tests for PAMProjectKCMCleanupCommand."""

    def test_missing_args_raises(self):
        """Should require --name or --config."""
        cmd = PAMProjectKCMCleanupCommand()
        params = MagicMock()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params)
        self.assertIn('--name or --config', str(ctx.exception))

    @patch('keepercommander.api.sync_down')
    def test_config_not_found_raises(self, mock_sync):
        """Should raise if config UID doesn't exist in vault."""
        cmd = PAMProjectKCMCleanupCommand()
        params = MagicMock()
        with patch('keepercommander.commands.pam_import.kcm_import.vault.KeeperRecord.load',
                   return_value=None):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params, config_uid='nonexistent')
        self.assertIn('not found', str(ctx.exception))

    @patch('keepercommander.api.sync_down')
    def test_project_name_not_found_raises(self, mock_sync):
        """Should raise if project name doesn't match any config."""
        cmd = PAMProjectKCMCleanupCommand()
        params = MagicMock()
        params.shared_folder_cache = {}
        params.folder_cache = {}
        params.subfolder_record_cache = {}

        # vault_extensions is imported locally inside execute()
        mock_ve = MagicMock()
        mock_ve.find_records.return_value = []
        with patch.dict('sys.modules',
                        {'keepercommander.vault_extensions': mock_ve}):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params, project_name='DoesNotExist')
        self.assertIn('not found', str(ctx.exception))

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.api.communicate')
    @patch('keepercommander.api.delete_record')
    def test_dry_run_no_deletions(self, mock_del, mock_comm, mock_sync):
        """Dry run should not delete anything."""
        cmd = PAMProjectKCMCleanupCommand()
        params = MagicMock()
        params.shared_folder_cache = {}
        params.folder_cache = {}
        params.subfolder_record_cache = {}

        mock_config = MagicMock()
        mock_config.title = 'TestProject Configuration'
        mock_config.record_uid = 'cfg_uid_123'

        mock_config_helper = MagicMock()
        mock_config_helper.configuration_controller_get.side_effect = Exception('skip')
        mock_gw_helper = MagicMock()

        with patch('keepercommander.commands.pam_import.kcm_import.vault.KeeperRecord.load',
                   return_value=mock_config):
            with patch.dict('sys.modules', {
                'keepercommander.commands.pam.config_helper': mock_config_helper,
                'keepercommander.commands.pam.gateway_helper': mock_gw_helper,
            }):
                cmd.execute(params, config_uid='cfg_uid_123', dry_run=True)

        mock_comm.assert_not_called()
        mock_del.assert_not_called()


class TestDetectDbType(unittest.TestCase):
    """Tests for _detect_db_type_from_docker."""

    @patch('subprocess.run')
    def test_postgresql_detected(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='POSTGRES_USER=guac\nPOSTGRES_PASSWORD=secret\n')
        result = PAMProjectKCMImportCommand._detect_db_type_from_docker('db-1')
        self.assertEqual(result, 'postgresql')

    @patch('subprocess.run')
    def test_mysql_detected(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='MYSQL_USER=guac\nMYSQL_PASSWORD=secret\n')
        result = PAMProjectKCMImportCommand._detect_db_type_from_docker('db-1')
        self.assertEqual(result, 'mysql')

    @patch('subprocess.run')
    def test_both_prefers_postgresql(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='POSTGRES_PASSWORD=x\nMYSQL_PASSWORD=y\n')
        result = PAMProjectKCMImportCommand._detect_db_type_from_docker('db-1')
        self.assertEqual(result, 'postgresql')

    @patch('subprocess.run')
    def test_fallback_mysql(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout='PATH=/usr/bin\nHOME=/root\n')
        result = PAMProjectKCMImportCommand._detect_db_type_from_docker('db-1')
        self.assertEqual(result, 'mysql')

    @patch('subprocess.run', side_effect=FileNotFoundError)
    def test_docker_not_found(self, mock_run):
        result = PAMProjectKCMImportCommand._detect_db_type_from_docker('db-1')
        self.assertEqual(result, 'mysql')


class TestDiscoverDockerContainer(unittest.TestCase):
    """Tests for _discover_docker_container."""

    @patch('subprocess.run')
    def test_single_candidate(self, mock_run):
        def side_effect(cmd, **kw):
            if 'ps' in cmd:
                return MagicMock(returncode=0, stdout='web-1\ndb-1\nredis-1\n')
            # docker inspect for each container
            name = cmd[-1]
            if name == 'db-1':
                return MagicMock(returncode=0,
                                 stdout='POSTGRES_PASSWORD=secret\n')
            return MagicMock(returncode=0, stdout='PATH=/usr/bin\n')
        mock_run.side_effect = side_effect
        result = PAMProjectKCMImportCommand._discover_docker_container()
        self.assertEqual(result, 'db-1')

    @patch('subprocess.run')
    def test_kcm_db_preferred(self, mock_run):
        """Prefer container with 'kcm' + 'db' in name over others."""
        def side_effect(cmd, **kw):
            if 'ps' in cmd:
                return MagicMock(returncode=0,
                                 stdout='app-db-1\nkcm-setup-db-1\nother-db-1\n')
            return MagicMock(returncode=0,
                             stdout='POSTGRES_PASSWORD=secret\n')
        mock_run.side_effect = side_effect
        result = PAMProjectKCMImportCommand._discover_docker_container()
        self.assertEqual(result, 'kcm-setup-db-1')

    @patch('subprocess.run')
    def test_guacamole_db_preferred(self, mock_run):
        """Prefer container with 'guacamole' + 'db' over just 'guacamole'."""
        def side_effect(cmd, **kw):
            if 'ps' in cmd:
                return MagicMock(returncode=0,
                                 stdout='app-db-1\nguacamole-db-1\nguacamole-app-1\n')
            return MagicMock(returncode=0,
                             stdout='POSTGRES_PASSWORD=secret\n')
        mock_run.side_effect = side_effect
        result = PAMProjectKCMImportCommand._discover_docker_container()
        self.assertEqual(result, 'guacamole-db-1')

    @patch('subprocess.run')
    def test_no_candidates_raises(self, mock_run):
        def side_effect(cmd, **kw):
            if 'ps' in cmd:
                return MagicMock(returncode=0, stdout='web-1\nredis-1\n')
            return MagicMock(returncode=0, stdout='PATH=/usr/bin\n')
        mock_run.side_effect = side_effect
        with self.assertRaises(CommandError):
            PAMProjectKCMImportCommand._discover_docker_container()


class TestBuildRedactedCommand(unittest.TestCase):
    """Tests for _build_redacted_command."""

    def test_redacts_password_record(self):
        kwargs = {
            'docker_detect': True,
            'db_type': 'postgresql',
            'db_host': '192.168.64.5',
            'db_password_record': 'secret-uid-123',
            'auto_confirm': True,
        }
        result = PAMProjectKCMImportCommand._build_redacted_command(kwargs)
        self.assertIn('--docker-detect', result)
        self.assertIn('--db-type "postgresql"', result)
        self.assertIn('--db-host "192.168.64.5"', result)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('secret-uid-123', result)
        self.assertIn('--yes', result)

    def test_empty_kwargs(self):
        result = PAMProjectKCMImportCommand._build_redacted_command({})
        self.assertEqual(result, 'pam project kcm-import')


class TestBuildImportReport(unittest.TestCase):
    """Tests for _build_import_report."""

    def test_report_contains_sections(self):
        report = PAMProjectKCMImportCommand._build_import_report(
            project_name='Test Project',
            config_uid='cfg-123',
            is_new_project=True,
            assets={'gateway_name': 'Test GW', 'gateway_uid': 'gw-1',
                    'app_uid': 'app-1',
                    'res_sf_name': 'Test - Resources', 'res_sf_uid': 'sf-1',
                    'usr_sf_name': 'Test - Users', 'usr_sf_uid': 'sf-2'},
            num_resources=100,
            num_users=50,
            created=145,
            expected=150,
            total_time=3600.0,
            throttler_summary={
                'throttle_count': 2, 'total_batches': 50,
                'final_res_batch': 1, 'final_res_delay': 12.0,
                'final_usr_batch': 4, 'final_usr_delay': 19.0,
                'base_rtt': 1.5},
            warnings=['5 records missing password'],
            kwargs={'docker_detect': True, 'db_type': 'postgresql'},
        )
        self.assertIn('Test Project', report)
        self.assertIn('PROJECT ASSETS', report)
        self.assertIn('Test GW', report)
        self.assertIn('IMPORT RESULTS', report)
        self.assertIn('145', report)
        self.assertIn('THROTTLE STATISTICS', report)
        self.assertIn('WARNINGS', report)
        self.assertIn('GATEWAY DEPLOYMENT', report)
        self.assertIn('WHAT TO DO NEXT', report)
        self.assertIn('COMMAND USED (redacted)', report)

    def test_no_gateway_deploy_for_extend(self):
        report = PAMProjectKCMImportCommand._build_import_report(
            project_name='Existing',
            config_uid='cfg-456',
            is_new_project=False,
            assets={},
            num_resources=10,
            num_users=5,
            created=15,
            expected=15,
            total_time=60.0,
            throttler_summary={'throttle_count': 0, 'total_batches': 5,
                               'final_res_batch': 2, 'final_res_delay': 12.0,
                               'final_usr_batch': 4, 'final_usr_delay': 19.0},
            warnings=[],
            kwargs={},
        )
        self.assertNotIn('GATEWAY DEPLOYMENT', report)
        self.assertIn('EXISTING', report)

    def test_report_includes_gateway_token(self):
        """Gateway token should appear in report when captured."""
        report = PAMProjectKCMImportCommand._build_import_report(
            project_name='Token Project',
            config_uid='cfg-789',
            is_new_project=True,
            assets={'gateway_name': 'GW', 'gateway_uid': 'gw-1',
                    'gateway_token': 'MY_SECRET_TOKEN_123'},
            num_resources=5, num_users=2, created=7, expected=7,
            total_time=30.0, throttler_summary=None, warnings=[],
            kwargs={},
        )
        self.assertIn('GATEWAY DEPLOYMENT', report)
        self.assertIn('Access Token: MY_SECRET_TOKEN_123', report)
        self.assertIn('GATEWAY_CONFIG="MY_SECRET_TOKEN_123"', report)

    def test_report_missing_token_placeholder(self):
        """When no token captured, report shows placeholder."""
        report = PAMProjectKCMImportCommand._build_import_report(
            project_name='No Token',
            config_uid='cfg-000',
            is_new_project=True,
            assets={},
            num_resources=5, num_users=2, created=7, expected=7,
            total_time=30.0, throttler_summary=None, warnings=[],
            kwargs={},
        )
        self.assertIn('Token not captured', report)
        self.assertIn('<access_token>', report)

    def test_report_per_record_breakdown(self):
        """Per-record tracking should render in the report."""
        results = [
            {'name': 'Server1', 'type': 'pamMachine', 'phase': 'resource',
             'status': 'ok', 'reason': ''},
            {'name': 'Server2', 'type': 'pamMachine', 'phase': 'resource',
             'status': 'ok', 'reason': ''},
            {'name': 'DB1', 'type': 'pamDatabase', 'phase': 'resource',
             'status': 'skipped', 'reason': 'missing field X'},
            {'name': 'admin', 'type': 'pamUser', 'phase': 'user',
             'status': 'ok', 'reason': ''},
            {'name': 'broke_user', 'type': 'login', 'phase': 'user',
             'status': 'error', 'reason': 'API timeout'},
        ]
        report = PAMProjectKCMImportCommand._build_import_report(
            project_name='Detail Test',
            config_uid='cfg-det',
            is_new_project=False,
            assets={},
            num_resources=3, num_users=2, created=3, expected=5,
            total_time=120.0, throttler_summary=None, warnings=[],
            kwargs={}, import_results=results,
        )
        self.assertIn('FAILED / SKIPPED RECORDS', report)
        self.assertIn('RECORD BREAKDOWN', report)
        self.assertIn('SKIP', report)
        self.assertIn('ERR', report)
        self.assertIn('pamMachine', report)
        self.assertIn('pamDatabase', report)
        self.assertIn('DB1', report)
        self.assertIn('broke_user', report)
        # Check the breakdown table has TOTAL row
        self.assertIn('TOTAL', report)

    def test_report_no_failures_no_detail_section(self):
        """When all records succeed, no FAILED section shown."""
        results = [
            {'name': 'Server1', 'type': 'pamMachine', 'phase': 'resource',
             'status': 'ok', 'reason': ''},
        ]
        report = PAMProjectKCMImportCommand._build_import_report(
            project_name='All OK',
            config_uid='cfg-ok',
            is_new_project=False,
            assets={},
            num_resources=1, num_users=0, created=1, expected=1,
            total_time=10.0, throttler_summary=None, warnings=[],
            kwargs={}, import_results=results,
        )
        self.assertNotIn('FAILED / SKIPPED RECORDS', report)
        self.assertIn('RECORD BREAKDOWN', report)


class TestGatewayTokenParsing(unittest.TestCase):
    """Test gateway token extraction from captured stdout."""

    def test_parses_token_from_json_output(self):
        """Should extract access_token from edit.py's JSON output."""
        import re
        captured = json.dumps({
            'access_token': 'CAPTURED_TOKEN_XYZ',
            'device_uid': 'dev-1',
        }, indent=2)
        # Replicate the parsing logic from _create_project_skeleton
        gateway_token = ''
        for line in captured.splitlines():
            stripped = line.strip()
            if stripped.startswith('{'):
                try:
                    parsed = json.loads(stripped)
                    if 'access_token' in parsed:
                        gateway_token = parsed['access_token']
                        break
                except json.JSONDecodeError:
                    continue
        if not gateway_token:
            match = re.search(
                r'\{[^{}]*"access_token"\s*:\s*"([^"]*)"[^{}]*\}',
                captured, re.DOTALL)
            if match:
                gateway_token = match.group(1)
        self.assertEqual(gateway_token, 'CAPTURED_TOKEN_XYZ')

    def test_returns_empty_for_no_token(self):
        """Should return empty string when no access_token in output."""
        import re
        captured = 'some random output\nno json here'
        gateway_token = ''
        for line in captured.splitlines():
            stripped = line.strip()
            if stripped.startswith('{'):
                try:
                    parsed = json.loads(stripped)
                    if 'access_token' in parsed:
                        gateway_token = parsed['access_token']
                        break
                except json.JSONDecodeError:
                    continue
        if not gateway_token:
            match = re.search(
                r'\{[^{}]*"access_token"\s*:\s*"([^"]*)"[^{}]*\}',
                captured, re.DOTALL)
            if match:
                gateway_token = match.group(1)
        self.assertEqual(gateway_token, '')

    def test_parses_multiline_json(self):
        """Should handle multi-line pretty-printed JSON."""
        import re
        captured = 'Starting import...\n' + json.dumps({
            'access_token': 'MULTI_LINE_TOKEN',
            'device_uid': 'dev-2',
            'shared_folder_resources_uid': 'sf-1',
        }, indent=2) + '\nDone.'
        gateway_token = ''
        for line in captured.splitlines():
            stripped = line.strip()
            if stripped.startswith('{'):
                try:
                    parsed = json.loads(stripped)
                    if 'access_token' in parsed:
                        gateway_token = parsed['access_token']
                        break
                except json.JSONDecodeError:
                    continue
        if not gateway_token:
            match = re.search(
                r'\{[^{}]*"access_token"\s*:\s*"([^"]*)"[^{}]*\}',
                captured, re.DOTALL)
            if match:
                gateway_token = match.group(1)
        self.assertEqual(gateway_token, 'MULTI_LINE_TOKEN')


class TestFilterByGroups(unittest.TestCase):
    """Tests for _filter_by_groups."""

    def _make_groups(self):
        return [
            {'connection_group_id': 1, 'connection_group_name': 'Production',
             'parent_id': None, 'ksm_config': None},
            {'connection_group_id': 2, 'connection_group_name': 'Staging',
             'parent_id': None, 'ksm_config': None},
            {'connection_group_id': 3, 'connection_group_name': 'SSH Connections',
             'parent_id': 1, 'ksm_config': None},
            {'connection_group_id': 4, 'connection_group_name': 'Incomplete Stuff',
             'parent_id': None, 'ksm_config': None},
            {'connection_group_id': 5, 'connection_group_name': 'Test Lab',
             'parent_id': 2, 'ksm_config': None},
        ]

    def _make_items(self):
        resources = [
            {'title': 'Prod SSH 1', '_group_id': 3},
            {'title': 'Prod SSH 2', '_group_id': 3},
            {'title': 'Staging DB', '_group_id': 2},
            {'title': 'Root Item', '_group_id': None},
            {'title': 'Incomplete Box', '_group_id': 4},
            {'title': 'Test VM', '_group_id': 5},
        ]
        users = [
            {'title': 'admin', '_group_id': 1},
            {'title': 'tester', '_group_id': 5},
        ]
        return resources, users

    def test_include_filter_wildcard(self):
        groups = self._make_groups()
        resolver = KCMGroupResolver(groups, mode='exact')
        resources, users = self._make_items()
        filtered_res, filtered_usr = PAMProjectKCMImportCommand._filter_by_groups(
            resources, users, groups, resolver,
            include_pattern='Production*', exclude_pattern='')
        titles = [r['title'] for r in filtered_res]
        self.assertIn('Prod SSH 1', titles)
        self.assertIn('Prod SSH 2', titles)
        self.assertNotIn('Staging DB', titles)
        self.assertNotIn('Root Item', titles)
        # admin is in group 1 (Production) — should match via path segment
        usr_titles = [u['title'] for u in filtered_usr]
        self.assertIn('admin', usr_titles)

    def test_exclude_filter_wildcard(self):
        groups = self._make_groups()
        resolver = KCMGroupResolver(groups, mode='exact')
        resources, users = self._make_items()
        filtered_res, filtered_usr = PAMProjectKCMImportCommand._filter_by_groups(
            resources, users, groups, resolver,
            include_pattern='', exclude_pattern='Incomplete*,Test*')
        titles = [r['title'] for r in filtered_res]
        self.assertIn('Prod SSH 1', titles)
        self.assertIn('Staging DB', titles)
        self.assertNotIn('Incomplete Box', titles)
        self.assertNotIn('Test VM', titles)
        # Root items kept when only --exclude-groups is active (no --groups)
        self.assertIn('Root Item', titles)

    def test_include_excludes_root_items(self):
        groups = self._make_groups()
        resolver = KCMGroupResolver(groups, mode='exact')
        resources, users = self._make_items()
        filtered_res, _ = PAMProjectKCMImportCommand._filter_by_groups(
            resources, users, groups, resolver,
            include_pattern='Staging*', exclude_pattern='')
        titles = [r['title'] for r in filtered_res]
        self.assertNotIn('Root Item', titles)
        self.assertIn('Staging DB', titles)
        self.assertIn('Test VM', titles)  # child of Staging

    def test_combined_include_and_exclude(self):
        groups = self._make_groups()
        resolver = KCMGroupResolver(groups, mode='exact')
        resources, users = self._make_items()
        filtered_res, _ = PAMProjectKCMImportCommand._filter_by_groups(
            resources, users, groups, resolver,
            include_pattern='Staging*',
            exclude_pattern='Test*')
        titles = [r['title'] for r in filtered_res]
        self.assertIn('Staging DB', titles)
        self.assertNotIn('Test VM', titles)  # excluded by Test*

    def test_no_filters_returns_all(self):
        groups = self._make_groups()
        resolver = KCMGroupResolver(groups, mode='exact')
        resources, users = self._make_items()
        filtered_res, filtered_usr = PAMProjectKCMImportCommand._filter_by_groups(
            resources, users, groups, resolver,
            include_pattern='', exclude_pattern='')
        self.assertEqual(len(filtered_res), len(resources))
        self.assertEqual(len(filtered_usr), len(users))

    def test_no_match_returns_empty(self):
        groups = self._make_groups()
        resolver = KCMGroupResolver(groups, mode='exact')
        resources, users = self._make_items()
        filtered_res, filtered_usr = PAMProjectKCMImportCommand._filter_by_groups(
            resources, users, groups, resolver,
            include_pattern='NonExistent*', exclude_pattern='')
        self.assertEqual(len(filtered_res), 0)
        self.assertEqual(len(filtered_usr), 0)


class TestGetContainerIp(unittest.TestCase):
    """Tests for _get_container_ip."""

    @patch('subprocess.run')
    def test_returns_first_ip(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout='192.168.64.5 172.17.0.3 ')
        ip = PAMProjectKCMImportCommand._get_container_ip('mydb')
        self.assertEqual(ip, '192.168.64.5')

    @patch('subprocess.run')
    def test_returns_empty_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout='')
        ip = PAMProjectKCMImportCommand._get_container_ip('missing')
        self.assertEqual(ip, '')

    @patch('subprocess.run')
    def test_handles_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('docker', 10)
        ip = PAMProjectKCMImportCommand._get_container_ip('slow')
        self.assertEqual(ip, '')


if __name__ == '__main__':
    unittest.main()
