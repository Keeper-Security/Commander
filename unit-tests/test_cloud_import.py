import json
import sys
import os
from unittest import TestCase, mock
from typing import List

sys.path.insert(0, os.path.dirname(__file__))

from data_vault import get_synced_params

from keepercommander import utils as keeper_utils, vault
from keepercommander.subfolder import SharedFolderNode, BaseFolderNode
from keepercommander.error import CommandError
from keepercommander.proto import record_pb2
from keepercommander.commands._cloud_import_base import CloudImportMixin
from keepercommander.commands.aws_import import AwsSecretsImportCommand
from keepercommander.commands.azure_import import AzureSecretsImportCommand
from keepercommander.commands.gcp_import import GcpSecretsImportCommand

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FOLDER_UID = 'TEST_SHARED_FOLDER_UID'


def _make_params():
    """Return synced KeeperParams with a shared folder in the cache."""
    params = get_synced_params()
    folder = SharedFolderNode()
    folder.uid = FOLDER_UID
    params.folder_cache[FOLDER_UID] = folder
    return params


def _fake_add_record_pb(captured):
    """
    Side-effect for record_management.add_record_to_folder that supports the
    pb_only=True batch path.

    - Always appends the record to *captured* so tests can assert on it.
    - When pb_only=True, returns a real record_pb2.RecordAdd whose record_uid
      bytes match the record's UID string so the batch-response matcher works.
    """
    def _side_effect(params, record, folder_uid, pb_only=False):
        if not record.record_uid:
            record.record_uid = keeper_utils.generate_uid()
        captured.append(record)
        if pb_only:
            pb = record_pb2.RecordAdd()
            pb.record_uid = keeper_utils.base64_url_decode(record.record_uid)
            return pb
    return _side_effect


def _fake_records_add_success(params_arg, rq, endpoint, rs_type=None):
    """
    Side-effect for api.communicate_rest that returns a successful
    RecordsModifyResponse for every record in the request.
    """
    rs = record_pb2.RecordsModifyResponse()
    rs.revision = 1
    for pb_rec in rq.records:
        rec_rs = record_pb2.RecordModifyStatus()
        rec_rs.record_uid = bytes(pb_rec.record_uid)
        rec_rs.status = record_pb2.RS_SUCCESS
        rs.records.append(rec_rs)
    return rs


# ---------------------------------------------------------------------------
# Shared base-class logic (CloudImportMixin)
# ---------------------------------------------------------------------------

class TestCloudImportBase(TestCase):
    """Tests for the shared parsing/filtering/building helpers in CloudImportMixin."""

    # --- _parse_secret_string ---

    def test_parse_json_object(self):
        result = CloudImportMixin._parse_secret_string('{"username": "admin", "password": "s3cr3t"}')
        self.assertEqual(result, {'username': 'admin', 'password': 's3cr3t'})

    def test_parse_kv_lines(self):
        result = CloudImportMixin._parse_secret_string('username=admin\npassword=s3cr3t')
        self.assertEqual(result, {'username': 'admin', 'password': 's3cr3t'})

    def test_parse_kv_lines_ignores_comments_and_blanks(self):
        raw = '# comment\n\nusername=admin\npassword=s3cr3t\n'
        result = CloudImportMixin._parse_secret_string(raw)
        self.assertEqual(result, {'username': 'admin', 'password': 's3cr3t'})

    def test_parse_kv_value_may_contain_equals(self):
        result = CloudImportMixin._parse_secret_string('token=abc=def=ghi')
        self.assertEqual(result, {'token': 'abc=def=ghi'})

    def test_parse_plain_string_fallback(self):
        result = CloudImportMixin._parse_secret_string('just-a-plain-secret')
        self.assertEqual(result, {'value': 'just-a-plain-secret'})

    def test_parse_empty_string_returns_empty_dict(self):
        self.assertEqual(CloudImportMixin._parse_secret_string(''), {})
        self.assertEqual(CloudImportMixin._parse_secret_string(None), {})

    def test_parse_invalid_json_falls_through_to_kv(self):
        # Looks like JSON but is malformed → falls through to KEY=VALUE
        result = CloudImportMixin._parse_secret_string('{bad json')
        self.assertEqual(result, {'value': '{bad json'})

    # --- _build_keeper_record ---

    def test_build_record_sets_title_and_type(self):
        record = CloudImportMixin._build_keeper_record('My Secret', {}, 'login')
        self.assertEqual(record.title, 'My Secret')
        self.assertEqual(record.type_name, 'login')

    def test_build_record_maps_username_to_login_typed_field(self):
        record = CloudImportMixin._build_keeper_record('s', {'username': 'admin'}, 'login')
        types = [f.type for f in record.fields]
        self.assertIn('login', types)
        self.assertEqual(len(record.custom), 0)

    def test_build_record_maps_password_to_typed_field(self):
        record = CloudImportMixin._build_keeper_record('s', {'password': 'pw'}, 'login')
        types = [f.type for f in record.fields]
        self.assertIn('password', types)

    def test_build_record_maps_url_to_typed_field(self):
        record = CloudImportMixin._build_keeper_record('s', {'url': 'https://example.com'}, 'login')
        types = [f.type for f in record.fields]
        self.assertIn('url', types)

    def test_build_record_unmapped_key_uses_text_typed_field(self):
        # Keys with no special mapping fall back to keeper_type='text',
        # which is in KNOWN_TYPED_FIELDS, so they land in record.fields not custom.
        record = CloudImportMixin._build_keeper_record('s', {'region': 'us-east-1'}, 'login')
        self.assertEqual(len(record.fields), 1)
        self.assertEqual(record.fields[0].type, 'text')
        self.assertEqual(record.fields[0].label, 'region')
        self.assertEqual(len(record.custom), 0)

    def test_build_record_mixed_fields(self):
        # All three fields land in record.fields: login and password by explicit mapping,
        # region by the default 'text' fallback (which is in KNOWN_TYPED_FIELDS).
        fields = {'username': 'admin', 'password': 'pw', 'region': 'us-east-1'}
        record = CloudImportMixin._build_keeper_record('s', fields, 'login')
        typed_types = {f.type for f in record.fields}
        self.assertIn('login', typed_types)
        self.assertIn('password', typed_types)
        self.assertIn('text', typed_types)
        self.assertEqual(len(record.custom), 0)

    # --- _parse_tag_filter ---

    def test_parse_tag_filter_single(self):
        result = CloudImportMixin._parse_tag_filter('Env=prod', 'cmd')
        self.assertEqual(result, [('Env', 'prod')])

    def test_parse_tag_filter_multiple(self):
        result = CloudImportMixin._parse_tag_filter('Env=prod,Team=ops', 'cmd')
        self.assertEqual(result, [('Env', 'prod'), ('Team', 'ops')])

    def test_parse_tag_filter_invalid_raises(self):
        with self.assertRaises(CommandError):
            CloudImportMixin._parse_tag_filter('Env', 'cmd')

    def test_parse_tag_filter_ignores_empty_tokens(self):
        result = CloudImportMixin._parse_tag_filter('Env=prod,', 'cmd')
        self.assertEqual(result, [('Env', 'prod')])

    # --- _matches_name_filters ---

    def test_name_filter_exact_match(self):
        self.assertTrue(CloudImportMixin._matches_name_filters('prod/db', 'prod/db', None, None, None))
        self.assertFalse(CloudImportMixin._matches_name_filters('prod/db', 'prod/other', None, None, None))

    def test_name_filter_starts_with(self):
        self.assertTrue(CloudImportMixin._matches_name_filters('prod/db', None, 'prod/', None, None))
        self.assertFalse(CloudImportMixin._matches_name_filters('dev/db', None, 'prod/', None, None))

    def test_name_filter_ends_with(self):
        self.assertTrue(CloudImportMixin._matches_name_filters('prod/db/creds', None, None, '/creds', None))
        self.assertFalse(CloudImportMixin._matches_name_filters('prod/db/config', None, None, '/creds', None))

    def test_name_filter_contains(self):
        self.assertTrue(CloudImportMixin._matches_name_filters('prod/rds/creds', None, None, None, 'rds'))
        self.assertFalse(CloudImportMixin._matches_name_filters('prod/mysql/creds', None, None, None, 'rds'))

    def test_name_filter_no_filters_always_passes(self):
        self.assertTrue(CloudImportMixin._matches_name_filters('anything', None, None, None, None))

    def test_name_filter_combined_all_must_pass(self):
        # starts with prod/ AND contains rds → pass
        self.assertTrue(CloudImportMixin._matches_name_filters(
            'prod/rds/pw', None, 'prod/', None, 'rds'))
        # starts with prod/ but doesn't contain rds → fail
        self.assertFalse(CloudImportMixin._matches_name_filters(
            'prod/mysql/pw', None, 'prod/', None, 'rds'))

    # --- _matches_tag_filters ---

    def test_tag_filter_all_match(self):
        tags = {'Env': 'prod', 'Team': 'ops'}
        self.assertTrue(CloudImportMixin._matches_tag_filters(tags, [('Env', 'prod'), ('Team', 'ops')]))

    def test_tag_filter_one_mismatch(self):
        tags = {'Env': 'staging', 'Team': 'ops'}
        self.assertFalse(CloudImportMixin._matches_tag_filters(tags, [('Env', 'prod'), ('Team', 'ops')]))

    def test_tag_filter_missing_key(self):
        tags = {'Team': 'ops'}
        self.assertFalse(CloudImportMixin._matches_tag_filters(tags, [('Env', 'prod')]))

    def test_tag_filter_empty_required_always_passes(self):
        self.assertTrue(CloudImportMixin._matches_tag_filters({}, []))

    # --- _validate_folder ---

    def test_validate_folder_empty_uid_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            CloudImportMixin._validate_folder(params, '', 'cmd')

    def test_validate_folder_unknown_uid_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            CloudImportMixin._validate_folder(params, 'NONEXISTENT_UID', 'cmd')

    def test_validate_folder_known_uid_passes(self):
        params = _make_params()
        CloudImportMixin._validate_folder(params, FOLDER_UID, 'cmd')

    # --- _run_import ---

    def test_run_import_dry_run_does_not_create_records(self):
        """In dry-run mode _run_import should print but not call add_record_to_folder."""
        mixin = CloudImportMixin()
        params = _make_params()
        secrets = [{'name': 'my-secret', 'value': 'pw=s3cr3t', 'tags': {}}]

        with mock.patch('keepercommander.record_management.add_record_to_folder') as add_mock, \
                mock.patch('keepercommander.api.communicate_rest') as rest_mock, \
                mock.patch('builtins.print') as print_mock:
            mixin._run_import(params, secrets, FOLDER_UID, 'login',
                              None, None, None, None, [], True, 'cmd')

        add_mock.assert_not_called()
        rest_mock.assert_not_called()
        printed = ' '.join(str(a) for call in print_mock.call_args_list for a in call.args)
        self.assertIn('my-secret', printed)

    def test_run_import_creates_records(self):
        mixin = CloudImportMixin()
        params = _make_params()
        secrets = [
            {'name': 'secret-a', 'value': '{"username": "alice"}', 'tags': {}},
            {'name': 'secret-b', 'value': 'password=hunter2', 'tags': {}},
        ]
        captured = []

        with mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            mixin._run_import(params, secrets, FOLDER_UID, 'login',
                              None, None, None, None, [], False, 'cmd')

        self.assertEqual(len(captured), 2)
        self.assertEqual(captured[0].title, 'secret-a')
        self.assertEqual(captured[1].title, 'secret-b')

    def test_run_import_name_filter_applied(self):
        mixin = CloudImportMixin()
        params = _make_params()
        secrets = [
            {'name': 'prod/db', 'value': 'password=pw', 'tags': {}},
            {'name': 'dev/db', 'value': 'password=pw', 'tags': {}},
        ]
        captured = []

        with mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            mixin._run_import(params, secrets, FOLDER_UID, 'login',
                              None, 'prod/', None, None, [], False, 'cmd')

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].title, 'prod/db')

    def test_run_import_tag_filter_applied(self):
        mixin = CloudImportMixin()
        params = _make_params()
        secrets = [
            {'name': 'secret-a', 'value': 'v=1', 'tags': {'Env': 'prod'}},
            {'name': 'secret-b', 'value': 'v=2', 'tags': {'Env': 'staging'}},
        ]
        captured = []

        with mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            mixin._run_import(params, secrets, FOLDER_UID, 'login',
                              None, None, None, None, [('Env', 'prod')], False, 'cmd')

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].title, 'secret-a')

    def test_run_import_sets_sync_data_when_records_created(self):
        mixin = CloudImportMixin()
        params = _make_params()
        params.sync_data = False
        secrets = [{'name': 'sec', 'value': 'v=1', 'tags': {}}]

        with mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb([])), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            mixin._run_import(params, secrets, FOLDER_UID, 'login',
                              None, None, None, None, [], False, 'cmd')

        self.assertTrue(params.sync_data)


# ---------------------------------------------------------------------------
# AWS Secrets Manager
# ---------------------------------------------------------------------------

class TestAwsSecretsImport(TestCase):

    def setUp(self):
        self.cmd = AwsSecretsImportCommand()

    def tearDown(self):
        mock.patch.stopall()

    # --- argument / folder validation ---

    def test_execute_missing_folder_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder='')

    def test_execute_unknown_folder_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder='NONEXISTENT')

    def test_execute_access_key_without_secret_key_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder=FOLDER_UID, access_key='AKIA123')

    def test_execute_secret_key_without_access_key_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder=FOLDER_UID, secret_key='secret')

    # --- happy path ---

    def _run_with_mocked_aws(self, params, aws_secrets, **extra_kwargs):
        """Helper: run execute() with _list_secrets and _get_secret_value mocked."""
        secret_values = {s['Name']: s.get('_value', '') for s in aws_secrets}
        captured = []

        with mock.patch.object(self.cmd, '_list_secrets', return_value=aws_secrets), \
             mock.patch.object(self.cmd, '_get_secret_value',
                               side_effect=lambda name, region: secret_values.get(name, '')), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, **extra_kwargs)

        return captured

    def test_execute_imports_all_secrets(self):
        params = _make_params()
        aws_secrets = [
            {'Name': 'prod/db', 'Tags': [], '_value': '{"username": "admin", "password": "pw"}'},
            {'Name': 'prod/api', 'Tags': [], '_value': 'token=abc123'},
        ]
        records = self._run_with_mocked_aws(params, aws_secrets)
        self.assertEqual(len(records), 2)
        titles = {r.title for r in records}
        self.assertIn('prod/db', titles)
        self.assertIn('prod/api', titles)

    def test_execute_json_secret_fields_mapped_correctly(self):
        params = _make_params()
        aws_secrets = [{'Name': 'my-cred', 'Tags': [],
                        '_value': '{"username": "alice", "password": "s3cr3t"}'}]
        records = self._run_with_mocked_aws(params, aws_secrets)
        self.assertEqual(len(records), 1)
        rec = records[0]
        field_types = {f.type for f in rec.fields}
        self.assertIn('login', field_types)
        self.assertIn('password', field_types)

    def test_execute_dry_run_does_not_create_records(self):
        params = _make_params()
        aws_secrets = [{'Name': 'prod/db', 'Tags': [], '_value': 'pw=secret'}]

        with mock.patch.object(self.cmd, '_list_secrets', return_value=aws_secrets), \
             mock.patch.object(self.cmd, '_get_secret_value', return_value=''), \
             mock.patch('keepercommander.record_management.add_record_to_folder') as add_mock, \
             mock.patch('keepercommander.api.communicate_rest') as rest_mock, \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, dry_run=True)

        add_mock.assert_not_called()
        rest_mock.assert_not_called()

    def test_execute_name_filter(self):
        params = _make_params()
        aws_secrets = [
            {'Name': 'prod/db', 'Tags': [], '_value': 'v=1'},
            {'Name': 'dev/db', 'Tags': [], '_value': 'v=2'},
        ]
        records = self._run_with_mocked_aws(params, aws_secrets,
                                            filter_name_starts_with='prod/')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod/db')

    def test_execute_tag_filter_aws_format(self):
        """AWS tags are a list of {Key, Value} dicts."""
        params = _make_params()
        aws_secrets = [
            {'Name': 'prod/db', 'Tags': [{'Key': 'Env', 'Value': 'prod'}], '_value': 'v=1'},
            {'Name': 'dev/db',  'Tags': [{'Key': 'Env', 'Value': 'dev'}],  '_value': 'v=2'},
        ]
        records = self._run_with_mocked_aws(params, aws_secrets, filter_tags='Env=prod')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod/db')

    def test_execute_no_secrets_returns_without_error(self):
        params = _make_params()
        with mock.patch.object(self.cmd, '_list_secrets', return_value=[]):
            self.cmd.execute(params, folder=FOLDER_UID)

    def test_execute_get_value_error_skips_secret(self):
        """A secret that raises during value fetch should be skipped, not abort."""
        params = _make_params()
        aws_secrets = [
            {'Name': 'good/secret', 'Tags': [], '_value': 'password=pw'},
            {'Name': 'bad/secret', 'Tags': []},
        ]

        def _get_value(name, region):
            if name == 'bad/secret':
                raise RuntimeError('access denied')
            return 'password=pw'

        captured = []
        with mock.patch.object(self.cmd, '_list_secrets', return_value=aws_secrets), \
             mock.patch.object(self.cmd, '_get_secret_value', side_effect=_get_value), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID)

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].title, 'good/secret')

    # --- _parse_tags (AWS-specific method) ---

    def test_parse_tags_single(self):
        result = self.cmd._parse_tags('Env=prod')
        self.assertEqual(result, [('Env', 'prod')])

    def test_parse_tags_multiple(self):
        result = self.cmd._parse_tags('Env=prod,Team=ops')
        self.assertEqual(result, [('Env', 'prod'), ('Team', 'ops')])

    def test_parse_tags_invalid_raises(self):
        with self.assertRaises(CommandError):
            self.cmd._parse_tags('NotAKeyValuePair')

    # --- _matches_filters (AWS list-of-dicts tag format) ---

    def test_matches_filters_tag_match(self):
        meta = {'Name': 'prod/db', 'Tags': [{'Key': 'Env', 'Value': 'prod'}]}
        self.assertTrue(self.cmd._matches_filters(meta, None, None, None, None, [('Env', 'prod')]))

    def test_matches_filters_tag_mismatch(self):
        meta = {'Name': 'dev/db', 'Tags': [{'Key': 'Env', 'Value': 'dev'}]}
        self.assertFalse(self.cmd._matches_filters(meta, None, None, None, None, [('Env', 'prod')]))

    def test_matches_filters_no_tags_on_secret(self):
        meta = {'Name': 'prod/db', 'Tags': []}
        self.assertFalse(self.cmd._matches_filters(meta, None, None, None, None, [('Env', 'prod')]))


# ---------------------------------------------------------------------------
# Azure Key Vault
# ---------------------------------------------------------------------------

class TestAzureSecretsImport(TestCase):

    def setUp(self):
        self.cmd = AzureSecretsImportCommand()

    def tearDown(self):
        mock.patch.stopall()

    # --- argument / folder validation ---

    def test_execute_missing_vault_name_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, vault_name='', folder=FOLDER_UID)

    def test_execute_unknown_folder_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, vault_name='my-vault', folder='NONEXISTENT')

    def test_execute_partial_sp_credentials_raises(self):
        """Providing only some service-principal flags should raise."""
        params = _make_params()
        # tenant only
        with self.assertRaises(CommandError):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID,
                             tenant_id='tid', client_id=None, client_secret=None)
        # tenant + client_id, missing secret
        with self.assertRaises(CommandError):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID,
                             tenant_id='tid', client_id='cid', client_secret=None)

    # --- happy path ---

    def _run_with_mocked_azure(self, params, secrets, **extra_kwargs):
        """Helper: run execute() with _fetch_secrets and _get_credential mocked."""
        mock_credential = mock.MagicMock()
        captured = []

        with mock.patch.object(self.cmd, '_get_credential', return_value=mock_credential), \
             mock.patch.object(self.cmd, '_fetch_secrets', return_value=secrets), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID, **extra_kwargs)

        return captured

    def test_execute_imports_all_secrets(self):
        params = _make_params()
        secrets = [
            {'name': 'db-password', 'value': '{"username": "admin", "password": "pw"}', 'tags': {}},
            {'name': 'api-token',   'value': 'token=abc123', 'tags': {}},
        ]
        records = self._run_with_mocked_azure(params, secrets)
        self.assertEqual(len(records), 2)
        titles = {r.title for r in records}
        self.assertIn('db-password', titles)
        self.assertIn('api-token', titles)

    def test_execute_dry_run_does_not_create_records(self):
        params = _make_params()
        secrets = [{'name': 'db-password', 'value': 'pw=s3cr3t', 'tags': {}}]
        mock_credential = mock.MagicMock()

        with mock.patch.object(self.cmd, '_get_credential', return_value=mock_credential), \
             mock.patch.object(self.cmd, '_fetch_secrets', return_value=secrets), \
             mock.patch('keepercommander.record_management.add_record_to_folder') as add_mock, \
             mock.patch('keepercommander.api.communicate_rest') as rest_mock, \
             mock.patch('builtins.print'):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID, dry_run=True)

        add_mock.assert_not_called()
        rest_mock.assert_not_called()

    def test_execute_name_filter(self):
        params = _make_params()
        secrets = [
            {'name': 'prod-db', 'value': 'v=1', 'tags': {}},
            {'name': 'dev-db',  'value': 'v=2', 'tags': {}},
        ]
        records = self._run_with_mocked_azure(params, secrets,
                                              filter_name_starts_with='prod-')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod-db')

    def test_execute_tag_filter_azure_format(self):
        """Azure tags are a plain dict (already converted in _fetch_secrets)."""
        params = _make_params()
        secrets = [
            {'name': 'prod-secret', 'value': 'v=1', 'tags': {'Env': 'prod'}},
            {'name': 'dev-secret',  'value': 'v=2', 'tags': {'Env': 'dev'}},
        ]
        records = self._run_with_mocked_azure(params, secrets, filter_tags='Env=prod')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod-secret')

    def test_execute_no_secrets_returns_without_error(self):
        params = _make_params()
        mock_credential = mock.MagicMock()
        with mock.patch.object(self.cmd, '_get_credential', return_value=mock_credential), \
             mock.patch.object(self.cmd, '_fetch_secrets', return_value=[]):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID)

    def test_execute_uses_default_record_type(self):
        params = _make_params()
        secrets = [{'name': 'sec', 'value': 'password=pw', 'tags': {}}]
        records = self._run_with_mocked_azure(params, secrets)
        self.assertEqual(records[0].type_name, 'login')

    def test_execute_custom_record_type(self):
        params = _make_params()
        secrets = [{'name': 'sec', 'value': 'password=pw', 'tags': {}}]
        records = self._run_with_mocked_azure(params, secrets, record_type='serverCredentials')
        self.assertEqual(records[0].type_name, 'serverCredentials')


# ---------------------------------------------------------------------------
# GCP Secret Manager
# ---------------------------------------------------------------------------

class TestGcpSecretsImport(TestCase):

    def setUp(self):
        self.cmd = GcpSecretsImportCommand()

    def tearDown(self):
        mock.patch.stopall()

    # --- argument / folder validation ---

    def test_execute_missing_project_id_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder=FOLDER_UID, project_id='')

    def test_execute_unknown_folder_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder='NONEXISTENT', project_id='my-project')

    # --- happy path ---

    def _run_with_mocked_gcp(self, params, secrets, **extra_kwargs):
        """Helper: run execute() with _get_client and _fetch_secrets mocked."""
        mock_client = mock.MagicMock()
        captured = []

        with mock.patch.object(self.cmd, '_get_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_fetch_secrets', return_value=secrets), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, project_id='my-project', **extra_kwargs)

        return captured

    def test_execute_imports_all_secrets(self):
        params = _make_params()
        secrets = [
            {'name': 'db-password', 'value': '{"username": "root", "password": "pw"}', 'tags': {}},
            {'name': 'api-key',     'value': 'token=xyz789', 'tags': {}},
        ]
        records = self._run_with_mocked_gcp(params, secrets)
        self.assertEqual(len(records), 2)
        titles = {r.title for r in records}
        self.assertIn('db-password', titles)
        self.assertIn('api-key', titles)

    def test_execute_dry_run_does_not_create_records(self):
        params = _make_params()
        secrets = [{'name': 'db-password', 'value': 'pw=s3cr3t', 'tags': {}}]
        mock_client = mock.MagicMock()

        with mock.patch.object(self.cmd, '_get_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_fetch_secrets', return_value=secrets), \
             mock.patch('keepercommander.record_management.add_record_to_folder') as add_mock, \
             mock.patch('keepercommander.api.communicate_rest') as rest_mock, \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, project_id='my-project', dry_run=True)

        add_mock.assert_not_called()
        rest_mock.assert_not_called()

    def test_execute_name_filter(self):
        params = _make_params()
        secrets = [
            {'name': 'prod-db', 'value': 'v=1', 'tags': {}},
            {'name': 'dev-db',  'value': 'v=2', 'tags': {}},
        ]
        records = self._run_with_mocked_gcp(params, secrets,
                                            filter_name_starts_with='prod-')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod-db')

    def test_execute_label_filter_gcp_format(self):
        """GCP labels are already a plain dict (normalised in _fetch_secrets)."""
        params = _make_params()
        secrets = [
            {'name': 'prod-secret', 'value': 'v=1', 'tags': {'env': 'prod'}},
            {'name': 'dev-secret',  'value': 'v=2', 'tags': {'env': 'dev'}},
        ]
        records = self._run_with_mocked_gcp(params, secrets, filter_tags='env=prod')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod-secret')

    def test_execute_no_secrets_returns_without_error(self):
        params = _make_params()
        mock_client = mock.MagicMock()
        with mock.patch.object(self.cmd, '_get_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_fetch_secrets', return_value=[]):
            self.cmd.execute(params, folder=FOLDER_UID, project_id='my-project')

    def test_execute_uses_default_record_type(self):
        params = _make_params()
        secrets = [{'name': 'sec', 'value': 'password=pw', 'tags': {}}]
        records = self._run_with_mocked_gcp(params, secrets)
        self.assertEqual(records[0].type_name, 'login')

    def test_execute_custom_record_type(self):
        params = _make_params()
        secrets = [{'name': 'sec', 'value': 'password=pw', 'tags': {}}]
        records = self._run_with_mocked_gcp(params, secrets, record_type='serverCredentials')
        self.assertEqual(records[0].type_name, 'serverCredentials')

    def test_execute_sets_sync_data_after_import(self):
        params = _make_params()
        params.sync_data = False
        secrets = [{'name': 'sec', 'value': 'password=pw', 'tags': {}}]
        self._run_with_mocked_gcp(params, secrets)   # already mocks communicate_rest
        self.assertTrue(params.sync_data)
