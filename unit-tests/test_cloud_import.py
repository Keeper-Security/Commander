import json
import sys
import os
from unittest import TestCase, mock
from typing import List

sys.path.insert(0, os.path.dirname(__file__))

from data_vault import get_synced_params

from keepercommander import utils as keeper_utils, vault
from keepercommander.subfolder import SharedFolderNode, SharedFolderFolderNode, BaseFolderNode
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
PERSONAL_FOLDER_UID = 'TEST_PERSONAL_FOLDER_UID'


def _make_params():
    """Return synced KeeperParams with a shared folder and a personal folder."""
    params = get_synced_params()

    shared = SharedFolderNode()
    shared.uid = FOLDER_UID
    params.folder_cache[FOLDER_UID] = shared

    # Personal (user) folder — should be rejected by _validate_folder
    from keepercommander.subfolder import UserFolderNode
    personal = UserFolderNode()
    personal.uid = PERSONAL_FOLDER_UID
    params.folder_cache[PERSONAL_FOLDER_UID] = personal

    return params


def _fake_add_record_pb(captured):
    """
    Side-effect for record_management.add_record_to_folder (pb_only path).

    Appends the record to *captured* and returns a real RecordAdd whose
    record_uid bytes match the record UID so the batch response matcher works.
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
    """Side-effect for api.communicate_rest: returns RS_SUCCESS for every record."""
    rs = record_pb2.RecordsModifyResponse()
    rs.revision = 1
    for pb_rec in rq.records:
        rec_rs = record_pb2.RecordModifyStatus()
        rec_rs.record_uid = bytes(pb_rec.record_uid)
        rec_rs.status = record_pb2.RS_SUCCESS
        rs.records.append(rec_rs)
    return rs


def _fake_records_add_empty_response(params_arg, rq, endpoint, rs_type=None):
    """Side-effect that returns an empty records list (simulates truncated response)."""
    rs = record_pb2.RecordsModifyResponse()
    rs.revision = 1
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

    def test_parse_invalid_json_falls_through_to_fallback(self):
        result = CloudImportMixin._parse_secret_string('{bad json')
        self.assertEqual(result, {'value': '{bad json'})

    def test_parse_kv_non_posix_key_falls_through_to_fallback(self):
        """A line whose key contains non-POSIX chars must not be parsed as KEY=VALUE."""
        # JWT-like single line: key contains dots and slashes
        jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123=='
        result = CloudImportMixin._parse_secret_string(jwt)
        # '=' in the JWT triggers partition but the key contains '.' → not POSIX → fallback
        self.assertEqual(result, {'value': jwt})

    def test_parse_kv_single_line_with_posix_key_still_parsed(self):
        """A single KEY=VALUE with a valid POSIX key is legitimately parsed."""
        result = CloudImportMixin._parse_secret_string('API_TOKEN=abc123')
        self.assertEqual(result, {'API_TOKEN': 'abc123'})

    def test_parse_json_null_value_becomes_empty_string(self):
        """JSON null must not become the literal string 'None'."""
        result = CloudImportMixin._parse_secret_string('{"dbname": null}')
        self.assertEqual(result['dbname'], '')

    def test_parse_json_bool_true_becomes_lowercase(self):
        """JSON true must become 'true', not Python's 'True'."""
        result = CloudImportMixin._parse_secret_string('{"enabled": true}')
        self.assertEqual(result['enabled'], 'true')

    def test_parse_json_bool_false_becomes_lowercase(self):
        result = CloudImportMixin._parse_secret_string('{"enabled": false}')
        self.assertEqual(result['enabled'], 'false')

    def test_parse_json_nested_object_becomes_json_string(self):
        """Nested dict must be json.dumps'd, not Python repr'd."""
        result = CloudImportMixin._parse_secret_string('{"config": {"host": "x", "port": 5432}}')
        import json as _json
        # Must be valid JSON, not Python repr with single quotes
        parsed = _json.loads(result['config'])
        self.assertEqual(parsed, {'host': 'x', 'port': 5432})

    def test_parse_json_array_becomes_json_string(self):
        result = CloudImportMixin._parse_secret_string('{"hosts": ["h1", "h2"]}')
        import json as _json
        self.assertEqual(_json.loads(result['hosts']), ['h1', 'h2'])

    def test_parse_json_integer_becomes_string(self):
        result = CloudImportMixin._parse_secret_string('{"port": 5432}')
        self.assertEqual(result['port'], '5432')

    # --- _build_keeper_record ---

    def test_build_record_sets_title_and_type(self):
        record = CloudImportMixin._build_keeper_record('My Secret', {}, 'login')
        self.assertEqual(record.title, 'My Secret')
        self.assertEqual(record.type_name, 'login')

    def test_build_record_maps_username_to_login_typed_field(self):
        record = CloudImportMixin._build_keeper_record('s', {'username': 'admin'}, 'login')
        self.assertIn('login', {f.type for f in record.fields})

    def test_build_record_maps_password_to_typed_field(self):
        record = CloudImportMixin._build_keeper_record('s', {'password': 'pw'}, 'login')
        self.assertIn('password', {f.type for f in record.fields})

    def test_build_record_maps_url_to_typed_field(self):
        record = CloudImportMixin._build_keeper_record('s', {'url': 'https://example.com'}, 'login')
        self.assertIn('url', {f.type for f in record.fields})

    def test_build_record_unmapped_key_uses_text_typed_field(self):
        record = CloudImportMixin._build_keeper_record('s', {'region': 'us-east-1'}, 'login')
        self.assertEqual(len(record.fields), 1)
        self.assertEqual(record.fields[0].type, 'text')
        self.assertEqual(record.fields[0].label, 'region')
        self.assertEqual(len(record.custom), 0)

    def test_build_record_note_key_goes_to_notes_property(self):
        """'note' and 'notes' must be written to record.notes, not a typed field."""
        record = CloudImportMixin._build_keeper_record('s', {'note': 'rotate weekly'}, 'login')
        self.assertEqual(record.notes, 'rotate weekly')
        self.assertEqual(len(record.fields), 0)
        self.assertEqual(len(record.custom), 0)

    def test_build_record_notes_key_goes_to_notes_property(self):
        record = CloudImportMixin._build_keeper_record('s', {'notes': 'rotate monthly'}, 'login')
        self.assertEqual(record.notes, 'rotate monthly')

    def test_build_record_first_note_wins(self):
        """Only the first note/notes field populates record.notes."""
        record = CloudImportMixin._build_keeper_record(
            's', {'note': 'first', 'notes': 'second'}, 'login')
        self.assertEqual(record.notes, 'first')

    def test_build_record_duplicate_login_goes_to_custom(self):
        """Second 'login'-typed field should be stored in custom fields."""
        fields = {'username': 'u1', 'login': 'u2'}
        record = CloudImportMixin._build_keeper_record('s', fields, 'login')
        typed_types = [f.type for f in record.fields]
        self.assertEqual(typed_types.count('login'), 1)
        self.assertEqual(len(record.custom), 1)
        self.assertEqual(record.custom[0].type, 'text')

    def test_build_record_duplicate_password_goes_to_custom(self):
        """Second 'password'-typed field should be stored in custom fields."""
        fields = {'password': 'p1', 'pass': 'p2'}
        record = CloudImportMixin._build_keeper_record('s', fields, 'login')
        typed_types = [f.type for f in record.fields]
        self.assertEqual(typed_types.count('password'), 1)
        self.assertEqual(len(record.custom), 1)

    def test_build_record_email_key_maps_to_email_typed_field(self):
        """'email' and 'mail' keys must produce a typed email field, not text."""
        record = CloudImportMixin._build_keeper_record('s', {'email': 'u@example.com'}, 'login')
        types = [f.type for f in record.fields]
        self.assertIn('email', types)
        self.assertEqual(len(record.custom), 0)

    def test_build_record_mail_key_maps_to_email_typed_field(self):
        record = CloudImportMixin._build_keeper_record('s', {'mail': 'u@example.com'}, 'login')
        self.assertIn('email', {f.type for f in record.fields})

    def test_build_record_duplicate_email_goes_to_custom(self):
        fields = {'email': 'primary@example.com', 'mail': 'alt@example.com'}
        record = CloudImportMixin._build_keeper_record('s', fields, 'login')
        self.assertEqual([f.type for f in record.fields].count('email'), 1)
        self.assertEqual(len(record.custom), 1)

    def test_build_record_mixed_fields(self):
        fields = {'username': 'admin', 'password': 'pw', 'region': 'us-east-1'}
        record = CloudImportMixin._build_keeper_record('s', fields, 'login')
        typed_types = {f.type for f in record.fields}
        self.assertIn('login', typed_types)
        self.assertIn('password', typed_types)
        self.assertIn('text', typed_types)
        self.assertEqual(len(record.custom), 0)

    # --- _parse_tag_filter ---

    def test_parse_tag_filter_single(self):
        self.assertEqual(CloudImportMixin._parse_tag_filter('Env=prod', 'cmd'),
                         [('Env', 'prod')])

    def test_parse_tag_filter_multiple(self):
        self.assertEqual(CloudImportMixin._parse_tag_filter('Env=prod,Team=ops', 'cmd'),
                         [('Env', 'prod'), ('Team', 'ops')])

    def test_parse_tag_filter_invalid_raises(self):
        with self.assertRaises(CommandError):
            CloudImportMixin._parse_tag_filter('Env', 'cmd')

    def test_parse_tag_filter_ignores_empty_tokens(self):
        self.assertEqual(CloudImportMixin._parse_tag_filter('Env=prod,', 'cmd'),
                         [('Env', 'prod')])

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
        self.assertTrue(CloudImportMixin._matches_name_filters(
            'prod/rds/pw', None, 'prod/', None, 'rds'))
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
        self.assertFalse(CloudImportMixin._matches_tag_filters({'Team': 'ops'}, [('Env', 'prod')]))

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

    def test_validate_folder_personal_folder_raises(self):
        """A personal (user) folder UID must be rejected."""
        params = _make_params()
        with self.assertRaises(CommandError):
            CloudImportMixin._validate_folder(params, PERSONAL_FOLDER_UID, 'cmd')

    def test_validate_folder_shared_uid_passes(self):
        params = _make_params()
        CloudImportMixin._validate_folder(params, FOLDER_UID, 'cmd')

    def test_validate_folder_shared_folder_folder_passes(self):
        """A SharedFolderFolderNode (sub-folder inside a shared folder) is also valid."""
        params = _make_params()
        from keepercommander.subfolder import SharedFolderFolderNode
        sff = SharedFolderFolderNode()
        sff.uid = 'SFF_UID'
        params.folder_cache['SFF_UID'] = sff
        CloudImportMixin._validate_folder(params, 'SFF_UID', 'cmd')

    # --- _run_import ---

    def test_run_import_dry_run_does_not_create_records(self):
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
            {'name': 'dev/db',  'value': 'password=pw', 'tags': {}},
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

    def test_run_import_value_fetcher_called_after_filter(self):
        """value_fetcher must only be called for secrets that pass all filters."""
        mixin = CloudImportMixin()
        params = _make_params()
        secrets = [
            {'name': 'prod/db', 'tags': {}},
            {'name': 'dev/db',  'tags': {}},
        ]
        fetched_names = []

        def _fetcher(name):
            fetched_names.append(name)
            return 'password=pw'

        captured = []
        with mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            mixin._run_import(params, secrets, FOLDER_UID, 'login',
                              None, 'prod/', None, None, [], False, 'cmd',
                              value_fetcher=_fetcher)

        self.assertEqual(fetched_names, ['prod/db'])
        self.assertEqual(len(captured), 1)

    def test_run_import_value_fetcher_not_called_on_dry_run(self):
        """value_fetcher must NOT be called during a dry run."""
        mixin = CloudImportMixin()
        params = _make_params()
        secrets = [{'name': 'sec', 'tags': {}}]
        fetch_calls = []

        with mock.patch('keepercommander.api.communicate_rest'), \
             mock.patch('builtins.print'):
            mixin._run_import(params, secrets, FOLDER_UID, 'login',
                              None, None, None, None, [], True, 'cmd',
                              value_fetcher=lambda n: fetch_calls.append(n) or 'v=1')

        self.assertEqual(fetch_calls, [])

    def test_run_import_absent_uid_in_response_counts_as_skipped(self):
        """Records missing from the server response must be counted as skipped, not created."""
        mixin = CloudImportMixin()
        params = _make_params()
        params.sync_data = False
        secrets = [{'name': 'sec', 'value': 'v=1', 'tags': {}}]

        with mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb([])), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_empty_response), \
             mock.patch('builtins.print') as print_mock:
            mixin._run_import(params, secrets, FOLDER_UID, 'login',
                              None, None, None, None, [], False, 'cmd')

        # sync_data must NOT be set — nothing was successfully created
        self.assertFalse(params.sync_data)
        printed = ' '.join(str(a) for call in print_mock.call_args_list for a in call.args)
        self.assertIn('0 record(s) created', printed)
        self.assertIn('1 skipped', printed)

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

    def test_execute_personal_folder_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder=PERSONAL_FOLDER_UID)

    def test_execute_access_key_without_secret_key_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder=FOLDER_UID, access_key='AKIA123')

    def test_execute_secret_key_without_access_key_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder=FOLDER_UID, secret_key='secret')

    # --- happy path ---

    def _run_with_mocked_aws(self, params, secret_meta, value_map=None, **extra_kwargs):
        """
        Run execute() with AWS internals mocked.

        *secret_meta* is a list of {'name', 'tags'} dicts (the normalised format
        returned by _list_secret_metadata after this refactor).
        *value_map* maps name → secret value string.
        """
        value_map = value_map or {}
        captured = []

        with mock.patch.object(self.cmd, '_list_secret_metadata', return_value=secret_meta), \
             mock.patch.object(self.cmd, '_get_secret_value',
                               side_effect=lambda name, region: value_map.get(name, '')), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, **extra_kwargs)

        return captured

    def test_execute_imports_all_secrets(self):
        params = _make_params()
        meta = [{'name': 'prod/db', 'tags': {}}, {'name': 'prod/api', 'tags': {}}]
        values = {'prod/db': '{"username": "admin", "password": "pw"}',
                  'prod/api': 'token=abc123'}
        records = self._run_with_mocked_aws(params, meta, values)
        self.assertEqual(len(records), 2)
        self.assertEqual({r.title for r in records}, {'prod/db', 'prod/api'})

    def test_execute_json_secret_fields_mapped_correctly(self):
        params = _make_params()
        meta = [{'name': 'my-cred', 'tags': {}}]
        values = {'my-cred': '{"username": "alice", "password": "s3cr3t"}'}
        records = self._run_with_mocked_aws(params, meta, values)
        self.assertEqual(len(records), 1)
        self.assertIn('login', {f.type for f in records[0].fields})
        self.assertIn('password', {f.type for f in records[0].fields})

    def test_execute_dry_run_does_not_create_records(self):
        params = _make_params()
        meta = [{'name': 'prod/db', 'tags': {}}]
        with mock.patch.object(self.cmd, '_list_secret_metadata', return_value=meta), \
             mock.patch.object(self.cmd, '_get_secret_value') as val_mock, \
             mock.patch('keepercommander.record_management.add_record_to_folder') as add_mock, \
             mock.patch('keepercommander.api.communicate_rest') as rest_mock, \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, dry_run=True)

        val_mock.assert_not_called()
        add_mock.assert_not_called()
        rest_mock.assert_not_called()

    def test_execute_name_filter(self):
        params = _make_params()
        meta = [{'name': 'prod/db', 'tags': {}}, {'name': 'dev/db', 'tags': {}}]
        values = {'prod/db': 'v=1'}
        records = self._run_with_mocked_aws(params, meta, values,
                                            filter_name_starts_with='prod/')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod/db')

    def test_execute_tag_filter_normalised_format(self):
        """Tags are now plain dicts (normalised in _list_secret_metadata)."""
        params = _make_params()
        meta = [
            {'name': 'prod/db', 'tags': {'Env': 'prod'}},
            {'name': 'dev/db',  'tags': {'Env': 'dev'}},
        ]
        values = {'prod/db': 'v=1'}
        records = self._run_with_mocked_aws(params, meta, values, filter_tags='Env=prod')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod/db')

    def test_execute_no_secrets_returns_without_error(self):
        params = _make_params()
        with mock.patch.object(self.cmd, '_list_secret_metadata', return_value=[]):
            self.cmd.execute(params, folder=FOLDER_UID)

    def test_execute_get_value_error_skips_secret(self):
        params = _make_params()
        meta = [{'name': 'good', 'tags': {}}, {'name': 'bad', 'tags': {}}]

        def _get_value(name, region):
            if name == 'bad':
                raise RuntimeError('access denied')
            return 'password=pw'

        captured = []
        with mock.patch.object(self.cmd, '_list_secret_metadata', return_value=meta), \
             mock.patch.object(self.cmd, '_get_secret_value', side_effect=_get_value), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID)

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].title, 'good')

    # --- _list_secret_metadata tag normalisation ---

    def test_list_secret_metadata_normalises_aws_tags(self):
        """AWS list-of-dicts tags must be converted to a plain dict."""
        mock_sm = mock.MagicMock()
        mock_sm.get_paginator.return_value.paginate.return_value = [{
            'SecretList': [
                {'Name': 'prod/db',
                 'Tags': [{'Key': 'Env', 'Value': 'prod'}, {'Key': 'Team', 'Value': 'ops'}]},
            ]
        }]
        self.cmd._access_key = None
        with mock.patch.object(self.cmd, 'get_client', return_value=mock_sm):
            result = self.cmd._list_secret_metadata('us-east-1')

        self.assertEqual(result, [{'name': 'prod/db', 'tags': {'Env': 'prod', 'Team': 'ops'}}])


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

    def test_execute_personal_folder_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, vault_name='my-vault', folder=PERSONAL_FOLDER_UID)

    def test_execute_partial_sp_credentials_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID,
                             tenant_id='tid', client_id=None, client_secret=None)
        with self.assertRaises(CommandError):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID,
                             tenant_id='tid', client_id='cid', client_secret=None)

    # --- happy path ---

    def _run_with_mocked_azure(self, params, secret_meta, value_map=None, **extra_kwargs):
        """
        Run execute() with Azure internals mocked.

        *secret_meta*: list of {'name', 'tags'} dicts.
        *value_map*:   name → secret value string.
        """
        value_map = value_map or {}
        mock_credential = mock.MagicMock()
        mock_client = mock.MagicMock()
        captured = []

        with mock.patch.object(self.cmd, '_get_credential', return_value=mock_credential), \
             mock.patch.object(self.cmd, '_make_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_list_secret_metadata', return_value=secret_meta), \
             mock.patch.object(self.cmd, '_get_secret_value',
                               side_effect=lambda client, name: value_map.get(name, '')), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID, **extra_kwargs)

        return captured

    def test_execute_imports_all_secrets(self):
        params = _make_params()
        meta = [{'name': 'db-password', 'tags': {}}, {'name': 'api-token', 'tags': {}}]
        values = {'db-password': '{"username": "admin", "password": "pw"}',
                  'api-token': 'token=abc123'}
        records = self._run_with_mocked_azure(params, meta, values)
        self.assertEqual(len(records), 2)
        self.assertEqual({r.title for r in records}, {'db-password', 'api-token'})

    def test_execute_dry_run_does_not_create_records(self):
        params = _make_params()
        meta = [{'name': 'db-password', 'tags': {}}]
        mock_credential = mock.MagicMock()
        mock_client = mock.MagicMock()

        with mock.patch.object(self.cmd, '_get_credential', return_value=mock_credential), \
             mock.patch.object(self.cmd, '_make_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_list_secret_metadata', return_value=meta), \
             mock.patch.object(self.cmd, '_get_secret_value') as val_mock, \
             mock.patch('keepercommander.record_management.add_record_to_folder') as add_mock, \
             mock.patch('keepercommander.api.communicate_rest') as rest_mock, \
             mock.patch('builtins.print'):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID, dry_run=True)

        val_mock.assert_not_called()
        add_mock.assert_not_called()
        rest_mock.assert_not_called()

    def test_execute_name_filter(self):
        params = _make_params()
        meta = [{'name': 'prod-db', 'tags': {}}, {'name': 'dev-db', 'tags': {}}]
        values = {'prod-db': 'v=1'}
        records = self._run_with_mocked_azure(params, meta, values,
                                              filter_name_starts_with='prod-')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod-db')

    def test_execute_tag_filter(self):
        params = _make_params()
        meta = [{'name': 'prod-secret', 'tags': {'Env': 'prod'}},
                {'name': 'dev-secret',  'tags': {'Env': 'dev'}}]
        values = {'prod-secret': 'v=1'}
        records = self._run_with_mocked_azure(params, meta, values, filter_tags='Env=prod')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod-secret')

    def test_execute_no_secrets_returns_without_error(self):
        params = _make_params()
        mock_credential = mock.MagicMock()
        mock_client = mock.MagicMock()
        with mock.patch.object(self.cmd, '_get_credential', return_value=mock_credential), \
             mock.patch.object(self.cmd, '_make_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_list_secret_metadata', return_value=[]):
            self.cmd.execute(params, vault_name='my-vault', folder=FOLDER_UID)

    def test_execute_uses_default_record_type(self):
        params = _make_params()
        records = self._run_with_mocked_azure(params, [{'name': 'sec', 'tags': {}}],
                                              {'sec': 'password=pw'})
        self.assertEqual(records[0].type_name, 'login')

    def test_execute_custom_record_type(self):
        params = _make_params()
        records = self._run_with_mocked_azure(params, [{'name': 'sec', 'tags': {}}],
                                              {'sec': 'password=pw'},
                                              record_type='serverCredentials')
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

    def test_execute_personal_folder_raises(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            self.cmd.execute(params, folder=PERSONAL_FOLDER_UID, project_id='my-project')

    # --- happy path ---

    def _run_with_mocked_gcp(self, params, secret_meta, value_map=None, **extra_kwargs):
        """
        Run execute() with GCP internals mocked.

        *secret_meta*: list of {'name', 'tags'} dicts.
        *value_map*:   name → secret value string.
        """
        value_map = value_map or {}
        mock_client = mock.MagicMock()
        captured = []

        with mock.patch.object(self.cmd, '_get_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_list_secret_metadata', return_value=secret_meta), \
             mock.patch.object(self.cmd, '_get_secret_value',
                               side_effect=lambda client, full_name: value_map.get(full_name.split('/')[-1], '')), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, project_id='my-project', **extra_kwargs)

        return captured

    def test_execute_imports_all_secrets(self):
        params = _make_params()
        meta = [{'name': 'db-password', 'tags': {}}, {'name': 'api-key', 'tags': {}}]
        values = {'db-password': '{"username": "root", "password": "pw"}',
                  'api-key': 'token=xyz789'}
        records = self._run_with_mocked_gcp(params, meta, values)
        self.assertEqual(len(records), 2)
        self.assertEqual({r.title for r in records}, {'db-password', 'api-key'})

    def test_execute_dry_run_does_not_create_records(self):
        params = _make_params()
        meta = [{'name': 'db-password', 'tags': {}}]
        mock_client = mock.MagicMock()

        with mock.patch.object(self.cmd, '_get_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_list_secret_metadata', return_value=meta), \
             mock.patch.object(self.cmd, '_get_secret_value') as val_mock, \
             mock.patch('keepercommander.record_management.add_record_to_folder') as add_mock, \
             mock.patch('keepercommander.api.communicate_rest') as rest_mock, \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, project_id='my-project', dry_run=True)

        val_mock.assert_not_called()
        add_mock.assert_not_called()
        rest_mock.assert_not_called()

    def test_execute_name_filter(self):
        params = _make_params()
        meta = [{'name': 'prod-db', 'tags': {}}, {'name': 'dev-db', 'tags': {}}]
        values = {'prod-db': 'v=1'}
        records = self._run_with_mocked_gcp(params, meta, values,
                                            filter_name_starts_with='prod-')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod-db')

    def test_execute_label_filter(self):
        params = _make_params()
        meta = [{'name': 'prod-secret', 'tags': {'env': 'prod'}},
                {'name': 'dev-secret',  'tags': {'env': 'dev'}}]
        values = {'prod-secret': 'v=1'}
        records = self._run_with_mocked_gcp(params, meta, values, filter_tags='env=prod')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, 'prod-secret')

    def test_execute_no_secrets_returns_without_error(self):
        params = _make_params()
        mock_client = mock.MagicMock()
        with mock.patch.object(self.cmd, '_get_client', return_value=mock_client), \
             mock.patch.object(self.cmd, '_list_secret_metadata', return_value=[]):
            self.cmd.execute(params, folder=FOLDER_UID, project_id='my-project')

    def test_execute_uses_default_record_type(self):
        params = _make_params()
        records = self._run_with_mocked_gcp(params, [{'name': 'sec', 'tags': {}}],
                                            {'sec': 'password=pw'})
        self.assertEqual(records[0].type_name, 'login')

    def test_execute_custom_record_type(self):
        params = _make_params()
        records = self._run_with_mocked_gcp(params, [{'name': 'sec', 'tags': {}}],
                                            {'sec': 'password=pw'},
                                            record_type='serverCredentials')
        self.assertEqual(records[0].type_name, 'serverCredentials')

    def test_execute_sets_sync_data_after_import(self):
        params = _make_params()
        params.sync_data = False
        self._run_with_mocked_gcp(params, [{'name': 'sec', 'tags': {}}], {'sec': 'pw=x'})
        self.assertTrue(params.sync_data)

    def test_get_secret_value_binary_raises_command_error(self):
        """Binary (non-UTF-8) payloads must raise CommandError, not propagate UnicodeDecodeError."""
        import sys
        import types

        # google-cloud-secret-manager is an optional extra and may not be installed
        # in the test environment.  Provide a minimal mock so the import inside
        # _get_secret_value succeeds without the real package.
        mock_exc_module = types.ModuleType('google.api_core.exceptions')
        mock_exc_module.NotFound = type('NotFound', (Exception,), {})
        mock_exc_module.PermissionDenied = type('PermissionDenied', (Exception,), {})

        mock_client = mock.MagicMock()
        binary_payload = b'\x30\x82\x03\x01\x00\x01'   # DER-encoded bytes
        mock_version = mock.MagicMock()
        mock_version.payload.data = binary_payload
        mock_client.access_secret_version.return_value = mock_version

        with mock.patch.dict(sys.modules, {'google.api_core.exceptions': mock_exc_module}), \
             self.assertRaises(CommandError) as ctx:
            self.cmd._get_secret_value(mock_client, 'projects/p/secrets/tls-cert')

        self.assertIn('binary data', str(ctx.exception).lower())
        self.assertIn('tls-cert', str(ctx.exception))

    def test_get_secret_value_binary_skipped_gracefully_in_run_import(self):
        """
        A binary secret raises CommandError from _get_secret_value; execute()
        must count it as skipped while still importing text secrets.

        _get_secret_value is mocked directly here — the binary-detection logic
        is already covered by test_get_secret_value_binary_raises_command_error.
        This test focuses on the execute() / _run_import integration.
        """
        params = _make_params()

        def _get_value(client, full_name):
            if 'tls-cert' in full_name:
                raise CommandError('gcp-secrets-import',
                                   '"tls-cert" contains binary data which is not supported.')
            return 'password=s3cr3t'

        meta = [{'name': 'my-db', 'tags': {}}, {'name': 'tls-cert', 'tags': {}}]
        captured = []

        with mock.patch.object(self.cmd, '_get_client', return_value=mock.MagicMock()), \
             mock.patch.object(self.cmd, '_list_secret_metadata', return_value=meta), \
             mock.patch.object(self.cmd, '_get_secret_value', side_effect=_get_value), \
             mock.patch('keepercommander.record_management.add_record_to_folder',
                        side_effect=_fake_add_record_pb(captured)), \
             mock.patch('keepercommander.api.communicate_rest',
                        side_effect=_fake_records_add_success), \
             mock.patch('builtins.print'):
            self.cmd.execute(params, folder=FOLDER_UID, project_id='my-project')

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].title, 'my-db')
