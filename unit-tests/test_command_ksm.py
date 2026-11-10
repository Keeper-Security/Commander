"""Unit tests for secrets-manager (KSM) CLI commands."""
import datetime
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.ksm import KSMCommand, KSM_EVENT_TYPES, KSM_USAGE_EVENT_TYPE


class TestKSMSecretResolution(unittest.TestCase):

    def _make_params(self):
        params = MagicMock()
        params.record_cache = {}
        params.shared_folder_cache = {}
        params.nested_share_records = {}
        params.nested_share_folders = {}
        params.nested_share_record_data = {}
        params.folder_cache = {}
        return params

    def test_resolve_secret_uid_from_nsf_record_cache(self):
        params = self._make_params()
        record_uid = 'OYNvVgpPPJBrVfYOIRtdag'
        params.nested_share_records = {record_uid: {'record_key_unencrypted': b'key'}}
        self.assertEqual(KSMCommand.resolve_secret_uid(params, record_uid), record_uid)

    def test_resolve_secret_uid_from_nsf_folder_cache(self):
        params = self._make_params()
        folder_uid = 'bU2LVM6LjX_hmCoSMDA7vg'
        params.nested_share_folders = {folder_uid: {'name': 'Project Folder'}}
        with patch('keepercommander.commands.ksm.is_nested_share_folder', return_value=True):
            self.assertEqual(KSMCommand.resolve_secret_uid(params, folder_uid), folder_uid)

    @patch('keepercommander.commands.ksm.resolve_nested_share_record_uid')
    def test_resolve_secret_uid_by_record_title(self, mock_resolve_record):
        params = self._make_params()
        mock_resolve_record.return_value = 'resolved_record_uid'
        self.assertEqual(KSMCommand.resolve_secret_uid(params, 'My Record'), 'resolved_record_uid')

    @patch('keepercommander.commands.ksm.resolve_folder_uid')
    @patch('keepercommander.commands.ksm.resolve_nested_share_record_uid', return_value=None)
    def test_resolve_secret_uid_by_folder_path(self, _mock_resolve_record, mock_resolve_folder):
        params = self._make_params()
        mock_resolve_folder.return_value = 'resolved_folder_uid'
        with patch('keepercommander.commands.ksm.is_nested_share_folder',
                   side_effect=lambda _params, uid: uid == 'resolved_folder_uid'):
            with patch('keepercommander.commands.ksm.api.is_shared_folder', return_value=False):
                self.assertEqual(KSMCommand.resolve_secret_uid(params, 'NSF/Folder'), 'resolved_folder_uid')

    def test_classify_secret_nsf_record(self):
        params = self._make_params()
        record_uid = 'OYNvVgpPPJBrVfYOIRtdag'
        params.nested_share_records = {record_uid: {'record_key_unencrypted': b'record_key'}}
        with patch('keepercommander.commands.ksm.is_nested_share_record', return_value=True):
            secret = KSMCommand.classify_secret(params, record_uid)
        self.assertIsNotNone(secret)
        self.assertEqual(secret['share_type'], 'SHARE_TYPE_RECORD')
        self.assertEqual(secret['share_key'], b'record_key')

    def test_classify_secret_nsf_folder(self):
        params = self._make_params()
        folder_uid = 'bU2LVM6LjX_hmCoSMDA7vg'
        with patch('keepercommander.commands.ksm.is_nested_share_folder', return_value=True):
            with patch('keepercommander.commands.ksm.api.is_shared_folder', return_value=False):
                with patch('keepercommander.commands.ksm.get_folder_key', return_value=b'folder_key'):
                    secret = KSMCommand.classify_secret(params, folder_uid)
        self.assertIsNotNone(secret)
        self.assertEqual(secret['share_type'], 'SHARE_TYPE_FOLDER')
        self.assertEqual(secret['share_key'], b'folder_key')

    @patch('keepercommander.commands.ksm.KSMCommand.update_secrets_user_permissions')
    @patch('keepercommander.commands.ksm.api.sync_down')
    @patch('keepercommander.nested_share_folder.record_api.share_record_to_application_v3',
           return_value={'success': True, 'results': []})
    @patch('keepercommander.commands.ksm.KSMCommand.get_app_record')
    def test_share_secret_adds_nsf_record(self, mock_get_app_record, mock_share_record,
                                          _mock_sync_down, _mock_update_perms):
        params = self._make_params()
        record_uid = 'OYNvVgpPPJBrVfYOIRtdag'
        params.nested_share_records = {record_uid: {'record_key_unencrypted': b'record_key'}}
        mock_get_app_record.return_value = {
            'record_uid': 'app_uid___________',
            'record_key_unencrypted': b'a' * 32,
        }
        with patch('keepercommander.commands.ksm.is_nested_share_record', return_value=True):
            with patch('keepercommander.commands.ksm.is_nested_share_folder', return_value=False):
                KSMCommand.add_app_share(params, [record_uid], 'MyApp', False)
        mock_share_record.assert_called_once()
        self.assertEqual(mock_share_record.call_args.args[1], record_uid)

    @patch('keepercommander.commands.ksm.KSMCommand.update_secrets_user_permissions')
    @patch('keepercommander.commands.ksm.api.sync_down')
    @patch('keepercommander.nested_share_folder.folder_api.grant_folder_access_to_application_v3',
           return_value={'success': True})
    @patch('keepercommander.commands.ksm.KSMCommand.get_app_record')
    def test_share_secret_adds_nsf_folder(self, mock_get_app_record, mock_grant_folder,
                                          _mock_sync_down, _mock_update_perms):
        params = self._make_params()
        folder_uid = 'AF3KOMHTcC7ZVwOLrz1ODA'
        params.nested_share_folders = {folder_uid: {'name': 'Test NSF'}}
        mock_get_app_record.return_value = {
            'record_uid': 'il3OLH0CurRQezXUJ6WB9Q',
            'record_key_unencrypted': b'a' * 32,
        }
        with patch('keepercommander.commands.ksm.is_nested_share_folder', return_value=True):
            with patch('keepercommander.commands.ksm.is_nested_share_record', return_value=False):
                with patch('keepercommander.commands.ksm.api.is_shared_folder', return_value=False):
                    with patch('keepercommander.commands.ksm.get_folder_key', return_value=b'folder_key'):
                        KSMCommand.add_app_share(params, [folder_uid], 'MyApp', True)
        mock_grant_folder.assert_called_once()
        self.assertEqual(mock_grant_folder.call_args.args[1], folder_uid)
        self.assertTrue(mock_grant_folder.call_args.kwargs.get('is_editable'))

    def test_resolve_secret_uid_strips_brackets(self):
        params = self._make_params()
        folder_uid = 'AF3KOMHTcC7ZVwOLrz1ODA'
        params.nested_share_folders = {folder_uid: {'name': 'Test NSF'}}
        with patch('keepercommander.commands.ksm.is_nested_share_folder', return_value=True):
            self.assertEqual(
                KSMCommand.resolve_secret_uid(params, f'[{folder_uid}]'),
                folder_uid)


class TestKSMAppRecordResolution(unittest.TestCase):

    def _make_params(self):
        params = MagicMock()
        params.record_cache = {}
        params.nested_share_records = {}
        params.nested_share_record_data = {}
        return params

    def test_get_app_record_from_nsf_cache(self):
        params = self._make_params()
        app_uid = 'appUid00000000000001'
        params.nested_share_records = {
            app_uid: {'version': 5, 'record_key_unencrypted': b'app_key', 'revision': 1}
        }
        params.nested_share_record_data = {
            app_uid: {'data_json': {'title': 'NSF App', 'type': 'app'}}
        }
        with patch('keepercommander.commands.ksm.is_nested_share_record', return_value=True):
            rec = KSMCommand.get_app_record(params, app_uid)
        self.assertIsNotNone(rec)
        self.assertEqual(rec['record_uid'], app_uid)
        self.assertEqual(rec['record_key_unencrypted'], b'app_key')

    @patch('keepercommander.commands.ksm.resolve_nested_share_record_uid')
    def test_get_app_record_by_nsf_path(self, mock_resolve):
        params = self._make_params()
        app_uid = 'appUid00000000000001'
        mock_resolve.return_value = app_uid
        params.nested_share_records = {
            app_uid: {'version': 5, 'record_key_unencrypted': b'app_key', 'revision': 1}
        }
        params.nested_share_record_data = {
            app_uid: {'data_json': {'title': 'NSF App', 'type': 'app'}}
        }
        rec = KSMCommand.get_app_record(params, 'NSF/NSF App')
        self.assertIsNotNone(rec)
        self.assertEqual(rec['record_uid'], app_uid)

    def test_get_ksm_app_display_info_from_nsf_metadata(self):
        params = self._make_params()
        app_uid = 'appUid00000000000001'
        with patch('keepercommander.commands.ksm.KSMCommand.get_app_record', return_value=None):
            with patch('keepercommander.commands.ksm.KSMCommand.get_app_title', return_value='NSF App'):
                title, accessible, info = KSMCommand.get_ksm_app_display_info(params, app_uid)
        self.assertEqual(title, 'NSF App')
        self.assertFalse(accessible)
        self.assertIn('NSF App', info)


class TestKSMUserResolution(unittest.TestCase):
    """Email <-> user_id for app-user commands; non-admins have no enterprise directory."""

    EMAIL = 'member@example.com'

    def _make_params(self, directory=None):
        params = MagicMock()
        params.enterprise = {'users': directory} if directory is not None else None
        return params

    def _share_users(self, **users):
        return {'users': users}

    def _visible(self, user_id=7, category='enterprise'):
        return {self.EMAIL: dict(name='Member', category=category, user_id=user_id)}

    @patch('keepercommander.commands.ksm.api.get_share_objects')
    def test_resolve_user_id_prefers_admin_directory(self, mock_share):
        params = self._make_params([{'username': 'Member@Example.com', 'user_id': 42}])
        self.assertEqual(KSMCommand.resolve_enterprise_user_id(params, self.EMAIL), 42)
        mock_share.assert_not_called()

    @patch('keepercommander.commands.ksm.api.get_share_objects')
    def test_resolve_user_id_non_admin_uses_share_objects(self, mock_share):
        mock_share.return_value = {'users': self._visible(user_id=7)}
        params = self._make_params()
        self.assertEqual(
            KSMCommand.resolve_enterprise_user_id(params, 'MEMBER@example.com'), 7,
            'non-admin should resolve through get_share_objects, case-insensitively')

    @patch('keepercommander.commands.ksm.api.get_share_objects')
    def test_resolve_user_id_ignores_non_enterprise_users(self, mock_share):
        mock_share.return_value = {'users': self._visible(user_id=7, category='relationship')}
        self.assertIsNone(KSMCommand.resolve_enterprise_user_id(self._make_params(), self.EMAIL))

    @patch('keepercommander.commands.ksm.api.get_share_objects')
    def test_resolve_user_id_ignores_unpopulated_user_id(self, mock_share):
        # an older server leaves userId at 0
        mock_share.return_value = {'users': self._visible(user_id=0)}
        self.assertIsNone(KSMCommand.resolve_enterprise_user_id(self._make_params(), self.EMAIL))

    @patch('keepercommander.commands.ksm.api.get_share_objects')
    def test_resolve_user_id_unknown_email(self, mock_share):
        mock_share.return_value = {'users': self._visible(user_id=7)}
        self.assertIsNone(KSMCommand.resolve_enterprise_user_id(self._make_params(), 'other@example.com'))

    @patch('keepercommander.commands.ksm.api.get_share_objects', side_effect=Exception('boom'))
    def test_resolve_user_id_share_objects_failure(self, _mock_share):
        self.assertIsNone(KSMCommand.resolve_enterprise_user_id(self._make_params(), self.EMAIL))

    @patch('keepercommander.commands.ksm.api.get_share_objects')
    def test_resolve_username_prefers_admin_directory(self, mock_share):
        params = self._make_params([{'username': self.EMAIL, 'user_id': 42}])
        self.assertEqual(KSMCommand.resolve_username_by_user_id(params, 42), self.EMAIL)
        mock_share.assert_not_called()

    @patch('keepercommander.commands.ksm.api.get_share_objects')
    def test_resolve_username_non_admin_uses_share_objects(self, mock_share):
        mock_share.return_value = {'users': self._visible(user_id=7)}
        self.assertEqual(KSMCommand.resolve_username_by_user_id(self._make_params(), 7), self.EMAIL)

    @patch('keepercommander.commands.ksm.api.get_share_objects')
    def test_resolve_username_unknown_id_falls_back_to_number(self, mock_share):
        mock_share.return_value = {'users': self._visible(user_id=7)}
        self.assertEqual(KSMCommand.resolve_username_by_user_id(self._make_params(), 99), '99')


class TestKSMAutoShareFailure(unittest.TestCase):
    """The member is already added when auto-share runs, so a failure must only warn."""

    def _folder_app_info(self):
        from keepercommander.proto import APIRequest_pb2
        share = MagicMock()
        share.secretUid = bytes(range(16))
        share.shareType = APIRequest_pb2.SHARE_TYPE_FOLDER
        app_info = MagicMock()
        app_info.shares = [share]
        return [app_info]

    def _params_with_folder(self):
        from keepercommander import utils
        params = MagicMock()
        params.shared_folder_cache = {utils.base64_url_encode(bytes(range(16))): {}}
        return params

    @patch('keepercommander.commands.ksm.KSMCommand.get_app_info', side_effect=Exception('boom'))
    def test_app_info_failure_only_warns(self, _mock_info):
        with self.assertLogs(level='WARNING') as logs:
            KSMCommand._auto_share_app_folders(MagicMock(), 'appUid', users=['member@example.com'])
        self.assertIn('could not share its folders', logs.output[0])

    @patch('keepercommander.commands.register.ShareFolderCommand.send_requests',
           side_effect=Exception('internal error'))
    @patch('keepercommander.commands.register.ShareFolderCommand.prepare_request')
    @patch('keepercommander.commands.ksm.KSMCommand.get_app_info')
    def test_share_request_failure_only_warns(self, mock_info, _mock_prepare, _mock_send):
        mock_info.return_value = self._folder_app_info()
        with self.assertLogs(level='WARNING') as logs:
            KSMCommand._auto_share_app_folders(
                self._params_with_folder(), 'appUid', users=['member@example.com'])
        self.assertIn('internal error', logs.output[0])

    @patch('keepercommander.commands.register.ShareFolderCommand.send_requests')
    @patch('keepercommander.commands.register.ShareFolderCommand.prepare_request')
    @patch('keepercommander.commands.ksm.KSMCommand.get_app_info')
    def test_success_sends_without_warning(self, mock_info, _mock_prepare, mock_send):
        mock_info.return_value = self._folder_app_info()
        KSMCommand._auto_share_app_folders(
            self._params_with_folder(), 'appUid', users=['member@example.com'])
        mock_send.assert_called_once()


class TestGetShareObjectsUserId(unittest.TestCase):
    """api.get_share_objects keeps ShareUser.userId for enterprise users."""

    @patch('keepercommander.api.communicate_rest')
    def test_user_id_is_cached(self, mock_rest):
        from keepercommander import api
        from keepercommander.proto import record_pb2

        rs = record_pb2.GetShareObjectsResponse()
        member = rs.shareEnterpriseUsers.add()
        member.username = 'member@example.com'
        member.enterpriseId = 8049
        member.userId = 7
        mock_rest.return_value = rs
        params = MagicMock()
        params.share_object_cache = None

        users = api.get_share_objects(params)['users']

        self.assertEqual(users['member@example.com']['user_id'], 7)
        self.assertEqual(users['member@example.com']['category'], 'enterprise')


class TestKSMTokenAdd(unittest.TestCase):
    """secrets-manager token add <app-uid> → calls add_client."""

    def _make_params(self, record_uid='test-app-uid'):
        params = MagicMock()
        params.record_cache = {}
        return params

    @patch('keepercommander.commands.ksm.KSMCommand.add_client')
    def test_token_add_calls_add_client(self, mock_add_client):
        mock_add_client.return_value = [{'oneTimeToken': 'US:abc123', 'deviceToken': 'dt1'}]
        params = self._make_params()
        cmd = KSMCommand()
        result = cmd.execute(params, command=['token', 'add', 'MyApp'],
                             count=1, unlockIp=False, firstAccessExpiresIn=None,
                             accessExpireInMin=None, name=None, config_init=None,
                             returnTokens=False, format='table')
        mock_add_client.assert_called_once()
        call_args = mock_add_client.call_args
        assert call_args[0][1] == 'MyApp', f"Expected 'MyApp', got {call_args[0][1]}"

    @patch('keepercommander.commands.ksm.KSMCommand.add_client')
    def test_token_add_return_tokens(self, mock_add_client):
        mock_add_client.return_value = [{'oneTimeToken': 'US:tok1'}, {'oneTimeToken': 'US:tok2'}]
        params = self._make_params()
        cmd = KSMCommand()
        result = cmd.execute(params, command=['token', 'add', 'MyApp'],
                             count=2, unlockIp=False, firstAccessExpiresIn=None,
                             accessExpireInMin=None, name=None, config_init=None,
                             returnTokens=True, format='table')
        assert result == 'US:tok1, US:tok2', f"Expected 'US:tok1, US:tok2', got {result!r}"

    def test_token_add_missing_app_prints_help(self):
        params = self._make_params()
        cmd = KSMCommand()
        # Should print help and return None without calling add_client
        with patch('keepercommander.commands.ksm.KSMCommand.add_client') as mock_ac:
            result = cmd.execute(params, command=['token', 'add'],
                                 count=1, unlockIp=False, firstAccessExpiresIn=None,
                                 accessExpireInMin=None, name=None, config_init=None,
                                 returnTokens=False, format='table')
            mock_ac.assert_not_called()
            assert result is None, f"Expected None, got {result!r}"


class TestKSMUsage(unittest.TestCase):
    """secrets-manager usage report - aggregation, billing cycle, timeline, flag matrix."""

    SAMPLE_ROWS = [
        {'username': 'a@x.com', 'device_name': 'D1', 'app_uid': 'APP1', 'occurrences': 10},
        {'username': 'a@x.com', 'device_name': 'D2', 'app_uid': 'APP1', 'occurrences': 5},
        {'username': 'b@x.com', 'device_name': 'D1', 'app_uid': 'APP2', 'occurrences': 3},
    ]

    def _make_params(self):
        params = MagicMock()
        params.environment_variables = {}
        params.enterprise = {
            'users': [
                {'username': 'a@x.com', 'data': {'displayname': 'Alice A'}},
                {'username': 'b@x.com', 'data': {'displayname': 'Bob B'}},
            ],
            'licenses': [{
                'next_billing_date': int(datetime.datetime(2026, 1, 15, 12, 0, 0).timestamp() * 1000),
                'add_ons': [{'name': 'secrets_manager',
                             'created': int(datetime.datetime(2025, 1, 1).timestamp() * 1000)}],
            }],
        }
        return params

    # ---- unit helpers ----

    def test_event_type_constants(self):
        self.assertEqual(len(KSM_EVENT_TYPES), 16)
        self.assertIn('app_client_access', KSM_EVENT_TYPES)
        self.assertEqual(KSM_USAGE_EVENT_TYPE, 'app_client_access')

    def test_ts_to_ms_normalization(self):
        self.assertEqual(KSMCommand._ts_to_ms(1_700_000_000), 1_700_000_000_000)  # seconds -> ms
        self.assertEqual(KSMCommand._ts_to_ms(1_700_000_000_000), 1_700_000_000_000)  # ms passthrough
        self.assertEqual(KSMCommand._ts_to_ms(0), 0)
        self.assertEqual(KSMCommand._ts_to_ms(None), 0)

    def test_set_month_day_clamp(self):
        jan31 = datetime.datetime(2026, 1, 31, 9, 0, 0)
        feb = KSMCommand._set_month(jan31, 1, 2026)  # month0=1 -> February
        self.assertEqual((feb.month, feb.day), (2, 28))

    def test_billing_cycle_run_after_billing_day(self):
        params = self._make_params()
        run_ms = int(datetime.datetime(2026, 7, 16, 9, 0, 0).timestamp() * 1000)
        min_sec, max_sec = KSMCommand._ksm_billing_cycle(params, run_on_ms=run_ms)
        start = datetime.datetime.fromtimestamp(min_sec)
        end = datetime.datetime.fromtimestamp(max_sec)
        self.assertEqual((start.year, start.month, start.day), (2026, 7, 15))
        self.assertEqual((end.year, end.month, end.day), (2026, 8, 15))
        self.assertLess(min_sec, max_sec)

    def test_billing_cycle_none_without_billing_date(self):
        params = self._make_params()
        params.enterprise['licenses'][0]['next_billing_date'] = 0
        self.assertIsNone(KSMCommand._ksm_billing_cycle(params))

    # ---- aggregation / rendering (assert the table handed to dump_report_data) ----

    # One device -> one app, for clean per-device Exist assertions.
    ONE_DEV_ROWS = [{'username': 'u@x.com', 'device_name': 'Donly', 'app_uid': 'APPX', 'occurrences': 7}]

    def _run_metrics(self, params, sox=None, rows=None, **flags):
        # sox: None (compliance unavailable) or (live_uids, trash_uids) returned by the --exists path.
        rows = list(self.SAMPLE_ROWS if rows is None else rows)
        with patch('keepercommander.commands.aram.fetch_audit_events', return_value=rows), \
             patch('keepercommander.commands.ksm.KSMCommand._compliance_app_status', return_value=sox), \
             patch('keepercommander.commands.ksm.dump_report_data') as mock_dump:
            KSMCommand._usage_metrics(params, format='json', **flags)
        self.assertTrue(mock_dump.called)
        _args, kwargs = mock_dump.call_args
        table = _args[0]
        headers = kwargs.get('headers') or (_args[1] if len(_args) > 1 else None)
        return table, headers

    def test_default_top_application_usage_no_exist_column(self):
        table, headers = self._run_metrics(self._make_params())
        self.assertEqual(headers, ['Application Owner', 'Count'])
        self.assertEqual(table, [['a@x.com', 15], ['b@x.com', 3]])

    def test_usage_metrics_uses_secrets_manager_command_label(self):
        params = self._make_params()
        with patch('keepercommander.commands.aram.fetch_audit_events', return_value=[]) as mock_fetch, \
                patch('keepercommander.commands.ksm.dump_report_data'):
            KSMCommand._usage_metrics(params, format='json')
        self.assertEqual(mock_fetch.call_args.kwargs.get('cmd'), 'secrets-manager usage')

    def test_by_device_no_exist_column_by_default(self):
        # Without --exists there is NO Exist column - just Device/Count. Names shared by multiple apps
        # are still split with a UID suffix so each row maps to one app.
        table, headers = self._run_metrics(self._make_params(), by_device=True)
        self.assertEqual(headers, ['Device', 'Count'])
        self.assertEqual(table, [['D1 (APP1)', 10], ['D2', 5], ['D1 (APP2)', 3]])

    def test_by_device_sort_by_name(self):
        # --sort name groups related device names alphabetically instead of by count.
        rows = [{'username': 'u@x.com', 'device_name': 'zeta', 'app_uid': 'A1', 'occurrences': 100},
                {'username': 'u@x.com', 'device_name': 'Playground B', 'app_uid': 'A2', 'occurrences': 5},
                {'username': 'u@x.com', 'device_name': 'Playground A', 'app_uid': 'A3', 'occurrences': 50}]
        table, _ = self._run_metrics(self._make_params(), rows=rows, by_device=True, sort='name')
        self.assertEqual([r[0] for r in table], ['Playground A', 'Playground B', 'zeta'])
        # default (count) keeps descending-usage order
        table2, _ = self._run_metrics(self._make_params(), rows=rows, by_device=True, sort='count')
        self.assertEqual([r[0] for r in table2], ['zeta', 'Playground A', 'Playground B'])

    def test_by_device_unique_name_no_suffix(self):
        rows = [{'username': 'u@x.com', 'device_name': 'Solo', 'app_uid': 'APP1', 'occurrences': 9}]
        table, headers = self._run_metrics(self._make_params(), rows=rows, by_device=True)
        self.assertEqual(headers, ['Device', 'Count'])
        self.assertEqual(table, [['Solo', 9]])  # single app -> no UID suffix

    def test_by_device_exists_live_and_purged(self):
        # --exists: compliance says APP1 live, APP2 unknown -> purged (N).
        table, headers = self._run_metrics(self._make_params(), sox=(frozenset({'APP1'}), frozenset()),
                                           by_device=True, exists=True)
        self.assertEqual(headers, ['Device', 'Count', 'Exist'])
        self.assertEqual(table, [['D1 (APP1)', 10, 'Y'], ['D2', 5, 'Y'], ['D1 (APP2)', 3, 'N']])

    def test_by_device_exists_trash(self):
        table, _ = self._run_metrics(self._make_params(), sox=(frozenset(), frozenset({'APPX'})),
                                     rows=self.ONE_DEV_ROWS, by_device=True, exists=True)
        self.assertEqual(table, [['Donly', 7, 'T']])  # in_trash per compliance

    def test_by_device_exists_unknown_when_compliance_unavailable(self):
        # --exists but compliance data can't be loaded -> '?'
        table, _ = self._run_metrics(self._make_params(), sox=None,
                                     rows=self.ONE_DEV_ROWS, by_device=True, exists=True)
        self.assertEqual(table, [['Donly', 7, '?']])

    def test_exists_not_queried_without_flag(self):
        params = self._make_params()
        with patch('keepercommander.commands.aram.fetch_audit_events', return_value=list(self.SAMPLE_ROWS)), \
             patch('keepercommander.commands.ksm.KSMCommand._compliance_app_status') as mock_sox, \
             patch('keepercommander.commands.ksm.dump_report_data'):
            KSMCommand._usage_metrics(params, format='json', by_device=True)  # no --exists
            mock_sox.assert_not_called()

    def test_exists_ignored_off_by_device(self):
        # --exists only applies to --by-device; on default/summary/detail the compliance sync must not run.
        params = self._make_params()
        for flags in ({}, {'summary': True}, {'detail': True}, {'detail': True, 'by_device': True}):
            with patch('keepercommander.commands.aram.fetch_audit_events', return_value=list(self.SAMPLE_ROWS)), \
                 patch('keepercommander.commands.ksm.KSMCommand._compliance_app_status') as mock_sox, \
                 patch('keepercommander.commands.ksm.dump_report_data'):
                KSMCommand._usage_metrics(params, format='json', exists=True, **flags)
                mock_sox.assert_not_called()

    def test_detail_full_user_usage_no_exist_column(self):
        table, headers = self._run_metrics(self._make_params(), detail=True)
        self.assertEqual(headers, ['Owner', 'Email', 'Device', 'API Usage per Month'])
        self.assertEqual(table, [['Alice A', 'a@x.com', 'D1', 10],
                                 ['Alice A', 'a@x.com', 'D2', 5],
                                 ['Bob B', 'b@x.com', 'D1', 3]])

    def test_detail_by_device_full_device_usage_no_exist_column(self):
        table, headers = self._run_metrics(self._make_params(), detail=True, by_device=True)
        self.assertEqual(headers, ['Device', 'Application UID', 'Owner', 'Email', 'API Usage per Month'])
        self.assertEqual(table, [['D1', 'APP1', 'Alice A', 'a@x.com', 10],
                                 ['D2', 'APP1', 'Alice A', 'a@x.com', 5],
                                 ['D1', 'APP2', 'Bob B', 'b@x.com', 3]])

    def test_summary(self):
        table, headers = self._run_metrics(self._make_params(), summary=True)
        self.assertEqual(headers, ['Metric', 'Value'])
        as_dict = {row[0]: row[1] for row in table}
        self.assertEqual(as_dict['Total API Usage This Cycle'], 18)
        self.assertEqual(as_dict['Applications'], 2)
        self.assertEqual(as_dict['Devices'], 2)
        self.assertEqual(as_dict['Average API Calls Per User'], 9.0)
        self.assertNotIn('  live (Y)', as_dict)
        self.assertNotIn('  purged (N)', as_dict)

    def _capture_table_footer(self, sox=None, **flags):
        import io
        import contextlib
        params = self._make_params()
        buf = io.StringIO()
        with patch('keepercommander.commands.aram.fetch_audit_events', return_value=list(self.SAMPLE_ROWS)), \
             patch('keepercommander.commands.ksm.KSMCommand._compliance_app_status', return_value=sox), \
             contextlib.redirect_stdout(buf):
            KSMCommand._usage_metrics(params, format='table', **flags)
        return buf.getvalue()

    def test_footer_exist_legend_only_with_exists(self):
        # No --exists anywhere -> app-list note present, Exist legend absent.
        for flags in ({}, {'by_device': True}, {'detail': True}, {'summary': True}):
            out = self._capture_table_footer(**flags)
            self.assertIn('secrets-manager app list', out)
            self.assertNotIn('Exist:', out)
        # --by-device --exists -> legend present.
        out = self._capture_table_footer(sox=(frozenset({'APP1'}), frozenset()), by_device=True, exists=True)
        self.assertIn('Exist:', out)

    def test_usage_uses_only_app_client_access_filter(self):
        params = self._make_params()
        with patch('keepercommander.commands.aram.fetch_audit_events', return_value=[]) as mock_fetch, \
             patch('keepercommander.commands.ksm.dump_report_data'):
            KSMCommand._usage_metrics(params, format='table')
        _args, kwargs = mock_fetch.call_args
        audit_filter = _args[1]
        self.assertEqual(audit_filter['audit_event_type'], ['app_client_access'])
        self.assertEqual(kwargs.get('columns'), ['app_uid', 'device_name', 'username'])
        self.assertEqual(kwargs.get('aggregate'), ['occurrences'])

    # ---- timeline ----

    def test_timeline_export_all_row_shape(self):
        params = self._make_params()
        rows = [
            {'audit_event_type': 'app_client_access', 'created': 1_700_000_100, 'occurrences': 4},
            {'audit_event_type': 'app_client_added', 'created': 1_700_000_000, 'occurrences': 2},
        ]
        with patch('keepercommander.commands.aram.fetch_audit_events', return_value=rows) as mock_fetch, \
             patch('keepercommander.commands.ksm.dump_report_data') as mock_dump:
            KSMCommand._usage_timeline(params, format='csv', export_all=True, range='7d')
        # full KSM event set requested for timeline
        _fargs, fkwargs = mock_fetch.call_args
        self.assertEqual(_fargs[1]['audit_event_type'], KSM_EVENT_TYPES)
        self.assertEqual(fkwargs.get('report_type'), 'day')
        self.assertEqual(fkwargs.get('cmd'), 'secrets-manager usage')
        _args, kwargs = mock_dump.call_args
        table = _args[0]
        headers = kwargs.get('headers')
        self.assertEqual(headers, ['Date', 'Event', 'Number of Events'])
        # sorted ascending by created; count in last column
        self.assertEqual([r[2] for r in table], [2, 4])
        self.assertEqual(len(table[0]), 3)

    def test_timeline_default_totals(self):
        params = self._make_params()
        rows = [
            {'audit_event_type': 'app_client_access', 'created': 1_700_000_000, 'occurrences': 6},
            {'audit_event_type': 'app_client_access', 'created': 1_700_100_000, 'occurrences': 4},
            {'audit_event_type': 'app_client_added', 'created': 1_700_000_000, 'occurrences': 10},
        ]
        with patch('keepercommander.commands.aram.fetch_audit_events', return_value=rows), \
             patch('keepercommander.commands.ksm.dump_report_data') as mock_dump:
            KSMCommand._usage_timeline(params, format='table', range='24h')
        _args, kwargs = mock_dump.call_args
        table = _args[0]
        self.assertEqual(kwargs.get('headers'), ['Event', 'Count', '% of Total'])
        counts = {row[0]: row[1] for row in table}
        # app_client_access totals to 10, app_client_added to 10
        self.assertEqual(sorted(counts.values(), reverse=True), [10, 10])

    # ---- flag validation & routing ----

    def test_timeline_conflicts_with_detail(self):
        params = self._make_params()
        with patch('keepercommander.commands.aram.fetch_audit_events') as mock_fetch:
            KSMCommand.execute_usage(params, timeline=True, detail=True)
            mock_fetch.assert_not_called()

    def test_range_without_timeline_rejected(self):
        params = self._make_params()
        with patch('keepercommander.commands.aram.fetch_audit_events') as mock_fetch:
            KSMCommand.execute_usage(params, range='7d')
            mock_fetch.assert_not_called()

    def test_requires_enterprise(self):
        params = self._make_params()
        params.enterprise = None
        with patch('keepercommander.commands.aram.fetch_audit_events') as mock_fetch:
            KSMCommand.execute_usage(params)
            mock_fetch.assert_not_called()

    def test_execute_args_routes_usage_verb(self):
        params = self._make_params()
        cmd = KSMCommand()
        with patch('keepercommander.commands.ksm.KSMCommand.execute_usage') as mock_usage:
            cmd.execute_args(params, 'usage --by-device')
            self.assertTrue(mock_usage.called)
            _args, kwargs = mock_usage.call_args
            self.assertTrue(kwargs.get('by_device'))

    def test_execute_args_non_usage_delegates(self):
        params = self._make_params()
        cmd = KSMCommand()
        with patch('keepercommander.commands.ksm.KSMCommand.execute_usage') as mock_usage, \
             patch('keepercommander.commands.base.Command.execute_args') as mock_super:
            cmd.execute_args(params, 'app list')
            mock_usage.assert_not_called()
            mock_super.assert_called_once()


def _status_response(rs_class, status, message=''):
    rs = rs_class()
    entry = rs.statuses.add()
    entry.status = status
    entry.message = message
    return rs


class TestKSMMembershipEntryStatus(unittest.TestCase):
    """_membership_entry_ok: anything but 'ok' warns with the server message and returns False."""

    def test_missing_response_is_ok(self):
        self.assertTrue(KSMCommand._membership_entry_ok(None, 'User "x"'))

    def test_empty_statuses_are_ok(self):
        from keepercommander.proto import APIRequest_pb2
        self.assertTrue(KSMCommand._membership_entry_ok(APIRequest_pb2.AppUserAddResponse(), 'User "x"'))

    def test_ok_status_is_ok_and_silent(self):
        from keepercommander.proto import APIRequest_pb2
        rs = _status_response(APIRequest_pb2.AppUserAddResponse, 'ok')
        with patch('keepercommander.commands.ksm.logging.warning') as warn:
            self.assertTrue(KSMCommand._membership_entry_ok(rs, 'User "x"'))
        warn.assert_not_called()

    def test_failed_status_warns_with_message_and_hint(self):
        from keepercommander.proto import APIRequest_pb2
        rs = _status_response(APIRequest_pb2.AppUserAddResponse, 'already_member', 'User is already on this app')
        with patch('keepercommander.commands.ksm.logging.warning') as warn:
            self.assertFalse(KSMCommand._membership_entry_ok(rs, 'User "x"', 'Use "app-user update".'))
        text = warn.call_args[0][0]
        self.assertIn('User "x"', text)
        self.assertIn('User is already on this app', text)
        self.assertIn('Use "app-user update".', text)

    def test_failed_status_without_message_falls_back_to_status_code(self):
        from keepercommander.proto import APIRequest_pb2
        rs = _status_response(APIRequest_pb2.AppUserAddResponse, 'user_not_found')
        with patch('keepercommander.commands.ksm.logging.warning') as warn:
            self.assertFalse(KSMCommand._membership_entry_ok(rs, 'User "x"'))
        self.assertIn('user_not_found', warn.call_args[0][0])


class TestKSMMembershipCommandStatus(unittest.TestCase):
    """The six app-user/app-team commands: a failed entry warns, skips the success line and, on add, the auto-share."""

    EMAIL = 'member@example.com'
    TEAM = 'Team A'

    def setUp(self):
        from keepercommander import utils
        self.app_uid = utils.base64_url_encode(bytes(range(16)))
        self.team_uid = utils.base64_url_encode(bytes(range(16, 32)))
        self.params = MagicMock()
        # Sync-down only carries the caller's own membership rows, so update must not rely on them.
        self.params.ksm_app_users = {}
        self.params.ksm_app_teams = {}
        self.app_info = [self._app_info(user_id=7, team_uid=self.team_uid)]

    @staticmethod
    def _app_info(user_id=None, team_uid=None):
        from keepercommander import utils
        from keepercommander.proto import APIRequest_pb2
        ai = APIRequest_pb2.AppInfo()
        if user_id is not None:
            u = ai.users.add()
            u.userId = user_id
            u.canManageUsers = True
        if team_uid is not None:
            t = ai.teams.add()
            t.teamUid = utils.base64_url_decode(team_uid)
            t.canManageUsers = True
        return ai

    def _run(self, command, rs_class, status, *args):
        """Runs a KSMCommand method with the lookups and the server call faked. Returns (printed, warn, auto_share)."""
        app = {'record_uid': self.app_uid, 'record_key_unencrypted': b'k' * 32}
        patches = [
            patch('keepercommander.commands.ksm.KSMCommand.get_app_record', return_value=app),
            patch('keepercommander.commands.ksm.KSMCommand.resolve_enterprise_user_id', return_value=7),
            patch('keepercommander.commands.ksm.KSMCommand.resolve_team_uid', return_value=self.team_uid),
            patch('keepercommander.commands.ksm.get_user_public_key', return_value=(MagicMock(), True, None, None)),
            patch('keepercommander.commands.ksm.crypto.encrypt_ec', return_value=b'encrypted'),
            patch('keepercommander.commands.ksm.get_team_keys', return_value=MagicMock()),
            patch('keepercommander.commands.ksm.encrypt_for_team', return_value=(b'encrypted', 2)),
            patch('keepercommander.commands.ksm.api.communicate_rest',
                  return_value=_status_response(rs_class, status, 'server says no')),
            patch('keepercommander.commands.ksm.KSMCommand.get_app_info', side_effect=lambda *a: self.app_info),
        ]
        auto_share = patch('keepercommander.commands.ksm.KSMCommand._auto_share_app_folders')
        printer = patch('builtins.print')
        warner = patch('keepercommander.commands.ksm.logging.warning')
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        mock_share = auto_share.start()
        self.addCleanup(auto_share.stop)
        mock_print = printer.start()
        self.addCleanup(printer.stop)
        mock_warn = warner.start()
        self.addCleanup(warner.stop)
        command(self.params, self.app_uid, *args)
        printed = ' '.join(str(c[0][0]) for c in mock_print.call_args_list if c[0])
        return printed, mock_warn, mock_share

    def test_add_user_ok_prints_success_and_auto_shares(self):
        from keepercommander.proto import APIRequest_pb2
        printed, warn, share = self._run(
            KSMCommand.add_app_user, APIRequest_pb2.AppUserAddResponse, 'ok', self.EMAIL, True, False, False)
        self.assertIn('Successfully added user', printed)
        warn.assert_not_called()
        share.assert_called_once_with(self.params, self.app_uid, users=[self.EMAIL])

    def test_add_user_already_member_warns_and_skips_auto_share(self):
        from keepercommander.proto import APIRequest_pb2
        printed, warn, share = self._run(
            KSMCommand.add_app_user, APIRequest_pb2.AppUserAddResponse, 'already_member',
            self.EMAIL, True, False, False)
        self.assertNotIn('Successfully', printed)
        warn.assert_called_once()
        self.assertIn('server says no', warn.call_args[0][0])
        share.assert_not_called()

    def test_add_team_ok_prints_success_and_auto_shares(self):
        from keepercommander.proto import APIRequest_pb2
        printed, warn, share = self._run(
            KSMCommand.add_app_team, APIRequest_pb2.AppTeamAddResponse, 'ok', self.TEAM, True, False, False)
        self.assertIn('Successfully added team', printed)
        warn.assert_not_called()
        share.assert_called_once_with(self.params, self.app_uid, teams=[self.team_uid])

    def test_add_team_already_member_warns_and_skips_auto_share(self):
        from keepercommander.proto import APIRequest_pb2
        printed, warn, share = self._run(
            KSMCommand.add_app_team, APIRequest_pb2.AppTeamAddResponse, 'already_member',
            self.TEAM, True, False, False)
        self.assertNotIn('Successfully', printed)
        warn.assert_called_once()
        share.assert_not_called()

    def test_update_user_ok_and_not_a_member(self):
        from keepercommander.proto import APIRequest_pb2
        printed, warn, _ = self._run(
            KSMCommand.update_app_user, APIRequest_pb2.AppUserUpdateResponse, 'ok', self.EMAIL, None, 'on', None)
        self.assertIn('Successfully updated user', printed)
        warn.assert_not_called()
        printed, warn, _ = self._run(
            KSMCommand.update_app_user, APIRequest_pb2.AppUserUpdateResponse, 'not_a_member',
            self.EMAIL, None, 'on', None)
        self.assertNotIn('Successfully', printed)
        warn.assert_called_once()

    def test_update_team_ok_and_not_a_member(self):
        from keepercommander.proto import APIRequest_pb2
        printed, warn, _ = self._run(
            KSMCommand.update_app_team, APIRequest_pb2.AppTeamUpdateResponse, 'ok', self.TEAM, None, None, 'on')
        self.assertIn('Successfully updated team', printed)
        warn.assert_not_called()
        printed, warn, _ = self._run(
            KSMCommand.update_app_team, APIRequest_pb2.AppTeamUpdateResponse, 'not_a_member',
            self.TEAM, None, None, 'on')
        self.assertNotIn('Successfully', printed)
        warn.assert_called_once()

    def test_remove_user_ok_and_not_a_member(self):
        from keepercommander.proto import APIRequest_pb2
        printed, warn, _ = self._run(
            KSMCommand.remove_app_user, APIRequest_pb2.AppUserRemoveResponse, 'ok', self.EMAIL)
        self.assertIn('Successfully removed user', printed)
        warn.assert_not_called()
        printed, warn, _ = self._run(
            KSMCommand.remove_app_user, APIRequest_pb2.AppUserRemoveResponse, 'not_a_member', self.EMAIL)
        self.assertNotIn('Successfully', printed)
        warn.assert_called_once()

    def test_remove_team_ok_and_not_a_member(self):
        from keepercommander.proto import APIRequest_pb2
        printed, warn, _ = self._run(
            KSMCommand.remove_app_team, APIRequest_pb2.AppTeamRemoveResponse, 'ok', self.TEAM)
        self.assertIn('Successfully removed team', printed)
        warn.assert_not_called()
        printed, warn, _ = self._run(
            KSMCommand.remove_app_team, APIRequest_pb2.AppTeamRemoveResponse, 'not_a_member', self.TEAM)
        self.assertNotIn('Successfully', printed)
        warn.assert_called_once()

    def test_update_member_not_on_app_warns(self):
        """A member missing from vault/get_app_info is reported, and no update is claimed."""
        from keepercommander.proto import APIRequest_pb2
        self.app_info = [self._app_info()]
        for command, rs_class, subject in (
                (KSMCommand.update_app_user, APIRequest_pb2.AppUserUpdateResponse, self.EMAIL),
                (KSMCommand.update_app_team, APIRequest_pb2.AppTeamUpdateResponse, self.TEAM)):
            printed, warn, _ = self._run(command, rs_class, 'ok', subject, None, 'on', None)
            self.assertNotIn('Successfully', printed)
            self.assertIn('not currently a member', warn.call_args[0][0])

    def test_update_team_keeps_bits_that_are_not_passed(self):
        """Omitted options keep the team's current bits from vault/get_app_info."""
        from keepercommander.proto import APIRequest_pb2
        sent = {}

        def capture(params, rq, endpoint, rs_type=None):
            sent['entry'] = rq.teams[0]
            return _status_response(APIRequest_pb2.AppTeamUpdateResponse, 'ok')

        app = {'record_uid': self.app_uid}
        with patch('keepercommander.commands.ksm.KSMCommand.get_app_record', return_value=app), \
             patch('keepercommander.commands.ksm.KSMCommand.resolve_team_uid', return_value=self.team_uid), \
             patch('keepercommander.commands.ksm.KSMCommand.get_app_info', return_value=self.app_info), \
             patch('keepercommander.commands.ksm.api.communicate_rest', side_effect=capture), \
             patch('builtins.print'):
            KSMCommand.update_app_team(self.params, self.app_uid, self.TEAM, None, None, 'on')
        self.assertTrue(sent['entry'].canManageUsers, 'can_manage_users was not passed, so it keeps its value')
        self.assertFalse(sent['entry'].canManageShares)
        self.assertTrue(sent['entry'].canManageDevices, 'can_manage_devices was passed on')

    def test_update_user_keeps_bits_that_are_not_passed(self):
        """Omitted options keep the member's current bits from vault/get_app_info."""
        from keepercommander.proto import APIRequest_pb2
        sent = {}

        def capture(params, rq, endpoint, rs_type=None):
            sent['entry'] = rq.users[0]
            return _status_response(APIRequest_pb2.AppUserUpdateResponse, 'ok')

        app = {'record_uid': self.app_uid}
        with patch('keepercommander.commands.ksm.KSMCommand.get_app_record', return_value=app), \
             patch('keepercommander.commands.ksm.KSMCommand.resolve_enterprise_user_id', return_value=7), \
             patch('keepercommander.commands.ksm.KSMCommand.get_app_info', return_value=self.app_info), \
             patch('keepercommander.commands.ksm.api.communicate_rest', side_effect=capture), \
             patch('builtins.print'):
            KSMCommand.update_app_user(self.params, self.app_uid, self.EMAIL, None, 'on', None)
        self.assertTrue(sent['entry'].canManageUsers, 'can_manage_users was not passed, so it keeps its value')
        self.assertTrue(sent['entry'].canManageShares, 'can_manage_shares was passed on')
        self.assertFalse(sent['entry'].canManageDevices)


class TestKSMAutoShareFolders(unittest.TestCase):
    """_auto_share_app_folders: which folders are shared, and how."""

    def setUp(self):
        from keepercommander import utils
        from keepercommander.proto import APIRequest_pb2
        self.folder_a = bytes(range(16))
        self.folder_b = bytes(range(16, 32))
        self.record = bytes(range(32, 48))
        self.uid_a = utils.base64_url_encode(self.folder_a)
        self.uid_b = utils.base64_url_encode(self.folder_b)

        def share(uid, share_type):
            s = MagicMock()
            s.secretUid = uid
            s.shareType = share_type
            return s

        self.shares = [share(self.folder_a, APIRequest_pb2.SHARE_TYPE_FOLDER),
                       share(self.folder_b, APIRequest_pb2.SHARE_TYPE_FOLDER),
                       share(self.record, APIRequest_pb2.SHARE_TYPE_RECORD)]
        self.params = MagicMock()
        self.params.shared_folder_cache = {self.uid_a: {'shared_folder_uid': self.uid_a},
                                           self.uid_b: {'shared_folder_uid': self.uid_b}}

    def _run(self, **kwargs):
        app_info = MagicMock()
        app_info.shares = self.shares
        with patch('keepercommander.commands.ksm.KSMCommand.get_app_info', return_value=[app_info]), \
             patch('keepercommander.commands.register.ShareFolderCommand.prepare_request') as prepare, \
             patch('keepercommander.commands.register.ShareFolderCommand.send_requests') as send:
            KSMCommand._auto_share_app_folders(self.params, 'appUid', **kwargs)
        return prepare, send

    def test_only_folder_shares_are_shared(self):
        prepare, _ = self._run(users=['member@example.com'])
        shared = {c[0][2]['shared_folder_uid'] for c in prepare.call_args_list}
        self.assertEqual({self.uid_a, self.uid_b}, shared, 'the record share must not be sent')

    def test_folders_missing_from_the_cache_are_skipped(self):
        del self.params.shared_folder_cache[self.uid_b]
        prepare, _ = self._run(users=['member@example.com'])
        self.assertEqual(1, prepare.call_count)
        self.assertEqual(self.uid_a, prepare.call_args[0][2]['shared_folder_uid'])

    def test_grant_is_read_only_regardless_of_folder_defaults(self):
        prepare, _ = self._run(users=['member@example.com'])
        kwargs = prepare.call_args[0][1]
        self.assertEqual('grant', kwargs['action'])
        self.assertEqual('off', kwargs['manage_records'])
        self.assertEqual('off', kwargs['manage_users'])

    def test_users_and_teams_are_passed_to_the_request(self):
        prepare, _ = self._run(users=['member@example.com'])
        self.assertEqual(['member@example.com'], prepare.call_args[0][3])
        self.assertEqual([], prepare.call_args[0][4])
        prepare, _ = self._run(teams=['teamUid'])
        self.assertEqual([], prepare.call_args[0][3])
        self.assertEqual(['teamUid'], prepare.call_args[0][4])

    def test_requests_are_sent_in_one_batch(self):
        _, send = self._run(users=['member@example.com'])
        send.assert_called_once()
        batches = send.call_args[0][1]
        self.assertEqual(1, len(batches))
        self.assertEqual(2, len(batches[0]), 'one request per linked folder')

    def test_no_linked_folders_sends_nothing(self):
        self.shares = [s for s in self.shares if s.secretUid == self.record]
        prepare, send = self._run(users=['member@example.com'])
        prepare.assert_not_called()
        send.assert_not_called()

    def test_linked_folders_not_in_the_cache_send_nothing(self):
        self.params.shared_folder_cache = {}
        prepare, send = self._run(users=['member@example.com'])
        prepare.assert_not_called()
        send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
