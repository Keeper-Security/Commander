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


if __name__ == '__main__':
    unittest.main()
