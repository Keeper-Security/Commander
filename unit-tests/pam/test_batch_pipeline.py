"""Unit tests for PAM batch import pipeline (Phase A foundation)."""
import os
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.pam._layer_b import (
    clear_layer_b_feature_cache,
    is_layer_b_feature_disabled,
    mark_layer_b_feature_disabled,
)
from keepercommander.commands.pam_import.base import (
    ConnectionSettingsHTTP,
    ConnectionSettingsSSH,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamRemoteBrowserSettings,
    PamSettingsFieldData,
    PamUserObject,
)
from keepercommander.commands.pam_import.batch_attachments import BatchAttachmentSummary
from keepercommander.commands.pam_import.batch_pipeline import (
    BatchPamImportEngine,
    assign_record_keys,
    assign_uids,
    build_creation_plan,
    _parse_batch_results,
)
from keepercommander.proto import record_pb2
from keepercommander.commands.pam_import.deferred_refs import (
    DeferredRefApplySummary,
    DeferredRefUpdate,
)
from keepercommander.recordv3 import RecordV3

CONFIG_UID = 'CCCCCCCCCCCCCCCCCCCCCC'
MACH_UID = 'MMMMMMMMMMMMMMMMMMMMMA'
TEST_ROUTER_URL = 'http://test-krouter-batch'


class TestAssignUids(unittest.TestCase):
    def test_assign_uids_preserves_valid_json_uid(self):
        mach = PamMachineObject()
        mach.uid = 'AAAAAAAAAAAAAAAAAAAAAA'
        mach._extend_tag = 'new'
        assign_uids([mach], only_new=False)
        self.assertEqual(mach.uid, 'AAAAAAAAAAAAAAAAAAAAAA')

    def test_assign_uids_skips_existing_on_extend(self):
        mach = PamMachineObject()
        mach.uid = ''
        mach._extend_tag = 'existing'
        assign_uids([mach], only_new=True)
        self.assertEqual(mach.uid, '')

    def test_assign_uids_generates_for_new(self):
        mach = PamMachineObject()
        mach.uid = ''
        mach._extend_tag = 'new'
        assign_uids([mach], only_new=True)
        self.assertTrue(RecordV3.is_valid_ref_uid(mach.uid))


class TestBuildCreationPlan(unittest.TestCase):
    def test_tier_order_users_before_resources(self):
        user = PamUserObject()
        user.uid = 'UUUUUUUUUUUUUUUUUUUUUU'
        user._extend_tag = 'new'
        mach = PamMachineObject()
        mach.uid = 'RRRRRRRRRRRRRRRRRRRRRR'
        mach._extend_tag = 'new'
        mach.users = [user]
        tiers = build_creation_plan([], [mach], only_new=True)
        names = [t.name for t in tiers]
        self.assertIn('tier1_nested_users', names)
        self.assertIn('resources', names)
        self.assertLess(names.index('tier1_nested_users'), names.index('resources'))

    def test_cycle_detection_raises(self):
        a = PamMachineObject()
        a.uid = 'AAAAAAAAAAAAAAAAAAAAAA'
        a._extend_tag = 'new'
        b = PamMachineObject()
        b.uid = 'BBBBBBBBBBBBBBBBBBBBBB'
        b._extend_tag = 'new'
        # Simulate circular sftpResourceUid dependency
        class _Conn:
            userRecordUid = None
        class _Ps:
            connection = _Conn()
        a.pam_settings = _Ps()
        b.pam_settings = _Ps()
        with patch('keepercommander.commands.pam_import.batch_pipeline.get_sftp_attribute') as gs:
            gs.side_effect = lambda obj, name: {
                (a, 'sftpResourceUid'): b.uid,
                (b, 'sftpResourceUid'): a.uid,
            }.get((obj, name), '')
            with self.assertRaises(ValueError):
                build_creation_plan([], [a, b], only_new=True)

    def test_rbi_http_credentials_uid_list_does_not_crash_plan(self):
        """autofill resolve stores httpCredentialsUid as a list — must not set().add(list)."""
        login = PamUserObject()
        login.uid = 'LLLLLLLLLLLLLLLLLLLLLL'
        login._extend_tag = 'new'
        rbi = PamRemoteBrowserObject()
        rbi.uid = 'RRRRRRRRRRRRRRRRRRRRRR'
        rbi._extend_tag = 'new'
        rbi.title = 'RBI'
        rbi.rbiUrl = 'https://example.com'
        conn = ConnectionSettingsHTTP()
        conn.httpCredentialsUid = [login.uid]
        rbi.rbi_settings = PamRemoteBrowserSettings(connection=conn)
        # Must not raise TypeError: unhashable type: 'list'
        tiers = build_creation_plan([login], [rbi], only_new=True)
        names = [t.name for t in tiers]
        self.assertIn('tier0_global_users', names)
        self.assertIn('resources', names)

    def test_sftp_self_resource_uid_ignored(self):
        """sftp_resource pointing at the same machine must not abort as a cycle."""
        mach = PamMachineObject()
        mach.uid = 'AAAAAAAAAAAAAAAAAAAAAA'
        mach._extend_tag = 'new'
        mach.title = 'SelfSftp'
        class _Conn:
            userRecordUid = None
        class _Ps:
            connection = _Conn()
        mach.pam_settings = _Ps()
        with patch('keepercommander.commands.pam_import.batch_pipeline.get_sftp_attribute') as gs:
            gs.side_effect = lambda obj, name: mach.uid if name == 'sftpResourceUid' else ''
            tiers = build_creation_plan([], [mach], only_new=True)
        self.assertEqual([t.name for t in tiers], ['resources'])
        self.assertEqual(tiers[0].objects[0].uid, mach.uid)


class TestBatchEngineStep1bAbort(unittest.TestCase):
    def test_run_continues_and_records_1b_failure(self):
        params = MagicMock()
        params.record_cache = {}
        mach_uid = 'MMMMMMMMMMMMMMMMMMMMMA'
        user_uid = 'UUUUUUUUUUUUUUUUUUUUUA'
        engine = BatchPamImportEngine(
            params, {}, [], [],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        engine.deferred_refs = [
            DeferredRefUpdate(
                record_uid=mach_uid,
                settings_field='pamSettings',
                json_path=('connection', 'userRecords'),
                value=[user_uid],
            ),
        ]
        with patch.object(engine, 'build_plan', return_value=[]), \
             patch.object(engine, '_layer_b_hygiene'), \
             patch.object(engine, '_execute_step_1c'), \
             patch.object(engine, '_execute_step_2', return_value=True) as step2, \
             patch('keepercommander.commands.pam_import.batch_pipeline.apply_deferred_ref_updates') as apply:
            apply.return_value = DeferredRefApplySummary(failures=[(mach_uid, 'RS_ACCESS_DENIED')])
            # Records exist: a 1b failure is tracked (for `pam project update`), not fatal.
            self.assertTrue(engine.run())
            apply.assert_called_once()
            step2.assert_called_once()
            self.assertEqual(len(engine.vault_update_errors), 1)


class TestBatchPamImportEngineSimulate(unittest.TestCase):
    def test_simulate_reports_deferred_refs_for_unbatched_targets(self):
        params = MagicMock()
        params.record_cache = {}
        mach = PamMachineObject()
        mach.uid = 'MMMMMMMMMMMMMMMMMMMMMA'
        mach._extend_tag = 'new'
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsSSH(port='22')
        conn.userRecordUid = ['UUUUUUUUUUUUUUUUUUUUUA']
        mach.pam_settings.connection = conn
        engine = BatchPamImportEngine(
            params, {}, [], [mach],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        plan = engine.simulate()
        self.assertEqual(plan['deferred_ref_count'], 1)
        self.assertEqual(plan['deferred_refs'][0]['json_path'], ['connection', 'userRecords'])

    def test_simulate_zero_deferred_refs_when_nested_user_precedes_resource(self):
        params = MagicMock()
        params.record_cache = {}
        user = PamUserObject()
        user.uid = 'UUUUUUUUUUUUUUUUUUUUUA'
        user._extend_tag = 'new'
        mach = PamMachineObject()
        mach.uid = 'MMMMMMMMMMMMMMMMMMMMMA'
        mach._extend_tag = 'new'
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsSSH(port='22')
        conn.userRecordUid = [user.uid]
        mach.pam_settings.connection = conn
        mach.users = [user]
        engine = BatchPamImportEngine(
            params, {}, [], [mach],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        plan = engine.simulate()
        self.assertEqual(plan['deferred_ref_count'], 0)

    def test_simulate_returns_plan_without_writes(self):
        params = MagicMock()
        params.record_cache = {}
        mach = PamMachineObject()
        mach.uid = 'MMMMMMMMMMMMMMMMMMMMMM'
        mach._extend_tag = 'new'
        engine = BatchPamImportEngine(
            params, {}, [], [mach],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        plan = engine.simulate()
        self.assertIn('tiers', plan)
        self.assertIn('step2_dispatch', plan)


class TestBatchEngineStep1cAbort(unittest.TestCase):
    def test_run_continues_and_records_1c_failure(self):
        params = MagicMock()
        params.record_cache = {}
        mach = PamMachineObject()
        mach.uid = 'MMMMMMMMMMMMMMMMMMMMMA'
        mach._extend_tag = 'new'
        mach._batch_vault_status = 'created'
        engine = BatchPamImportEngine(
            params, {}, [], [mach],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        with patch.object(engine, 'build_plan', return_value=[]), \
             patch.object(engine, '_layer_b_hygiene'), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.run_step_1c_for_objects',
             ) as step1c, \
             patch.object(engine, '_execute_step_2', return_value=True):
            step1c.return_value = BatchAttachmentSummary(failures=[(mach.uid, 'PUT upload failed')])
            self.assertTrue(engine.run())
            step1c.assert_called_once()
            self.assertEqual(len(engine.vault_update_errors), 1)


class TestLayerBHygiene(unittest.TestCase):
    def test_run_clears_cache_and_warns_on_fallback_env(self):
        params = MagicMock()
        params.record_cache = {}
        engine = BatchPamImportEngine(
            params, {}, [], [],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch('keepercommander.commands.pam_import.batch_pipeline.clear_layer_b_feature_cache') as clc, \
             patch.object(engine, 'build_plan', return_value=[]), \
             patch.object(engine, '_execute_step_1c'), \
             patch.object(engine, '_execute_step_2', return_value=True):
            self.assertTrue(engine.run())
            clc.assert_called_once()


class TestLayerBWarmCacheIntegration(unittest.TestCase):
    """Phase C: stale Layer-B 404 cache from a prior CLI must not block batch Step 2."""

    def setUp(self):
        clear_layer_b_feature_cache()

    def tearDown(self):
        clear_layer_b_feature_cache()

    def _engine_with_new_machine(self):
        params = MagicMock()
        params.record_cache = {MACH_UID: {}}
        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach._extend_tag = 'new'
        mach.users = []
        engine = BatchPamImportEngine(
            params, {}, [], [mach],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid=CONFIG_UID,
        )
        return engine, params

    @staticmethod
    def _build_tdag(params):
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG

        tg = TunnelDAG.__new__(TunnelDAG)
        tg.params = params
        tg.record = MagicMock()
        tg.record.record_uid = CONFIG_UID
        tg.linking_dag = MagicMock()
        tg.linking_dag.has_graph = True
        resource_vertex = MagicMock()
        resource_vertex.vertex_type = 'PAM_MACHINE'
        tg.linking_dag.get_vertex.return_value = resource_vertex
        tg.linking_dag.add_vertex.return_value = resource_vertex
        tg._defer_saves = False
        tg._persist_graph = MagicMock()
        tg.resource_belongs_to_config = MagicMock(return_value=True)
        tg.link_resource_to_config = MagicMock()
        return tg

    def test_run_clears_warm_cache_and_step2_uses_legacy_dag(self):
        """Warm 404 cache is cleared at run start; Step 2 forces legacy Layer-B
        (deferred graph flush) so configure_resource is not called."""
        configure_calls = []

        def _capture_configure_resource(_params, rq):
            configure_calls.append(rq)

        engine, params = self._engine_with_new_machine()
        tdag = self._build_tdag(params)

        with patch.dict(os.environ, {
            'KEEPER_DAG_LB_FALLBACK': '1',
            'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300',
        }), \
             patch(
                 'keepercommander.commands.pam.router_helper.get_router_url',
                 return_value=TEST_ROUTER_URL,
             ), \
             patch(
                 'keepercommander.commands.tunnel.port_forward.TunnelGraph.get_vertex_content',
                 return_value=None,
             ), \
             patch.object(engine, 'build_plan', return_value=[]), \
             patch.object(engine, '_execute_step_1c', return_value=True), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.get_keeper_tokens',
                 return_value=('sess', 'trans', b'key'),
             ), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.TunnelDAG',
                 return_value=tdag,
             ), \
             patch(
                 'keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch',
             ), \
             patch(
                 'keepercommander.commands.pam.router_helper.router_configure_resource',
                 side_effect=_capture_configure_resource,
             ), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.sync_down_after_batch',
             ), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.call_with_throttle_retry',
                 side_effect=lambda fn, **kwargs: fn(),
             ):
            mark_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_resource')
            self.assertTrue(
                is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_resource'),
            )

            self.assertTrue(engine.run())

            self.assertFalse(
                is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_resource'),
                'engine.run() must clear a warm 404 cache; Step 2 force-legacy must end cleared',
            )
            self.assertEqual(
                configure_calls, [],
                'Batch Step 2 must not call configure_resource (legacy deferred DAG only)',
            )
            tdag._persist_graph.assert_called()

    def test_stale_cache_without_hygiene_skips_configure_resource(self):
        configure_calls = []
        engine, params = self._engine_with_new_machine()
        tdag = self._build_tdag(params)

        with patch.dict(os.environ, {
            'KEEPER_DAG_LB_FALLBACK': '1',
            'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300',
        }), \
             patch(
                 'keepercommander.commands.pam.router_helper.get_router_url',
                 return_value=TEST_ROUTER_URL,
             ), \
             patch(
                 'keepercommander.commands.tunnel.port_forward.TunnelGraph.get_vertex_content',
                 return_value=None,
             ), \
             patch.object(engine, 'build_plan', return_value=[]), \
             patch.object(engine, '_layer_b_hygiene'), \
             patch.object(engine, '_execute_step_1c', return_value=True), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.get_keeper_tokens',
                 return_value=('sess', 'trans', b'key'),
             ), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.TunnelDAG',
                 return_value=tdag,
             ), \
             patch(
                 'keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch',
             ), \
             patch(
                 'keepercommander.commands.pam.router_helper.router_configure_resource',
                 side_effect=lambda _p, rq: configure_calls.append(rq),
             ), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.sync_down_after_batch',
             ), \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.call_with_throttle_retry',
                 side_effect=lambda fn, **kwargs: fn(),
             ):
            mark_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_resource')
            self.assertTrue(engine.run())

            self.assertTrue(
                is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_resource'),
            )
            self.assertEqual(configure_calls, [])
            tdag._persist_graph.assert_called()


class TestParseBatchResultsExtend(unittest.TestCase):
    def test_rs_record_exists_treated_as_success_when_in_vault(self):
        params = MagicMock()
        params.record_cache = {'UUUUUUUUUUUUUUUUUUUUUA': {}}
        user = PamUserObject()
        user.uid = 'UUUUUUUUUUUUUUUUUUUUUA'
        user.title = 'u1'
        from keepercommander import utils
        rs = MagicMock()
        rs.record_uid = utils.base64_url_decode(user.uid)
        rs.status = record_pb2.RS_RECORD_EXISTS
        summary = _parse_batch_results(
            params, [user], [rs], extend_mode=True,
        )
        self.assertEqual(summary.successes, [user.uid])
        self.assertEqual(user._batch_vault_status, 'created')

    def test_rs_record_exists_fails_when_not_in_vault(self):
        params = MagicMock()
        params.record_cache = {}
        user = PamUserObject()
        user.uid = 'UUUUUUUUUUUUUUUUUUUUUA'
        from keepercommander import utils
        rs = MagicMock()
        rs.record_uid = utils.base64_url_decode(user.uid)
        rs.status = record_pb2.RS_RECORD_EXISTS
        summary = _parse_batch_results(
            params, [user], [rs], extend_mode=False,
        )
        self.assertEqual(len(summary.failures), 1)


class TestStep2DotProgress(unittest.TestCase):
    def test_multiline_milestones_and_remainder(self):
        from io import StringIO
        from keepercommander.commands.pam_import.batch_pipeline import _Step2DotProgress

        # start() + ETA samples at 100/200/300/400/500 (not at final 520)
        times = iter([0.0, 100.0, 200.0, 300.0, 400.0, 500.0])
        buf = StringIO()
        with patch('sys.stderr', buf), patch(
            'keepercommander.commands.pam_import.batch_pipeline.time.monotonic',
            side_effect=lambda: next(times),
        ):
            p = _Step2DotProgress(total=520, milestone=100)
            for _ in range(520):
                p.tick()
            p.finish(ok=True)
        lines = buf.getvalue().splitlines()
        self.assertEqual(
            lines[0],
            'Setting up DAG (0/520)' + ('.' * 99) + '100 7m left',
        )
        self.assertEqual(
            lines[1],
            'Setting up DAG (100/520)' + ('.' * 99) + '200 5m left',
        )
        self.assertEqual(
            lines[4],
            'Setting up DAG (400/520)' + ('.' * 99) + '500 20s left',
        )
        self.assertEqual(
            lines[5],
            'Setting up DAG (500/520)' + ('.' * 19) + '520 done (520 resource(s))',
        )

    def test_exact_milestone_total_no_extra_line(self):
        from io import StringIO
        from keepercommander.commands.pam_import.batch_pipeline import _Step2DotProgress

        # start() + ETA at 100 only (200 is final — no ETA)
        times = iter([0.0, 100.0])
        buf = StringIO()
        with patch('sys.stderr', buf), patch(
            'keepercommander.commands.pam_import.batch_pipeline.time.monotonic',
            side_effect=lambda: next(times),
        ):
            p = _Step2DotProgress(total=200, milestone=100)
            for _ in range(200):
                p.tick()
            p.finish(ok=True)
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(
            lines[0],
            'Setting up DAG (0/200)' + ('.' * 99) + '100 1m left',
        )
        self.assertEqual(
            lines[1],
            'Setting up DAG (100/200)' + ('.' * 99) + '200 done (200 resource(s))',
        )

    def test_no_eta_when_total_below_milestone(self):
        from io import StringIO
        from keepercommander.commands.pam_import.batch_pipeline import _Step2DotProgress

        buf = StringIO()
        with patch('sys.stderr', buf):
            p = _Step2DotProgress(total=50, milestone=100)
            for _ in range(50):
                p.tick()
            p.finish(ok=True)
        # No ETA tokens after the final count (before " done")
        body, _, _ = buf.getvalue().partition(' done')
        self.assertTrue(body.endswith('50'))

    def test_format_eta(self):
        from keepercommander.commands.pam_import.batch_pipeline import _Step2DotProgress

        self.assertEqual(_Step2DotProgress._format_eta(45), '45s left')
        self.assertEqual(_Step2DotProgress._format_eta(32 * 60), '32m left')
        self.assertEqual(_Step2DotProgress._format_eta(3600 + 56 * 60), '1h56m left')
        self.assertEqual(_Step2DotProgress._format_eta(7200), '2h left')
        # Sub-minute remainder floors to whole minutes when >= 60s
        self.assertEqual(_Step2DotProgress._format_eta(100), '1m left')


class TestRecordAddProgress(unittest.TestCase):
    def test_announces_immediately_before_chunks(self):
        from io import StringIO
        from keepercommander.commands.pam_import.batch_pipeline import _RecordAddProgress

        buf = StringIO()
        with patch('sys.stderr', buf):
            p = _RecordAddProgress('Resource records', total=2000)
            p.start()
            self.assertEqual(buf.getvalue(), 'Resource records (2000)...')
            p.tick_n(999)
            self.assertEqual(buf.getvalue(), 'Resource records (2000)...999')
            p.tick_n(999)
            p.tick_n(2)
            p.finish(ok=True)
        self.assertEqual(
            buf.getvalue(),
            'Resource records (2000)...999...1998...2000\n',
        )

    def test_announces_total_and_chunk_counts(self):
        from io import StringIO
        from keepercommander.commands.pam_import.batch_pipeline import _RecordAddProgress

        buf = StringIO()
        with patch('sys.stderr', buf):
            p = _RecordAddProgress('User records', total=2500)
            p.start()
            p.tick_n(999)
            p.tick_n(999)
            p.tick_n(502)
            p.finish(ok=True)
        out = buf.getvalue()
        self.assertEqual(
            out,
            'User records (2500)...999...1998...2500\n',
        )

    def test_single_chunk_below_api_max(self):
        from io import StringIO
        from keepercommander.commands.pam_import.batch_pipeline import _RecordAddProgress

        buf = StringIO()
        with patch('sys.stderr', buf):
            p = _RecordAddProgress('Resource records', total=490)
            p.tick_n(490)
            p.finish(ok=True)
        out = buf.getvalue()
        self.assertEqual(out, 'Resource records (490)...490\n')


class TestSimulateNoSideEffects(unittest.TestCase):
    def test_simulate_never_calls_vault_or_layer_b_hygiene(self):
        params = MagicMock()
        params.record_cache = {}
        engine = BatchPamImportEngine(
            params, {}, [], [],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        with patch(
            'keepercommander.commands.pam_import.batch_pipeline.imp_exp.execute_records_add',
        ) as add, patch(
            'keepercommander.commands.pam_import.batch_pipeline.clear_layer_b_feature_cache',
        ) as clc:
            engine.simulate()
            add.assert_not_called()
            clc.assert_not_called()


if __name__ == '__main__':
    unittest.main()
