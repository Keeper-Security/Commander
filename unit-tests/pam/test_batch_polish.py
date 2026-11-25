"""Tests for rotation throttle and remaining batch pipeline polish."""
import time
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.pam_import.base import (
    PamMachineObject,
    PamUserObject,
)
from keepercommander.commands.pam_import.batch_pipeline import (
    BatchPamImportEngine,
)
from keepercommander.commands.pam_import.batch_step2 import _apply_rotation
from keepercommander.commands.pam_import.deferred_refs import MAX_NUMBER_OF_RECORD_LINKS
from keepercommander.commands.pam_import.rotation_throttle import RotationThrottle


MACH_UID = 'MMMMMMMMMMMMMMMMMMMMMA'
USER_UID = 'UUUUUUUUUUUUUUUUUUUUUA'


class TestRotationThrottle(unittest.TestCase):
    def test_pauses_every_tenth_call(self):
        throttle = RotationThrottle(batch_size=3, pause_seconds=0)
        with patch('keepercommander.commands.pam_import.rotation_throttle.time.sleep') as sleep:
            for _ in range(7):
                throttle.before_call()
            sleep.assert_called()
            self.assertEqual(sleep.call_count, 2)

    def test_is_throttle_error(self):
        self.assertTrue(RotationThrottle.is_throttle_error(Exception('Request throttled')))
        self.assertFalse(RotationThrottle.is_throttle_error(Exception('access denied')))


class TestApplyRotationThrottle(unittest.TestCase):
    def test_retries_on_throttle_error(self):
        params = MagicMock()
        prc = MagicMock()
        user = PamUserObject()
        user.uid = USER_UID
        user.rotation_settings = MagicMock()
        user.rotation_settings.enabled = 'off'
        user.rotation_settings.schedule = None
        user.rotation_settings.password_complexity = None
        mach = PamMachineObject()
        mach.uid = MACH_UID
        prc.execute.side_effect = [Exception('throttled'), None]
        throttle = RotationThrottle(batch_size=100, pause_seconds=0)
        with patch('keepercommander.commands.pam_import.throttle_retry.time.sleep'):
            _apply_rotation(
                params, prc, user, mach, USER_UID, 'CFG_UID',
                rotation_throttle=throttle,
            )
        self.assertEqual(prc.execute.call_count, 2)


class TestSimulateLinkCountWarnings(unittest.TestCase):
    def test_warns_when_projected_links_exceed_limit(self):
        params = MagicMock()
        params.record_cache = {}
        mach = PamMachineObject()
        mach.uid = MACH_UID
        engine = BatchPamImportEngine(
            params, {}, [], [mach],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        with patch.object(
            engine,
            '_project_record_link_counts',
            return_value={MACH_UID: MAX_NUMBER_OF_RECORD_LINKS + 1},
        ), patch.object(engine, 'build_plan', return_value=[]):
            plan = engine.simulate()
        self.assertEqual(len(plan['link_count_warnings']), 1)
        self.assertEqual(plan['link_count_warnings'][0]['record_uid'], MACH_UID)


class TestStep2SyncAfterFlush(unittest.TestCase):
    def test_step_2_syncs_down_after_graph_save(self):
        params = MagicMock()
        params.record_cache = {}
        engine = BatchPamImportEngine(
            params, {}, [], [],
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        tdag = MagicMock()
        tdag.linking_dag.save.return_value = None
        with patch(
            'keepercommander.commands.pam_import.batch_pipeline.get_keeper_tokens',
            return_value=('a', 'b', 'c'),
        ), patch(
            'keepercommander.commands.pam_import.batch_pipeline.TunnelDAG',
            return_value=tdag,
        ), patch(
            'keepercommander.commands.pam_import.batch_pipeline.configure_batch_tdag',
        ) as cfg_tdag, patch(
            'keepercommander.commands.pam_import.batch_pipeline.api.sync_down',
        ) as sync:
            self.assertTrue(engine._execute_step_2())
            cfg_tdag.assert_called_once_with(tdag)
            sync.assert_called_once_with(params)
            self.assertTrue(params.sync_data)

    def test_mid_flushes_every_n_resources(self):
        params = MagicMock()
        params.record_cache = {}
        resources = []
        for i in range(120):
            mach = PamMachineObject()
            mach.uid = f'M{"%021d" % i}'[:22]
            mach._extend_tag = 'new'
            resources.append(mach)
        engine = BatchPamImportEngine(
            params, {}, [], resources,
            users_folder_uid='sfu',
            resources_folder_uid='sfr',
            pam_cfg_uid='cfg',
        )
        tdag = MagicMock()
        tdag.linking_dag.save.return_value = None
        with patch(
            'keepercommander.commands.pam_import.batch_pipeline.get_keeper_tokens',
            return_value=('a', 'b', 'c'),
        ), patch(
            'keepercommander.commands.pam_import.batch_pipeline.TunnelDAG',
            return_value=tdag,
        ), patch(
            'keepercommander.commands.pam_import.batch_pipeline.configure_batch_tdag',
        ), patch(
            'keepercommander.commands.pam_import.batch_pipeline.run_step2_full',
        ), patch(
            'keepercommander.commands.pam_import.batch_pipeline.add_jit_domain_links',
            return_value=False,
        ), patch(
            'keepercommander.commands.pam_import.batch_pipeline.PAM_DAG_FLUSH_EVERY',
            50,
        ), patch(
            'keepercommander.commands.pam_import.batch_pipeline.api.sync_down',
        ), patch(
            'sys.stderr',
        ):
            self.assertTrue(engine._execute_step_2())
        # mid @50, mid @100, plus final flush
        self.assertEqual(tdag.linking_dag.save.call_count, 3)

    def test_flush_deferred_graph_halves_batch_on_500(self):
        from keepercommander.commands.pam_import.batch_pipeline import flush_deferred_graph
        from keepercommander.keeper_dag.exceptions import DAGConnectionException

        params = MagicMock()
        tdag = MagicMock()
        tdag.linking_dag.save_batch_count = 50
        calls = {'n': 0}

        def _save():
            calls['n'] += 1
            if calls['n'] == 1:
                raise DAGConnectionException(
                    'Call to graph web service https://x/api/user/add_data, '
                    'after 5 attempts, failed!: 500, ; Internal server error'
                )
            return None

        tdag.linking_dag.save.side_effect = _save
        with patch(
            'keepercommander.commands.pam_import.batch_pipeline.call_with_throttle_retry',
            side_effect=lambda fn, **kwargs: fn(),
        ):
            flush_deferred_graph(tdag, params, label='test flush')
        self.assertEqual(calls['n'], 2)
        self.assertEqual(tdag.linking_dag.save_batch_count, 25)


if __name__ == '__main__':
    unittest.main()
