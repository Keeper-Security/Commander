"""Step 1a chunk-level retry / sync_down reconcile and Step 2 DAG-error tolerance."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander import utils, vault
from keepercommander.commands.pam_import import batch_pipeline
from keepercommander.commands.pam_import.base import PamMachineObject, PamUserObject
from keepercommander.commands.pam_import.batch_pipeline import (
    BatchPamImportEngine,
    CreationTier,
    assign_uids,
)
from keepercommander.commands.pam_import.throttle_retry import (
    ChunkedAddError,
    chunked_with_retry,
)
from keepercommander.proto import record_pb2

UID_A = 'AAAAAAAAAAAAAAAAAAAAAA'
UID_B = 'BBBBBBBBBBBBBBBBBBBBBA'
UID_C = 'CCCCCCCCCCCCCCCCCCCCCA'


def _status(uid, status=record_pb2.RS_SUCCESS):
    r = record_pb2.RecordModifyStatus()
    r.record_uid = utils.base64_url_decode(uid)
    r.status = status
    return r


class TestChunkedWithRetry(unittest.TestCase):
    def setUp(self):
        self.params = MagicMock()
        self.params.rest_context = None

    def test_throttle_on_second_chunk_resends_only_that_chunk(self):
        calls = []

        def send(chunk):
            calls.append(list(chunk))
            if chunk == [3, 4] and calls.count([3, 4]) == 1:
                raise Exception('request throttled, try again')
            return [f'r{x}' for x in chunk]

        with patch('keepercommander.commands.pam_import.throttle_retry.time.sleep'):
            out = chunked_with_retry(self.params, [1, 2, 3, 4, 5], send, chunk_size=2)
        self.assertEqual(out, ['r1', 'r2', 'r3', 'r4', 'r5'])
        # chunk [1, 2] was sent exactly once; only [3, 4] was repeated
        self.assertEqual(calls, [[1, 2], [3, 4], [3, 4], [5]])

    def test_non_throttle_error_keeps_results_of_earlier_chunks(self):
        def send(chunk):
            if chunk == [3, 4]:
                raise RuntimeError('boom')
            return [f'r{x}' for x in chunk]

        with self.assertRaises(ChunkedAddError) as ctx:
            chunked_with_retry(self.params, [1, 2, 3, 4, 5], send, chunk_size=2)
        self.assertEqual(ctx.exception.results, ['r1', 'r2'])
        self.assertIsInstance(ctx.exception.cause, RuntimeError)


def _engine(extend_mode=False, project=None):
    params = MagicMock()
    params.record_cache = {}
    params.nested_share_records = {}
    params.nested_share_record_data = {}
    return BatchPamImportEngine(
        params, project or {}, [], [],
        users_folder_uid='sfu', resources_folder_uid='sfr',
        pam_cfg_uid='CFGUID', extend_mode=extend_mode,
    )


def _user(uid, generated=True):
    u = PamUserObject()
    u.uid = uid
    u.title = f'user-{uid[:1]}'
    if generated:
        u._uid_generated = True
    return u


class TestTierReconcile(unittest.TestCase):
    def _run_tier(self, eng, users, add_side_effect, in_vault):
        """Run _execute_tier_1a with classic adds mocked; ``in_vault`` lists UIDs present after sync."""
        def fake_sync(params, project=None):
            for uid in in_vault:
                params.record_cache[uid] = {}

        with patch.object(batch_pipeline, 'pam_object_to_typed_record', return_value=vault.TypedRecord()), \
             patch.object(batch_pipeline, 'is_nested_share_folder', return_value=False), \
             patch.object(batch_pipeline, 'add_record_to_folder', return_value=MagicMock()), \
             patch.object(batch_pipeline, '_populate_linked_keys'), \
             patch.object(batch_pipeline, 'execute_records_add_with_retry',
                          side_effect=add_side_effect) as add, \
             patch.object(batch_pipeline, 'sync_down_after_batch', side_effect=fake_sync) as sync:
            ok = eng._execute_tier_1a(
                CreationTier(name='tier0_global_users', objects=users), inserted_uids=set(),
            )
        return ok, add, sync

    def test_partial_chunk_failure_syncs_and_resends_only_missing(self):
        eng = _engine()
        a, b, c = _user(UID_A), _user(UID_B), _user(UID_C)
        # first attempt: only A answered, then a transport error
        first = ChunkedAddError([_status(UID_A)], RuntimeError('502'))
        # B actually landed server-side (found by sync), C must be re-sent
        second = [_status(UID_C)]
        ok, add, sync = self._run_tier(eng, [a, b, c], [first, second], in_vault=[UID_B])
        self.assertTrue(ok)
        self.assertEqual(add.call_count, 2)
        resent = add.call_args_list[1].args[1]
        self.assertEqual(len(resent), 1)   # only C
        for u in (a, b, c):
            self.assertEqual(u._batch_vault_status, 'created')

    def test_explicit_server_error_is_not_resent_and_aborts(self):
        eng = _engine()
        a = _user(UID_A)
        bad = _status(UID_A, record_pb2.RS_ACCESS_DENIED)
        ok, add, _sync = self._run_tier(eng, [a], [[bad]], in_vault=[])
        self.assertFalse(ok)
        add.assert_called_once()
        self.assertEqual(a._batch_vault_status, 'failed')

    def test_record_exists_for_generated_uid_is_accepted_in_import_mode(self):
        eng = _engine(extend_mode=False)
        a = _user(UID_A, generated=True)
        exists = _status(UID_A, record_pb2.RS_RECORD_EXISTS)
        ok, _add, _sync = self._run_tier(eng, [a], [[exists]], in_vault=[UID_A])
        self.assertTrue(ok)
        self.assertEqual(a._batch_vault_status, 'created')

    def test_record_exists_for_user_supplied_uid_still_fails_in_import_mode(self):
        eng = _engine(extend_mode=False)
        a = _user(UID_A, generated=False)
        exists = _status(UID_A, record_pb2.RS_RECORD_EXISTS)
        ok, _add, _sync = self._run_tier(eng, [a], [[exists]], in_vault=[UID_A])
        self.assertFalse(ok)

    def test_resend_gives_up_after_max_passes(self):
        eng = _engine()
        a = _user(UID_A)
        always_missing = [ChunkedAddError([], RuntimeError('503'))
                          for _ in range(batch_pipeline.MAX_TIER_RECONCILE_PASSES + 2)]
        ok, add, _sync = self._run_tier(eng, [a], always_missing, in_vault=[])
        self.assertFalse(ok)
        self.assertEqual(add.call_count, 1 + batch_pipeline.MAX_TIER_RECONCILE_PASSES)


class TestAssignUidsMarksGenerated(unittest.TestCase):
    def test_only_generated_uids_are_marked(self):
        gen = PamMachineObject()
        gen.uid = ''
        keep = PamMachineObject()
        keep.uid = UID_B
        assign_uids([gen, keep])
        self.assertTrue(getattr(gen, '_uid_generated', False))
        self.assertFalse(getattr(keep, '_uid_generated', False))


class TestStep2DagErrorsDoNotAbort(unittest.TestCase):
    def _run_step2(self, project, full_side_effect=None, flush_side_effect=None):
        mach = PamMachineObject()
        mach.uid = UID_A
        mach.title = 'M1'
        mach._extend_tag = 'new'
        eng = _engine(project=project)
        eng.resources = [mach]
        with patch.object(batch_pipeline, 'get_keeper_tokens', return_value=(b'a', b'b', b'c')), \
             patch.object(batch_pipeline, 'TunnelDAG', return_value=MagicMock()), \
             patch.object(batch_pipeline, 'configure_batch_tdag'), \
             patch.object(batch_pipeline, 'run_step2_full', side_effect=full_side_effect), \
             patch.object(batch_pipeline, 'add_jit_domain_links', return_value=False), \
             patch.object(batch_pipeline, 'flush_deferred_graph', side_effect=flush_side_effect), \
             patch.object(batch_pipeline, 'sync_down_after_batch'):
            self.assertTrue(eng._execute_step_2())
        return eng

    def test_resource_and_flush_errors_are_counted_not_raised(self):
        eng = self._run_step2(
            {'options': {'file_name': 'import.json'}},
            full_side_effect=RuntimeError('rotation failed'),
            flush_side_effect=RuntimeError('add_data 500'),
        )
        self.assertEqual(len(eng.dag_errors), 2)

    def test_summary_names_config_and_file(self):
        eng = _engine(project={'options': {'file_name': 'import.json'}})
        eng.dag_errors = ['x']
        with patch('sys.stderr') as err:
            eng._print_dag_error_summary()
        text = ''.join(c.args[0] for c in err.write.call_args_list if c.args)
        self.assertIn('pam project update --config=CFGUID --filename=import.json', text)

    def test_summary_placeholder_when_input_was_inline_json(self):
        eng = _engine(project={'options': {'file_name': '{"pam_data": {}}'}})
        eng.dag_errors = ['x']
        with patch('sys.stderr') as err:
            eng._print_dag_error_summary()
        text = ''.join(c.args[0] for c in err.write.call_args_list if c.args)
        self.assertIn('--filename=<import_extend.json>', text)

    def test_no_errors_prints_nothing(self):
        eng = _engine()
        with patch('sys.stderr') as err:
            eng._print_dag_error_summary()
        err.write.assert_not_called()


class TestMissingRecordsHint(unittest.TestCase):
    @staticmethod
    def _stderr_text(err):
        return ''.join(c.args[0] for c in err.write.call_args_list if c.args)

    def test_hint_suggests_extend_then_update(self):
        eng = _engine(project={'options': {'file_name': 'import.json'}})
        with patch('sys.stderr') as err:
            eng._print_missing_records_summary(failed=2, not_attempted=5)
        text = self._stderr_text(err)
        self.assertIn('2 record(s) could not be created', text)
        self.assertIn('5 more were not attempted', text)
        self.assertIn('pam project extend --config=CFGUID --filename=import.json', text)
        self.assertIn('pam project update --config=CFGUID --filename=import.json', text)

    def test_no_command_without_input_file(self):
        eng = _engine(project={'options': {'file_name': ''}})
        with patch('sys.stderr') as err:
            eng._print_missing_records_summary(failed=1, not_attempted=0)
            eng.dag_errors = ['x']
            eng._print_dag_error_summary()
        text = self._stderr_text(err)
        self.assertNotIn('pam project', text)

    def test_run_prints_hint_when_tier_fails(self):
        eng = _engine(project={'options': {'file_name': 'import.json'}})
        u1, u2 = _user(UID_A), _user(UID_B)
        tiers = [CreationTier('tier0_global_users', [u1]), CreationTier('tier1_resources', [u2])]
        with patch.object(eng, '_layer_b_hygiene'),              patch.object(batch_pipeline, 'assign_record_keys'),              patch.object(batch_pipeline, '_collect_create_objects', return_value=[]),              patch.object(batch_pipeline, 'iter_accessible_record_uids', return_value=[]),              patch.object(eng, 'build_plan', return_value=tiers),              patch.object(eng, '_execute_tier_1a', return_value=False),              patch.object(eng, '_print_missing_records_summary') as hint:
            self.assertFalse(eng.run())
        hint.assert_called_once_with(1, 1)   # first tier failed (1), second not attempted (1)


class TestStep1bc1cErrorsAreNotFatal(unittest.TestCase):
    def _engine_with_steps(self, b_summary=None, b_exc=None, c_summary=None, c_exc=None):
        eng = _engine(project={'options': {'file_name': 'import.json'}})
        u = _user(UID_A)
        u._batch_vault_status = 'created'
        eng.users = [u]
        eng.deferred_refs = [MagicMock()]
        patches = [
            patch.object(batch_pipeline, 'apply_deferred_ref_updates',
                         side_effect=b_exc, return_value=b_summary),
            patch.object(batch_pipeline, 'run_step_1c_for_objects',
                         side_effect=c_exc, return_value=c_summary),
            patch.object(batch_pipeline, '_collect_create_objects', return_value=[u]),
        ]
        return eng, patches

    def test_failures_and_skips_are_recorded_and_return_false(self):
        b = MagicMock(failures=[(UID_A, 'boom')], warnings=[(UID_B, 'target uid not in vault')])
        c = MagicMock(failures=[(UID_A, 'upload failed')], warnings=[(UID_A, 'parent record missing')],
                      uploaded_count=0)
        eng, patches = self._engine_with_steps(b_summary=b, c_summary=c)
        with patches[0], patches[1], patches[2]:
            self.assertFalse(eng._apply_deferred_ref_updates())
            self.assertFalse(eng._execute_step_1c())
        joined = ' | '.join(eng.vault_update_errors)
        for needle in ('Step 1b %s: boom' % UID_A, 'Step 1b skipped %s' % UID_B,
                       'Step 1c %s: upload failed' % UID_A, 'Step 1c skipped %s' % UID_A):
            self.assertIn(needle, joined)

    def test_exceptions_are_recorded(self):
        eng, patches = self._engine_with_steps(b_exc=RuntimeError('b'), c_exc=RuntimeError('c'))
        with patches[0], patches[1], patches[2]:
            self.assertFalse(eng._apply_deferred_ref_updates())
            self.assertFalse(eng._execute_step_1c())
        self.assertEqual(len(eng.vault_update_errors), 2)

    def test_run_continues_to_step2_and_suggests_update(self):
        eng, patches = self._engine_with_steps()
        eng.vault_update_errors = []

        def fail_1b():
            eng.vault_update_errors.append('Step 1b x: y')
            return False

        with patch.object(eng, '_layer_b_hygiene'),              patch.object(batch_pipeline, 'assign_record_keys'),              patch.object(batch_pipeline, '_collect_create_objects', return_value=[]),              patch.object(batch_pipeline, 'iter_accessible_record_uids', return_value=[]),              patch.object(eng, 'build_plan', return_value=[]),              patch.object(eng, '_apply_deferred_ref_updates', side_effect=fail_1b),              patch.object(eng, '_execute_step_1c', return_value=False),              patch.object(eng, '_execute_step_2', return_value=True) as step2,              patch('sys.stderr') as err:
            self.assertTrue(eng.run())
        step2.assert_called_once()
        text = ''.join(c.args[0] for c in err.write.call_args_list if c.args)
        self.assertIn('record update error(s)', text)
        self.assertIn('pam project update --config=CFGUID --filename=import.json', text)


if __name__ == '__main__':
    unittest.main()
