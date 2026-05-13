import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.orchestrator import (
    Checkpoint,
    Orchestrator,
    OrchestratorContext,
    STAGE_ORDER,
    Stage,
    Status,
    choose_stage_range,
    compute_resume_stage,
)


class ChooseStageRangeTests(unittest.TestCase):
    def test_full_range_when_no_bounds(self):
        self.assertEqual(choose_stage_range(None, None), STAGE_ORDER)

    def test_start_only(self):
        self.assertEqual(choose_stage_range(Stage.STRUCTURE, None),
                         [Stage.STRUCTURE, Stage.RECORDS, Stage.VERIFY,
                          Stage.RECONCILE, Stage.GATE])

    def test_end_only(self):
        self.assertEqual(choose_stage_range(None, Stage.STRUCTURE),
                         [Stage.PLAN, Stage.USERS, Stage.STRUCTURE])

    def test_both_bounds_inclusive(self):
        self.assertEqual(
            choose_stage_range(Stage.USERS, Stage.RECORDS),
            [Stage.USERS, Stage.STRUCTURE, Stage.RECORDS],
        )

    def test_unknown_stage_raises(self):
        with self.assertRaises(ValueError):
            choose_stage_range('bogus', None)

    def test_start_after_end_raises(self):
        with self.assertRaises(ValueError):
            choose_stage_range(Stage.GATE, Stage.PLAN)


class ComputeResumeStageTests(unittest.TestCase):
    def test_no_checkpoint_starts_at_first_stage(self):
        self.assertEqual(compute_resume_stage(None), STAGE_ORDER[0])

    def test_passed_advances(self):
        self.assertEqual(
            compute_resume_stage({'PHASE': Stage.PLAN, 'STATUS': Status.PASSED}),
            Stage.USERS,
        )

    def test_skipped_advances(self):
        self.assertEqual(
            compute_resume_stage({'PHASE': Stage.USERS, 'STATUS': Status.SKIPPED}),
            Stage.STRUCTURE,
        )

    def test_failed_repeats_same_stage(self):
        self.assertEqual(
            compute_resume_stage({'PHASE': Stage.STRUCTURE, 'STATUS': Status.FAILED}),
            Stage.STRUCTURE,
        )

    def test_paused_repeats_same_stage(self):
        self.assertEqual(
            compute_resume_stage({'PHASE': Stage.RECORDS, 'STATUS': Status.PAUSED}),
            Stage.RECORDS,
        )

    def test_final_stage_passed_returns_none(self):
        self.assertIsNone(
            compute_resume_stage({'PHASE': Stage.GATE, 'STATUS': Status.AUTHORIZED}),
        )

    def test_unknown_phase_restarts_from_beginning(self):
        self.assertEqual(
            compute_resume_stage({'PHASE': 'unknown', 'STATUS': Status.PASSED}),
            STAGE_ORDER[0],
        )


class CheckpointTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.NamedTemporaryFile(suffix='.state', delete=False) as t:
            path = t.name
        try:
            cp = Checkpoint(path)
            cp.write(Stage.USERS, Status.PASSED)
            state = cp.read()
            self.assertEqual(state['PHASE'], Stage.USERS)
            self.assertEqual(state['STATUS'], Status.PASSED)
            self.assertIn('TIMESTAMP', state)
        finally:
            os.unlink(path)

    def test_missing_file_returns_none(self):
        self.assertIsNone(Checkpoint('/nonexistent/path').read())


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cp_path = os.path.join(self.tmp, '.state')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make(self, stages):
        return Orchestrator(stages, self.cp_path)

    def test_run_all_stages_happy_path(self):
        called = []

        def make(name):
            def fn(ctx):
                called.append(name)
                return Status.PASSED
            return fn

        stages = {s: make(s) for s in STAGE_ORDER}
        orch = self._make(stages)
        ctx = OrchestratorContext()
        orch.run(ctx)
        self.assertEqual(called, STAGE_ORDER)
        self.assertEqual(len(ctx.stage_results), len(STAGE_ORDER))
        last = ctx.stage_results[-1]
        self.assertEqual(last['stage'], Stage.GATE)

    def test_missing_handler_is_skipped(self):
        stages = {Stage.PLAN: lambda ctx: Status.PASSED}
        orch = self._make(stages)
        ctx = OrchestratorContext()
        orch.run(ctx, end_stage=Stage.USERS)
        statuses = [r['status'] for r in ctx.stage_results]
        self.assertEqual(statuses, [Status.PASSED, Status.SKIPPED])

    def test_failed_stage_stops_the_pipeline(self):
        called = []

        def fail_stage(ctx):
            called.append(Stage.STRUCTURE)
            return Status.FAILED

        stages = {
            Stage.PLAN: lambda ctx: Status.PASSED,
            Stage.USERS: lambda ctx: Status.PASSED,
            Stage.STRUCTURE: fail_stage,
            Stage.RECORDS: lambda ctx: called.append(Stage.RECORDS),
        }
        orch = self._make(stages)
        ctx = OrchestratorContext()
        orch.run(ctx)
        self.assertNotIn(Stage.RECORDS, called)
        self.assertEqual(ctx.stage_results[-1]['status'], Status.FAILED)

    def test_exception_captured_and_run_halts(self):
        def boom(ctx):
            raise RuntimeError('kaboom')

        stages = {Stage.PLAN: boom, Stage.USERS: lambda ctx: Status.PASSED}
        orch = self._make(stages)
        ctx = OrchestratorContext()
        orch.run(ctx)
        self.assertEqual(ctx.stage_results[-1]['status'], Status.FAILED)
        self.assertIn('kaboom', ctx.stage_results[-1]['notes'])

    def test_resume_skips_completed_stages(self):
        # Seed checkpoint as if PLAN + USERS already passed
        Checkpoint(self.cp_path).write(Stage.USERS, Status.PASSED)
        called = []
        stages = {s: (lambda s_=s: (lambda ctx: (called.append(s_), Status.PASSED)[1]))()
                  for s in STAGE_ORDER}
        orch = self._make(stages)
        orch.run(OrchestratorContext(), resume=True, end_stage=Stage.STRUCTURE)
        self.assertEqual(called, [Stage.STRUCTURE])

    def test_save_state_writes_json(self):
        stages = {Stage.PLAN: lambda ctx: Status.PASSED}
        orch = self._make(stages)
        ctx = OrchestratorContext()
        orch.run(ctx, end_stage=Stage.PLAN)
        out_dir = os.path.join(self.tmp, 'out')
        path = orch.save_state(ctx, out_dir)
        self.assertTrue(os.path.exists(path))


if __name__ == '__main__':
    unittest.main()
