"""Tests for the resumable-loop checkpoint protocol."""

import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate import checkpoint


class TestHashRows(unittest.TestCase):
    def test_stable_across_key_order(self):
        a = checkpoint.hash_rows([{'x': 1, 'y': 2}])
        b = checkpoint.hash_rows([{'y': 2, 'x': 1}])
        self.assertEqual(a, b)

    def test_different_rows_yield_different_hash(self):
        a = checkpoint.hash_rows([{'x': 1}])
        b = checkpoint.hash_rows([{'x': 2}])
        self.assertNotEqual(a, b)

    def test_empty_list_has_stable_hash(self):
        a = checkpoint.hash_rows([])
        b = checkpoint.hash_rows([])
        self.assertEqual(a, b)


class TestResumeFrom(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.run_dir = self._td.name

    def _ckpt(self, stage='records-shares'):
        return checkpoint.Checkpoint(stage, self.run_dir)

    def test_no_checkpoint_starts_at_one(self):
        ck = self._ckpt()
        self.assertEqual(
            ck.resume_from([{'a': 1}, {'a': 2}], resume=True,
                           force_restart=False),
            1,
        )

    def test_matching_checkpoint_resumes(self):
        rows = [{'r': i} for i in range(10)]
        sha = checkpoint.hash_rows(rows)
        ck = self._ckpt()
        ck.mark_done(3, input_sha256=sha)
        self.assertEqual(
            ck.resume_from(rows, resume=True, force_restart=False),
            4,
        )

    def test_mismatched_input_refuses_without_force_restart(self):
        original = [{'a': 1}]
        changed = [{'a': 2}]
        ck = self._ckpt()
        ck.mark_done(1, input_sha256=checkpoint.hash_rows(original))
        with self.assertRaises(checkpoint.CheckpointMismatchError):
            ck.resume_from(changed, resume=True, force_restart=False)

    def test_force_restart_clears_and_starts_fresh(self):
        rows = [{'a': 1}]
        sha = checkpoint.hash_rows(rows)
        ck = self._ckpt()
        ck.mark_done(1, input_sha256=sha)
        # Even with an input mismatch, force_restart wipes the ckpt.
        self.assertEqual(
            ck.resume_from([{'a': 2}], resume=True, force_restart=True),
            1,
        )
        self.assertFalse(os.path.exists(ck.path))

    def test_resume_false_warns_and_restarts(self):
        rows = [{'a': 1}, {'a': 2}]
        sha = checkpoint.hash_rows(rows)
        ck = self._ckpt()
        ck.mark_done(1, input_sha256=sha)
        # Not opting in — run from the top, don't silently skip.
        self.assertEqual(
            ck.resume_from(rows, resume=False, force_restart=False),
            1,
        )


class TestMarkDonePersistence(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.run_dir = self._td.name

    def test_mark_done_writes_atomic_file_with_0600(self):
        ck = checkpoint.Checkpoint('records-shares', self.run_dir)
        ck.mark_done(5, input_sha256='abc')
        self.assertTrue(os.path.exists(ck.path))
        mode = os.stat(ck.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        with open(ck.path) as f:
            data = json.load(f)
        self.assertEqual(data['last_index'], 5)
        self.assertEqual(data['input_sha256'], 'abc')
        self.assertEqual(data['stage'], 'records-shares')

    def test_mark_done_preserves_started_at_across_updates(self):
        ck = checkpoint.Checkpoint('records-shares', self.run_dir)
        ck.mark_done(1, input_sha256='abc')
        first = ck.load()['started_at']
        # Second update — started_at must not drift
        ck.mark_done(2, input_sha256='abc')
        second = ck.load()['started_at']
        self.assertEqual(first, second)

    def test_clear_removes_file(self):
        ck = checkpoint.Checkpoint('records-shares', self.run_dir)
        ck.mark_done(1, input_sha256='abc')
        ck.clear()
        self.assertFalse(os.path.exists(ck.path))
        # Clearing a missing checkpoint is a no-op — never raise.
        ck.clear()

    def test_mark_done_accepts_extra_metadata(self):
        ck = checkpoint.Checkpoint('records-shares', self.run_dir)
        ck.mark_done(1, input_sha256='abc', extra={'batch': 'A'})
        data = ck.load()
        self.assertEqual(data['extra'], {'batch': 'A'})


class TestCorruptCheckpointIsSafe(unittest.TestCase):
    def test_unreadable_checkpoint_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            ck = checkpoint.Checkpoint('records-shares', d)
            os.makedirs(os.path.dirname(ck.path), exist_ok=True)
            with open(ck.path, 'w') as f:
                f.write('not valid json{{{')
            # Returns None without raising
            self.assertIsNone(ck.load())
            # resume_from treats a corrupt file as "no checkpoint"
            start = ck.resume_from([{'a': 1}], resume=True,
                                   force_restart=False)
            self.assertEqual(start, 1)


class TestValidationErrors(unittest.TestCase):
    def test_empty_stage_rejected(self):
        with self.assertRaises(ValueError):
            checkpoint.Checkpoint('', '/tmp')


if __name__ == '__main__':
    unittest.main()
