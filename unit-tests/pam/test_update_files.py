"""`update_files`: the attachment / script writer of `pam project update` (no server: the batch run is replaced)."""
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(__file__))

from keepercommander.commands.pam_import import update_files as uf
from keepercommander.commands.pam_import import update_plan as up
from keepercommander.commands.pam_import.batch_attachments import BatchAttachmentSummary
from keepercommander.commands.pam_import.import_items import load_items

import test_update_plan as tp


class TestApplyFiles(unittest.TestCase):
    def plan(self, tmp, files=None, size=30, name='bigger.txt'):
        path = os.path.join(tmp, name)
        with open(path, 'wb') as fh:
            fh.write(b'x' * size)
        raw = tp.machine_json(users=[], attachments=[path])
        items, _ = load_items({'resources': [raw]}, tp.CFG)
        return up.build_plan(items, tp.index(), tp.state(files=files or []), config_uid=tp.CFG, scope_records=[])

    def test_the_uploads_are_collected_and_reported_per_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.plan(tmp, files=[{'record_uid': 'OLD', 'name': 'bigger.txt', 'size': 20}])
            seen = []

            def execute(pending):
                seen.extend(pending)
                return BatchAttachmentSummary(uploaded_count=len(pending))

            report = uf.apply_files(MagicMock(), plan, execute=execute)
        self.assertEqual([(p.parent_uid, p.name, p.size, p.kind, p.replaces) for p in seen],
                         [(tp.M1, 'bigger.txt', 30, 'attachment', 'OLD')])
        self.assertEqual((report.applied, report.errors), (['M1: files (1)'], []))

    def test_a_failure_of_one_record_is_an_error_for_that_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.plan(tmp)
            summary = BatchAttachmentSummary(failures=[(tp.M1, 'PUT upload failed')])
            report = uf.apply_files(MagicMock(), plan, execute=lambda pending: summary)
        self.assertEqual(report.applied, [])
        self.assertEqual(report.errors, ['M1: files were not written: PUT upload failed'])

    def test_a_parent_missing_from_the_cache_is_an_error_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.plan(tmp)
            summary = BatchAttachmentSummary(warnings=[(tp.M1, 'parent record missing for bigger.txt')])
            report = uf.apply_files(MagicMock(), plan, execute=lambda pending: summary)
        self.assertEqual(report.applied, [])
        self.assertIn('parent record missing', report.errors[0])

    def test_a_raising_run_marks_every_record_as_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.plan(tmp)

            def boom(pending):
                raise RuntimeError('throttled')

            report = uf.apply_files(MagicMock(), plan, execute=boom)
        self.assertEqual(report.errors, ['M1: files were not written: throttled'])

    def test_a_file_that_vanished_or_became_empty_since_the_plan_is_an_error_and_nothing_is_uploaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.plan(tmp)
            path = os.path.join(tmp, 'bigger.txt')
            open(path, 'wb').close()                                 # now empty
            called = []
            report = uf.apply_files(MagicMock(), plan, execute=lambda pending: called.append(pending))
            self.assertIn('is empty or larger', report.errors[0])
            os.remove(path)
            report = uf.apply_files(MagicMock(), plan, execute=lambda pending: called.append(pending))
        self.assertIn('not readable', report.errors[0])
        self.assertEqual(called, [])

    def test_a_plan_without_file_changes_does_nothing(self):
        items, _ = load_items({'resources': [tp.machine_json(users=[])]}, tp.CFG)
        plan = up.build_plan(items, tp.index(), tp.state(), config_uid=tp.CFG, scope_records=[])
        report = uf.apply_files(MagicMock(), plan, execute=lambda pending: self.fail('no upload expected'))
        self.assertEqual((report.applied, report.errors), ([], []))


if __name__ == '__main__':
    unittest.main()
