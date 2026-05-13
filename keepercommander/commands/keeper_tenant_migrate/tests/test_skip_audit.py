import csv
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.skip_audit import (
    CATEGORIES,
    audit_structure_results,
    classify_skip,
    summarize_audit,
    write_audit_csv,
)


class ClassifySkipTests(unittest.TestCase):
    def test_self_reference_is_by_design(self):
        c, _ = classify_skip(
            'self-reference (role requires account share through itself)')
        self.assertEqual(c, 'by-design')

    def test_intentional_users_skip_is_by_design(self):
        c, _ = classify_skip(
            'users invite is high-risk (sends real emails) and requires '
            'an explicit roster CSV')
        self.assertEqual(c, 'by-design')

    def test_role_never_created_is_cascade(self):
        c, _ = classify_skip(
            'role never created on target — 28 enforcement(s) suppressed')
        self.assertEqual(c, 'cascade')

    def test_lacks_transfer_account_is_source_quality(self):
        c, action = classify_skip(
            'source role lacks TRANSFER_ACCOUNT privilege — '
            'require_account_share enforcement is invalid')
        self.assertEqual(c, 'source-quality')
        self.assertIn('Bug 64', action)

    def test_invalid_privilege_is_target_capability(self):
        c, _ = classify_skip(
            'target does not support this (Add/Remove managed node '
            'privilege: invalid privilege: privilege_access)')
        self.assertEqual(c, 'target-capability')

    def test_cli_shape_is_bug_pending(self):
        # FILE-phase colon-path issue (Bug 62) — message text the
        # plugin emits when Commander rejects the file path shape.
        c, action = classify_skip(
            'enforcement value shape not accepted by Commander CLI')
        self.assertEqual(c, 'bug-pending')
        self.assertIn('Bug 62', action)

    def test_dependency_missing_is_cascade(self):
        c, _ = classify_skip(
            'dependency missing on target (no such user(s)); '
            'usually resolves after `users` stage runs')
        self.assertEqual(c, 'cascade')

    def test_unknown_pattern_returns_unknown(self):
        c, action = classify_skip('something completely new')
        self.assertEqual(c, 'unknown')
        self.assertEqual(action, '')

    def test_empty_notes_returns_unknown(self):
        c, _ = classify_skip('')
        self.assertEqual(c, 'unknown')

    def test_renamed_role_is_bug_pending(self):
        # Bug 61 — verify reports renamed roles as NOT FOUND pre-fix.
        # Structure-side notes carry "renamed from" markers.
        c, _ = classify_skip('renamed from "Departaments - Finance Interns"')
        self.assertEqual(c, 'bug-pending')


class AuditStructureResultsTests(unittest.TestCase):
    def _write_csv(self, rows):
        fd, path = tempfile.mkstemp(suffix='.csv')
        os.close(fd)
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['category', 'name', 'action', 'status', 'notes'])
            for r in rows:
                writer.writerow(r)
        self.addCleanup(os.unlink, path)
        return path

    def test_classifies_only_skipped_rows(self):
        path = self._write_csv([
            ['role', 'A', 'create', 'SUCCESS', ''],
            ['role', 'B', 'create', 'FAILED', 'some error'],
            ['enforcement', 'X', 'apply', 'SKIPPED',
             'self-reference (role requires)'],
        ])
        rows = audit_structure_results(path)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]['audit_category'], '')
        self.assertEqual(rows[1]['audit_category'], '')
        self.assertEqual(rows[2]['audit_category'], 'by-design')

    def test_missing_csv_returns_empty(self):
        self.assertEqual(audit_structure_results('/tmp/does_not_exist'), [])

    def test_summarize_counts_each_category(self):
        path = self._write_csv([
            ['e', '1', 'apply', 'SKIPPED', 'self-reference'],
            ['e', '2', 'apply', 'SKIPPED', 'role never created on target'],
            ['e', '3', 'apply', 'SKIPPED',
             'invalid privilege: privilege_access'],
            ['e', '4', 'apply', 'SKIPPED', 'something completely new'],
        ])
        counts = summarize_audit(audit_structure_results(path))
        self.assertEqual(counts['by-design'], 1)
        self.assertEqual(counts['cascade'], 1)
        self.assertEqual(counts['target-capability'], 1)
        self.assertEqual(counts['unknown'], 1)
        self.assertEqual(counts['total_skipped'], 4)


class WriteAuditCsvTests(unittest.TestCase):
    def test_emits_classified_csv_with_audit_columns(self):
        rows = [{
            'category': 'enforcement', 'name': 'X', 'action': 'apply',
            'status': 'SKIPPED', 'notes': 'self-reference',
            'audit_category': 'by-design',
            'audit_action': 'Bug 47 self-ref guard',
        }]
        fd, path = tempfile.mkstemp(suffix='.csv')
        os.close(fd)
        try:
            counts = write_audit_csv(rows, path)
            self.assertEqual(counts['by-design'], 1)
            with open(path) as f:
                content = f.read()
            self.assertIn('audit_category', content)
            self.assertIn('Bug 47', content)
            # 0o600 enforced
            self.assertEqual(oct(os.stat(path).st_mode)[-3:], '600')
        finally:
            os.unlink(path)


class CategoriesContractTests(unittest.TestCase):
    def test_categories_match_classify_outputs(self):
        # All categories returned by classify_skip must be in the
        # exported CATEGORIES tuple — keeps consumers (CSV writer,
        # verify phase) in sync.
        observed = set()
        for marker, _category, _action in [
            ('self-reference', 'by-design', ''),
            ('role never created on target', 'cascade', ''),
            ('invalid privilege', 'target-capability', ''),
            ('lacks transfer_account', 'source-quality', ''),
            ('shape not accepted', 'bug-pending', ''),
        ]:
            c, _ = classify_skip(marker)
            observed.add(c)
        observed.add('unknown')
        for c in observed:
            self.assertIn(c, CATEGORIES)
