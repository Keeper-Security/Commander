"""Tests for the plan-only + manual-completion decommission flow.

The existing decommission automated path keeps its test coverage in
test_decommission.py / test_commands.py; this file only covers the
new safer flow added in 2026-04 after customer feedback.
"""

import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.decommission import (
    append_manual_completion_audit,
    generate_plan_markdown,
)


class TestGeneratePlanMarkdown(unittest.TestCase):
    def test_empty_list_produces_header_but_no_commands(self):
        md = generate_plan_markdown([], source_config_path='/path/src.json')
        self.assertIn('# Decommission plan — 0 user(s)', md)
        self.assertNotIn('enterprise-user', md)

    def test_plan_contains_lock_and_delete_for_each_user(self):
        md = generate_plan_markdown(
            ['alice@x', 'bob@y'],
            source_config_path='/cfg/src.json',
        )
        self.assertIn('# Decommission plan — 2 user(s)', md)
        self.assertIn('alice@x', md)
        self.assertIn('bob@y', md)
        # Each user should have both --lock and --delete
        self.assertEqual(md.count('--lock -f'), 2)
        self.assertEqual(md.count('--delete -f'), 2)
        # And a verification step per user (lines ending with `# expect: 0`)
        self.assertEqual(md.count('# expect: 0'), 2)

    def test_plan_uses_provided_source_config(self):
        md = generate_plan_markdown(
            ['u@x'], source_config_path='/my/src.json',
        )
        self.assertIn('/my/src.json', md)

    def test_plan_warns_about_irreversibility(self):
        md = generate_plan_markdown(['u@x'], source_config_path='/cfg.json')
        self.assertIn('Irreversible', md)
        self.assertIn('no resurrect-user api', md.lower())

    def test_plan_includes_manual_completion_pointer(self):
        md = generate_plan_markdown(['u@x'], source_config_path='/cfg.json')
        self.assertIn('--confirm-manual-completion', md)

    def test_empty_emails_are_filtered(self):
        md = generate_plan_markdown(
            ['alice@x', '', None, 'bob@y'],
            source_config_path='/cfg.json',
        )
        self.assertIn('# Decommission plan — 2 user(s)', md)
        self.assertEqual(md.count('--lock -f'), 2)


class TestAppendManualCompletionAudit(unittest.TestCase):
    def test_writes_event_to_audit_log(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            event = append_manual_completion_audit(
                ['alice@x', 'bob@y'],
                audit_log_path=log,
                operator='jlima@hotmail.com',
            )
            self.assertEqual(event['summary']['count'], 2)
            self.assertEqual(event['summary']['operator'],
                             'jlima@hotmail.com')
            self.assertEqual(event['mode'], 'manual-completion')

            # Log file exists and contains one JSON line
            self.assertTrue(os.path.exists(log))
            with open(log) as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 1)
            logged = json.loads(lines[0])
            self.assertEqual(logged['subcommand'], 'decommission')
            self.assertEqual(logged['mode'], 'manual-completion')
            self.assertEqual(logged['summary']['manually_deleted_emails'],
                             ['alice@x', 'bob@y'])

    def test_operator_defaults_to_unspecified(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            event = append_manual_completion_audit(
                ['u@x'], audit_log_path=log,
            )
            self.assertEqual(event['summary']['operator'], 'unspecified')

    def test_empty_emails_filtered_before_audit(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            event = append_manual_completion_audit(
                ['alice@x', '', None, 'bob@y'],
                audit_log_path=log,
            )
            self.assertEqual(event['summary']['count'], 2)
            self.assertEqual(event['summary']['manually_deleted_emails'],
                             ['alice@x', 'bob@y'])


if __name__ == '__main__':
    unittest.main()
