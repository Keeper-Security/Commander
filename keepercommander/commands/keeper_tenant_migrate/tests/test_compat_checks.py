import unittest

from keepercommander.commands.keeper_tenant_migrate import compat_checks
from keepercommander.commands.keeper_tenant_migrate.compat_checks import (
    CompatCheck,
    FAIL,
    OK,
    WARN,
    attachment_size_survey,
    max_node_depth,
    node_depth_compat,
    record_type_compat,
    run_all,
)


class NodeDepthTests(unittest.TestCase):
    def test_empty_list_depth_zero(self):
        self.assertEqual(max_node_depth([]), 0)

    def test_counts_backslash_segments(self):
        # 'a\\b\\c' literal → 2 backslashes → 3 segments → depth 3
        nodes = [
            {'name': 'lvl1', 'parent': ''},              # depth 1
            {'name': 'lvl2', 'parent': 'lvl1'},          # depth 1
            {'name': 'lvl3', 'parent': 'lvl1\\lvl2'},    # depth 2
            {'name': 'lvl4', 'parent': 'a\\b\\c'},       # depth 3
        ]
        self.assertEqual(max_node_depth(nodes), 3)

    def test_plan_shape_uses_parent_node(self):
        # 4 backslashes → depth 5
        nodes = [{'name': 'x', 'parent_node': 'a\\b\\c\\d\\e'}]
        self.assertEqual(max_node_depth(nodes), 5)

    def test_depth_ok_when_no_limit(self):
        check = node_depth_compat(
            [{'name': 'x', 'parent': 'a\\b\\c\\d\\e\\f'}])   # depth 6
        self.assertEqual(check.verdict, OK)
        self.assertIn('no target limit', check.details[0])

    def test_depth_fail_when_over_limit(self):
        check = node_depth_compat(
            [{'name': 'x', 'parent': 'a\\b\\c\\d\\e'}],     # depth 5
            target_max_depth=3)
        self.assertEqual(check.verdict, FAIL)
        self.assertIn('5', check.message)
        self.assertIn('3', check.message)

    def test_depth_ok_when_within_limit(self):
        check = node_depth_compat(
            [{'name': 'x', 'parent': 'a\\b'}],    # depth 2 (1 backslash + 1)
            target_max_depth=4)
        self.assertEqual(check.verdict, OK)


class RecordTypeTests(unittest.TestCase):
    def test_all_types_present(self):
        src = [{'content': {'$id': 'login'}},
               {'content': {'$id': 'bankAccount'}}]
        tgt = [{'content': {'$id': 'login'}},
               {'content': {'$id': 'bankAccount'}},
               {'content': {'$id': 'creditCard'}}]
        check = record_type_compat(src, tgt)
        self.assertEqual(check.verdict, OK)

    def test_missing_type_fails(self):
        src = [{'content': {'$id': 'custom_x'}},
               {'content': {'$id': 'login'}}]
        tgt = [{'content': {'$id': 'login'}}]
        check = record_type_compat(src, tgt)
        self.assertEqual(check.verdict, FAIL)
        self.assertIn('custom_x', ' '.join(check.details))

    def test_empty_both_is_ok(self):
        check = record_type_compat([], [])
        self.assertEqual(check.verdict, OK)

    def test_handles_flat_name_key(self):
        # When record_type dict has no `content.$id`, the helper falls
        # back to top-level `name`, so it IS captured.
        src = [{'name': 'unmigrated_type'}]
        tgt = []
        check = record_type_compat(src, tgt)
        self.assertEqual(check.verdict, FAIL)
        self.assertIn('unmigrated_type', ' '.join(check.details))


class AttachmentSizeTests(unittest.TestCase):
    def test_no_metadata_is_ok_not_warn(self):
        check = attachment_size_survey([{'title': 'r', 'attachments': []}])
        self.assertEqual(check.verdict, OK)
        self.assertIn('no attachments', check.message)

    def test_under_cap_is_ok(self):
        records = [{'title': 'r',
                    'attachments': [{'name': 'f', 'size': 1024}]}]
        check = attachment_size_survey(records)
        self.assertEqual(check.verdict, OK)

    def test_over_cap_warns(self):
        records = [{'title': 'big',
                    'attachments': [
                        {'name': 'big.bin', 'size': 200 * 1024 * 1024}
                    ]}]
        check = attachment_size_survey(records)
        self.assertEqual(check.verdict, WARN)
        self.assertIn('big', check.details[0])
        self.assertIn('200', check.details[0])

    def test_many_offenders_truncated(self):
        records = [{'title': f'r{i}',
                    'attachments': [
                        {'name': f'f{i}', 'size': 200 * 1024 * 1024}
                    ]}
                   for i in range(25)]
        check = attachment_size_survey(records)
        self.assertEqual(check.verdict, WARN)
        self.assertTrue(any('more' in d for d in check.details))

    def test_custom_cap_bytes(self):
        records = [{'title': 'r',
                    'attachments': [{'name': 'f', 'size': 500}]}]
        check = attachment_size_survey(records, cap_bytes=100)
        self.assertEqual(check.verdict, WARN)

    def test_invalid_size_defaults_to_zero(self):
        records = [{'title': 'r',
                    'attachments': [{'name': 'f', 'size': 'huge'}]}]
        check = attachment_size_survey(records)
        # invalid size → 0, under cap → OK
        self.assertEqual(check.verdict, OK)


class RunAllTests(unittest.TestCase):
    def test_runs_three_checks(self):
        inventory = {'entities': {'nodes': [], 'records': []},
                     'record_types': []}
        target_state = {'record_types': []}
        checks = run_all(inventory, target_state)
        self.assertEqual(len(checks), 3)
        names = [c.name for c in checks]
        self.assertIn('node_depth', names)
        self.assertIn('record_types', names)
        self.assertIn('attachment_size', names)

    def test_passes_target_max_depth_to_node_check(self):
        inventory = {'entities': {'nodes': [
            {'name': 'x', 'parent': 'a\\b\\c\\d\\e'}]}}
        checks = run_all(inventory, {}, target_max_depth=4)
        node_check = next(c for c in checks if c.name == 'node_depth')
        self.assertEqual(node_check.verdict, FAIL)

    def test_tolerates_none_inputs(self):
        checks = run_all(None, None)
        self.assertEqual(len(checks), 3)
        for c in checks:
            self.assertIn(c.verdict, (OK, WARN, FAIL))


if __name__ == '__main__':
    unittest.main()
