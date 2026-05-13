import unittest

from keepercommander.commands.keeper_tenant_migrate.pam_detection import (
    detect_pam_records,
    summarize_pam_impact,
)


class DetectByTypeTests(unittest.TestCase):
    def test_pam_machine_flagged(self):
        records = [{'uid': 'u1', 'title': 'srv1', 'type': 'pamMachine'}]
        self.assertEqual(len(detect_pam_records(records)), 1)

    def test_pam_database_flagged(self):
        records = [{'uid': 'u1', 'title': 'db', 'type': 'pamDatabase'}]
        out = detect_pam_records(records)
        self.assertEqual(len(out), 1)
        self.assertIn('pamDatabase', out[0]['reason'])

    def test_non_pam_type_not_flagged(self):
        records = [{'uid': 'u1', 'title': 'login', 'type': 'login'}]
        self.assertEqual(detect_pam_records(records), [])


class DetectByFieldTypeTests(unittest.TestCase):
    def test_pam_field_triggers_match(self):
        records = [{
            'uid': 'u1', 'title': 'r', 'type': 'login',
            'fields': [{'type': 'pamHostname', 'value': ['host1']}],
        }]
        out = detect_pam_records(records)
        self.assertEqual(len(out), 1)
        self.assertIn('pamHostname', out[0]['reason'])


class DetectByCustomLabelTests(unittest.TestCase):
    def test_custom_field_label_with_rotation(self):
        records = [{
            'uid': 'u1', 'title': 'r', 'type': 'login',
            'custom_fields': {'rotation_schedule': 'daily'},
        }]
        self.assertEqual(len(detect_pam_records(records)), 1)

    def test_custom_array_label_with_pam(self):
        records = [{
            'uid': 'u1', 'title': 'r', 'type': 'login',
            'custom': [{'label': 'pam_gateway_id', 'value': '42'}],
        }]
        self.assertEqual(len(detect_pam_records(records)), 1)

    def test_unrelated_custom_label_ignored(self):
        records = [{
            'uid': 'u1', 'title': 'r', 'type': 'login',
            'custom_fields': {'notes_field': 'hello'},
        }]
        self.assertEqual(detect_pam_records(records), [])


class SummarizeTests(unittest.TestCase):
    def test_summary_counts_by_type(self):
        inventory = {'entities': {'records': [
            {'uid': 'a', 'type': 'pamMachine', 'title': 'm1'},
            {'uid': 'b', 'type': 'pamMachine', 'title': 'm2'},
            {'uid': 'c', 'type': 'pamDatabase', 'title': 'db1'},
            {'uid': 'd', 'type': 'login', 'title': 'normal'},
        ]}}
        summary = summarize_pam_impact(inventory)
        self.assertEqual(summary['total_flagged'], 3)
        self.assertEqual(summary['by_type']['pamMachine'], 2)
        self.assertEqual(summary['by_type']['pamDatabase'], 1)

    def test_empty_inventory(self):
        self.assertEqual(
            summarize_pam_impact({})['total_flagged'], 0)
        self.assertEqual(
            summarize_pam_impact(None)['total_flagged'], 0)


class ManualActionsIntegrationTests(unittest.TestCase):
    def test_pam_summary_emits_manual_action(self):
        from keepercommander.commands.keeper_tenant_migrate.manual_actions import enumerate_actions
        inventory = {
            'entities': {
                'users': [],
                'records': [
                    {'uid': 'a', 'type': 'pamMachine', 'title': 'srv'},
                    {'uid': 'b', 'type': 'pamDatabase', 'title': 'db'},
                ],
                'shared_folders': [],
            },
        }
        actions = enumerate_actions(inventory)
        pam_actions = [a for a in actions if 'PAM' in a['note']
                        and 'gateway' in a['note'].lower()]
        self.assertEqual(len(pam_actions), 1)
        self.assertIn('pamMachine=1', pam_actions[0]['note'])
        self.assertIn('pamDatabase=1', pam_actions[0]['note'])

    def test_no_pam_no_extra_action(self):
        from keepercommander.commands.keeper_tenant_migrate.manual_actions import enumerate_actions
        inventory = {
            'entities': {
                'users': [],
                'records': [{'uid': 'r', 'type': 'login', 'title': 'normal'}],
                'shared_folders': [],
            },
        }
        actions = enumerate_actions(inventory)
        pam_actions = [a for a in actions if 'PAM' in a['note']
                        and 'gateway' in a['note'].lower()]
        self.assertEqual(pam_actions, [])


if __name__ == '__main__':
    unittest.main()
