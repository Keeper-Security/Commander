import csv
import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.transition import (
    CATEGORY_A,
    CATEGORY_D,
    CATEGORY_E,
    CATEGORY_UNKNOWN,
    UserTransitionChecker,
    categorize,
    classify_user,
    load_source_users_from_inventory,
    load_source_users_from_roster,
    load_target_user_map,
    render_summary_markdown,
    write_plan_csv,
)


class ClassifyUserTests(unittest.TestCase):
    def test_empty_status_is_category_a(self):
        cat, action, actor, _ = classify_user('a@x.com', '')
        self.assertEqual(cat, CATEGORY_A)
        self.assertEqual(action, 'auto_invite')
        self.assertEqual(actor, 'admin')

    def test_active_is_category_d(self):
        cat, *_ = classify_user('a@x', 'Active')
        self.assertEqual(cat, CATEGORY_D)

    def test_invited_or_pending_is_category_e(self):
        self.assertEqual(classify_user('a@x', 'Invited')[0], CATEGORY_E)
        self.assertEqual(classify_user('a@x', 'Pending')[0], CATEGORY_E)

    def test_locked_and_disabled_are_unknown(self):
        self.assertEqual(classify_user('a@x', 'Locked')[0], CATEGORY_UNKNOWN)
        self.assertEqual(classify_user('a@x', 'Disabled')[0], CATEGORY_UNKNOWN)

    def test_weird_status_is_unknown_with_note(self):
        cat, _, _, notes = classify_user('a@x', 'InterstellarLimbo')
        self.assertEqual(cat, CATEGORY_UNKNOWN)
        self.assertIn('InterstellarLimbo', notes)

    def test_status_match_is_case_insensitive(self):
        self.assertEqual(classify_user('a', 'ACTIVE')[0], CATEGORY_D)


class LoadSourceUsersFromInventoryTests(unittest.TestCase):
    def test_extracts_email_node_teams_roles(self):
        inv = {
            'entities': {
                'users': [
                    {'email': 'Alice@X.com', 'node': 'R', 'teams': ['T1'], 'roles': ['R1']},
                    {'email': '', 'node': '', 'teams': [], 'roles': []},
                    {'email': 'bob@x.com', 'node': '', 'teams': [], 'roles': []},
                ],
            },
        }
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as t:
            json.dump(inv, t)
            path = t.name
        try:
            out = load_source_users_from_inventory(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]['email'], 'alice@x.com')
        self.assertEqual(out[0]['teams'], ['T1'])


class LoadSourceUsersFromRosterTests(unittest.TestCase):
    def test_reads_email_column_case_insensitive(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            t.write('Email,full_name\nALICE@X.com,Alice\nbob@x.com,Bob\n')
            path = t.name
        try:
            out = load_source_users_from_roster(path)
        finally:
            os.unlink(path)
        self.assertEqual([u['email'] for u in out], ['alice@x.com', 'bob@x.com'])

    def test_skips_empty_emails(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            t.write('email,name\n,Nobody\nalice@x.com,Alice\n')
            path = t.name
        try:
            out = load_source_users_from_roster(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(out), 1)


class LoadTargetUserMapTests(unittest.TestCase):
    def test_parses_keeper_users_csv(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            t.write('User ID,Email,Status\n')
            t.write('1,alice@x.com,Active\n')
            t.write('2,BOB@X.com,Invited\n')
            path = t.name
        try:
            m = load_target_user_map(path)
        finally:
            os.unlink(path)
        self.assertEqual(m['alice@x.com'], 'Active')
        self.assertEqual(m['bob@x.com'], 'Invited')

    def test_header_with_reordered_columns(self):
        """When columns are in a non-default order, resolve by header name."""
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            # Reordered: id, status, something, email, node
            t.write('User ID,Status,Transfer Status,Email,Node\n')
            t.write('1,Active,,alice@x.com,MIGTEST-Root\n')
            t.write('2,Locked,,bob@x.com,MIGTEST-Root\n')
            path = t.name
        try:
            m = load_target_user_map(path)
        finally:
            os.unlink(path)
        self.assertEqual(m['alice@x.com'], 'Active')
        self.assertEqual(m['bob@x.com'], 'Locked')

    def test_positional_fallback_when_no_header(self):
        """`enterprise-info --format csv` without a header still parses via position."""
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            t.write('1234,alice@x.com,Active,Not required,Some-Node,0,,1,Role,,false\n')
            t.write('5678,bob@x.com,Invited,,Some-Node,0,,1,Role,,false\n')
            path = t.name
        try:
            m = load_target_user_map(path)
        finally:
            os.unlink(path)
        self.assertEqual(m['alice@x.com'], 'Active')
        self.assertEqual(m['bob@x.com'], 'Invited')

    def test_empty_file_returns_empty_mapping(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            path = t.name
        try:
            self.assertEqual(load_target_user_map(path), {})
        finally:
            os.unlink(path)

    def test_short_row_is_skipped_when_positional(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            t.write('1,alice@x.com\n')   # too short — no status column
            t.write('2,bob@x.com,Active\n')
            path = t.name
        try:
            m = load_target_user_map(path)
        finally:
            os.unlink(path)
        self.assertNotIn('alice@x.com', m)
        self.assertEqual(m['bob@x.com'], 'Active')


class CategorizeTests(unittest.TestCase):
    def test_produces_mixed_tally(self):
        sources = [
            {'email': 'new@x', 'node': '', 'teams': [], 'roles': []},
            {'email': 'active@x', 'node': '', 'teams': [], 'roles': []},
            {'email': 'pending@x', 'node': '', 'teams': [], 'roles': []},
            {'email': 'weird@x', 'node': '', 'teams': [], 'roles': []},
        ]
        target_map = {'active@x': 'Active', 'pending@x': 'Invited', 'weird@x': 'Zombie'}
        rows, tally = categorize(sources, target_map)
        self.assertEqual(len(rows), 4)
        self.assertEqual(tally[CATEGORY_A], 1)
        self.assertEqual(tally[CATEGORY_D], 1)
        self.assertEqual(tally[CATEGORY_E], 1)
        self.assertEqual(tally[CATEGORY_UNKNOWN], 1)


class WritePlanCsvTests(unittest.TestCase):
    def test_writes_expected_columns_and_joins_lists(self):
        rows = [{
            'source_email': 'a@x', 'source_node': 'N',
            'source_teams': ['T1', 'T2'], 'source_roles': ['R1'],
            'target_status': 'not_found', 'category': 'A',
            'action_required': 'auto_invite', 'actor': 'admin', 'notes': 'ok',
        }]
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as t:
            path = t.name
        try:
            write_plan_csv(rows, path)
            with open(path, newline='') as f:
                data = list(csv.DictReader(f))
        finally:
            os.unlink(path)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['source_teams'], 'T1|T2')
        self.assertEqual(data[0]['source_roles'], 'R1')


class RenderMarkdownTests(unittest.TestCase):
    def test_summary_contains_counts_and_blockers(self):
        rows = [
            {'source_email': 'l@x', 'source_node': '', 'target_status': 'Locked',
             'category': CATEGORY_UNKNOWN, 'action_required': 'unlock_first',
             'actor': 'admin', 'notes': 'User Locked', 'source_teams': [], 'source_roles': []},
            {'source_email': 'p@x', 'source_node': '', 'target_status': 'Invited',
             'category': CATEGORY_E, 'action_required': 'resend_or_extend',
             'actor': 'admin', 'notes': '', 'source_teams': [], 'source_roles': []},
        ]
        tally = {CATEGORY_A: 0, CATEGORY_D: 0, CATEGORY_E: 1, CATEGORY_UNKNOWN: 1}
        md = render_summary_markdown(rows, tally, 'srcfile', 'tgtfile', 2, 2, 'plan.csv')
        self.assertIn('# User Transition Plan', md)
        self.assertIn('UNKNOWN', md)
        self.assertIn('l@x', md)
        self.assertIn('PENDING_INVITE', md)


class UserTransitionCheckerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_run_from_inventory_writes_both_outputs(self):
        inv_path = os.path.join(self.tmp, 'inv.json')
        target_csv = os.path.join(self.tmp, 'target.csv')
        with open(inv_path, 'w') as f:
            json.dump({'entities': {'users': [
                {'email': 'a@x', 'node': 'R', 'teams': ['T'], 'roles': []},
                {'email': 'b@x', 'node': 'R', 'teams': [], 'roles': []},
            ]}}, f)
        with open(target_csv, 'w') as f:
            f.write('User ID,Email,Status\n1,a@x,Active\n')

        checker = UserTransitionChecker.from_inventory(inv_path, target_csv,
                                                        target_label='target.config')
        csv_out = os.path.join(self.tmp, 'plan.csv')
        md_out = os.path.join(self.tmp, 'plan.md')
        result = checker.run(csv_out, md_out)

        self.assertEqual(result['tally'][CATEGORY_A], 1)  # b@x
        self.assertEqual(result['tally'][CATEGORY_D], 1)  # a@x
        self.assertEqual(result['blockers'], 0)
        self.assertTrue(os.path.exists(csv_out))
        self.assertTrue(os.path.exists(md_out))

    def test_run_from_roster_flags_unknown_blocker(self):
        roster = os.path.join(self.tmp, 'roster.csv')
        target_csv = os.path.join(self.tmp, 'target.csv')
        with open(roster, 'w') as f:
            f.write('email,name\nlocked@x,Lou\n')
        with open(target_csv, 'w') as f:
            f.write('User ID,Email,Status\n1,locked@x,Locked\n')

        checker = UserTransitionChecker.from_roster(roster, target_csv)
        csv_out = os.path.join(self.tmp, 'plan.csv')
        md_out = os.path.join(self.tmp, 'plan.md')
        result = checker.run(csv_out, md_out)
        self.assertEqual(result['blockers'], 1)


if __name__ == '__main__':
    unittest.main()
