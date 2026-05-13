import csv
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.preflight import (
    _parse_version,
    check_disk_space,
    check_enterprise_admin,
    check_keeper_version,
    check_output_dir_writable,
    check_roster_duplicates,
    check_roster_email_format,
    check_roster_empty_fields,
    check_roster_exists,
    check_roster_folder_convention,
    check_roster_header,
    check_roster_row_count,
    check_session,
    run,
)


class _FakeParams:
    def __init__(self, user='admin@x', enterprise=None):
        self.user = user
        self.enterprise = enterprise if enterprise is not None else {
            'enterprise_name': 'Keeperdemo',
        }


def _write_roster(path, rows, header=None):
    header = header or [
        'email', 'full_name', 'department', 'record_count', 'migration_folder_name',
    ]
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


class ParseVersionTests(unittest.TestCase):
    def test_plain_triple(self):
        self.assertEqual(_parse_version('17.0.3'), (17, 0, 3))

    def test_suffixed(self):
        self.assertEqual(_parse_version('17.2.11-dev'), (17, 2, 11))

    def test_malformed_returns_none(self):
        self.assertIsNone(_parse_version(''))
        self.assertIsNone(_parse_version('abc'))


class KeeperVersionTests(unittest.TestCase):
    def test_pass_with_real_keepercommander(self):
        # The installed Commander should satisfy the minimum.
        check = check_keeper_version()
        self.assertIn(check.status, ('PASS', 'WARN'))  # tolerant

    def test_fail_when_below_minimum(self):
        check = check_keeper_version(min_version=(99, 0, 0))
        self.assertEqual(check.status, 'FAIL')


class RosterChecksTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'roster.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_exists_fail_when_missing(self):
        missing = os.path.join(self.tmp, 'does_not_exist.csv')
        self.assertEqual(check_roster_exists(missing).status, 'FAIL')

    def test_exists_pass_when_present(self):
        open(self.path, 'w').close()
        self.assertEqual(check_roster_exists(self.path).status, 'PASS')

    def test_header_pass_on_canonical(self):
        _write_roster(self.path, [])
        self.assertEqual(check_roster_header(self.path).status, 'PASS')

    def test_header_fail_on_mismatch(self):
        _write_roster(self.path, [], header=['email', 'name'])
        self.assertEqual(check_roster_header(self.path).status, 'FAIL')

    def test_row_count_warn_when_empty(self):
        _write_roster(self.path, [])
        self.assertEqual(check_roster_row_count(self.path).status, 'WARN')

    def test_row_count_pass_with_users(self):
        _write_roster(self.path,
                      [['a@x.com', 'A', 'Eng', '5', 'MIGRATION-A']])
        self.assertEqual(check_roster_row_count(self.path).status, 'PASS')

    def test_duplicates_flagged(self):
        _write_roster(self.path, [
            ['a@x.com', 'A', '', '1', 'MIGRATION-A'],
            ['A@X.COM', 'A2', '', '2', 'MIGRATION-A2'],  # case-insensitive dupe
        ])
        self.assertEqual(check_roster_duplicates(self.path).status, 'FAIL')

    def test_no_duplicates_passes(self):
        _write_roster(self.path, [
            ['a@x.com', 'A', '', '1', 'MIGRATION-A'],
            ['b@x.com', 'B', '', '2', 'MIGRATION-B'],
        ])
        self.assertEqual(check_roster_duplicates(self.path).status, 'PASS')

    def test_email_format_warn_on_bad(self):
        _write_roster(self.path,
                      [['notanemail', 'X', '', '1', 'MIGRATION-X']])
        self.assertEqual(check_roster_email_format(self.path).status, 'WARN')

    def test_folder_convention_fail_on_wrong(self):
        _write_roster(self.path,
                      [['a@x.com', 'A', '', '1', 'SomeOtherFolder']])
        self.assertEqual(check_roster_folder_convention(self.path).status, 'FAIL')

    def test_folder_convention_pass(self):
        _write_roster(self.path,
                      [['a@x.com', 'A', '', '1', 'MIGRATION-Something-42']])
        self.assertEqual(check_roster_folder_convention(self.path).status, 'PASS')

    def test_empty_fields_warn(self):
        _write_roster(self.path,
                      [['a@x.com', 'A', '', '1', 'MIGRATION-A']])
        self.assertEqual(check_roster_empty_fields(self.path).status, 'WARN')


class SessionChecksTests(unittest.TestCase):
    def test_session_pass_with_user(self):
        self.assertEqual(check_session(_FakeParams()).status, 'PASS')

    def test_session_fail_without_user(self):
        self.assertEqual(check_session(_FakeParams(user='')).status, 'FAIL')

    def test_enterprise_admin_pass_with_enterprise_data(self):
        self.assertEqual(check_enterprise_admin(_FakeParams()).status, 'PASS')

    def test_enterprise_admin_warn_without_enterprise_data(self):
        params = _FakeParams(enterprise={})
        self.assertEqual(check_enterprise_admin(params).status, 'WARN')


class EnvironmentChecksTests(unittest.TestCase):
    def test_disk_space_ok(self):
        # 1GB minimum — any sane test box passes
        self.assertEqual(check_disk_space('.', min_gb=1).status, 'PASS')

    def test_disk_space_fails_when_higher_than_available(self):
        check = check_disk_space('.', min_gb=10 ** 12)
        self.assertEqual(check.status, 'FAIL')

    def test_output_dir_writable(self):
        tmp = tempfile.mkdtemp()
        try:
            self.assertEqual(check_output_dir_writable(tmp).status, 'PASS')
        finally:
            import shutil
            shutil.rmtree(tmp)


class RunIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_happy_path_no_fails(self):
        roster = os.path.join(self.tmp, 'roster.csv')
        _write_roster(roster, [
            ['alice@x.com', 'Alice', 'Eng', '5', 'MIGRATION-ALICE'],
            ['bob@x.com', 'Bob', 'Ops', '3', 'MIGRATION-BOB'],
        ])
        results, fails, warns = run(_FakeParams(), roster, self.tmp, min_disk_gb=1)
        self.assertEqual(fails, 0)

    def test_missing_roster_halts_roster_checks(self):
        roster = os.path.join(self.tmp, 'no_such_roster.csv')
        results, fails, warns = run(_FakeParams(), roster, self.tmp)
        # roster.file FAILS, no other roster.* checks run
        names = [r.name for r in results]
        self.assertIn('roster.file', names)
        self.assertNotIn('roster.header', names)
        self.assertGreaterEqual(fails, 1)


class PreflightCheckReprTests(unittest.TestCase):
    """Regression guard: rehearsal .out artifacts dump the results list,
    so the default `<PreflightCheck object at 0x...>` repr hid
    FAIL/WARN diagnostic messages from operators."""

    def test_repr_includes_status_and_name(self):
        from keepercommander.commands.keeper_tenant_migrate.preflight import PreflightCheck
        r = repr(PreflightCheck('keeper.version', 'PASS', 'v17.2.13'))
        self.assertIn('PASS', r)
        self.assertIn('keeper.version', r)
        self.assertIn('v17.2.13', r)
        self.assertNotIn('object at 0x', r)

    def test_repr_without_message(self):
        from keepercommander.commands.keeper_tenant_migrate.preflight import PreflightCheck
        r = repr(PreflightCheck('login', 'FAIL'))
        self.assertIn('FAIL', r)
        self.assertIn('login', r)


if __name__ == '__main__':
    unittest.main()
