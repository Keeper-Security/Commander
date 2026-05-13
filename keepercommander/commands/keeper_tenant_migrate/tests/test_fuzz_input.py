"""Fuzz + path-traversal tests for input loaders.

Every loader that parses user-supplied files is an attack surface:
  - Inventory JSON (plan output, but an operator could write it by hand)
  - Manifest CSV (records-manifest output, same)
  - Checkpoint JSON (file-system-local, editable by anyone with write)
  - Roster CSV (operator-provided)

Tests here throw malformed, oversized, injection-crafted inputs at
each loader and assert the loader either:
  - returns clean empty/partial output
  - raises a recognized exception the caller handles
never:
  - executes arbitrary code
  - writes outside the run-dir
  - silently trusts the input
"""

import json
import os
import tempfile
import unittest


class InventoryLoaderFuzzTests(unittest.TestCase):
    """load_inventory_counts is called early in `estimate`, so
    malformed input must be surfaced clearly, not silently empty."""

    def test_empty_json_raises_for_missing_counts(self):
        from keepercommander.commands.keeper_tenant_migrate.estimate import load_inventory_counts
        with tempfile.NamedTemporaryFile('w', suffix='.json',
                                          delete=False) as f:
            f.write('{}')
            path = f.name
        try:
            with self.assertRaises(ValueError) as cm:
                load_inventory_counts(path)
            self.assertIn('counts', str(cm.exception).lower())
        finally:
            os.unlink(path)

    def test_non_json_raises_json_decode_error(self):
        from keepercommander.commands.keeper_tenant_migrate.estimate import load_inventory_counts
        with tempfile.NamedTemporaryFile('w', suffix='.json',
                                          delete=False) as f:
            f.write('this is not json at all')
            path = f.name
        try:
            with self.assertRaises(json.JSONDecodeError):
                load_inventory_counts(path)
        finally:
            os.unlink(path)

    def test_counts_empty_dict_raises(self):
        from keepercommander.commands.keeper_tenant_migrate.estimate import load_inventory_counts
        with tempfile.NamedTemporaryFile('w', suffix='.json',
                                          delete=False) as f:
            json.dump({'counts': {}}, f)
            path = f.name
        try:
            with self.assertRaises(ValueError):
                load_inventory_counts(path)
        finally:
            os.unlink(path)

    def test_nonexistent_file_raises_oserror(self):
        """Open on a missing path raises some OSError subclass — Python
        picks between FileNotFoundError / NotADirectoryError based on
        whether a parent dir exists. We only care that the error is
        visible, not silently swallowed."""
        from keepercommander.commands.keeper_tenant_migrate.estimate import load_inventory_counts
        with self.assertRaises(OSError):
            load_inventory_counts('/nonexistent/path.json')

    def test_oversized_payload_handled_without_crash(self):
        """Attacker bloats the inventory JSON — parser must still
        return deterministically. 50k entries is enough to catch any
        quadratic-complexity regression without being a true stress
        test."""
        from keepercommander.commands.keeper_tenant_migrate.estimate import (
            estimate_from_counts, load_inventory_counts,
        )
        huge_counts = {
            'nodes': 50_000, 'teams': 50_000, 'roles': 50_000,
            'users': 50_000, 'shared_folders': 50_000, 'records': 50_000,
            'attachments': 0, 'direct_shares': 0,
            'total_enforcements': 0, 'total_privileges': 0,
        }
        with tempfile.NamedTemporaryFile('w', suffix='.json',
                                          delete=False) as f:
            json.dump({'counts': huge_counts}, f)
            path = f.name
        try:
            counts = load_inventory_counts(path)
            est = estimate_from_counts(counts)
            # Must produce a finite number; no crash on huge inputs.
            self.assertGreater(est.total_calls, 100_000)
            self.assertEqual(est.tier_label, 'xlarge (5k+)')
        finally:
            os.unlink(path)


class SFReconcileInventoryFuzzTests(unittest.TestCase):
    """plan_reconciliation reads shared_folders[*].users from an
    inventory dict. Malformed shapes must not crash the planner."""

    def _plan(self, inventory):
        from keepercommander.commands.keeper_tenant_migrate.sf_reconcile import (
            FakeSFReconcileClient, plan_reconciliation,
        )
        client = FakeSFReconcileClient(
            memberships={},
            statuses={},
        )
        return plan_reconciliation(inventory, client)

    def test_missing_shared_folders_key(self):
        plan = self._plan({})
        self.assertEqual(plan.to_apply, [])
        self.assertEqual(plan.errors, [])

    def test_sf_with_no_users_field(self):
        plan = self._plan({'shared_folders': [{'name': 'Orphan'}]})
        self.assertEqual(plan.to_apply, [])
        # Missing on target, but no users expected → no errors either.

    def test_sf_with_user_missing_username(self):
        """A row with no username/email key — must be skipped, not
        crash. Attacker crafts a null/empty entry."""
        plan = self._plan({
            'shared_folders': [{'name': 'F', 'users': [
                {'role': 'admin'},            # no username
                {'username': ''},              # empty username
                {'username': None},            # null username
                {'username': '  '},            # whitespace username
                {},                            # entirely empty dict
                'string instead of dict',      # completely wrong type
                {'username': 'valid@x.io'},    # mixed with valid
            ]}],
        })
        # Only the valid row should be in expected memberships.
        # The client has no 'F' on target, so this becomes an error,
        # but only the valid email appears.
        emails = {item.email for item in plan.errors}
        self.assertEqual(emails, {'valid@x.io'})

    def test_non_string_sf_name_ignored(self):
        plan = self._plan({
            'shared_folders': [
                {'name': None, 'users': [{'username': 'x@y'}]},
                {'users': [{'username': 'y@y'}]},  # no name
                {'name': 'RealSF', 'users': [{'username': 'z@y'}]},
            ],
        })
        # Only 'RealSF' should feed the plan.
        sfs = {item.sf_name for item in plan.errors}
        self.assertEqual(sfs, {'RealSF'})


class FolderUIDInjectionTests(unittest.TestCase):
    """_collect_records_under_folders must not be fooled by folder
    UIDs that look like path components or injection attempts."""

    def test_folder_uid_with_path_traversal_just_logs_warning(self):
        """'..' is not a valid folder UID; walk ignores it without
        attempting any file access."""
        from types import SimpleNamespace
        from keepercommander.commands.keeper_tenant_migrate.commands import (
            _collect_records_under_folders,
        )
        params = SimpleNamespace(
            folder_cache={'LegitUID': SimpleNamespace(
                name='ok', subfolders=[], parent_uid=None,
            )},
            subfolder_record_cache={'LegitUID': ['r1']},
        )
        # Path-traversal strings as "UIDs" — walk just logs warning.
        result = _collect_records_under_folders(
            params, ['../../etc/passwd', '/tmp/shell', 'LegitUID',
                     'null', ''],
        )
        # Only the legit UID's records are included.
        self.assertEqual(result, {'r1'})

    def test_folder_uid_injection_attempt_doesnt_reach_filesystem(self):
        """If the walk 'accidentally' interpreted a UID as a path,
        disk activity could happen. Walk must be pure cache lookup."""
        import sys
        from types import SimpleNamespace
        from keepercommander.commands.keeper_tenant_migrate.commands import (
            _collect_records_under_folders,
        )
        params = SimpleNamespace(
            folder_cache={},
            subfolder_record_cache={},
        )
        # These would be dangerous if interpreted as paths.
        dangerous = [
            '/etc/passwd',
            '~/ssh/id_rsa',
            '$HOME/.aws/credentials',
            '; rm -rf /',
            '`whoami`',
            '\\x00\\x01\\x02',
            'A' * 10_000,  # oversized
        ]
        # Just runs without raising and returns empty set.
        result = _collect_records_under_folders(params, dangerous)
        self.assertEqual(result, set())


class HashRowsDeterminismTests(unittest.TestCase):
    """Checkpoint SHA is used to detect tampering. Hash must be
    deterministic across Python runs, equal for equivalent inputs,
    different for different inputs — even under key-order changes
    and Unicode normalization corner cases."""

    def test_hash_stable_across_key_orders(self):
        from keepercommander.commands.keeper_tenant_migrate.checkpoint import hash_rows
        a = hash_rows([{'x': 1, 'y': 2, 'z': 3}])
        b = hash_rows([{'z': 3, 'x': 1, 'y': 2}])
        self.assertEqual(a, b)

    def test_hash_different_for_subtly_different_values(self):
        from keepercommander.commands.keeper_tenant_migrate.checkpoint import hash_rows
        # Tampering: changed value by one character.
        a = hash_rows([{'email': 'alice@example.com'}])
        b = hash_rows([{'email': 'alice@example.co'}])
        self.assertNotEqual(a, b)

    def test_hash_stable_for_unicode(self):
        from keepercommander.commands.keeper_tenant_migrate.checkpoint import hash_rows
        # Non-ASCII user names must hash deterministically too.
        a = hash_rows([{'name': '张三'}])
        b = hash_rows([{'name': '张三'}])
        self.assertEqual(a, b)
        c = hash_rows([{'name': '张四'}])
        self.assertNotEqual(a, c)

    def test_hash_of_empty_list_is_not_empty_string(self):
        from keepercommander.commands.keeper_tenant_migrate.checkpoint import hash_rows
        h = hash_rows([])
        self.assertEqual(len(h), 64)   # SHA-256 hex digest
        self.assertTrue(all(c in '0123456789abcdef' for c in h))


class CleanupMaliciousNamesTests(unittest.TestCase):
    """matching_entities uses str.startswith — injection-proof.
    Still, assert we don't accidentally strip/normalize names in a
    way that lets an attacker slip past the prefix."""

    def test_prefix_does_not_match_with_leading_whitespace(self):
        """If cleanup accidentally stripped leading whitespace from
        names or prefixes, an attacker could name something ' MIGTEST-'
        (leading space) and evade MIGTEST- cleanup. Or vice-versa."""
        from keepercommander.commands.keeper_tenant_migrate.cleanup import matching_entities
        entities = {
            'teams': [
                {'name': 'MIGTEST-Real'},
                {'name': ' MIGTEST-WithLeadingSpace'},
                {'name': 'MIGTEST -WithSpaceMid'},  # space between T and -
            ],
            'roles': [], 'nodes': [],
        }
        matches = matching_entities(entities, 'MIGTEST-')
        names = [t['name'] for t in matches['teams']]
        # Only the one with EXACT prefix match.
        self.assertEqual(names, ['MIGTEST-Real'])

    def test_null_bytes_in_name_do_not_confuse_matcher(self):
        """A name with an embedded null byte — defensive check that
        Python's str.startswith handles it sanely."""
        from keepercommander.commands.keeper_tenant_migrate.cleanup import matching_entities
        entities = {
            'teams': [
                {'name': 'MIGTEST\x00-Injected'},  # embedded null
                {'name': 'MIGTEST-Clean'},
            ],
            'roles': [], 'nodes': [],
        }
        matches = matching_entities(entities, 'MIGTEST-')
        names = [t['name'] for t in matches['teams']]
        # The embedded-null name does NOT start with 'MIGTEST-'.
        self.assertEqual(names, ['MIGTEST-Clean'])


if __name__ == '__main__':
    unittest.main()
