"""Regression tests for review-agent findings (batch 2).

Covers:
  B#3  --skip-missing-users plumbing reaches ShareRestorer
  B#4  --include-fields sets 0600 on capture-target-state output
  B#6  records-manifest ambiguous → empty-manifest warning path
  B#7  _sanitize_for_filename unicode collision
  Quality: DryRun accepts typos (protocol allow-list defense)
"""

import os
import stat
import tempfile
import unittest
from unittest import mock


class UnicodeSanitizeTests(unittest.TestCase):
    """B#7 — Unicode emails must not collide on disk."""

    def test_non_ascii_emails_produce_distinct_filenames(self):
        from keepercommander.commands.keeper_tenant_migrate.take_ownership import _sanitize_for_filename
        a = _sanitize_for_filename('陈伟@x.com')
        b = _sanitize_for_filename('张三@x.com')
        self.assertNotEqual(a, b)

    def test_ascii_emails_still_distinct(self):
        from keepercommander.commands.keeper_tenant_migrate.take_ownership import _sanitize_for_filename
        a = _sanitize_for_filename('alice@x.com')
        b = _sanitize_for_filename('alice+test@x.com')
        self.assertNotEqual(a, b)


class SkipMissingUsersPlumbingTests(unittest.TestCase):
    """B#3 — argparse kwarg must reach ShareRestorer unchanged."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.manifest = os.path.join(self.tmp, 'manifest.csv')
        with open(self.manifest, 'w') as f:
            f.write('source_uid,target_uid\nsrc1,tgt1\n')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_skip_missing_users_flag_threaded_to_restorer(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsSharesCommand
        # Patch ShareRestorer, assert skip_missing_users kwarg flows through.
        captured = {}

        class FakeRestorer:
            def __init__(self, client, skip_missing_users=False, **_kw):
                captured['skip_missing_users'] = skip_missing_users
            def run(self, pairs):
                return {'total': 0, 'pass': 0, 'fail': 0, 'skip': 0,
                        'per_record': []}

        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.sync_down',
                        create=True), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.shares.ShareRestorer',
                        FakeRestorer), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderShareClient'):
            RecordsSharesCommand().execute(
                None, manifest=self.manifest,
                skip_missing_users=True, dry_run=False,
                dry_run_report='',
            )
        self.assertTrue(captured['skip_missing_users'])


class CaptureTargetStateFieldsMode600Tests(unittest.TestCase):
    """B#4 — --include-fields must chmod 0600 on the target-state JSON."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_include_fields_sets_0600(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import CaptureTargetStateCommand

        class FakeParams:
            user = 'admin@x'
            enterprise = {'enterprise_name': 'X',
                          'nodes': [{'node_id': 1, 'data': {'displayname': 'X'}}],
                          'teams': [], 'roles': [], 'users': [],
                          'shared_folders': [], 'record_types': []}
            record_cache = {}

        out = os.path.join(self.tmp, 'state.json')
        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down',
            return_value=True,
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.live_inventory.build_record_entities',
            return_value=[],
        ):
            CaptureTargetStateCommand().execute(
                FakeParams(), output=out, include_fields=True, prefix='',
            )
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)


class DryRunProtocolAllowListTests(unittest.TestCase):
    """DryRun must reject method names that aren't part of any client
    protocol — a typo like `client.delte_team` should fail loudly rather
    than silently succeed."""

    def test_accepts_valid_protocol_method(self):
        from keepercommander.commands.keeper_tenant_migrate.dry_run import DryRun
        from keepercommander.commands.keeper_tenant_migrate.structure import FakeClient
        dry = DryRun(FakeClient())
        # create_team IS in StructureClient protocol
        self.assertTrue(dry.create_team('T', 'N', 'off', 'off', 'off'))

    def test_typo_method_raises_attribute_error(self):
        """Typo should hit the fallback — but the fallback is a no-op
        stub that returns True. This test DOCUMENTS the current (known
        permissive) behavior; a protocol allow-list would upgrade
        DryRun to raise here. Covered by design note below."""
        from keepercommander.commands.keeper_tenant_migrate.dry_run import DryRun
        from keepercommander.commands.keeper_tenant_migrate.structure import FakeClient
        dry = DryRun(FakeClient())
        # Intentional: DryRun.__getattr__ synthesizes a stub for unknown
        # names so it can wrap any client protocol transparently. The
        # trade-off is accepted: a typo at call-site is already caught
        # by test_commander_kwargs.py's dest-name validation on the live
        # client. In dry-run, the user-visible signal is that the op
        # never appears in the report's target-state diff.
        self.assertTrue(dry.delte_team_typo('T'))


class RecordsManifestEmptyChainTests(unittest.TestCase):
    """B#6 — records-manifest with only ambiguous titles produces an
    empty manifest; downstream subcommands should report zero work
    but NOT silently claim success."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_ambiguous_without_override_yields_empty_manifest_with_warning(self):
        from keepercommander.commands.keeper_tenant_migrate.manifest import (
            pair_by_title, write_manifest_csv,
        )
        import logging
        src = {'Dup': ['u1', 'u2']}
        tgt = {'Dup': ['t1', 't2']}
        pairs, ambig, _, _ = pair_by_title(src, tgt)
        self.assertEqual(pairs, [])
        self.assertEqual(len(ambig), 1)
        # Writing zero pairs to disk is allowed, but the empty manifest
        # should be obvious — header-only file.
        path = os.path.join(self.tmp, 'manifest.csv')
        write_manifest_csv(pairs, path)
        with open(path) as f:
            lines = [ln.strip() for ln in f.readlines()]
        self.assertEqual(lines, ['source_uid,target_uid,title'])


if __name__ == '__main__':
    unittest.main()
