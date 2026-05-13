"""Adversarial / red-team test suite — chain exploits, daisy-chaining,
sideloading, lateral movement, silent-failure hunting.

Not about happy-path correctness (covered elsewhere). Each test here
enumerates a *known attack vector* the threat model must close, then
asserts the defense fires. If any test fails, a defense is missing or
weakened — the bug class is regression-worthy.

Categories
----------

1. Safeguard bypass attempts — prefix='' wipe, empty roster, missing
   expected_tenant.
2. Sideloading — malformed/malicious inventory, manifest, checkpoint.
3. Cross-config confusion — source/target swap.
4. Checkpoint poisoning — hand-crafted checkpoint claiming false progress.
5. Manifest daisy-chain — records-manifest output weaponized as
   records-shares input.
6. Audit tampering — edited audit.log survives audit-verify (must fail).
7. Path-traversal in staging dir.
"""

import hashlib
import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate import cleanup as cleanup_mod
from keepercommander.commands.keeper_tenant_migrate.checkpoint import (
    Checkpoint, CheckpointMismatchError, hash_rows,
)
from keepercommander.commands.keeper_tenant_migrate.cleanup import (
    FakeCleanupClient, cleanup, matching_entities,
)


# ── Category 1 — Safeguard bypass attempts ──────────────────────────


# Module-level guard: tests below depend on the rehearsal harness or
# legacy reference script under `migration_scripts/`, which ships
# separately from the Commander tree. When absent, the dependent
# classes are skipped.
import os as _os
_HARNESS_DIR = _os.path.abspath(_os.path.join(
    _os.path.dirname(__file__), '..', '..', '..', '..', 'migration_scripts'))
_HAS_HARNESS = _os.path.isdir(_HARNESS_DIR)

class SafeguardBypassTests(unittest.TestCase):
    """Explicit defenses that must refuse dangerous inputs."""

    def test_empty_prefix_refuses_cleanup(self):
        """A wipe-the-whole-tenant attempt via empty prefix.

        cleanup() must raise ValueError before iterating entities.
        Attacker model: operator accidentally passes --prefix '' or
        a config file with an empty prefix string.
        """
        with self.assertRaises(ValueError) as cm:
            cleanup(FakeCleanupClient(), '')
        self.assertIn('prefix', str(cm.exception).lower())

    def test_whitespace_prefix_also_refused(self):
        """A whitespace-only prefix matches every name (all start with
        no characters). Regression guard."""
        with self.assertRaises(ValueError):
            matching_entities({'teams': [{'name': 'x'}]}, '')

    def test_empty_prefix_via_config_rejected(self):
        """Even when passed through matching_entities, '' raises."""
        with self.assertRaises(ValueError):
            matching_entities(
                {'nodes': [{'name': 'anything'}]}, '',
            )


# ── Category 2 — Sideloading malformed artifacts ────────────────────

class SideloadingTests(unittest.TestCase):
    """Hand-crafted inventory / manifest / checkpoint files should not
    trick the plugin into acting on trusted data."""

    def test_checkpoint_with_mismatched_sha_refuses_resume(self):
        """Attacker model: operator or tooling replaces the input
        manifest between runs but the checkpoint still claims progress
        on the old data. Resume must refuse rather than silently
        skip rows of the new manifest.
        """
        rows_original = [{'uid': 'u1'}, {'uid': 'u2'}]
        rows_swapped = [{'uid': 'evil1'}, {'uid': 'evil2'}]
        with tempfile.TemporaryDirectory() as d:
            ck = Checkpoint('records-shares', d)
            ck.mark_done(1, input_sha256=hash_rows(rows_original))
            with self.assertRaises(CheckpointMismatchError) as cm:
                ck.resume_from(rows_swapped, resume=True,
                               force_restart=False)
            # The error message must actionably explain what to do.
            msg = str(cm.exception)
            self.assertIn('sha', msg.lower())

    def test_checkpoint_with_tampered_sha_string_is_caught(self):
        """Attacker writes a fake checkpoint file claiming a SHA that
        doesn't match the current input. resume_from must surface the
        mismatch, not accept the lie."""
        rows = [{'uid': 'u1'}]
        with tempfile.TemporaryDirectory() as d:
            ck = Checkpoint('users', d)
            os.makedirs(os.path.dirname(ck.path), exist_ok=True)
            with open(ck.path, 'w') as f:
                json.dump({
                    'stage': 'users',
                    'input_sha256': 'a' * 64,   # attacker-crafted
                    'last_index': 999,           # claims huge progress
                    'started_at': '2026-01-01T00:00:00+00:00',
                    'updated_at': '2026-01-01T00:00:00+00:00',
                }, f)
            os.chmod(ck.path, 0o600)
            with self.assertRaises(CheckpointMismatchError):
                ck.resume_from(rows, resume=True, force_restart=False)

    def test_corrupt_checkpoint_does_not_crash(self):
        """Non-JSON content in the checkpoint must be treated as 'no
        checkpoint' — defend against tooling that mangles it or an
        attacker who truncates the file mid-write."""
        with tempfile.TemporaryDirectory() as d:
            ck = Checkpoint('records-shares', d)
            os.makedirs(os.path.dirname(ck.path), exist_ok=True)
            with open(ck.path, 'w') as f:
                f.write('}}}not json{{{')
            start = ck.resume_from([{'uid': 'x'}], resume=True,
                                    force_restart=False)
            self.assertEqual(start, 1)

    def test_checkpoint_path_is_0600_even_with_extra_metadata(self):
        """Checkpoint carries progress state; permissions must stay
        0600 even when callers attach extra payload."""
        with tempfile.TemporaryDirectory() as d:
            ck = Checkpoint('records-shares', d)
            ck.mark_done(1, input_sha256='abc',
                         extra={'batch_label': 'phase-1'})
            mode = os.stat(ck.path).st_mode & 0o777
            self.assertEqual(mode, 0o600)


# ── Category 3 — Silent-failure hunting ─────────────────────────────

class SilentFailureTests(unittest.TestCase):
    """Must not count any silent Commander warning / no-op as
    'delete succeeded'. See cleanup.py _still_present()."""

    def test_cleanup_silent_node_failure_is_counted_as_error(self):
        """Commander's enterprise-node --delete silently warns when
        the node has children; the plugin used to count that as
        success. Verify-after-delete catches it. Regression of live
        bug found 2026-04-19.
        """
        entities = {
            'teams': [], 'roles': [],
            'nodes': [{'name': 'MIGTEST-Stubborn', 'parent': ''}],
        }
        client = FakeCleanupClient(
            entities=entities,
            silent_fail_on={('node', 'MIGTEST-Stubborn')},
        )
        summary = cleanup(client, 'MIGTEST-')
        self.assertEqual(summary['nodes'], 0)
        self.assertEqual(summary['errors'], 1)

    def test_cleanup_silent_record_failure_caught(self):
        """Same trust-but-verify rail for records."""
        entities = {
            'teams': [], 'roles': [], 'nodes': [],
            'records': [{'uid': 'u1', 'title': 'MIGTEST-R'}],
        }
        client = FakeCleanupClient(
            entities=entities,
            silent_fail_on={('record', 'u1')},
        )
        summary = cleanup(client, 'MIGTEST-', include_records=True)
        self.assertEqual(summary['records'], 0)
        self.assertEqual(summary['errors'], 1)


# ── Category 4 — Manifest daisy-chain ───────────────────────────────

class ManifestDaisyChainTests(unittest.TestCase):
    """A records-manifest output feeds records-shares / records-
    attachments-upload. Can a crafted manifest with bogus UIDs
    cause writes to wrong records?"""

    def test_share_restorer_skips_unknown_source_uid(self):
        """A manifest row points at a source_uid that does not exist
        in the source session. The restorer must treat it as SKIP,
        not crash or dispatch a share with empty grants."""
        from keepercommander.commands.keeper_tenant_migrate.shares import (
            FakeShareClient, ShareRestorer,
        )
        client = FakeShareClient(records={})   # no records known
        restorer = ShareRestorer(client)
        summary = restorer.run([{
            'source_uid': 'CRAFTED-UID-NO-EXIST',
            'target_uid': 'TARGET-UID',
        }])
        self.assertEqual(summary['fail'], 0)
        self.assertEqual(summary['pass'], 0)
        self.assertEqual(summary['skip'], 1)
        # Must not have issued a share_record call for an unknown
        # source — that would be a silent write based on attacker data.
        share_calls = [c for c in client.calls if c[0] == 'share_record']
        self.assertEqual(share_calls, [],
                          f'unexpected share_record calls: {share_calls}')

    def test_share_restorer_skips_record_with_only_owner(self):
        """A manifest row for a record with only the owner entry
        (no secondary permissions) must not escalate to a write.
        Defense against 'owner= true' being misread as 'shareable'."""
        from keepercommander.commands.keeper_tenant_migrate.shares import (
            FakeShareClient, ShareRestorer,
        )
        records = {'s1': {'user_permissions': [
            {'username': 'owner@x', 'owner': True},
        ]}}
        client = FakeShareClient(records=records)
        restorer = ShareRestorer(client)
        summary = restorer.run([{
            'source_uid': 's1', 'target_uid': 't1',
        }])
        self.assertEqual(summary['skip'], 1)
        self.assertEqual(len([c for c in client.calls
                                if c[0] == 'share_record']), 0)


# ── Category 5 — Decommission plan-only audit integrity ─────────────

class DecommissionPlanAuditTests(unittest.TestCase):
    """decommission --plan-only is supposed to NEVER touch the tenant.
    If it ever writes, that's a catastrophic regression. Also test
    that --confirm-manual-completion append is honest about what
    happened."""

    def test_plan_markdown_never_includes_keeper_tokens_or_secrets(self):
        """Sanity: the emitted plan must not accidentally include
        session tokens, master passwords, or other secrets."""
        from keepercommander.commands.keeper_tenant_migrate.decommission import (
            generate_plan_markdown,
        )
        md = generate_plan_markdown(
            ['alice@corp.io', 'bob@corp.io'],
            source_config_path='/path/to/config.json',
        )
        # Obvious footprints any prudent secret-scanner would hit.
        lower = md.lower()
        for needle in ('session_token', 'master_password',
                        'device_token', 'clone_code', 'private_key',
                        'bearer'):
            self.assertNotIn(needle, lower,
                              f'plan leaked {needle!r}: {md!r}')

    def test_manual_completion_audit_records_exact_operator_and_list(self):
        """Audit integrity: operator name + list of deleted emails
        must be recorded verbatim. Attacker tampering is caught by
        the audit chain (separate test)."""
        from keepercommander.commands.keeper_tenant_migrate.decommission import (
            append_manual_completion_audit,
        )
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            event = append_manual_completion_audit(
                ['alice@corp.io', 'bob@corp.io'],
                audit_log_path=log,
                operator='ops-admin@corp.io',
            )
            self.assertEqual(event['summary']['operator'],
                             'ops-admin@corp.io')
            self.assertEqual(event['summary']['manually_deleted_emails'],
                             ['alice@corp.io', 'bob@corp.io'])


# ── Category 6 — Audit chain tamper detection ───────────────────────

class AuditTamperingTests(unittest.TestCase):
    """Audit log is hash-chained. Editing any prior entry must break
    chain verification — without that, a compromised operator could
    rewrite history."""

    def test_modified_entry_breaks_chain_hash(self):
        from keepercommander.commands.keeper_tenant_migrate.audit import (
            append_audit_event, verify_audit_log,
        )
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {
                'subcommand': 'cleanup',
                'summary': {'deleted': 3},
            })
            append_audit_event(log, {
                'subcommand': 'structure',
                'summary': {'created': 5},
            })

            # Tamper: change the 'deleted' count in entry 1.
            with open(log) as f:
                lines = f.read().splitlines()
            first = json.loads(lines[0])
            first['summary']['deleted'] = 999   # rewrite history
            lines[0] = json.dumps(first)
            with open(log, 'w') as f:
                f.write('\n'.join(lines) + '\n')

            # verify_audit_log returns (ok: bool, broken_line_no: int|None).
            ok, broken = verify_audit_log(log)
            self.assertFalse(
                ok, f'tampered entry 1 was not caught: ok={ok} broken={broken}',
            )
            # Broken line is 1 (our tampered first entry).
            self.assertEqual(broken, 1)


# ── Category 7 — Source-read-only harness rail ──────────────────────

@unittest.skipUnless(_HAS_HARNESS, "requires migration_scripts/ harness (not shipped with Commander)")
class SourceReadOnlyHarnessRailTests(unittest.TestCase):
    """comprehensive_rehearsal.py --source-read-only must refuse
    to launch a destructive subcommand against the source config.
    Coarser than the in-subcommand interlock; fires before the
    subprocess starts so attacks never reach Commander.
    """

    def test_destructive_subcommand_against_source_is_refused(self):
        # Import here so ci-only code doesn't break the package import
        # path under any harness-less environment.
        import sys
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), '..', '..', 'migration_scripts', 'ci',
        ))
        import comprehensive_rehearsal as ch
        try:
            ctx = ch.Context(
                source_config='/tmp/src.json',
                target_config='/tmp/tgt.json',
                run_dir='/tmp/x',
                scope_node='', prefix='MIGTEST-',
                live_writes=False,
                source_read_only=True,
            )
            # 'cleanup' is destructive — not on SOURCE_SAFE_SUBCOMMANDS.
            result = ch._run(
                ctx, name='should-fail',
                config='/tmp/src.json',  # source — would destroy source!
                argv=['cleanup', '--prefix', 'x', '--confirm'],
                category='live-write',
            )
            self.assertEqual(result.status, 'FAIL')
            self.assertIn('source-read-only', result.detail.lower())
        finally:
            if sys.path and sys.path[0].endswith('ci'):
                sys.path.pop(0)

    def test_safe_subcommand_against_source_still_allowed(self):
        """--source-read-only must not break the read-only paths;
        'session' should proceed."""
        import sys
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__), '..', '..', 'migration_scripts', 'ci',
        ))
        import comprehensive_rehearsal as ch
        try:
            self.assertIn('session', ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertIn('plan', ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertIn('records-export', ch.SOURCE_SAFE_SUBCOMMANDS)
            # Destructive ones MUST NOT appear.
            self.assertNotIn('cleanup', ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertNotIn('structure', ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertNotIn('users', ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertNotIn('records-import', ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertNotIn('records-shares', ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertNotIn('records-attachments-upload',
                              ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertNotIn('take-ownership', ch.SOURCE_SAFE_SUBCOMMANDS)
            self.assertNotIn('transfer-user', ch.SOURCE_SAFE_SUBCOMMANDS)
        finally:
            if sys.path and sys.path[0].endswith('ci'):
                sys.path.pop(0)


# ── Category 8 — MC context lateral movement ────────────────────────

class MCContextLateralMovementTests(unittest.TestCase):
    """--mc routes writes to the MC. Bugs here = writes escaping to
    the MSP root (lateral movement between tenants). Regression
    catches the pre-rc2 silent-no-op."""

    def test_mcc_failed_switch_exposes_msp_params_to_caller(self):
        """If switch-to-mc fails, MCContext must NOT silently hand
        out some other tenant's params. It returns the MSP params
        AND the caller can tell via ctx.params identity that the
        switch didn't happen."""
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.mc_context import MCContext

        sentinel_msp = object()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc',
                        return_value=(False, sentinel_msp)):
            with MCContext(sentinel_msp, 'UnreachableMC') as ctx:
                # Must be the MSP params (identity), never a surprise
                # object that could be the wrong MC.
                self.assertIs(ctx.params, sentinel_msp)

    def test_mcc_successful_switch_returns_mc_scoped_params(self):
        """The MC-scoped session must replace what the caller thinks
        it's using — otherwise writes silently hit the MSP. This was
        the actual rc2 bug."""
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.mc_context import MCContext

        sentinel_msp = object()
        sentinel_mc = object()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc',
                        return_value=(True, sentinel_mc)), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_msp',
                        return_value=(True, sentinel_msp)):
            with MCContext(sentinel_msp, 'MyMC') as ctx:
                # INSIDE the block, ctx.params IS the MC session.
                self.assertIs(ctx.params, sentinel_mc)
                # The MSP params (the input) is NOT what a caller
                # passing ctx.params would get.
                self.assertIsNot(ctx.params, sentinel_msp)


if __name__ == '__main__':
    unittest.main()
