"""Unit tests for auto_migrate — the single-command orchestrator.

The per-stage code paths are already covered by each subcommand's
tests (+ e2e integration). These tests lock down the auto-migrate
layer itself: config validation, stage filtering, session safety,
dispatch table correctness.

Live-session paths (attach_interactive_target / attach_config_target)
are exercised in the rehearsal harness, not here — they need a real
Commander SDK.
"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate import auto_migrate as am


# ── Config validation ──────────────────────────────────────────────

class ValidateConfigTests(unittest.TestCase):
    def _cfg(self, **overrides):
        base = dict(run_dir='/tmp/x', target_user='admin@y.io')
        base.update(overrides)
        return am.RunConfig(**base)

    def test_valid_minimal_config(self):
        am.validate_config(self._cfg())

    def test_requires_run_dir(self):
        with self.assertRaises(ValueError) as cm:
            am.validate_config(self._cfg(run_dir=''))
        self.assertIn('run-dir', str(cm.exception))

    def test_requires_exactly_one_target_auth(self):
        # Two set → error.
        with self.assertRaises(ValueError) as cm:
            am.validate_config(self._cfg(target_config='/t.json'))
        self.assertIn('target-user', str(cm.exception))
        self.assertIn('target-config', str(cm.exception))
        self.assertIn('target-vault-record', str(cm.exception))

        # All three set → error.
        with self.assertRaises(ValueError):
            am.validate_config(self._cfg(
                target_config='/t.json',
                target_vault_record='abc',
            ))

        # Neither set → error.
        with self.assertRaises(ValueError):
            am.validate_config(self._cfg(target_user=''))

    def test_target_vault_record_is_valid_auth(self):
        """--target-vault-record is a legitimate standalone auth
        option (no --target-user / --target-config needed)."""
        am.validate_config(self._cfg(
            target_user='', target_vault_record='uid-abc',
        ))

    def test_rejects_unknown_only_stages(self):
        with self.assertRaises(ValueError) as cm:
            am.validate_config(self._cfg(only_stages=['plan', 'bogus']))
        self.assertIn('bogus', str(cm.exception))

    def test_rejects_unknown_skip_stages(self):
        with self.assertRaises(ValueError):
            am.validate_config(self._cfg(skip_stages=['attack-vector']))


# ── Stage filtering ────────────────────────────────────────────────

class EffectiveStagesTests(unittest.TestCase):
    def _cfg(self, **kw):
        return am.RunConfig(run_dir='/tmp/x', target_user='a@y',
                             **kw)

    def test_default_runs_all_canonical_stages(self):
        self.assertEqual(
            am.effective_stages(self._cfg()),
            am.CANONICAL_STAGES,
        )

    def test_only_stages_limits_to_whitelist(self):
        stages = am.effective_stages(self._cfg(
            only_stages=['plan', 'convert', 'verify'],
        ))
        # Order preserved from canonical.
        self.assertEqual(stages, ['plan', 'convert', 'verify'])

    def test_skip_stages_removes_named(self):
        stages = am.effective_stages(self._cfg(
            skip_stages=[am.STAGE_USERS, am.STAGE_ESTIMATE],
        ))
        self.assertNotIn('users', stages)
        self.assertNotIn('estimate', stages)
        # Others retained.
        self.assertIn('plan', stages)
        self.assertIn('structure', stages)

    def test_only_stages_takes_precedence_over_skip(self):
        stages = am.effective_stages(self._cfg(
            only_stages=['plan', 'convert'],
            skip_stages=['plan'],   # ignored under --only-stages
        ))
        self.assertEqual(stages, ['plan', 'convert'])


# ── SessionPair safety ─────────────────────────────────────────────

class SessionPairTests(unittest.TestCase):
    def _fake_params(self, tenant_name):
        return SimpleNamespace(
            enterprise={'enterprise_name': tenant_name},
        )

    def test_distinct_tenants_ok(self):
        src = self._fake_params('AcmeCorp')
        tgt = self._fake_params('WidgetInc')
        pair = am.SessionPair(source_params=src, target_params=tgt)
        pair.verify_distinct()
        self.assertEqual(pair.source_tenant_name, 'AcmeCorp')
        self.assertEqual(pair.target_tenant_name, 'WidgetInc')

    def test_same_tenant_refused(self):
        """Critical safeguard: if source == target the user's target
        writes would destroy source data. Block before any stage runs.
        """
        src = self._fake_params('AcmeCorp')
        tgt = self._fake_params('AcmeCorp')
        pair = am.SessionPair(source_params=src, target_params=tgt)
        with self.assertRaises(ValueError) as cm:
            pair.verify_distinct()
        self.assertIn('same tenant', str(cm.exception).lower())

    def test_missing_target_params_is_noop(self):
        """Before target auth the check is deferred — verify_distinct
        returns cleanly. The auth step re-runs it after attaching."""
        src = self._fake_params('AcmeCorp')
        pair = am.SessionPair(source_params=src, target_params=None)
        pair.verify_distinct()   # must not raise

    def test_empty_tenant_names_dont_false_positive(self):
        """Commander sometimes has an empty enterprise dict before
        query_enterprise runs. verify_distinct should not treat two
        unknowns as 'same tenant'."""
        src = self._fake_params('')
        tgt = self._fake_params('')
        pair = am.SessionPair(source_params=src, target_params=tgt)
        pair.verify_distinct()   # must not raise


# ── Interactive target login ───────────────────────────────────────

class AttachVaultRecordTargetTests(unittest.TestCase):
    """Bootstrap target session from a source-vault record."""

    def _sessions(self, source_records):
        src = SimpleNamespace(
            enterprise={'enterprise_name': 'Source'},
            record_cache=source_records,
        )
        return am.SessionPair(source_params=src)

    def _fake_record(self, login, password, url):
        r = SimpleNamespace(
            login=login, password=password, login_url=url,
        )
        return r

    def test_missing_record_raises(self):
        pair = self._sessions({})
        with mock.patch('keepercommander.api.get_record',
                        return_value=None):
            with self.assertRaises(ValueError) as cm:
                am.attach_vault_record_target(
                    pair, record_uid='no-such-uid',
                )
        self.assertIn('not found', str(cm.exception).lower())

    def test_record_without_password_raises(self):
        pair = self._sessions({})
        rec = self._fake_record('admin@x.io', '', 'https://x')
        with mock.patch('keepercommander.api.get_record',
                        return_value=rec):
            with self.assertRaises(ValueError) as cm:
                am.attach_vault_record_target(
                    pair, record_uid='uid',
                )
        self.assertIn('login or', str(cm.exception).lower())

    def test_server_derived_from_url_eu(self):
        """URL contains 'keepersecurity.eu' → target server set to EU."""
        pair = self._sessions({})
        rec = self._fake_record(
            'admin@demo.io', 'pw',
            'https://keepersecurity.eu/console/#login',
        )
        with mock.patch('keepercommander.api.get_record',
                        return_value=rec), \
             mock.patch('keepercommander.api.login'), \
             mock.patch('keepercommander.api.query_enterprise'), \
             mock.patch('keepercommander.api.sync_down'), \
             mock.patch('keepercommander.params.KeeperParams') as P:
            P.return_value = SimpleNamespace(
                enterprise={'enterprise_name': 'Target'},
                user='', server='', password='',
                auto_login=False, sync_data=True,
            )
            tgt = am.attach_vault_record_target(
                pair, record_uid='uid',
            )
        self.assertEqual(tgt.server, 'keepersecurity.eu')

    def test_server_override_wins(self):
        """Explicit server_override takes precedence over URL-derived."""
        pair = self._sessions({})
        rec = self._fake_record(
            'admin@demo.io', 'pw',
            'https://keepersecurity.com/',  # US URL
        )
        with mock.patch('keepercommander.api.get_record',
                        return_value=rec), \
             mock.patch('keepercommander.api.login'), \
             mock.patch('keepercommander.api.query_enterprise'), \
             mock.patch('keepercommander.api.sync_down'), \
             mock.patch('keepercommander.params.KeeperParams') as P:
            P.return_value = SimpleNamespace(
                enterprise={'enterprise_name': 'Target'},
                user='', server='', password='',
                auto_login=False, sync_data=True,
            )
            tgt = am.attach_vault_record_target(
                pair, record_uid='uid',
                server_override='keepersecurity.eu',
            )
        self.assertEqual(tgt.server, 'keepersecurity.eu')

    def test_password_wiped_after_login(self):
        pair = self._sessions({})
        rec = self._fake_record(
            'admin@demo.io', 'real-password',
            'https://keepersecurity.com/',
        )
        tgt_mock = SimpleNamespace(
            enterprise={'enterprise_name': 'Target'},
            user='', server='', password='',
            auto_login=False, sync_data=True,
        )
        with mock.patch('keepercommander.api.get_record',
                        return_value=rec), \
             mock.patch('keepercommander.api.login'), \
             mock.patch('keepercommander.api.query_enterprise'), \
             mock.patch('keepercommander.api.sync_down'), \
             mock.patch('keepercommander.params.KeeperParams',
                         return_value=tgt_mock):
            tgt = am.attach_vault_record_target(
                pair, record_uid='uid',
            )
        # Password must be wiped after login — session token is what we
        # keep, master password never persists in memory.
        self.assertEqual(tgt.password, '')


class AttachInteractiveTargetTests(unittest.TestCase):
    def test_prompt_fn_called_with_email(self):
        """The prompt_fn injection point lets tests run without
        getpass — confirm the email is in the prompt."""
        captured = []

        def fake_prompt(msg):
            captured.append(msg)
            return 'test-password'

        src = SimpleNamespace(enterprise={'enterprise_name': 'Acme'})
        pair = am.SessionPair(source_params=src)

        # We can't actually call api.login in a unit test, so mock
        # the imports. Patching the module-level imports.
        with mock.patch('keepercommander.api.login'), \
             mock.patch('keepercommander.api.query_enterprise'), \
             mock.patch('keepercommander.api.sync_down'), \
             mock.patch('keepercommander.params.KeeperParams') as P:
            fake_params = SimpleNamespace(
                enterprise={'enterprise_name': 'Target'},
                password='', user='', server='',
                auto_login=False, sync_data=True,
            )
            P.return_value = fake_params
            am.attach_interactive_target(
                pair, user='admin@acme.io',
                server='keepersecurity.eu',
                prompt_fn=fake_prompt,
            )

        self.assertEqual(len(captured), 1)
        self.assertIn('admin@acme.io', captured[0])
        self.assertIn('password', captured[0].lower())

    def test_password_cleared_after_login(self):
        """Master password must be wiped from params.password after
        login — session token is what we keep, password never persists."""
        src = SimpleNamespace(enterprise={'enterprise_name': 'Acme'})
        pair = am.SessionPair(source_params=src)

        with mock.patch('keepercommander.api.login'), \
             mock.patch('keepercommander.api.query_enterprise'), \
             mock.patch('keepercommander.api.sync_down'), \
             mock.patch('keepercommander.params.KeeperParams') as P:
            fake_params = SimpleNamespace(
                enterprise={'enterprise_name': 'Target'},
                password='', user='', server='',
                auto_login=False, sync_data=True,
            )
            P.return_value = fake_params
            result = am.attach_interactive_target(
                pair, user='admin@acme.io',
                prompt_fn=lambda m: 'the-password',
            )

        # After attach, result.password must be cleared.
        self.assertEqual(result.password, '')

    def test_sec4_password_cleared_even_on_login_failure(self):
        """SEC-4 — pre-fix tgt.password was set BEFORE api.login() and
        only cleared in the success path. Any login exception (bad
        password / MFA decline / throttle / network) left plaintext
        on the long-lived KeeperParams. Post-fix try/finally zeroes
        the password regardless of outcome.
        """
        src = SimpleNamespace(enterprise={'enterprise_name': 'Acme'})
        pair = am.SessionPair(source_params=src)

        # Make api.login raise — simulates bad-password / MFA-decline.
        with mock.patch('keepercommander.api.login',
                        side_effect=RuntimeError('bad password')), \
             mock.patch('keepercommander.api.query_enterprise'), \
             mock.patch('keepercommander.api.sync_down'), \
             mock.patch('keepercommander.params.KeeperParams') as P:
            fake_params = SimpleNamespace(
                enterprise={'enterprise_name': 'Target'},
                password='', user='', server='',
                auto_login=False, sync_data=True,
            )
            P.return_value = fake_params
            with self.assertRaises(RuntimeError):
                am.attach_interactive_target(
                    pair, user='admin@acme.io',
                    prompt_fn=lambda m: 'the-password',
                )
            # Post-fix invariant: even after the login exception
            # propagated, the KeeperParams.password must be cleared.
            self.assertEqual(fake_params.password, '',
                             'tgt.password retained plaintext after '
                             'login failure — SEC-4 regression')


# NOTE: SEC-4 fix applies the same try/finally pattern to
# attach_target_from_record (vault-record path) — covered structurally
# by the identical fix shape in auto_migrate.py:256-264. Mocking the
# api.get_record path requires more elaborate fixtures; the interactive
# path test above is the load-bearing regression.


class AttachConfigTargetSEC6Tests(unittest.TestCase):
    """HIGH-6: attach_config_target was calling api.login(tgt) BEFORE
    session_pair.verify_distinct(). If the target config accidentally
    pointed at the same tenant as the source, the misdirected login +
    enterprise-read + sync-down had already executed against the wrong
    tenant by the time verify_distinct raised. Post-fix a pre-login
    user/server comparison fires first.
    """

    def test_high6_same_tenant_target_caught_pre_login(self):
        import json as _json
        src = SimpleNamespace(
            enterprise={'enterprise_name': 'Acme'},
            user='admin@acme.io',
            server='keepersecurity.eu',
        )
        pair = am.SessionPair(source_params=src)

        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False) as t:
            _json.dump({
                'user': 'admin@acme.io',  # same as src
                'server': 'keepersecurity.eu',  # same as src
                'device_token': 'tok',
                'clone_code': 'clone',
                'private_key': 'pk',
            }, t)
            cfg_path = t.name

        try:
            # Mock api so we can detect whether login was called.
            login_called = []
            with mock.patch('keepercommander.api.login',
                            side_effect=lambda *a, **kw: login_called.append(1)), \
                 mock.patch('keepercommander.api.query_enterprise'), \
                 mock.patch('keepercommander.api.sync_down'), \
                 mock.patch('keepercommander.params.KeeperParams') as P:
                fake_params = SimpleNamespace(
                    enterprise={'enterprise_name': 'Acme'},
                    user='', server='', auto_login=False, sync_data=True,
                    password='', device_token=None, clone_code=None,
                    device_private_key=None,
                )
                P.return_value = fake_params
                with self.assertRaises(ValueError) as cm:
                    am.attach_config_target(pair, config_path=cfg_path)
            self.assertIn('same tenant', str(cm.exception).lower())
            # api.login MUST NOT have been called — pre-login check
            # must catch the misdirection before any side-effecting
            # network call.
            self.assertEqual(login_called, [],
                             'api.login was called despite same-tenant '
                             'target — HIGH-6 regression: pre-login '
                             'guard did not fire')
        finally:
            os.unlink(cfg_path)


# ── Run dispatch ───────────────────────────────────────────────────

class RunDispatchTests(unittest.TestCase):
    """Verify run() walks effective_stages and halts on FAIL."""

    def _sessions(self):
        src = SimpleNamespace(enterprise={'enterprise_name': 'S'})
        tgt = SimpleNamespace(enterprise={'enterprise_name': 'T'})
        return am.SessionPair(
            source_params=src, target_params=tgt,
            source_tenant_name='S', target_tenant_name='T',
        )

    def test_run_halts_on_first_fail(self):
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(
                run_dir=run_dir, target_user='a@y',
                only_stages=['plan', 'convert', 'verify'],
            )

            call_log = []

            def ok_stage(s, c):
                call_log.append('ok')
                return am.StageResult('plan', 'PASS')

            def fail_stage(s, c):
                call_log.append('fail')
                return am.StageResult('convert', 'FAIL',
                                       detail='simulated')

            def never(s, c):
                call_log.append('never')
                return am.StageResult('verify', 'PASS')

            with mock.patch.dict(am._STAGE_DISPATCH, {
                'plan': ok_stage,
                'convert': fail_stage,
                'verify': never,
            }):
                summary = am.run(self._sessions(), cfg)

            # verify was NOT called — pipeline halted.
            self.assertEqual(call_log, ['ok', 'fail'])
            self.assertEqual(summary['counts']['FAIL'], 1)
            self.assertEqual(summary['counts']['PASS'], 1)

    def test_run_stage_exception_is_caught_and_halts(self):
        """An uncaught exception in a stage → FAIL status, pipeline
        halts (does NOT let downstream stages run on unknown state)."""
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(
                run_dir=run_dir, target_user='a@y',
                only_stages=['plan', 'convert'],
            )

            def ok(s, c):
                return am.StageResult('plan', 'PASS')

            def boom(s, c):
                raise RuntimeError('stage crashed')

            with mock.patch.dict(am._STAGE_DISPATCH, {
                'plan': ok,
                'convert': boom,
            }):
                summary = am.run(self._sessions(), cfg)

            stages = summary['stages']
            self.assertEqual(stages[0].status, 'PASS')
            self.assertEqual(stages[1].status, 'FAIL')
            self.assertIn('RuntimeError', stages[1].detail)
            self.assertIn('stage crashed', stages[1].detail)

    def test_run_unknown_stage_becomes_skip(self):
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(
                run_dir=run_dir, target_user='a@y',
                only_stages=['plan'],
            )
            # Dispatch dict lacks 'plan' — only_stages filters canonical
            # list so 'plan' is requested; remove the dispatch entry so
            # run() falls into the 'unknown stage' branch.
            with mock.patch.dict(am._STAGE_DISPATCH, {}, clear=True):
                summary = am.run(self._sessions(), cfg)
            self.assertEqual(summary['counts']['SKIP'], 1)
            self.assertEqual(summary['stages'][0].status, 'SKIP')

    # Phase 2 Audit 3 #4 fix: --expected-source-tenant /
    # --expected-target-tenant were previously accepted at the CLI
    # and stored on RunConfig but never enforced. These regressions
    # fail-CLOSED if the assertion is ever reverted to warn-only.

    def test_run_blocks_when_expected_source_tenant_mismatches(self):
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(
                run_dir=run_dir, target_user='a@y',
                only_stages=['plan'],
                expected_source_tenant='WRONG-SRC',
            )
            with self.assertRaises(ValueError) as cm:
                am.run(self._sessions(), cfg)
            self.assertIn('expected-source-tenant', str(cm.exception))
            self.assertIn("'WRONG-SRC'", str(cm.exception))
            self.assertIn("'S'", str(cm.exception))

    def test_run_blocks_when_expected_target_tenant_mismatches(self):
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(
                run_dir=run_dir, target_user='a@y',
                only_stages=['plan'],
                expected_target_tenant='WRONG-TGT',
            )
            with self.assertRaises(ValueError) as cm:
                am.run(self._sessions(), cfg)
            self.assertIn('expected-target-tenant', str(cm.exception))
            self.assertIn("'WRONG-TGT'", str(cm.exception))
            self.assertIn("'T'", str(cm.exception))

    def test_run_passes_when_expected_tenants_match(self):
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(
                run_dir=run_dir, target_user='a@y',
                only_stages=['plan'],
                expected_source_tenant='S',
                expected_target_tenant='T',
            )
            def ok(s, c):
                return am.StageResult('plan', 'PASS')
            with mock.patch.dict(am._STAGE_DISPATCH, {'plan': ok}):
                summary = am.run(self._sessions(), cfg)
            self.assertEqual(summary['counts']['PASS'], 1)


# ── Dispatch completeness ─────────────────────────────────────────

class DispatchCompletenessTests(unittest.TestCase):
    def test_every_canonical_stage_has_a_dispatcher(self):
        """Regression guard: if someone adds a CANONICAL_STAGES entry
        but forgets to register it in _STAGE_DISPATCH, that stage
        silently gets SKIPped with no stage run. Catch early."""
        missing = [s for s in am.CANONICAL_STAGES
                    if s not in am._STAGE_DISPATCH]
        self.assertEqual(
            missing, [],
            f'CANONICAL_STAGES entries missing from _STAGE_DISPATCH: '
            f'{missing}',
        )

    def test_every_stage_has_phase_classification(self):
        missing = [s for s in am.CANONICAL_STAGES
                    if s not in am.STAGE_PHASE]
        self.assertEqual(
            missing, [],
            f'CANONICAL_STAGES missing from STAGE_PHASE: {missing}',
        )

    def test_stage_phases_use_known_values(self):
        allowed = {'source', 'target', 'local'}
        for s, phase in am.STAGE_PHASE.items():
            self.assertIn(
                phase, allowed,
                f'stage {s!r} has unknown phase {phase!r}',
            )


class ReferencesRewriteStageTests(unittest.TestCase):
    """Bug 33 (v1.5.2) — auto-migrate stage wiring.

    Pipeline ordering matters: references-rewrite must run AFTER
    records-import + att-upload (so target UIDs exist + the manifest
    is populated) but BEFORE shares-extract (so any share grants on
    rewritten records use the post-rewrite field values).
    """

    def test_canonical_stage_present_in_correct_position(self):
        stages = am.CANONICAL_STAGES
        self.assertIn(am.STAGE_RECORDS_REFERENCES_REWRITE, stages)
        idx_rewrite = stages.index(am.STAGE_RECORDS_REFERENCES_REWRITE)
        idx_att_upload = stages.index(am.STAGE_ATT_UPLOAD)
        idx_shares_extract = stages.index(am.STAGE_RECORDS_SHARES_EXTRACT)
        self.assertGreater(idx_rewrite, idx_att_upload,
                            'rewrite must run after att-upload')
        self.assertLess(idx_rewrite, idx_shares_extract,
                         'rewrite must run before shares-extract')

    def test_phase_is_target(self):
        # Mutates target tenant — same phase as records-import / att-upload.
        self.assertEqual(
            am.STAGE_PHASE[am.STAGE_RECORDS_REFERENCES_REWRITE], 'target')

    def test_dispatch_registered(self):
        self.assertIn(am.STAGE_RECORDS_REFERENCES_REWRITE,
                       am._STAGE_DISPATCH)

    def test_dry_run_returns_dry_skip(self):
        cfg = SimpleNamespace(dry_run=True, run_dir='/tmp/x')
        sessions = SimpleNamespace(target_params=None)
        # _s_dry_stage returns a StageResult with status='SKIP' and
        # dry-run banner detail. Calling the real dispatcher exercises
        # the stage's dry-run short-circuit.
        result = am._s_records_references_rewrite(sessions, cfg)
        self.assertEqual(result.name, am.STAGE_RECORDS_REFERENCES_REWRITE)
        self.assertIn(result.status, ('SKIP', 'PASS'))
        self.assertIn('dry-run', (result.detail or '').lower())

    def test_skip_when_manifest_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SimpleNamespace(dry_run=False, run_dir=tmp)
            sessions = SimpleNamespace(target_params=None)
            result = am._s_records_references_rewrite(sessions, cfg)
        self.assertEqual(result.status, 'SKIP')
        self.assertIn('manifest', (result.detail or '').lower())

    def test_pass_when_subcommand_returns_clean_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = os.path.join(tmp, 'manifest.csv')
            open(manifest, 'w').write('source_uid,target_uid,title\n')
            cfg = SimpleNamespace(dry_run=False, run_dir=tmp)
            sessions = SimpleNamespace(target_params=None)
            with mock.patch(
                    'keepercommander.commands.keeper_tenant_migrate.commands.RecordsReferencesRewriteCommand'
            ) as Cmd:
                Cmd.return_value.execute.return_value = {
                    'records_inspected': 5,
                    'records_with_refs': 3,
                    'records_rewritten': 2,
                    'refs_remapped': 4,
                    'refs_unknown': 1,
                    'refs_empty': 0,
                    'load_failures': 0,
                    'persist_failures': 0,
                    'rewritten_uids': ['t1', 't2'],
                    'failed_uids': [],
                }
                result = am._s_records_references_rewrite(sessions, cfg)
        self.assertEqual(result.status, 'PASS')
        self.assertIn('inspected=5', result.detail)
        self.assertIn('rewritten=2', result.detail)
        self.assertIn('refs_remapped=4', result.detail)

    def test_fail_when_persist_failures_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = os.path.join(tmp, 'manifest.csv')
            open(manifest, 'w').write('source_uid,target_uid,title\n')
            cfg = SimpleNamespace(dry_run=False, run_dir=tmp)
            sessions = SimpleNamespace(target_params=None)
            with mock.patch(
                    'keepercommander.commands.keeper_tenant_migrate.commands.RecordsReferencesRewriteCommand'
            ) as Cmd:
                Cmd.return_value.execute.return_value = {
                    'records_inspected': 5, 'records_with_refs': 3,
                    'records_rewritten': 0, 'refs_remapped': 0,
                    'refs_unknown': 0, 'refs_empty': 0,
                    'load_failures': 0, 'persist_failures': 2,
                    'rewritten_uids': [], 'failed_uids': ['t1', 't2'],
                }
                result = am._s_records_references_rewrite(sessions, cfg)
        self.assertEqual(result.status, 'FAIL')
        self.assertIn('persist_fail=2', result.detail)

    def test_fail_when_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = os.path.join(tmp, 'manifest.csv')
            open(manifest, 'w').write('source_uid,target_uid,title\n')
            cfg = SimpleNamespace(dry_run=False, run_dir=tmp)
            sessions = SimpleNamespace(target_params=None)
            with mock.patch(
                    'keepercommander.commands.keeper_tenant_migrate.commands.RecordsReferencesRewriteCommand'
            ) as Cmd:
                Cmd.return_value.execute.return_value = {
                    'blocked': True, 'reason': 'rate limit',
                }
                result = am._s_records_references_rewrite(sessions, cfg)
        self.assertEqual(result.status, 'FAIL')
        self.assertIn('rate limit', result.detail)


class FullPipelineE2ETests(unittest.TestCase):
    """End-to-end dispatch through every canonical stage with mocked
    stage functions. Locks in:
      - Every CANONICAL_STAGES entry runs exactly once
      - Execution order matches CANONICAL_STAGES
      - sessions + cfg are passed through verbatim to every stage
      - Summary dict shape is stable (stages, counts, source_tenant,
        target_tenant, run_dir, dry_run)
      - users stage SKIP status is honored by the counter, not summed
        into PASS/FAIL
    """

    def _sessions(self):
        src = SimpleNamespace(enterprise={'enterprise_name': 'SourceCo'})
        tgt = SimpleNamespace(enterprise={'enterprise_name': 'TargetCo'})
        return am.SessionPair(
            source_params=src, target_params=tgt,
            source_tenant_name='SourceCo', target_tenant_name='TargetCo',
        )

    def _make_happy_dispatch(self, call_log):
        """Dispatch table where every stage PASSes and appends its name
        to call_log so assertions can check ordering."""
        def _stage_factory(name):
            def _fn(sessions, cfg):
                call_log.append(name)
                return am.StageResult(name, 'PASS')
            return _fn
        return {s: _stage_factory(s) for s in am.CANONICAL_STAGES}

    def test_happy_path_runs_every_canonical_stage_in_order(self):
        call_log = []
        dispatch = self._make_happy_dispatch(call_log)
        # users auto-skip is baked into the real dispatch; override here
        # so every stage really runs and summary = 16 PASS / 0 SKIP.
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(run_dir=run_dir, target_user='admin@y.io')
            with mock.patch.dict(am._STAGE_DISPATCH, dispatch, clear=True):
                summary = am.run(self._sessions(), cfg)
        self.assertEqual(call_log, list(am.CANONICAL_STAGES))
        self.assertEqual(summary['counts']['PASS'],
                          len(am.CANONICAL_STAGES))
        self.assertEqual(summary['counts']['FAIL'], 0)
        self.assertEqual(summary['counts']['SKIP'], 0)

    def test_summary_dict_carries_session_context(self):
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(run_dir=run_dir, target_user='admin@y.io',
                                dry_run=True)
            with mock.patch.dict(am._STAGE_DISPATCH,
                                   self._make_happy_dispatch([]),
                                   clear=True):
                summary = am.run(self._sessions(), cfg)
        self.assertEqual(summary['source_tenant'], 'SourceCo')
        self.assertEqual(summary['target_tenant'], 'TargetCo')
        self.assertEqual(summary['run_dir'], run_dir)
        self.assertTrue(summary['dry_run'])

    def test_sessions_and_cfg_forwarded_verbatim_to_stages(self):
        """Paranoia check — auto-migrate must not mutate sessions/cfg
        between stages; a stage receiving a modified copy would see
        ghost bugs that don't reproduce in per-stage tests."""
        observed_ids = []

        def _probe(sessions, cfg):
            observed_ids.append((id(sessions), id(cfg)))
            return am.StageResult('plan', 'PASS')

        dispatch = {s: _probe for s in am.CANONICAL_STAGES}
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(run_dir=run_dir, target_user='admin@y.io')
            sessions = self._sessions()
            with mock.patch.dict(am._STAGE_DISPATCH, dispatch, clear=True):
                am.run(sessions, cfg)
        # All stages saw the SAME objects.
        session_ids = {sid for sid, _ in observed_ids}
        cfg_ids = {cid for _, cid in observed_ids}
        self.assertEqual(session_ids, {id(sessions)})
        self.assertEqual(cfg_ids, {id(cfg)})

    def test_stage_elapsed_seconds_populated(self):
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(run_dir=run_dir, target_user='admin@y.io')
            with mock.patch.dict(am._STAGE_DISPATCH,
                                   self._make_happy_dispatch([]),
                                   clear=True):
                summary = am.run(self._sessions(), cfg)
        for r in summary['stages']:
            self.assertIsNotNone(r.seconds, f'{r.name} missing seconds')
            self.assertGreaterEqual(r.seconds, 0.0)

    def test_only_stages_truncates_pipeline(self):
        call_log = []
        dispatch = self._make_happy_dispatch(call_log)
        picks = [am.STAGE_PLAN, am.STAGE_VERIFY]
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(run_dir=run_dir, target_user='admin@y.io',
                                only_stages=list(picks))
            with mock.patch.dict(am._STAGE_DISPATCH, dispatch, clear=True):
                summary = am.run(self._sessions(), cfg)
        self.assertEqual(call_log, picks)
        self.assertEqual(len(summary['stages']), 2)

    def test_skip_stages_removes_from_pipeline(self):
        call_log = []
        dispatch = self._make_happy_dispatch(call_log)
        dropped = {am.STAGE_USERS, am.STAGE_SF_RECONCILE}
        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(run_dir=run_dir, target_user='admin@y.io',
                                skip_stages=list(dropped))
            with mock.patch.dict(am._STAGE_DISPATCH, dispatch, clear=True):
                am.run(self._sessions(), cfg)
        # None of the dropped stages ran; every other canonical stage did.
        self.assertNotIn(am.STAGE_USERS, call_log)
        self.assertNotIn(am.STAGE_SF_RECONCILE, call_log)
        expected = [s for s in am.CANONICAL_STAGES if s not in dropped]
        self.assertEqual(call_log, expected)

    def test_fail_then_halt_then_skip_semantics(self):
        """Mixed run: plan PASS → convert FAIL → verify never runs. The
        halt contract is critical because any later stage running after
        a structure FAIL would operate on broken-state target."""
        call_log = []

        def _ok(s, c):
            call_log.append('plan'); return am.StageResult('plan', 'PASS')
        def _fail(s, c):
            call_log.append('convert')
            return am.StageResult('convert', 'FAIL', detail='simulated')
        def _never(s, c):
            call_log.append('verify'); return am.StageResult('verify', 'PASS')

        with tempfile.TemporaryDirectory() as run_dir:
            cfg = am.RunConfig(
                run_dir=run_dir, target_user='admin@y.io',
                only_stages=['plan', 'convert', 'verify'],
            )
            with mock.patch.dict(am._STAGE_DISPATCH, {
                'plan': _ok, 'convert': _fail, 'verify': _never,
            }, clear=True):
                summary = am.run(self._sessions(), cfg)

        self.assertEqual(call_log, ['plan', 'convert'])
        self.assertEqual(summary['counts']['PASS'], 1)
        self.assertEqual(summary['counts']['FAIL'], 1)
        self.assertEqual(summary['counts']['SKIP'], 0)
        # Exactly two stage records — verify never happened, no SKIP entry.
        self.assertEqual(len(summary['stages']), 2)

    def test_run_dir_auto_created(self):
        """run() is responsible for ensuring cfg.run_dir exists so stage
        functions can write artifacts without racing on mkdir. Regression
        guard: a stage that tries to write to a missing dir should NOT
        be what surfaces the error."""
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = os.path.join(tmp, 'nested', 'deep', 'run')
            self.assertFalse(os.path.exists(run_dir))
            cfg = am.RunConfig(run_dir=run_dir, target_user='admin@y.io')
            with mock.patch.dict(am._STAGE_DISPATCH,
                                   self._make_happy_dispatch([]),
                                   clear=True):
                am.run(self._sessions(), cfg)
            self.assertTrue(os.path.isdir(run_dir))


class RecordsManifestStageAllowAmbiguousTests(unittest.TestCase):
    """Bug 49 — auto-migrate's records-manifest stage must propagate
    `RunConfig.allow_ambiguous` into `RecordsManifestCommand.execute()`
    so duplicate-title source records can be positionally paired when
    the operator opts in. Default-False preserves prior strict
    behavior."""

    def _run_stage(self, *, allow_ambiguous):
        with tempfile.TemporaryDirectory() as tmp:
            export_dir = os.path.join(tmp, 'records_export')
            os.makedirs(export_dir)
            cfg = am.RunConfig(
                run_dir=tmp,
                target_user='admin@y.io',
                allow_ambiguous=allow_ambiguous,
            )
            sessions = SimpleNamespace(target_params=None)
            captured = {}

            class FakeManifest:
                def execute(_self, params, **kwargs):
                    captured.update(kwargs)
                    return {'counts': {'pairs': 0, 'ambiguous': 0,
                                        'source_only': 0,
                                        'target_only': 0}}

            with mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands.RecordsManifestCommand',
                return_value=FakeManifest(),
            ):
                result = am._s_records_manifest(sessions, cfg)
            return result, captured

    def test_default_passes_strict_false(self):
        """Default RunConfig.allow_ambiguous is False — must reach
        the manifest command unchanged so duplicate-title pairs are
        flagged, not silently positionally paired."""
        result, captured = self._run_stage(allow_ambiguous=False)
        self.assertEqual(result.status, 'PASS')
        self.assertEqual(captured.get('allow_ambiguous'), False)

    def test_opt_in_passes_true(self):
        """RunConfig.allow_ambiguous=True must reach the manifest
        command so positional pairing kicks in for duplicate-title
        groups (the rehearsal-4 unblock path)."""
        result, captured = self._run_stage(allow_ambiguous=True)
        self.assertEqual(result.status, 'PASS')
        self.assertEqual(captured.get('allow_ambiguous'), True)


if __name__ == '__main__':
    unittest.main()
