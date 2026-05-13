import logging
import unittest

from keepercommander.commands.keeper_tenant_migrate.safeguards import (
    SafeguardBlocked,
    banner_destructive,
    banner_for,
    banner_modifying,
    confirm_interactive,
    enforce_batch_cap,
    expect_tenant,
    preflight_destructive,
    production_tenant_warning,
    require_tenant_assertion,
)


class _FakeParams:
    def __init__(self, name='Keeperdemo'):
        self.enterprise = {'enterprise_name': name} if name is not None else {}


class ExpectTenantTests(unittest.TestCase):
    def test_empty_expected_disables_check(self):
        self.assertTrue(expect_tenant(_FakeParams(), ''))

    def test_exact_match_passes(self):
        self.assertTrue(expect_tenant(_FakeParams('Acme Inc'), 'Acme Inc'))

    def test_case_insensitive(self):
        self.assertTrue(expect_tenant(_FakeParams('Acme Inc'), 'acme inc'))

    def test_mismatch_raises(self):
        with self.assertRaises(SafeguardBlocked) as cm:
            expect_tenant(_FakeParams('Acme Inc'), 'Different Tenant')
        self.assertIn('mismatch', str(cm.exception))


class RequireTenantAssertionTests(unittest.TestCase):
    def test_exact_match_passes(self):
        self.assertTrue(
            require_tenant_assertion(_FakeParams('Acme Inc'), 'Acme Inc')
        )

    def test_case_insensitive_match_passes(self):
        self.assertTrue(
            require_tenant_assertion(_FakeParams('Acme Inc'), 'acme inc')
        )

    def test_mismatch_raises(self):
        with self.assertRaises(SafeguardBlocked) as cm:
            require_tenant_assertion(_FakeParams('Acme Inc'), 'OtherCorp')
        self.assertIn('mismatch', str(cm.exception))

    def test_empty_expected_without_skip_raises(self):
        with self.assertRaises(SafeguardBlocked) as cm:
            require_tenant_assertion(_FakeParams('Acme Inc'), '',
                                     subcommand='cleanup')
        msg = str(cm.exception)
        self.assertIn('cleanup', msg)
        self.assertIn('tenant assertion', msg)
        self.assertIn('--expected-tenant-name', msg)
        self.assertIn('--skip-tenant-check', msg)

    def test_empty_expected_message_includes_current_session(self):
        with self.assertRaises(SafeguardBlocked) as cm:
            require_tenant_assertion(_FakeParams('My company'), '',
                                     subcommand='decommission')
        self.assertIn("'My company'", str(cm.exception))

    def test_empty_expected_no_enterprise_shows_unknown(self):
        with self.assertRaises(SafeguardBlocked) as cm:
            require_tenant_assertion(_FakeParams(None), '',
                                     subcommand='cleanup')
        self.assertIn('(unknown)', str(cm.exception))

    def test_skip_check_bypasses_empty_expected(self):
        with self.assertLogs(level='WARNING') as captured:
            self.assertTrue(
                require_tenant_assertion(_FakeParams('Acme'), '',
                                         skip_check=True,
                                         subcommand='cleanup')
            )
        joined = '\n'.join(captured.output)
        self.assertIn('SKIPPED', joined)
        self.assertIn('cleanup', joined)
        self.assertIn("'Acme'", joined)

    def test_skip_check_bypasses_mismatch(self):
        # Explicit skip bypasses even a mismatched expected name. CI is
        # allowed to assert "I know what I'm doing" — the WARN logs it.
        with self.assertLogs(level='WARNING'):
            self.assertTrue(
                require_tenant_assertion(_FakeParams('Acme'), 'DifferentCorp',
                                         skip_check=True)
            )

    def test_default_subcommand_label_used(self):
        with self.assertRaises(SafeguardBlocked) as cm:
            require_tenant_assertion(_FakeParams('Acme'), '')
        self.assertIn('destructive op', str(cm.exception))


class EnforceBatchCapTests(unittest.TestCase):
    def test_under_cap_passes(self):
        self.assertTrue(enforce_batch_cap(5, 50))

    def test_at_cap_passes(self):
        self.assertTrue(enforce_batch_cap(50, 50))

    def test_over_cap_raises(self):
        with self.assertRaises(SafeguardBlocked) as cm:
            enforce_batch_cap(51, 50)
        self.assertIn('51', str(cm.exception))
        self.assertIn('cap=50', str(cm.exception))

    def test_override_allows_over_cap(self):
        self.assertTrue(enforce_batch_cap(1000, 50, override=True))


class ProductionTenantWarningTests(unittest.TestCase):
    def test_sandbox_keyword_suppresses_warning(self):
        self.assertFalse(production_tenant_warning(_FakeParams('test-tenant')))
        self.assertFalse(production_tenant_warning(_FakeParams('MyKeeperDemo')))
        self.assertFalse(production_tenant_warning(_FakeParams('DEV')))

    def test_production_name_emits_warning(self):
        self.assertTrue(production_tenant_warning(_FakeParams('Acme Production')))

    def test_empty_tenant_name_noop(self):
        self.assertFalse(production_tenant_warning(_FakeParams(None)))


class PreflightDestructiveTests(unittest.TestCase):
    def test_happy_path(self):
        preflight_destructive(_FakeParams('testdemo'),
                               expected_tenant='testdemo',
                               batch_count=5, batch_cap=50)

    def test_tenant_mismatch_blocks(self):
        with self.assertRaises(SafeguardBlocked):
            preflight_destructive(_FakeParams('Acme'),
                                   expected_tenant='Wrong',
                                   batch_count=5)

    def test_batch_cap_blocks(self):
        with self.assertRaises(SafeguardBlocked):
            preflight_destructive(_FakeParams('test'),
                                   batch_count=1000, batch_cap=50)


class BannerTests(unittest.TestCase):
    def _capture(self):
        """Return (records, logger) — logger captures to records list."""
        records = []

        class ListHandler(logging.Handler):
            def emit(self, rec):
                records.append(rec.getMessage())

        logger = logging.getLogger('safeguards_test_banner')
        logger.handlers = []
        logger.addHandler(ListHandler())
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        return records, logger

    def test_banner_destructive_emits_at_error(self):
        records, logger = self._capture()
        banner_destructive('decommission', logger=logger)
        self.assertTrue(any('DESTRUCTIVE' in r for r in records))
        self.assertTrue(any('IRREVERSIBLE' in r for r in records))

    def test_banner_modifying_emits_at_warning(self):
        records, logger = self._capture()
        banner_modifying('structure', logger=logger)
        self.assertTrue(any('MODIFYING' in r for r in records))

    def test_banner_for_skips_in_dry_run(self):
        records, logger = self._capture()
        banner_for('cleanup', dry_run=True, logger=logger)
        self.assertEqual(records, [])

    def test_banner_for_unknown_subcommand_is_noop(self):
        records, logger = self._capture()
        banner_for('not-a-real-subcommand', dry_run=False, logger=logger)
        self.assertEqual(records, [])


class ConfirmInteractiveTests(unittest.TestCase):
    def _run(self, answer, **kwargs):
        outputs = []
        return confirm_interactive(
            'TITLE', 'desc',
            input_fn=lambda prompt: answer,
            output_fn=outputs.append,
            require_interactive=False,
            **kwargs,
        ), outputs

    def test_yes_token(self):
        for t in ('yes', 'YES', 'y', 'Y'):
            ok, _ = self._run(t)
            self.assertTrue(ok, f'{t!r} should accept')

    def test_no_token(self):
        for t in ('no', 'NO', 'n', 'N', ''):
            ok, _ = self._run(t)
            self.assertFalse(ok, f'{t!r} should reject')

    def test_unrecognized_reprompts_then_rejects(self):
        outputs = []
        attempts = iter(['maybe', 'sort-of', 'dunno'])
        ok = confirm_interactive(
            'T', 'd',
            input_fn=lambda prompt: next(attempts),
            output_fn=outputs.append,
            require_interactive=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any('Unrecognized' in line for line in outputs))

    def test_eof_returns_false(self):
        def eof_input(_prompt):
            raise EOFError
        ok = confirm_interactive(
            'T', 'd', input_fn=eof_input, output_fn=lambda _: None,
            require_interactive=False,
        )
        self.assertFalse(ok)

    def test_keyboard_interrupt_returns_false(self):
        def kbd(_prompt):
            raise KeyboardInterrupt
        ok = confirm_interactive(
            'T', 'd', input_fn=kbd, output_fn=lambda _: None,
            require_interactive=False,
        )
        self.assertFalse(ok)

    def test_auto_yes_bypasses(self):
        ok, _ = self._run('', auto_yes=True)
        self.assertTrue(ok)

    def test_auto_no_bypasses(self):
        ok, _ = self._run('yes', auto_no=True)
        self.assertFalse(ok)

    def test_auto_both_raises(self):
        with self.assertRaises(ValueError):
            confirm_interactive('T', 'd', auto_yes=True, auto_no=True)


class _SessionParams:
    """Params shape that detect_session_role can match."""
    def __init__(self, user='', enterprise_name='', server='keepersecurity.eu',
                  session_token='fake'):
        self.user = user
        self.server = server
        self.enterprise = ({'enterprise_name': enterprise_name}
                            if enterprise_name else {})
        self.session_token = session_token


class EnforceSourceModeTests(unittest.TestCase):
    """Four-layer interlock:
    1. run_spec.source_mode == 'destructive'
    2. confirm_flag True
    3. expected_tenant_name non-empty and matches session
    4. expected_tenant_name matches run_spec.source.enterprise_name
    """

    def _spec(self, source_mode='read_only', source_name='Acme Source'):
        return {
            'source': {'enterprise_name': source_name},
            'target': {'enterprise_name': 'Target Corp'},
            'source_mode': source_mode,
        }

    def test_target_session_bypasses_entirely(self):
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Target Corp')
        # No spec fields needed; target role is a no-op.
        self.assertTrue(enforce_source_mode(p, self._spec()))

    def test_unknown_role_also_bypasses(self):
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Unrelated Inc')
        self.assertTrue(enforce_source_mode(p, self._spec()))

    def test_unknown_role_destructive_context_fails_closed(self):
        """SEC-1 regression — when role classification is 'unknown' AND
        the caller is invoking a destructive subcommand (signaled by a
        non-empty `subcommand` kwarg, which destructive wrappers always
        pass), enforce_source_mode must REFUSE rather than silently
        bypass.

        The reviewer's threat model: an operator's run-spec is
        ambiguous (e.g. source and target on the same region without
        distinguishing enterprise_name / user hints), so
        detect_session_role returns 'unknown'. Pre-fix: short-circuit
        returned True and the destructive call ran without the 4-layer
        interlock. Post-fix: SafeguardBlocked is raised so the operator
        is forced to tighten the spec.
        """
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        # Both source and target match the session (worst case from
        # session.py:104-117 — the explicit 'unknown' branch).
        spec = {
            'source': {'enterprise_name': 'Same Tenant'},
            'target': {'enterprise_name': 'Same Tenant'},
            'source_mode': 'destructive',
        }
        p = _SessionParams(enterprise_name='Same Tenant')
        with self.assertRaises(SafeguardBlocked) as cm:
            enforce_source_mode(
                p, spec,
                confirm_flag=True,
                expected_tenant_name='Same Tenant',
                subcommand='cleanup',  # destructive context
            )
        msg = str(cm.exception).lower()
        self.assertIn('unknown', msg)
        self.assertIn('cleanup', msg)
        # Operator should be told what to tighten:
        self.assertIn('enterprise_name', msg)

    def test_unknown_role_no_subcommand_still_bypasses(self):
        """SEC-1 regression — backward compat: when subcommand is empty
        (read-only callers, scope probes, tests), preserve the historical
        bypass on 'unknown'. Only destructive contexts fail-closed.
        """
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        spec = {
            'source': {'enterprise_name': 'Same Tenant'},
            'target': {'enterprise_name': 'Same Tenant'},
        }
        p = _SessionParams(enterprise_name='Same Tenant')
        # No subcommand kwarg → caller is not destructive → bypass.
        self.assertTrue(enforce_source_mode(p, spec))

    def test_layer1_read_only_blocks(self):
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Acme Source')
        with self.assertRaises(SafeguardBlocked) as cm:
            enforce_source_mode(p, self._spec('read_only'),
                                 confirm_flag=True,
                                 expected_tenant_name='Acme Source',
                                 subcommand='cleanup')
        self.assertIn('read_only', str(cm.exception))

    def test_layer1_invalid_mode_blocks(self):
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Acme Source')
        with self.assertRaises(SafeguardBlocked):
            enforce_source_mode(p, self._spec('yolo'),
                                 confirm_flag=True,
                                 expected_tenant_name='Acme Source')

    def test_layer2_missing_confirm_blocks(self):
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Acme Source')
        with self.assertRaises(SafeguardBlocked) as cm:
            enforce_source_mode(p, self._spec('destructive'),
                                 confirm_flag=False,
                                 expected_tenant_name='Acme Source')
        self.assertIn('confirm-source-destructive', str(cm.exception))

    def test_layer3_missing_tenant_name_blocks(self):
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Acme Source')
        with self.assertRaises(SafeguardBlocked) as cm:
            enforce_source_mode(p, self._spec('destructive'),
                                 confirm_flag=True,
                                 expected_tenant_name='')
        self.assertIn('expected-tenant-name', str(cm.exception))

    def test_layer3_wrong_tenant_name_blocks(self):
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Acme Source')
        with self.assertRaises(SafeguardBlocked):
            enforce_source_mode(p, self._spec('destructive'),
                                 confirm_flag=True,
                                 expected_tenant_name='Different Corp')

    def test_layer4_typed_name_disagrees_with_spec_source_blocks(self):
        # Session IS the spec.source — role matches, so the interlock
        # fires. The user typed --expected-tenant-name that matches the
        # session BUT not the spec — a sign they pointed at the wrong
        # migration.yaml. This should block.
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        spec = {
            'source': {'enterprise_name': 'Acme Source'},
            'source_mode': 'destructive',
        }
        # Session matches spec.source and the typed name matches the
        # session — but the spec says a DIFFERENT name: this mutates
        # the spec's source_name to prove the cross-check.
        p = _SessionParams(enterprise_name='Acme Source')
        # Simulate the admin typing 'Acme Source' while the spec they
        # loaded actually has a different source enterprise name.
        mismatched_spec = {
            'source': {'enterprise_name': 'Other Corp'},
            'source_mode': 'destructive',
        }
        # The session role lookup uses enterprise name match — if spec
        # has 'Other Corp' but session is 'Acme Source', detect_role
        # returns 'unknown' and the interlock skips. That's expected.
        # Layer 4 only kicks in when session + role BOTH agree with
        # the spec's source block, so we'd need an entry for both. Use
        # a user-hint as the match:
        aligned_spec = {
            'source': {'enterprise_name': 'Acme Source',
                        'user': 'admin@acme.example'},
            'source_mode': 'destructive',
        }
        p2 = _SessionParams(user='admin@acme.example',
                              enterprise_name='Acme Source')
        # Now role=source. Spec.source.enterprise_name='Acme Source'
        # but user types the target name instead by mistake.
        with self.assertRaises(SafeguardBlocked):
            enforce_source_mode(
                p2, aligned_spec,
                confirm_flag=True,
                expected_tenant_name='Target Corp',  # WRONG: target name
            )

    def test_all_four_layers_satisfied_passes(self):
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Acme Source')
        self.assertTrue(enforce_source_mode(
            p, self._spec('destructive'),
            confirm_flag=True,
            expected_tenant_name='Acme Source',
            subcommand='cleanup',
        ))

    def test_empty_spec_is_read_only(self):
        # No migration.yaml → treated as read_only by default.
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        p = _SessionParams(enterprise_name='Acme Source')
        # Empty spec can't match source role, so detect_session_role
        # returns 'unknown' and the check is a no-op.
        self.assertTrue(enforce_source_mode(p, {}))

    def test_spec_without_source_mode_key_defaults_to_read_only(self):
        # Session matches spec.source, but source_mode key is missing.
        # Default is read_only → block.
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        spec = {
            'source': {'enterprise_name': 'Acme Source',
                        'user': 'admin@acme.example'},
            # NO source_mode key
        }
        p = _SessionParams(user='admin@acme.example',
                            enterprise_name='Acme Source')
        with self.assertRaises(SafeguardBlocked) as cm:
            enforce_source_mode(
                p, spec, confirm_flag=True,
                expected_tenant_name='Acme Source',
            )
        self.assertIn('read_only', str(cm.exception))

    def test_session_matches_both_sides_is_unknown_not_source(self):
        # Ambiguity guard: when session matches both source and target
        # (e.g. same region, unclear spec), detect_session_role returns
        # 'unknown' which makes enforce_source_mode a no-op. This is
        # safer than returning 'source' and blocking target writes.
        from keepercommander.commands.keeper_tenant_migrate.safeguards import enforce_source_mode
        spec = {
            'source': {'region': 'EU'},
            'target': {'region': 'EU'},
            'source_mode': 'read_only',
        }
        p = _SessionParams(server='keepersecurity.eu')
        # Would-be blocker (source_mode=read_only) becomes no-op.
        self.assertTrue(enforce_source_mode(p, spec))


class EnforceSourceModeIntegrationTests(unittest.TestCase):
    """End-to-end: a destructive subcommand called with the wrong
    confirm_source_destructive flag must surface SafeguardBlocked as
    a {'blocked': True, ...} result — not silently continue."""

    def test_cleanup_blocks_when_source_mode_read_only(self):
        import os
        import tempfile
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import CleanupCommand
        from keepercommander.commands.keeper_tenant_migrate.wizard import save_migration_yaml

        with tempfile.TemporaryDirectory() as run_dir:
            save_migration_yaml(run_dir, {
                'source': {'enterprise_name': 'Acme Source',
                            'user': 'admin@acme.example'},
                'target': {'enterprise_name': 'Target Corp'},
                'source_mode': 'read_only',
            })

            class FakeParams:
                user = 'admin@acme.example'
                server = 'keepersecurity.eu'
                enterprise = {'enterprise_name': 'Acme Source'}
                session_token = 'fake'

            # Patch the client so if the safeguard DOESN'T fire, we
            # detect the leak — any attempt to hit the client fails.
            with mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderCleanupClient'
            ) as cc, mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'
            ):
                cc.return_value.list_entities.return_value = {
                    'teams': [], 'roles': [], 'nodes': []}
                result = CleanupCommand().execute(
                    FakeParams(),
                    prefix='MIGTEST-',
                    confirm=True,
                    yes=True,
                    batch_cap=50,
                    override_batch_cap=False,
                    expected_tenant_name='Acme Source',
                    run_dir=run_dir,
                    confirm_source_destructive=True,
                    dry_run=False,
                )
            self.assertIsNotNone(result)
            self.assertTrue(result.get('blocked'))
            self.assertIn('read_only', result.get('reason', ''))


if __name__ == '__main__':
    unittest.main()
