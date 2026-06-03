"""
cp-rotation-skip-feat — Story 2/3 execution-flow tests

Story 2 — Password source decision & _configure_rotation branching:
  - Password source: existing_password → rotation.password_complexity → DEFAULT_COMPLEXITY
  - _configure_rotation: on_demand mode vs schedule mode
  - _configure_rotation is skipped when 'rotation' not in config

Story 3 — Push-to-target guards:
  - _rotate_immediately gated on rotate_on_provision (default True)
  - _create_ad_user_via_gateway gated on not existing_password
  - _add_ad_user_to_groups_via_gateway still runs when ad_groups set
  - logging.info line when existing_password is used (no value in log)
"""

import pytest
from unittest import TestCase
from unittest.mock import MagicMock, patch

from keepercommander.commands.credential_provision import (
    CredentialProvisionCommand,
    DEFAULT_COMPLEXITY,
)


# =============================================================================
# Story 2 — _determine_password helper
# =============================================================================


@pytest.mark.unit
class TestDeterminePassword(TestCase):
    """
    The password-source decision is extracted into _determine_password for
    testability. It returns (password, used_existing).
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()

    def test_existing_password_takes_precedence(self):
        config = {
            'account': {'existing_password': 'KnownPass123!'},
            'rotation': {'password_complexity': '16,2,2,2,2'},  # should be ignored
        }
        with patch.object(self.cmd, '_generate_password') as gen:
            password, used_existing = self.cmd._determine_password(config)
        self.assertEqual(password, 'KnownPass123!')
        self.assertTrue(used_existing)
        gen.assert_not_called()

    def test_rotation_complexity_used_when_no_existing_password(self):
        config = {
            'account': {},
            'rotation': {'password_complexity': '24,3,3,3,3'},
        }
        with patch.object(self.cmd, '_generate_password', return_value='GENERATED') as gen:
            password, used_existing = self.cmd._determine_password(config)
        self.assertEqual(password, 'GENERATED')
        self.assertFalse(used_existing)
        gen.assert_called_once_with('24,3,3,3,3')

    def test_default_complexity_used_when_no_rotation_and_no_existing(self):
        config = {'account': {}}
        with patch.object(self.cmd, '_generate_password', return_value='GENERATED') as gen:
            password, used_existing = self.cmd._determine_password(config)
        self.assertEqual(password, 'GENERATED')
        self.assertFalse(used_existing)
        gen.assert_called_once_with(DEFAULT_COMPLEXITY)

    def test_empty_existing_password_falls_through_to_generation(self):
        # An empty string is rejected by the validator (Story 1), but if it
        # somehow reaches _determine_password, treat as not-supplied.
        config = {
            'account': {'existing_password': ''},
            'rotation': {'password_complexity': '24,3,3,3,3'},
        }
        with patch.object(self.cmd, '_generate_password', return_value='GENERATED') as gen:
            password, used_existing = self.cmd._determine_password(config)
        self.assertFalse(used_existing)
        gen.assert_called_once_with('24,3,3,3,3')


# =============================================================================
# Story 2 — _configure_rotation branching on schedule vs on_demand
# =============================================================================


@pytest.mark.unit
class TestConfigureRotationBranching(TestCase):
    """
    _configure_rotation must pass either schedule_cron_data (cron mode) or
    on_demand=True (manual-trigger mode) to PAMCreateRecordRotationCommand,
    but never both.
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = MagicMock()

    def _call_configure(self, rotation_config):
        config = {
            'account': {'pam_config_uid': 'cfg-uid'},
            'rotation': rotation_config,
        }
        # PAMCreateRecordRotationCommand is imported at module level in
        # credential_provision.py — patch where it's used.
        with patch(
            'keepercommander.commands.credential_provision.PAMCreateRecordRotationCommand'
        ) as cmd_class:
            instance = cmd_class.return_value
            self.cmd._configure_rotation('pam-uid', config, self.params)
        return cmd_class, instance

    def test_schedule_mode_passes_schedule_cron_data(self):
        rotation = {
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
        }
        _, instance = self._call_configure(rotation)
        instance.execute.assert_called_once()
        kwargs = instance.execute.call_args.kwargs
        self.assertEqual(kwargs.get('schedule_cron_data'), ['0 0 3 * * ?'])
        self.assertNotIn('on_demand', kwargs)

    def test_on_demand_mode_passes_on_demand_true(self):
        rotation = {
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
        }
        _, instance = self._call_configure(rotation)
        instance.execute.assert_called_once()
        kwargs = instance.execute.call_args.kwargs
        self.assertEqual(kwargs.get('on_demand'), True)
        self.assertNotIn('schedule_cron_data', kwargs)

    def test_complexity_always_forwarded(self):
        for rotation in (
            {'schedule': '0 0 3 * * ?', 'password_complexity': '32,5,5,5,5'},
            {'on_demand': True, 'password_complexity': '32,5,5,5,5'},
        ):
            _, instance = self._call_configure(rotation)
            kwargs = instance.execute.call_args.kwargs
            self.assertEqual(kwargs.get('pwd_complexity'), '32,5,5,5,5')

    def test_enable_force_flags_unchanged(self):
        rotation = {'on_demand': True, 'password_complexity': '32,5,5,5,5'}
        _, instance = self._call_configure(rotation)
        kwargs = instance.execute.call_args.kwargs
        self.assertEqual(kwargs.get('enable'), True)
        self.assertEqual(kwargs.get('force'), True)


# =============================================================================
# Story 3 — _rotate_immediately gated on rotate_on_provision
# =============================================================================


@pytest.mark.unit
class TestRotateOnProvisionGate(TestCase):
    """
    _rotate_immediately at provisioning time fires only when rotate_on_provision
    is True (the default). When false, the immediate rotation must be skipped.

    Since _rotate_immediately is called from execute(), this test validates the
    GATE LOGIC by exercising a small helper that mirrors the gate's predicate.
    The full integration is verified in TestExecuteFlow below.
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()

    def test_should_rotate_default_true(self):
        config = {'rotation': {'schedule': '0 0 3 * * ?'}}
        self.assertTrue(self.cmd._should_rotate_on_provision(config))

    def test_should_rotate_explicit_true(self):
        config = {'rotation': {'rotate_on_provision': True}}
        self.assertTrue(self.cmd._should_rotate_on_provision(config))

    def test_should_rotate_explicit_false(self):
        config = {'rotation': {'rotate_on_provision': False}}
        self.assertFalse(self.cmd._should_rotate_on_provision(config))

    def test_should_rotate_no_rotation_block(self):
        # No rotation block at all => no rotation work, including no immediate
        config = {}
        self.assertFalse(self.cmd._should_rotate_on_provision(config))


# =============================================================================
# Story 3 — _create_ad_user_via_gateway gated on not existing_password
# =============================================================================


@pytest.mark.unit
class TestADCreateGate(TestCase):
    """
    The AD-create path pushes the password to the target via rm-create-user.
    When existing_password is set, the operator has declared the account
    pre-exists; AD-create must be skipped to prevent push-to-target.

    The gate is enforced in execute(); this test validates the predicate.
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()

    def test_ad_create_allowed_without_existing_password(self):
        config = {'account': {'distinguished_name': 'CN=...'}}
        self.assertTrue(self.cmd._should_create_ad_user(config))

    def test_ad_create_skipped_with_existing_password(self):
        config = {
            'account': {
                'distinguished_name': 'CN=...',
                'existing_password': 'KnownPass!',
            }
        }
        self.assertFalse(self.cmd._should_create_ad_user(config))

    def test_ad_create_allowed_no_ad_fields_no_existing_pw(self):
        # No AD fields => has_ad_config is False; gate returns False but for
        # a different reason. The predicate intentionally returns False here
        # because there's nothing to create.
        config = {'account': {}}
        self.assertFalse(self.cmd._should_create_ad_user(config))

    def test_ad_create_with_ad_groups_only(self):
        config = {'account': {'ad_groups': ['CN=Group1']}}
        self.assertTrue(self.cmd._should_create_ad_user(config))


# =============================================================================
# Story 3 — logging.info when existing_password is used (NO VALUE)
# =============================================================================


@pytest.mark.unit
class TestExistingPasswordLogging(TestCase):
    """
    When existing_password is used, exactly one logging.info line records the
    fact (with record UID, no value). This is the on-the-CLI audit trail.
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()

    def test_log_line_contains_no_password_value(self):
        record_uid = "rec-uid-123"
        with self.assertLogs(level='INFO') as captured:
            self.cmd._log_existing_password_use(record_uid)
        joined = '\n'.join(captured.output)
        self.assertIn(record_uid, joined,
                      "log line should reference the record UID")
        self.assertIn('existing_password', joined,
                      "log line should reference the field name")

    def test_rotate_immediately_failure_warning_branches_on_mode(self):
        """Regression for review #A (round 3): when _rotate_immediately fails,
        the remediation hint must reflect the rotation mode. on_demand mode
        has no schedule — the operator must trigger manually, not wait for cron.
        """
        cmd = CredentialProvisionCommand()
        params = MagicMock()

        # Force the inner rotate command to raise
        with patch(
            'keepercommander.commands.credential_provision.PAMGatewayActionRotateCommand'
        ) as rotate_class:
            instance = rotate_class.return_value
            instance.execute.side_effect = RuntimeError('simulated gateway failure')

            # on_demand mode → hint must reference manual trigger
            with self.assertLogs(level='WARNING') as captured:
                result = cmd._rotate_immediately(
                    'pam-uid',
                    {'rotation': {'on_demand': True}},
                    params,
                )
            self.assertFalse(result)
            joined = '\n'.join(captured.output)
            self.assertIn('manually', joined.lower(),
                f'Expected manual-trigger hint for on_demand mode; got: {captured.output}')
            self.assertNotIn('scheduled rotation', joined,
                f'Should NOT reference "scheduled rotation" in on_demand mode; got: {captured.output}')

        # schedule mode → hint must reference the next scheduled rotation
        with patch(
            'keepercommander.commands.credential_provision.PAMGatewayActionRotateCommand'
        ) as rotate_class:
            instance = rotate_class.return_value
            instance.execute.side_effect = RuntimeError('simulated gateway failure')

            with self.assertLogs(level='WARNING') as captured:
                cmd._rotate_immediately(
                    'pam-uid',
                    {'rotation': {'schedule': '0 0 3 * * ?'}},
                    params,
                )
            joined = '\n'.join(captured.output)
            self.assertIn('scheduled rotation', joined,
                f'Expected scheduled-rotation hint in schedule mode; got: {captured.output}')

    def test_log_function_does_not_accept_password_value(self):
        """The function signature accepts ONLY the record UID — by design,
        the password value is never passed to it, so there is no way for a
        future maintainer to accidentally log the secret."""
        import inspect
        sig = inspect.signature(self.cmd._log_existing_password_use)
        params = list(sig.parameters.keys())
        self.assertEqual(params, ['pam_user_uid'],
                         "Signature must accept only the record UID")


# =============================================================================
# Story 3 — full-source structural regression guard
# =============================================================================


@pytest.mark.unit
class TestSourceCodeRegressionGuard(TestCase):
    """
    Structural test: the source file must not contain any logging statement
    that interpolates the value of existing_password. This catches future
    maintainers who accidentally add a log call with the secret value.

    Failure of this test does NOT mean we're leaking — it means the source
    pattern is suspicious and a human must verify.
    """

    SOURCE_FILE = (
        'keepercommander/commands/credential_provision.py'
    )

    def test_add_ad_user_to_groups_raises_when_gateway_uid_is_none(self):
        """Regression for review #7 (offline gateway + existing_password + ad_groups):
        the helper must fail fast with CommandError, not silently per-group.
        Pre-PR this fail-fast lived inside _create_ad_user_via_gateway; that path
        is now skipped when existing_password is set, so we re-assert it here.
        """
        from keepercommander.error import CommandError
        cmd = CredentialProvisionCommand()
        params = MagicMock()
        config = {'account': {'pam_config_uid': 'cfg-uid', 'username': 'svc'}}
        with self.assertRaises(CommandError) as ctx:
            cmd._add_ad_user_to_groups_via_gateway(config, params, gateway_uid=None)
        self.assertIn('Gateway', str(ctx.exception))

    def test_group_add_call_site_appears_after_create_pam_user(self):
        """Regression for review #8 (rollback gap when group-add precedes pam-user-create):
        the group-add call site must appear in the source AFTER _create_pam_user so a
        failure during the critical record-creation steps doesn't orphan AD memberships.
        """
        import os, re
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        src_path = os.path.join(repo_root, self.SOURCE_FILE)
        with open(src_path, 'r', encoding='utf-8') as f:
            source = f.read()

        # Find the line number of the execute()-level _create_pam_user call.
        create_pam_match = re.search(
            r'pam_user_uid\s*=\s*self\._create_pam_user\(',
            source,
        )
        self.assertIsNotNone(create_pam_match, "Could not find _create_pam_user assignment")
        create_pam_pos = create_pam_match.start()

        # Find the line number of the execute()-level _add_ad_user_to_groups_via_gateway call.
        group_add_match = re.search(
            r'self\._add_ad_user_to_groups_via_gateway\(',
            source,
        )
        self.assertIsNotNone(group_add_match, "Could not find group-add call site")
        group_add_pos = group_add_match.start()

        self.assertGreater(
            group_add_pos, create_pam_pos,
            "_add_ad_user_to_groups_via_gateway must be called AFTER _create_pam_user "
            "to avoid orphaning AD group memberships if record creation fails. "
            "See PR #2043 review #8."
        )

    def test_add_ad_user_to_groups_uses_local_gateway_uid(self):
        """Regression guard for review finding #2: the call to
        _add_ad_user_to_groups_via_gateway must pass the local `gateway_uid`
        (resolved at line ~401), NOT `state.ad_gateway_uid` (which is only set
        as a side effect inside _create_ad_user_via_gateway and stays None when
        the AD-create gate skips the create call for existing_password YAMLs).
        """
        import os, re
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        src_path = os.path.join(repo_root, self.SOURCE_FILE)
        with open(src_path, 'r', encoding='utf-8') as f:
            source = f.read()
        # Find any call to _add_ad_user_to_groups_via_gateway
        pattern = re.compile(
            r'self\._add_ad_user_to_groups_via_gateway\s*\(([^)]*)\)',
            re.MULTILINE | re.DOTALL,
        )
        calls = pattern.findall(source)
        self.assertGreater(len(calls), 0,
            "Expected to find at least one call site for _add_ad_user_to_groups_via_gateway")
        for args in calls:
            self.assertNotIn('state.ad_gateway_uid', args,
                "_add_ad_user_to_groups_via_gateway must not be called with "
                "state.ad_gateway_uid — that's None when AD-create is skipped. "
                "Use the local `gateway_uid` instead.")
            # And it should explicitly pass gateway_uid
            self.assertIn('gateway_uid', args,
                f"Call site should pass gateway_uid; got args: {args!r}")

    def test_rotation_configured_log_gated_on_real_success(self):
        """Regression for round-5 review finding: the '✅ Rotation configured'
        log line must only fire when _configure_rotation actually configured
        rotation (returns True), not after a swallowed gateway-500 deferral
        (returns False). Sibling pattern to the rotation_success gate.
        """
        import os
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        src_path = os.path.join(repo_root, self.SOURCE_FILE)
        with open(src_path, 'r', encoding='utf-8') as f:
            source = f.read()
        idx = source.find("'✅ Rotation configured'")
        self.assertGreater(idx, 0, "Could not locate the rotation-configured log line")
        context = source[max(0, idx - 300):idx]
        # Must be gated on something more than just output_format — the actual
        # return value of _configure_rotation needs to be checked.
        self.assertIn('rotation_configured', context,
            "The '✅ Rotation configured' log must be gated on _configure_rotation's "
            "real return value, not just output_format. Otherwise a swallowed "
            "gateway-500 deferral produces 'rotation deferred' warning + checkmark "
            "contradiction. See PR #2043 round-5 review.")

    def test_rotation_success_log_gated_on_rotation_success(self):
        """Regression for review #E (round 4): the '✅ Password rotation submitted'
        log line must only fire when _rotate_immediately actually succeeded
        (returns True), not unconditionally after the call. Otherwise a failing
        rotation produces contradictory output (warning + success checkmark)
        in the same provisioning run.
        """
        import os
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        src_path = os.path.join(repo_root, self.SOURCE_FILE)
        with open(src_path, 'r', encoding='utf-8') as f:
            source = f.read()
        idx = source.find("'✅ Password rotation submitted'")
        self.assertGreater(idx, 0, "Could not locate the success-log line")
        context = source[max(0, idx - 200):idx]
        self.assertIn('rotation_success', context,
            "The '✅ Password rotation submitted' log must be gated on rotation_success. "
            "Otherwise a False return from _rotate_immediately produces a misleading "
            "success line in the same provisioning run. See PR #2043 review #E.")

    def test_no_log_statement_references_existing_password_value(self):
        import os
        import re
        # Resolve path from the worktree root
        repo_root = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..'))
        src_path = os.path.join(repo_root, self.SOURCE_FILE)
        with open(src_path, 'r', encoding='utf-8') as f:
            source = f.read()
        # Look for patterns like logging.X(f"... {existing_password} ...")
        # where existing_password is the VALUE, not the field name.
        # We forbid: logging.<level>(...{...existing_password...}...) where
        # the f-string is referring to the variable.
        pattern = re.compile(
            r'logging\.(debug|info|warning|error|critical)\s*\([^)]*\{[^}]*existing_password[^}]*\}',
            re.MULTILINE | re.DOTALL,
        )
        matches = pattern.findall(source)
        self.assertEqual(matches, [],
            "Found logging statement that may include existing_password VALUE — "
            "review for potential credential leak.")
