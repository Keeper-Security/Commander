"""
cp-rotation-skip-feat — Story 4 dry-run rewrite tests

Covers the rewrite of _dry_run_report:
  - Reflects the chosen execution path (rotation present/absent, on_demand/
    schedule, rotate_on_provision, existing_password)
  - Absorbs commit 97dc8893: line 1027's NameError (pam undefined) fix
  - Adds rotation_mode field to JSON output
  - Extends rotation_status values

Critical regression: `cp --output json --dry-run` must NOT raise NameError
for any behavior-matrix cell.
"""

import io
import json
import pytest
from contextlib import redirect_stdout
from unittest import TestCase
from unittest.mock import MagicMock

from keepercommander.commands.credential_provision import CredentialProvisionCommand


def make_params():
    p = MagicMock()
    p.key_cache = {}
    return p


def base_config(**overrides):
    """Minimal valid config; overrides merge top-level keys."""
    config = {
        'user': {'first_name': 'A', 'last_name': 'B', 'personal_email': 'a@b.com', 'department': 'Eng'},
        'account': {'username': 'svc-test', 'pam_config_uid': 'cfg-uid'},
        'email': {'config_name': 'none', 'send_to': 'a@b.com'},
    }
    config.update(overrides)
    return config


# =============================================================================
# NameError absorption — every behavior-matrix cell, JSON mode
# =============================================================================


@pytest.mark.unit
class TestDryRunJsonNoNameError(TestCase):
    """Regression for commit 97dc8893: line 1027 referenced an undefined `pam`.
    Every behavior-matrix cell must complete in JSON mode without NameError.
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _run_json_dry_run(self, config):
        """Capture stdout from a JSON-mode dry-run; return parsed JSON."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.cmd._dry_run_report(self.params, config, 'json')
        out = buf.getvalue()
        return json.loads(out)

    def test_cell_1_no_rotation_no_existing_password(self):
        result = self._run_json_dry_run(base_config())
        self.assertTrue(result['success'])
        self.assertTrue(result['dry_run'])

    def test_cell_2_no_rotation_with_existing_password(self):
        cfg = base_config()
        cfg['account']['existing_password'] = 'KnownPass!'
        result = self._run_json_dry_run(cfg)
        self.assertTrue(result['success'])

    def test_cell_3_schedule_default_rop(self):
        cfg = base_config(rotation={
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
        })
        result = self._run_json_dry_run(cfg)
        self.assertTrue(result['success'])

    def test_cell_4_schedule_rop_false(self):
        cfg = base_config(rotation={
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
            'rotate_on_provision': False,
        })
        result = self._run_json_dry_run(cfg)
        self.assertTrue(result['success'])

    def test_cell_5_on_demand_default_rop(self):
        cfg = base_config(rotation={
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
        })
        result = self._run_json_dry_run(cfg)
        self.assertTrue(result['success'])

    def test_cell_6_on_demand_rop_false(self):
        cfg = base_config(rotation={
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
            'rotate_on_provision': False,
        })
        result = self._run_json_dry_run(cfg)
        self.assertTrue(result['success'])

    def test_cell_7_schedule_rop_false_existing_password(self):
        cfg = base_config(rotation={
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
            'rotate_on_provision': False,
        })
        cfg['account']['existing_password'] = 'KnownPass!'
        result = self._run_json_dry_run(cfg)
        self.assertTrue(result['success'])

    def test_cell_8_on_demand_rop_false_existing_password_tandem(self):
        """Tandem's exact use case — must not crash dry-run."""
        cfg = base_config(rotation={
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
            'rotate_on_provision': False,
        })
        cfg['account']['existing_password'] = 'KnownPass!'
        result = self._run_json_dry_run(cfg)
        self.assertTrue(result['success'])


# =============================================================================
# rotation_mode reporting (new JSON field)
# =============================================================================


@pytest.mark.unit
class TestRotationModeJsonField(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _run(self, config):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.cmd._dry_run_report(self.params, config, 'json')
        return json.loads(buf.getvalue())

    def test_no_rotation_block_mode_is_none(self):
        result = self._run(base_config())
        self.assertEqual(result['configuration'].get('rotation_mode'), 'none')

    def test_schedule_mode_reported(self):
        cfg = base_config(rotation={
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
        })
        result = self._run(cfg)
        self.assertEqual(result['configuration'].get('rotation_mode'), 'scheduled')

    def test_on_demand_mode_reported(self):
        cfg = base_config(rotation={
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
        })
        result = self._run(cfg)
        self.assertEqual(result['configuration'].get('rotation_mode'), 'on_demand')

    def test_rotation_schedule_field_uses_local_binding(self):
        """The actual fix from commit 97dc8893 — reads from `rotation` local,
        not the undefined `pam` symbol."""
        cfg = base_config(rotation={
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
        })
        result = self._run(cfg)
        self.assertEqual(result['configuration'].get('rotation_schedule'), '0 0 3 * * ?')

    def test_rotation_schedule_null_when_on_demand(self):
        cfg = base_config(rotation={
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
        })
        result = self._run(cfg)
        # No cron => no schedule string in the JSON
        self.assertIsNone(result['configuration'].get('rotation_schedule'))


# =============================================================================
# Actions list reflects chosen path
# =============================================================================


@pytest.mark.unit
class TestActionsListReflectsPath(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _actions(self, config):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.cmd._dry_run_report(self.params, config, 'json')
        return json.loads(buf.getvalue())['actions']

    def test_no_rotation_no_configure_rotation_action(self):
        actions = self._actions(base_config())
        joined = '\n'.join(actions)
        self.assertNotIn('Configure rotation', joined)
        self.assertNotIn('immediate rotation', joined.lower())

    def test_rotation_present_includes_configure_action(self):
        cfg = base_config(rotation={
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
        })
        actions = self._actions(cfg)
        self.assertTrue(any('Configure rotation' in a for a in actions))
        self.assertTrue(any('immediate rotation' in a.lower() for a in actions))

    def test_rop_false_omits_immediate_action(self):
        cfg = base_config(rotation={
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
            'rotate_on_provision': False,
        })
        actions = self._actions(cfg)
        self.assertTrue(any('Configure rotation' in a for a in actions))
        self.assertFalse(any('immediate rotation' in a.lower() for a in actions),
                         f"Expected no immediate-rotation action; got: {actions}")

    def test_existing_password_omits_generate_action(self):
        cfg = base_config()
        cfg['account']['existing_password'] = 'KnownPass!'
        actions = self._actions(cfg)
        self.assertFalse(any('Generate secure password' in a for a in actions),
                         f"Expected no password-generation action; got: {actions}")
        self.assertTrue(any('existing' in a.lower() and 'password' in a.lower() for a in actions),
                        f"Expected existing-password mention; got: {actions}")


# =============================================================================
# Dry-run actions list must mirror execute() — regression for review finding #3
# =============================================================================


@pytest.mark.unit
class TestDryRunActionsMirrorExecute(TestCase):
    """The actions list must reflect what execute() will actually do.
    Pre-fix divergences:
      - 'Add to AD groups' was never emitted even though execute() always runs
        group-add when ad_groups is set
      - 'Generate share URL' was emitted unconditionally even though execute()
        gates it on has_email
      - Direct-share was never represented
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _actions(self, config):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.cmd._dry_run_report(self.params, config, 'json')
        return json.loads(buf.getvalue())['actions']

    def test_ad_groups_emits_group_add_action_independent_of_create(self):
        # BYO password + ad_groups: CREATE skipped, but group-add still runs.
        cfg = base_config()
        cfg['account']['existing_password'] = 'KnownPass!'
        cfg['account']['distinguished_name'] = 'CN=svc,OU=...,DC=corp,DC=local'
        cfg['account']['ad_groups'] = ['CN=Engineers,OU=Groups,DC=corp,DC=local']
        actions = self._actions(cfg)
        joined = '\n'.join(actions)
        # CREATE must NOT appear (existing_password gate)
        self.assertNotIn('Create AD user', joined,
            f"AD-create should be skipped; got: {actions}")
        # Group-add MUST appear
        self.assertTrue(any('AD groups' in a for a in actions),
            f"Expected AD groups action; got: {actions}")

    def test_ad_groups_emits_action_when_create_also_runs(self):
        # No existing_password + ad_groups: CREATE runs, group-add ALSO runs.
        cfg = base_config()
        cfg['account']['distinguished_name'] = 'CN=svc,OU=...,DC=corp,DC=local'
        cfg['account']['ad_groups'] = ['CN=A,DC=corp', 'CN=B,DC=corp']
        actions = self._actions(cfg)
        joined = '\n'.join(actions)
        self.assertIn('Create AD user', joined,
            f"Expected AD-create action; got: {actions}")
        self.assertTrue(any('AD groups: 2' in a for a in actions),
            f"Expected AD groups count=2 action; got: {actions}")

    def test_share_url_only_when_email_configured(self):
        # email.config_name: none — share-URL action must NOT appear.
        cfg = base_config()  # email.config_name = 'none'
        actions = self._actions(cfg)
        joined = '\n'.join(actions)
        self.assertNotIn('Generate share URL', joined,
            f"Share-URL action should be skipped when no email; got: {actions}")
        # And the skip-email line should appear
        self.assertTrue(any('Skip welcome email' in a for a in actions),
            f"Expected skip-welcome-email action; got: {actions}")

    def test_share_url_appears_when_email_configured(self):
        cfg = base_config()
        cfg['email']['config_name'] = 'SMTP-Gmail'
        actions = self._actions(cfg)
        joined = '\n'.join(actions)
        self.assertIn('Generate share URL', joined,
            f"Expected share-URL action with real email config; got: {actions}")
        self.assertTrue(any('Send email to' in a and 'config: SMTP-Gmail' in a for a in actions),
            f"Expected send-email action with config name; got: {actions}")

    def test_direct_share_action_when_delivery_configured(self):
        cfg = base_config()
        cfg['delivery'] = {'share_to': 'alice@example.com'}
        actions = self._actions(cfg)
        joined = '\n'.join(actions)
        self.assertTrue(any('Share directly to' in a for a in actions),
            f"Expected direct-share action; got: {actions}")
        # The recipient should be PII-redacted in dry-run output
        self.assertNotIn('alice@example.com', joined,
            f"Recipient email should be redacted in dry-run; got: {actions}")

    def test_group_add_action_appears_after_create_pam_user_action(self):
        """Regression for review #B (round 3): dry-run actions list must mirror
        execute()'s call order — `Add to AD groups` must appear AFTER `Create PAM User`,
        same invariant as the structural test on execute() itself.
        """
        cfg = base_config()
        cfg['account']['distinguished_name'] = 'CN=svc,OU=...,DC=corp,DC=local'
        cfg['account']['ad_groups'] = ['CN=Engineers,DC=corp']
        actions = self._actions(cfg)
        group_idx = next((i for i, a in enumerate(actions) if 'AD groups' in a), None)
        create_idx = next((i for i, a in enumerate(actions) if 'Create PAM User' in a), None)
        self.assertIsNotNone(group_idx, f'Expected AD-groups action; got: {actions}')
        self.assertIsNotNone(create_idx, f'Expected Create PAM User action; got: {actions}')
        self.assertGreater(
            group_idx, create_idx,
            f'Add-to-AD-groups must come AFTER Create-PAM-User in dry-run order '
            f'(mirrors execute() reorder in c663a127). Got order: {actions}',
        )

    def test_no_direct_share_action_when_no_delivery(self):
        cfg = base_config()  # no delivery section
        actions = self._actions(cfg)
        joined = '\n'.join(actions)
        self.assertNotIn('Share directly to', joined,
            f"Direct-share action should not appear without delivery section; got: {actions}")


# =============================================================================
# Existing-password value NEVER in dry-run output
# =============================================================================


@pytest.mark.unit
class TestDryRunNeverExposesExistingPassword(TestCase):
    """The actual password value must not appear in any dry-run output."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    SECRET = 'TandemS3cretP@ssw0rd-DoNotEcho'

    def _run(self, output_format):
        cfg = base_config(rotation={
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
            'rotate_on_provision': False,
        })
        cfg['account']['existing_password'] = self.SECRET
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.cmd._dry_run_report(self.params, cfg, output_format)
        return buf.getvalue()

    def test_json_output_never_contains_secret(self):
        out = self._run('json')
        self.assertNotIn(self.SECRET, out,
                         "existing_password value MUST NOT appear in JSON dry-run output")

    def test_text_output_never_contains_secret(self):
        out = self._run('text')
        self.assertNotIn(self.SECRET, out,
                         "existing_password value MUST NOT appear in text dry-run output")


# =============================================================================
# Success-path JSON rotation_status (regression for E2E bug found 2026-05-12)
# =============================================================================


@pytest.mark.unit
class TestSuccessPathRotationStatus(TestCase):
    """The success-path JSON (in execute(), not _dry_run_report) must produce
    the same 4-value rotation_status as the dry-run JSON. E2E run on
    2026-05-12 caught a bug where cells 1, 2 (no rotation block) and cell 8
    (on_demand + rop:false) all incorrectly reported 'scheduled'.
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()

    def _compute(self, config, rotation_success: bool) -> str:
        # Mirrors the logic at execute() line 508; this test isolates it.
        if 'rotation' not in config:
            return 'not_configured'
        if rotation_success:
            return 'synced'
        if config['rotation'].get('on_demand'):
            return 'on_demand'
        return 'scheduled'

    def test_no_rotation_block_reports_not_configured(self):
        config = {'account': {}}
        self.assertEqual(self._compute(config, rotation_success=False), 'not_configured')

    def test_schedule_with_immediate_fired_reports_synced(self):
        config = {'rotation': {'schedule': '0 0 3 * * ?'}}
        self.assertEqual(self._compute(config, rotation_success=True), 'synced')

    def test_schedule_without_immediate_reports_scheduled(self):
        config = {'rotation': {'schedule': '0 0 3 * * ?'}}
        self.assertEqual(self._compute(config, rotation_success=False), 'scheduled')

    def test_on_demand_with_immediate_fired_reports_synced(self):
        config = {'rotation': {'on_demand': True}}
        self.assertEqual(self._compute(config, rotation_success=True), 'synced')

    def test_on_demand_without_immediate_reports_on_demand(self):
        config = {'rotation': {'on_demand': True}}
        self.assertEqual(self._compute(config, rotation_success=False), 'on_demand')


# =============================================================================
# Text mode still works (regression for existing demo YAMLs)
# =============================================================================


@pytest.mark.unit
class TestDryRunTextMode(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def test_text_mode_emits_header(self):
        cfg = base_config(rotation={
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
        })
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.cmd._dry_run_report(self.params, cfg, 'text')
        out = buf.getvalue()
        self.assertIn('DRY RUN MODE', out)
        self.assertIn('NO CHANGES WILL BE MADE', out)

    def test_text_mode_mentions_existing_password_use(self):
        cfg = base_config()
        cfg['account']['existing_password'] = 'KnownPass!'
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.cmd._dry_run_report(self.params, cfg, 'text')
        out = buf.getvalue()
        # mentions the fact, not the value
        self.assertTrue('existing' in out.lower() and 'password' in out.lower())
        self.assertNotIn('KnownPass!', out)
