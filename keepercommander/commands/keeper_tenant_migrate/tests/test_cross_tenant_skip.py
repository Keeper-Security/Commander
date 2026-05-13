"""Tests for cross-tenant-divergence skip-vs-fail classification.

When Commander rejects a role privilege or enforcement because the
target tenant doesn't support it (MSP-only privilege on a non-MSP
target, deprecated enforcement key between enterprise generations),
that's semantic divergence — not a bug. The structure stage should
record these as SKIPPED with a clear reason, not FAILED, so the
pipeline doesn't halt.
"""

import unittest
from unittest.mock import patch, MagicMock

from keepercommander.commands.keeper_tenant_migrate.structure import StructureRestore


class _Client:
    """Stub StructureClient that returns a scripted sequence of results."""

    def __init__(self, *, priv_result=True, admin_result=True):
        self.priv_result = priv_result
        self.admin_result = admin_result
        self.calls = []

    def add_role_privilege(self, role_name, priv, node_name):
        self.calls.append(('priv', role_name, priv, node_name))
        if callable(self.priv_result):
            return self.priv_result(role_name, priv, node_name)
        return self.priv_result

    def add_role_managed_node(self, role_name, node_name, cascade):
        self.calls.append(('admin', role_name, node_name, cascade))
        return self.admin_result


class ClassifyErrorTests(unittest.TestCase):

    def setUp(self):
        self.r = StructureRestore(_Client(), source_root='src', target_root='tgt')

    def test_invalid_privilege_marks_skipped(self):
        status, reason = self.r._classify_error('invalid privilege: privilege_access')
        self.assertEqual(status, 'SKIPPED')
        self.assertIn('target does not support', reason)
        self.assertIn('privilege_access', reason)

    def test_manage_billing_marks_skipped(self):
        status, _ = self.r._classify_error('invalid privilege: manage_billing')
        self.assertEqual(status, 'SKIPPED')

    def test_enforcement_key_retired_marks_skipped(self):
        status, _ = self.r._classify_error('invalid enforcement: foo_bar')
        self.assertEqual(status, 'SKIPPED')

    def test_user_not_found_marks_skipped(self):
        status, reason = self.r._classify_error(
            'User finance@example.com is not found: Skipping')
        self.assertEqual(status, 'SKIPPED')
        self.assertIn('dependency missing', reason)

    def test_role_not_found_marks_skipped(self):
        status, reason = self.r._classify_error(
            'Role Departaments - Staging admin is not found: Skipping')
        self.assertEqual(status, 'SKIPPED')
        self.assertIn('dependency missing', reason)

    def test_team_not_found_marks_skipped(self):
        status, _ = self.r._classify_error(
            'Team Support-L1 is not found: Skipping')
        self.assertEqual(status, 'SKIPPED')

    def test_generic_is_not_found_skipping_marks_skipped(self):
        # Commander's idiom "X is not found: Skipping" where X is an
        # arbitrary entity label.
        status, _ = self.r._classify_error(
            'MyCustomEntity is not found: Skipping')
        self.assertEqual(status, 'SKIPPED')

    def test_generic_error_marks_failed(self):
        status, reason = self.r._classify_error('connection reset')
        self.assertEqual(status, 'FAILED')
        self.assertEqual(reason, 'connection reset')

    def test_empty_error_marks_failed(self):
        status, _ = self.r._classify_error('')
        self.assertEqual(status, 'FAILED')

    def test_permission_denied_marks_failed(self):
        # Real errors must stay FAILED — we only soften known
        # cross-tenant-semantic or expected-cascade patterns.
        status, _ = self.r._classify_error('permission denied')
        self.assertEqual(status, 'FAILED')

    def test_enforcement_expected_format_marks_skipped(self):
        # restrict_record_types carries nested JSON that Commander's
        # enforcement-value parser rejects with "is skipped. Expected
        # format: KEY:[VALUE]". Route to SKIPPED with a note pointing
        # at the v1.4.1 enforcement_direct fix.
        status, reason = self.r._classify_error(
            'Enforcement restrict_record_types:{"std":[1,2]} '
            'is skipped. Expected format:  KEY:[VALUE]')
        self.assertEqual(status, 'SKIPPED')
        self.assertIn('enforcement_direct', reason)

    def test_generated_password_complexity_file_format_marks_skipped(self):
        # Second variant of the enforcement-shape error — Phase-C
        # file-path format rejected.
        status, _ = self.r._classify_error(
            'Enforcement "generated_password_complexity" is skipped. '
            'Expected format: KEY:$FILE=<FILEPATH>')
        self.assertEqual(status, 'SKIPPED')

    def test_upstream3_cross_ref_require_account_share_marks_skipped(self):
        # Bug 51 / Upstream-3: Commander rejects role-A → role-B
        # require_account_share with the same generic 'cannot update
        # enforcement' envelope as Upstream-1 (self-ref). Bug 47
        # caught self-refs pre-flight; cross-refs reach the API and
        # trip this. Plugin-side workaround: SKIPPED so structure
        # proceeds, with a loud reason telling the operator to apply
        # manually post-migration.
        err = (
            "cannot update enforcement: roleId=12058/51788715655777, "
            "enforcement=REQUIRE_ACCOUNT_SHARE, enforcementId=34, "
            "valueType=ACCOUNT_SHARE, category=SHARING_ENFORCEMENTS, "
            "value=12058/51788715655757"
        )
        status, reason = self.r._classify_error(err)
        self.assertEqual(status, 'SKIPPED')
        self.assertIn('Upstream-3', reason)
        self.assertIn('manually', reason)

    def test_upstream3_marker_does_not_mask_unrelated_failures(self):
        # The marker is narrow — substring 'require_account_share'
        # AND 'cannot update enforcement'. A plain enforcement-name
        # mention without the rejection envelope must still FAIL.
        status, _ = self.r._classify_error(
            'permission denied while reading require_account_share field')
        self.assertEqual(status, 'FAILED')

    def test_upstream3_marker_does_not_match_simple_unrelated_error(self):
        # Sanity: a generic 'cannot update enforcement' (e.g. for a
        # different enforcement key) without REQUIRE_ACCOUNT_SHARE
        # in the message AND without valueType=BOOLEAN (Upstream-4)
        # must still FAIL. Substring matches are narrow.
        status, _ = self.r._classify_error(
            'cannot update enforcement: roleId=X, '
            'enforcement=ALLOW_OFFLINE_ACCESS, value=foo')
        self.assertEqual(status, 'FAILED')

    def test_upstream4_boolean_value_null_marks_skipped(self):
        # Bug 53 / Upstream-4: ALLOW_CAN_EDIT_EXTERNAL_SHARES on
        # MSP target. Same envelope as Upstream-3 but different
        # constraint class — environmental (target tenant
        # restricts the enforcement). v1.5.3 + v1.5.5 attempted to
        # fix as a value-marshaling bug; rehearsal-8 proved the
        # rejection is server-side environmental.
        err = (
            "cannot update enforcement: roleId=12058/51788715655757, "
            "enforcement=ALLOW_CAN_EDIT_EXTERNAL_SHARES, "
            "enforcementId=247, valueType=BOOLEAN, "
            "category=ACCOUNT_ENFORCEMENTS, value=null"
        )
        status, reason = self.r._classify_error(err)
        self.assertEqual(status, 'SKIPPED')
        self.assertIn('Upstream-4', reason)
        self.assertIn('manually', reason)

    def test_upstream4_marker_requires_envelope(self):
        # 'valuetype=boolean' alone (e.g. in a docstring or unrelated
        # log line) must NOT trigger SKIP — the 'cannot update
        # enforcement' envelope is required.
        status, _ = self.r._classify_error(
            'docstring noise mentioning valueType=BOOLEAN somehow')
        self.assertEqual(status, 'FAILED')

    def test_no_such_user_marks_skipped(self):
        # Bug 54 (v1.5.6): Commander's `enterprise-user` command
        # uses 'No such user(s)' for the missing-user rejection
        # (different idiom from 'user not found' / 'is not found:
        # Skipping' which the existing markers covered). Surfaced
        # 2026-05-01 rehearsal-8 — 11 user_node assignments cascade-
        # failed when the users stage was skipped.
        status, reason = self.r._classify_error(
            'enterprise-user: No such user(s)')
        self.assertEqual(status, 'SKIPPED')
        self.assertIn('dependency missing', reason)

    def test_no_such_user_case_insensitive(self):
        # Marker matching is via lowercased haystack — verify
        # case-insensitivity for both 'no such user' and 'No such
        # User(s)' variants.
        for err in ('NO SUCH USER',
                     'enterprise-user: No Such Users',
                     'No such user.'):
            status, _ = self.r._classify_error(err)
            self.assertEqual(status, 'SKIPPED', f'failed on {err!r}')


class DependencyCascadeSkipTests(unittest.TestCase):
    """Steps 7-10 (user-nodes, user-teams, role-users, role-teams)
    must mark 'User/Role/Team is not found' failures as SKIPPED when
    the referenced entity wasn't created yet — e.g. auto-migrate skips
    the `users` stage by default (emails), so role-user / team-user
    assignments naturally fail when that stage hasn't run yet. Before
    v1.4.1 those landed as FAILED and halted the pipeline.
    """

    class _Client:
        def __init__(self, fail_on_calls=None):
            self.fail_on_calls = fail_on_calls or []
            self.calls = []

        def _mk(self, kind):
            def _do(*args):
                self.calls.append((kind,) + tuple(args))
                return kind not in self.fail_on_calls
            return _do

        def __getattr__(self, name):
            # Stub every client method the test might hit
            if name.startswith('_'):
                raise AttributeError(name)
            return self._mk(name)

    def _restore(self, client):
        r = StructureRestore(client, source_root='src', target_root='tgt')
        return r

    def test_role_users_not_found_is_skipped(self):
        client = self._Client(fail_on_calls=['add_user_to_role'])
        r = self._restore(client)
        roles = [{
            'name': 'role-a',
            'users': [{'email': 'ghost@example.com'}],
        }]
        with patch.object(r, '_last_error',
                           return_value='User ghost@example.com is not found: Skipping'):
            r.step_role_users(roles)
        self.assertEqual(r.counters['FAILED'], 0,
                          f'expected SKIPPED, got counters={r.counters}')
        self.assertGreaterEqual(r.counters['SKIPPED'], 1)

    def test_user_teams_not_found_is_skipped(self):
        client = self._Client(fail_on_calls=['add_user_to_team'])
        r = self._restore(client)
        users = [{
            'email': 'ghost@example.com',
            'teams': [{'name': 'team-a'}],
        }]
        with patch.object(r, '_last_error',
                           return_value='User ghost@example.com is not found: Skipping'):
            r.step_user_teams(users)
        self.assertEqual(r.counters['FAILED'], 0)

    def test_role_teams_team_not_found_is_skipped(self):
        client = self._Client(fail_on_calls=['add_team_to_role'])
        r = self._restore(client)
        roles = [{
            'name': 'role-a', 'default_role': False,
            'teams': [{'name': 'missing-team'}],
        }]
        with patch.object(r, '_last_error',
                           return_value='Team missing-team is not found: Skipping'):
            r.step_role_teams(roles)
        self.assertEqual(r.counters['FAILED'], 0)

    def test_real_error_still_fails(self):
        # Sanity: unrelated errors in these steps still FAIL, keeping
        # the silent-PASS guard intact.
        client = self._Client(fail_on_calls=['add_user_to_role'])
        r = self._restore(client)
        roles = [{
            'name': 'role-a',
            'users': [{'email': 'real@example.com'}],
        }]
        with patch.object(r, '_last_error', return_value='connection reset'):
            r.step_role_users(roles)
        self.assertEqual(r.counters['FAILED'], 1)


class StepManagedNodesSkipTests(unittest.TestCase):
    """End-to-end: step_managed_nodes sees an invalid-privilege error
    and routes it to SKIPPED, keeping the counters clean of false
    FAILEDs.
    """

    def _make_restore(self, client):
        r = StructureRestore(client, source_root='src', target_root='tgt')
        r.created_roles = {'role-a'}   # gate passes
        return r

    def _mk_roles(self):
        return [{
            'name': 'role-a',
            'managed_nodes': [{
                'node_name': 'src',   # source_root → target_root
                'cascade': True,
                'privileges': ['valid_priv', 'invalid_priv'],
            }],
        }]

    def test_invalid_privilege_does_not_increment_failed(self):
        # Second priv returns False with "invalid privilege" error text
        def scripted(role, priv, node):
            return priv == 'valid_priv'

        client = _Client(priv_result=scripted)
        r = self._make_restore(client)

        with patch.object(r, '_last_error',
                           return_value='invalid privilege: invalid_priv'):
            r.step_managed_nodes(self._mk_roles())

        # One SUCCESS (managed-node add), one SUCCESS (valid_priv),
        # one SKIPPED (invalid_priv) — zero FAILED.
        self.assertEqual(r.counters['FAILED'], 0,
                          f'unexpected FAILED: {r.counters}')
        self.assertGreaterEqual(r.counters['SKIPPED'], 1)
        self.assertGreaterEqual(r.counters['SUCCESS'], 2)

    def test_skipped_record_has_descriptive_reason(self):
        def scripted(role, priv, node):
            return priv != 'invalid_priv'
        client = _Client(priv_result=scripted)
        r = self._make_restore(client)
        with patch.object(r, '_last_error',
                           return_value='invalid privilege: invalid_priv'):
            r.step_managed_nodes(self._mk_roles())
        skipped = [x for x in r.results if x.status == 'SKIPPED']
        self.assertTrue(skipped, 'no SKIPPED entry recorded')
        self.assertIn('target does not support', skipped[-1].notes)

    def test_connection_reset_still_fails(self):
        # Sanity: non-privilege errors still FAIL — we only soften the
        # specific cross-tenant signatures.
        def scripted(role, priv, node):
            return False
        client = _Client(priv_result=scripted)
        r = self._make_restore(client)
        with patch.object(r, '_last_error', return_value='connection reset'):
            r.step_managed_nodes(self._mk_roles())
        # At least one FAILED (the privilege call with connection reset)
        self.assertGreaterEqual(r.counters['FAILED'], 1)


if __name__ == '__main__':
    unittest.main()
