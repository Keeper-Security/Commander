"""Per-category tests for VERIFICATION_GAPS comprehensive node fixtures.

Each TestCase pulls a fixture from
keepercommander.commands.keeper_tenant_migrate.tests.fixtures.comprehensive_node, runs it through
the relevant Fake* client + restorer + validator, and asserts every
field the gap calls out round-trips correctly. Fakes-only — never a
live Commander session.
"""

import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.inventory import summarize_record
from keepercommander.commands.keeper_tenant_migrate.shares import extract_direct_shares
from keepercommander.commands.keeper_tenant_migrate.structure import (
    FakeClient,
    StructureRestore,
    classify_enforcement,
    plan_managed_nodes,
    plan_role_team_assignments,
    plan_role_user_assignments,
    plan_user_node_assignments,
    plan_user_team_assignments,
    restricts_flags,
    target_node_for_user,
)
from keepercommander.commands.keeper_tenant_migrate.tests.fixtures import comprehensive_node as cn
from keepercommander.commands.keeper_tenant_migrate.users import (
    FakeUserClient,
    UserRunner,
    remap_user_node,
)
from keepercommander.commands.keeper_tenant_migrate.validate import (
    Severity,
    ValidationContext,
    phase_nodes,
    phase_records,
    phase_roles,
    phase_shared_folders,
    phase_teams,
)


def _make_restore():
    """Standard FakeClient + StructureRestore wired against MIGTEST scope."""
    client = FakeClient()
    restore = StructureRestore(
        client, source_root=cn.SOURCE_ROOT, target_root=cn.TARGET_ROOT,
        scope_node=cn.SCOPE_NODE,
    )
    return client, restore


# ─── Nodes (3 items) ────────────────────────────────────────────────────────


class ComprehensiveNodeTests(unittest.TestCase):
    """Verify every node-category gap from VERIFICATION_GAPS."""

    def test_node_with_custom_name_creates_under_scope(self):
        src, expected = cn.node_with_custom_name()
        nodes = [
            {'id': '100', 'name': cn.SCOPE_NODE, 'parent': cn.SOURCE_ROOT,
             'isolated': False},
            src,
        ]
        client, restore = _make_restore()
        restore.step_nodes(nodes)
        names = [c[1][0] for c in client.calls if c[0] == 'create_node']
        self.assertIn(expected['name'], names)
        self.assertEqual(restore.counters['FAILED'], 0)

    def test_nested_child_node_emitted_after_parent(self):
        nodes_src, expected = cn.node_nested_child()
        nodes = [
            {'id': '100', 'name': cn.SCOPE_NODE, 'parent': cn.SOURCE_ROOT,
             'isolated': False},
        ] + nodes_src
        client, restore = _make_restore()
        restore.step_nodes(nodes)
        names = [c[1][0] for c in client.calls if c[0] == 'create_node']
        # Parent before child invariant is the exact bug class this guards.
        self.assertLess(names.index(expected[0]['name']),
                        names.index(expected[1]['name']))

    def test_isolated_node_toggles_isolated_flag(self):
        src, expected = cn.node_isolated()
        nodes = [
            {'id': '100', 'name': cn.SCOPE_NODE, 'parent': cn.SOURCE_ROOT,
             'isolated': False},
            src,
        ]
        client, restore = _make_restore()
        restore.step_nodes(nodes)
        restore.step_isolated_flags(nodes)
        toggle_targets = [c[1][0] for c in client.calls
                           if c[0] == 'toggle_node_isolated']
        self.assertIn(expected['name'], toggle_targets)


# ─── Teams (7 items) ────────────────────────────────────────────────────────


class ComprehensiveTeamTests(unittest.TestCase):

    def _create_team(self, fixture_fn):
        src, expected = fixture_fn()
        client, restore = _make_restore()
        restore.step_teams([src])
        creates = [c for c in client.calls if c[0] == 'create_team']
        self.assertEqual(len(creates), 1)
        return creates[0][1], expected, restore

    def test_team_restrict_edit_only(self):
        args, expected, _ = self._create_team(cn.team_with_restrict_edit)
        # create_team(name, node, restrict_share, restrict_edit, restrict_view)
        share, edit, view = args[2], args[3], args[4]
        self.assertEqual((share, edit, view), restricts_flags(expected['restricts']))
        self.assertEqual(edit, 'on')
        self.assertEqual((share, view), ('off', 'off'))

    def test_team_restrict_share_only(self):
        args, _, _ = self._create_team(cn.team_with_restrict_share)
        share, edit, view = args[2], args[3], args[4]
        self.assertEqual(share, 'on')
        self.assertEqual((edit, view), ('off', 'off'))

    def test_team_restrict_view_only(self):
        args, _, _ = self._create_team(cn.team_with_restrict_view)
        share, edit, view = args[2], args[3], args[4]
        self.assertEqual(view, 'on')
        self.assertEqual((share, edit), ('off', 'off'))

    def test_team_with_all_three_restrictions(self):
        args, _, _ = self._create_team(cn.team_with_all_three_restrictions)
        self.assertEqual(args[2:5], ('on', 'on', 'on'))

    def test_team_with_no_restrictions(self):
        args, _, _ = self._create_team(cn.team_with_no_restrictions)
        self.assertEqual(args[2:5], ('off', 'off', 'off'))

    def test_team_users_queue_indexed_for_user_runner(self):
        from keepercommander.commands.keeper_tenant_migrate.users import _index_queued_team_membership
        team_src, expected = cn.team_with_users_assigned()
        inventory = {'entities': {'teams': [team_src]}}
        index = _index_queued_team_membership(inventory)
        for email in expected['queued_emails']:
            self.assertIn(email.lower(), index)
            self.assertIn(team_src['name'], index[email.lower()])

    def test_team_role_assignment_routed_for_non_admin_role(self):
        (team_src, role_src), expected = cn.team_with_role_assignment()
        plan = list(plan_role_team_assignments([role_src]))
        # Each row: (role_name, team_name, is_admin)
        self.assertEqual(plan, [(expected['role'], expected['team'],
                                 expected['is_admin'])])
        client, restore = _make_restore()
        restore.created_roles = {role_src['name']}
        restore.step_role_teams([role_src])
        kinds = [c[0] for c in client.calls]
        self.assertIn('add_team_to_role', kinds)
        self.assertEqual(restore.counters['SKIPPED'], 0)


# ─── Roles (13 items) ───────────────────────────────────────────────────────


class ComprehensiveRoleTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='migtest_complexity_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_role_with_new_user_flag(self):
        src, expected = cn.role_with_new_user_default()
        client, restore = _make_restore()
        restore.step_roles([src])
        create = next(c for c in client.calls if c[0] == 'create_role')
        # create_role args: (name, node, new_user)
        self.assertEqual(create[1][0], expected['name'])
        self.assertEqual(create[1][2], expected['new_user'])

    def test_role_managed_node_all_privileges(self):
        src, expected = cn.role_with_managed_node_all_privileges()
        plan = list(plan_managed_nodes([src], cn.SOURCE_ROOT, cn.TARGET_ROOT))
        self.assertEqual(len(plan), 1)
        name, node, cascade, privs = plan[0]
        self.assertEqual(name, expected['name'])
        self.assertEqual(node, expected['managed_node'])
        self.assertEqual(cascade, expected['cascade'])
        self.assertEqual(privs, expected['privileges'])
        client, restore = _make_restore()
        restore.created_roles = {src['name']}
        restore.step_managed_nodes([src])
        priv_calls = [c for c in client.calls
                       if c[0] == 'add_role_privilege']
        self.assertEqual(len(priv_calls), len(expected['privileges']))

    def _run_enforcement(self, src):
        client, restore = _make_restore()
        restore.created_roles = {src['name']}
        # Capture direct-API routing too. As of 2026-04-27, certain
        # enforcement types (`two_factor_duration`, `record_types`,
        # plus the original `json`/`jsonarray`) bypass the CLI parser
        # and go via api.communicate. Tests need to see both paths.
        direct_calls = {}

        def _direct_fn(role_name, enfs):
            direct_calls.setdefault(role_name, {}).update(enfs)
            return {k: (True, 'OK') for k in enfs}

        summary = restore.step_enforcements(
            [src], complexity_dir=self.tmp,
            direct_api_fn=_direct_fn,
        )
        sent_pairs = {}
        for c in client.calls:
            if c[0] == 'set_role_enforcement_simple':
                sent_pairs[c[1][1]] = c[1][2]
            elif c[0] == 'set_role_enforcements_simple_batch':
                for key, value in c[1][1]:
                    sent_pairs[key] = value
        # Direct-API enforcements are also "sent pairs" — fold them in
        # so existing tests that assert end-to-end value-fidelity see
        # the same map regardless of the CLI vs direct-API routing.
        for role_name, enfs in direct_calls.items():
            for key, value in enfs.items():
                sent_pairs[key] = value
        return summary, client, sent_pairs

    def test_role_every_boolean_enforcement(self):
        src, expected = cn.role_with_every_boolean_enforcement()
        summary, _, sent_pairs = self._run_enforcement(src)
        for k, v in expected['enforcements'].items():
            self.assertEqual(sent_pairs[k], 'true' if v else 'false')
        self.assertEqual(summary['failed'], 0)
        self.assertEqual(summary['simple'], len(expected['enforcements']))

    def test_role_long_enforcements(self):
        src, expected = cn.role_with_long_enforcements()
        summary, _, sent_pairs = self._run_enforcement(src)
        for k, v in expected['enforcements'].items():
            self.assertEqual(sent_pairs[k], str(v))
        self.assertEqual(summary['failed'], 0)

    def test_role_string_enforcements(self):
        src, expected = cn.role_with_string_enforcements()
        summary, _, sent_pairs = self._run_enforcement(src)
        for k, v in expected['enforcements'].items():
            self.assertEqual(sent_pairs[k], str(v))
        self.assertEqual(summary['failed'], 0)

    def test_role_ternary_enforcements(self):
        src, expected = cn.role_with_ternary_enforcements()
        summary, _, sent_pairs = self._run_enforcement(src)
        if expected['enforcements']:
            for k, v in expected['enforcements'].items():
                self.assertEqual(sent_pairs[k], str(v))
        else:
            # No ternary keys in this Commander version — assert
            # the empty-state contract: zero work, zero failures.
            self.assertEqual(sent_pairs, {})
        self.assertEqual(summary['failed'], 0)

    def test_role_ip_whitelist_passes_through(self):
        src, expected = cn.role_with_ip_whitelist()
        summary, _, sent_pairs = self._run_enforcement(src)
        self.assertEqual(sent_pairs['restrict_ip_addresses'],
                         expected['restrict_ip_addresses'])
        self.assertEqual(summary['failed'], 0)

    def test_role_two_factor_duration(self):
        src, expected = cn.role_with_two_factor_duration()
        summary, _, sent_pairs = self._run_enforcement(src)
        # require_two_factor is `boolean` type → CLI batch (stringified)
        self.assertEqual(sent_pairs['require_two_factor'], 'true')
        # two_factor_duration_* now route via direct API (Gap-2 fix
        # 2026-04-27 — CLI path was rejecting internal storage format
        # like '0,12,24'). The direct path preserves the raw value
        # type, so these come through as the source's native ints
        # rather than the CLI-stringified version.
        self.assertEqual(str(sent_pairs['two_factor_duration_desktop']),
                         str(expected['two_factor_duration_desktop']))
        self.assertEqual(str(sent_pairs['two_factor_duration_web']), '0')
        self.assertEqual(summary['failed'], 0)

    def test_role_password_complexity_file(self):
        src, expected = cn.role_with_password_complexity_file()
        summary, client, _ = self._run_enforcement(src)
        # FILE phase emitted exactly one set_role_enforcement_file call.
        file_calls = [c for c in client.calls
                       if c[0] == 'set_role_enforcement_file']
        self.assertEqual(len(file_calls), 1)
        self.assertEqual(summary['file'], 1)
        # The body file written under tmp must hold the JSON dict.
        path = file_calls[0][1][2]
        with open(path) as f:
            body = f.read()
        for needle in ('"minLength":', '"requireDigits":'):
            self.assertIn(needle, body)

    def test_role_require_account_share_self_reference(self):
        """Bug 47 (rehearsal-4 fix) — when require_account_share's
        resolved target name equals the role being modified, the call
        is a self-reference Commander rejects with a generic
        'cannot update enforcement' envelope. Plugin must skip
        cleanly before queueing the API call. Pre-fix this returned
        ACCOUNT_SHARE phase, the call was sent, and 5 admin-tier
        roles failed the structure stage of the 2026-04-30 full-
        tenant rehearsal."""
        src, _expected = cn.role_with_require_account_share()
        decision = classify_enforcement(
            src['name'], 'require_account_share',
            src['enforcements']['require_account_share'],
            id_to_name={src['role_id']: src['name']},
        )
        self.assertEqual(decision['phase'], 'SKIP')
        self.assertIn('self-reference', decision['reason'])

    def test_role_restrict_record_types(self):
        src, expected = cn.role_with_restrict_record_types()
        summary, _, sent_pairs = self._run_enforcement(src)
        self.assertEqual(sent_pairs['restrict_record_types'],
                         expected['restrict_record_types'])
        self.assertEqual(summary['failed'], 0)

    def test_role_with_user_assignments(self):
        src, expected = cn.role_with_user_assignments()
        plan = list(plan_role_user_assignments([src]))
        emails = sorted(e for _, e in plan)
        self.assertEqual(emails, sorted(expected['user_emails']))

    def test_role_with_team_assignments_non_admin(self):
        src, expected = cn.role_with_team_assignments()
        plan = list(plan_role_team_assignments([src]))
        team_names = sorted(t for _, t, _ in plan)
        self.assertEqual(team_names, sorted(expected['team_names']))
        for _, _, is_admin in plan:
            self.assertEqual(is_admin, expected['is_admin'])


# ─── Shared folders (8 items) ──────────────────────────────────────────────


class ComprehensiveSharedFolderTests(unittest.TestCase):

    def test_sf_at_root_level(self):
        src, expected = cn.sf_at_root_level()
        client, restore = _make_restore()
        uid_map = restore.step_vault_folders([src])
        self.assertIn(src['uid'], uid_map)
        sf_call = next(c for c in client.calls
                        if c[0] == 'add_shared_folder')
        # Tuple = (name, parent_uid, new_uid, mu, mr, ce, cs)
        self.assertEqual(sf_call[1][0], expected['name'])
        self.assertEqual(sf_call[1][1], expected['parent_uid'])

    def test_sf_inside_user_folder(self):
        chain, expected = cn.sf_inside_user_folder()
        client, restore = _make_restore()
        uid_map = restore.step_vault_folders(chain)
        # Both folders landed.
        self.assertEqual(len(uid_map), 2)
        # SF was created with the user-folder's resolved target UID as parent.
        sf_call = next(c for c in client.calls
                        if c[0] == 'add_shared_folder'
                        and c[1][0] == expected['sf_name'])
        # chain[0] = user-folder src UID
        uf_target_uid = uid_map[chain[0]['uid']]
        self.assertEqual(sf_call[1][1], uf_target_uid)

    def test_sf_with_slash_in_name_carries_through(self):
        src, expected = cn.sf_with_slash_in_name()
        client, restore = _make_restore()
        restore.step_vault_folders([src])
        sf_call = next(c for c in client.calls
                        if c[0] == 'add_shared_folder')
        self.assertEqual(sf_call[1][0], expected['name'])
        self.assertIn('/', sf_call[1][0])

    def test_sf_with_multiple_user_members(self):
        src, expected = cn.sf_with_multiple_user_members()
        # phase_shared_folders compares per-user permission flags.
        inv = {'source_user': 'admin@src',
               'entities': {'nodes': [], 'teams': [], 'roles': [],
                            'users': [], 'shared_folders': [src],
                            'records': []}}
        target = {'shared_folders': [src]}        # identical → all pass
        ctx = ValidationContext(inv, target)
        checks = list(phase_shared_folders(ctx))
        self.assertTrue(any(c.severity == Severity.PASS for c in checks))
        # No FAIL/WARN when source==target.
        self.assertFalse(any(c.severity in (Severity.FAIL, Severity.WARN)
                              for c in checks))
        # Three users × 4 flags accounted for.
        self.assertEqual(len(expected['user_perms']), 3)

    def test_sf_with_team_members(self):
        src, expected = cn.sf_with_team_members()
        inv = {'source_user': 'admin@src',
               'entities': {'nodes': [], 'teams': [], 'roles': [],
                            'users': [], 'shared_folders': [src],
                            'records': []}}
        ctx = ValidationContext(inv, {'shared_folders': [src]})
        checks = list(phase_shared_folders(ctx))
        self.assertFalse(any(c.severity in (Severity.FAIL, Severity.WARN)
                              for c in checks))
        self.assertEqual(len(expected['team_perms']), 2)

    def test_sf_with_subfolders_creates_in_order(self):
        chain, expected = cn.sf_with_subfolders()
        client, restore = _make_restore()
        uid_map = restore.step_vault_folders(chain)
        self.assertEqual(len(uid_map), 3)
        sub_calls = [c for c in client.calls if c[0] == 'add_subfolder']
        names = [c[1][0] for c in sub_calls]
        self.assertEqual(sorted(names), sorted(expected['subfolder_names']))

    def test_sf_with_records_inside_carries_record_uids(self):
        src, expected = cn.sf_with_records_inside()
        # The SF inventory entry preserves record uids verbatim — the
        # records-import stage uses these to bind records to the new SF.
        record_uids = [r['record_uid'] for r in src['records']]
        self.assertEqual(record_uids, expected['record_uids'])

    def test_sf_with_default_permissions_flags(self):
        src, expected = cn.sf_with_default_permissions()
        client, restore = _make_restore()
        restore.step_vault_folders([src])
        sf_call = next(c for c in client.calls
                        if c[0] == 'add_shared_folder')
        _, _, _, mu, mr, ce, cs = sf_call[1]
        self.assertEqual((mu, mr, ce, cs),
                         (expected['default_manage_users'],
                          expected['default_manage_records'],
                          expected['default_can_edit'],
                          expected['default_can_share']))


# ─── Users (6 items) ───────────────────────────────────────────────────────


class ComprehensiveUserTests(unittest.TestCase):

    def test_active_user_with_master_password(self):
        src, expected = cn.user_active_with_master_password()
        roster = [{'email': src['email'], 'full_name': 'Mp User'}]
        inv = {'entities': {'users': [src], 'teams': []}}
        client = FakeUserClient()
        runner = UserRunner(client, source_root=cn.SOURCE_ROOT,
                             target_root=cn.TARGET_ROOT,
                             default_node=cn.SCOPE_NODE,
                             sleeper=lambda *_: None)
        results = runner.run(roster, inventory=inv, transition_plan=[])
        self.assertEqual(results[0].email, expected['email'])
        self.assertEqual(results[0].status, 'YES')

    def test_user_in_specific_node_uses_leaf(self):
        src, expected = cn.user_in_specific_node()
        node = remap_user_node(src['node'], cn.SOURCE_ROOT, cn.TARGET_ROOT,
                                default_node=cn.SCOPE_NODE)
        self.assertEqual(node, expected['expected_node_leaf'])
        # Direct plan check too.
        pairs = list(plan_user_node_assignments([src], cn.SOURCE_ROOT,
                                                  cn.TARGET_ROOT))
        self.assertEqual(pairs, [(src['email'],
                                   expected['expected_node_leaf'])])

    def test_user_with_team_membership_iterates_teams(self):
        src, expected = cn.user_with_team_membership()
        pairs = list(plan_user_team_assignments([src]))
        team_names = [t for _, t in pairs]
        self.assertEqual(sorted(team_names), sorted(expected['teams']))

    def test_user_with_role_assignment_applied_during_placement(self):
        src, expected = cn.user_with_role_assignment()
        roster = [{'email': src['email'], 'full_name': 'Role User'}]
        inv = {'entities': {'users': [src], 'teams': []}}
        client = FakeUserClient()
        runner = UserRunner(client, source_root=cn.SOURCE_ROOT,
                             target_root=cn.TARGET_ROOT,
                             default_node=cn.SCOPE_NODE,
                             sleeper=lambda *_: None)
        results = runner.run(roster, inventory=inv, transition_plan=[])
        self.assertEqual(sorted(results[0].assignments['roles']),
                         sorted(expected['roles']))

    def test_user_transfer_acceptance_status_preserved_in_inventory(self):
        src, expected = cn.user_transfer_acceptance_accepted()
        # The inventory passes transfer_status through unchanged — verify
        # the field carries.
        self.assertEqual(src['transfer_status'], expected['transfer_status'])

    def test_invited_user_extended_via_category_e(self):
        src, expected = cn.user_invited_never_activated()
        roster = [{'email': src['email'], 'full_name': 'Pending Invite'}]
        plan = [{'source_email': src['email'], 'category': 'E'}]
        inv = {'entities': {'users': [src], 'teams': []}}
        client = FakeUserClient()
        runner = UserRunner(client, source_root=cn.SOURCE_ROOT,
                             target_root=cn.TARGET_ROOT,
                             default_node=cn.SCOPE_NODE,
                             sleeper=lambda *_: None)
        results = runner.run(roster, inventory=inv, transition_plan=plan)
        self.assertEqual(results[0].status, 'EXTENDED')
        self.assertEqual(results[0].category, 'E')
        self.assertEqual(src['status'], expected['status'])


# ─── Records (8 items) ─────────────────────────────────────────────────────


class ComprehensiveRecordTests(unittest.TestCase):

    def test_login_record_full_fields_round_trip(self):
        src, expected = cn.record_login_full_fields()
        summary = summarize_record(src, include_fields=True)
        for key in ('login', 'password', 'login_url', 'notes'):
            self.assertEqual(summary[key], expected[key])
        self.assertEqual(summary['title'], expected['title'])

    def test_record_with_custom_fields(self):
        src, expected = cn.record_with_custom_fields()
        summary = summarize_record(src, include_fields=True)
        self.assertEqual(summary['custom_fields'], expected['custom_fields'])

    def test_record_with_attachment_count(self):
        src, expected = cn.record_with_attachment()
        summary = summarize_record(src, include_fields=False)
        self.assertEqual(summary['attachment_count'],
                         expected['attachment_count'])

    def test_record_with_totp_seed(self):
        src, expected = cn.record_with_totp_seed()
        summary = summarize_record(src, include_fields=True)
        self.assertEqual(summary['has_totp'], expected['has_totp'])
        self.assertEqual(summary['totp_secret'], expected['totp_secret'])

    def test_record_in_shared_folder_via_uid_map(self):
        (sf, record), expected = cn.record_in_shared_folder()
        client, restore = _make_restore()
        uid_map = restore.step_vault_folders([sf])
        # The record's source folder_uid resolves to a target SF UID via uid_map.
        self.assertIn(record['folder_uid'], uid_map)
        target_sf_uid = uid_map[record['folder_uid']]
        # Cross-reference: the SF call wrote that UID.
        sf_call = next(c for c in client.calls
                        if c[0] == 'add_shared_folder'
                        and c[1][0] == expected['folder_name'])
        self.assertEqual(sf_call[1][2], target_sf_uid)

    def test_record_in_subfolder_of_shared_folder(self):
        (sf, sub, record), expected = cn.record_in_subfolder_of_shared_folder()
        client, restore = _make_restore()
        uid_map = restore.step_vault_folders([sf, sub])
        self.assertIn(record['folder_uid'], uid_map)
        sub_call = next(c for c in client.calls
                         if c[0] == 'add_subfolder')
        # Subfolder created with SF's target UID as parent.
        target_sf_uid = uid_map[sf['uid']]
        self.assertEqual(sub_call[1][1], target_sf_uid)
        self.assertEqual(sub_call[1][0], expected['folder_name'])

    def test_record_owned_by_specific_user(self):
        src, expected = cn.record_owned_by_specific_user()
        owner = next(p for p in src['user_permissions'] if p.get('owner'))
        self.assertEqual(owner['username'], expected['owner_email'])
        # And direct shares list (non-owners) is empty for this fixture.
        self.assertEqual(extract_direct_shares(src), [])

    def test_record_directly_shared_to_user(self):
        src, expected = cn.record_directly_shared_to_user()
        shares = extract_direct_shares(src)
        # Sort both sides by username so list ordering doesn't matter.
        shares_sorted = sorted(shares, key=lambda s: s['username'])
        expected_sorted = sorted(expected['direct_shares'],
                                 key=lambda s: s['username'])
        self.assertEqual(shares_sorted, expected_sorted)


if __name__ == '__main__':
    unittest.main()
