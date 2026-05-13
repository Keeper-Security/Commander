import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.live_inventory import (
    _build_node_path_map,
    _build_record_folder_map,
    _compute_descendants,
    _DEPRECATED_ENFORCEMENT_KEYS,
    _folder_name_path,
    _folder_parent_chain,
    _invert_bool_value,
    _remap_role_enforcement_values,
    _source_record_type_id_to_name,
    _translate_record_types_enforcement,
    build_inventory_from_params,
    build_node_entities,
    build_record_types,
    build_role_entities,
    build_shared_folder_entities,
    build_team_entities,
    build_user_entities,
    build_vault_folder_entities,
    compute_counts,
    resolve_scope_vault_root,
    restricts_code,
    scrape_team_hsf_users,
    write_inventory,
)


def _enterprise_fixture():
    return {
        'enterprise_name': 'My company',
        'nodes': [
            {'node_id': 1, 'data': {'displayname': 'My company'}, 'parent_id': None},
            {'node_id': 2, 'data': {'displayname': 'MIGRATION-TEST-NODE',
                                     'restrict_visibility': False},
             'parent_id': 1},
            {'node_id': 3, 'data': {'displayname': 'Isolated-Sub',
                                     'restrict_visibility': True},
             'parent_id': 2},
            {'node_id': 99, 'data': {'displayname': 'Unrelated'}, 'parent_id': 1},
        ],
        'teams': [
            {'team_uid': 'uid-t1', 'name': 'MIGTEST-Team', 'node_id': 2,
             'restrict_edit': True, 'restrict_view': False, 'restrict_share': True},
            {'team_uid': 'uid-t2', 'name': 'Other-Team', 'node_id': 99,
             'restrict_edit': False, 'restrict_view': False, 'restrict_share': False},
        ],
        'roles': [
            {'role_id': 42, 'data': {'displayname': 'MIGTEST-Admin',
                                      'default_role': False},
             'node_id': 2, 'enforcements': {'two_factor_required': True},
             'managed_nodes': [{'privileges': ['MANAGE_USER'], 'cascade': True}],
             'teams': [], 'users': []},
        ],
        'users': [
            {'enterprise_user_id': 1001, 'username': 'alice@x', 'node_id': 2,
             'status': 'Active', 'two_factor_enabled': True, 'job_title': 'Eng',
             'teams': [{'team_name': 'MIGTEST-Team'}], 'roles': [],
             'aliases': ['ALICE@X', 'alt@x']},
            {'enterprise_user_id': 1002, 'username': 'bob@x', 'node_id': 99,
             'status': 'Active', 'teams': [], 'roles': []},
        ],
        'shared_folders': [
            {'shared_folder_uid': 'sf-a', 'name': 'MIGTEST-SF-A',
             'default_can_edit': True, 'default_can_share': False,
             'users': [], 'teams': [], 'records': []},
            {'shared_folder_uid': 'sf-b', 'name': 'Unrelated-SF',
             'users': [], 'teams': [], 'records': []},
        ],
    }


class FakeParams:
    def __init__(self, ent, user='admin@src', server='https://keepersecurity.eu'):
        self.enterprise = ent
        self.user = user
        self.server = server


class NodeDisplaynameNormalizationTests(unittest.TestCase):
    """2026-04-20 regression: source 'My company' tenant stores its
    enterprise-root node with displayname='root' literally. Before this
    fix, every top-level team + role recorded node='root' in inventory;
    downstream enterprise-* commands then failed on target with
    'Node "root" is not found'. The source root must normalize to
    enterprise_name regardless of the literal displayname."""

    def _call(self, node, enterprise_name='My company'):
        from keepercommander.commands.keeper_tenant_migrate.live_inventory import _node_displayname
        return _node_displayname(node, enterprise_name)

    def test_empty_displayname_on_root_uses_enterprise_name(self):
        self.assertEqual(
            self._call({'parent_id': None, 'data': {'displayname': ''}}),
            'My company',
        )

    def test_literal_root_on_source_root_normalizes(self):
        self.assertEqual(
            self._call({'parent_id': None, 'data': {'displayname': 'root'}}),
            'My company',
        )

    def test_literal_Root_case_insensitive(self):
        self.assertEqual(
            self._call({'parent_id': None, 'data': {'displayname': 'Root'}}),
            'My company',
        )

    def test_normal_root_with_enterprise_name_displayname_passes_through(self):
        self.assertEqual(
            self._call({'parent_id': None,
                         'data': {'displayname': 'My company'}}),
            'My company',
        )

    def test_nested_node_named_root_is_NOT_normalized(self):
        """A child folder literally called 'root' (rare but legal) must
        keep its real name — the normalization only applies when the
        node sits at the enterprise root with no parent_id."""
        self.assertEqual(
            self._call({'parent_id': 12345,
                         'data': {'displayname': 'root'}}),
            'root',
        )


class RestrictsCodeTests(unittest.TestCase):
    def test_all_restrictions(self):
        self.assertEqual(
            restricts_code({'restrict_edit': True, 'restrict_view': True, 'restrict_share': True}),
            'R W S',
        )

    def test_single_flag(self):
        self.assertEqual(restricts_code({'restrict_edit': True}), 'R')
        self.assertEqual(restricts_code({'restrict_view': True}), 'W')
        self.assertEqual(restricts_code({'restrict_share': True}), 'S')

    def test_none_is_empty(self):
        self.assertEqual(restricts_code({}), '')


class ComputeDescendantsTests(unittest.TestCase):
    def test_includes_self_and_children(self):
        ent = _enterprise_fixture()
        descendants = _compute_descendants(ent, 'MIGRATION-TEST-NODE')
        self.assertEqual(descendants, {2, 3})

    def test_none_when_no_scope(self):
        self.assertIsNone(_compute_descendants(_enterprise_fixture(), ''))

    def test_case_insensitive_name_match(self):
        ent = _enterprise_fixture()
        descendants = _compute_descendants(ent, 'migration-test-node')
        self.assertEqual(descendants, {2, 3})


class BuildNodePathMapTests(unittest.TestCase):
    def test_produces_full_backslash_path(self):
        ent = _enterprise_fixture()
        paths = _build_node_path_map(ent)
        self.assertEqual(paths[1], 'My company')
        self.assertEqual(paths[2], 'My company\\MIGRATION-TEST-NODE')
        self.assertEqual(paths[3], 'My company\\MIGRATION-TEST-NODE\\Isolated-Sub')


class BuildNodeEntitiesTests(unittest.TestCase):
    def test_scoped_includes_only_subtree(self):
        ent = _enterprise_fixture()
        descendants = _compute_descendants(ent, 'MIGRATION-TEST-NODE')
        path_map = _build_node_path_map(ent)
        out = build_node_entities(ent, descendants, path_map, prefix='')
        names = {n['name'] for n in out}
        self.assertEqual(names, {'MIGRATION-TEST-NODE', 'Isolated-Sub'})

    def test_isolated_flag_propagated(self):
        ent = _enterprise_fixture()
        path_map = _build_node_path_map(ent)
        out = build_node_entities(ent, None, path_map, prefix='')
        iso = {n['name']: n['isolated'] for n in out}
        self.assertTrue(iso['Isolated-Sub'])
        self.assertFalse(iso['MIGRATION-TEST-NODE'])

    def test_prefix_filter(self):
        ent = _enterprise_fixture()
        path_map = _build_node_path_map(ent)
        out = build_node_entities(ent, None, path_map, prefix='MIGRATION-')
        self.assertEqual([n['name'] for n in out], ['MIGRATION-TEST-NODE'])


class BuildTeamEntitiesTests(unittest.TestCase):
    def test_scoped_and_restricts_composed(self):
        ent = _enterprise_fixture()
        descendants = _compute_descendants(ent, 'MIGRATION-TEST-NODE')
        path_map = _build_node_path_map(ent)
        out = build_team_entities(ent, descendants, path_map, prefix='')
        self.assertEqual(len(out), 1)
        t = out[0]
        self.assertEqual(t['name'], 'MIGTEST-Team')
        self.assertEqual(t['restricts'], 'R S')
        self.assertEqual(t['node'], 'My company\\MIGRATION-TEST-NODE')


class BuildRoleEntitiesTests(unittest.TestCase):
    def test_picks_managed_nodes_and_enforcements(self):
        ent = _enterprise_fixture()
        descendants = _compute_descendants(ent, 'MIGRATION-TEST-NODE')
        path_map = _build_node_path_map(ent)
        out = build_role_entities(ent, descendants, path_map, prefix='MIGTEST-')
        self.assertEqual(len(out), 1)
        r = out[0]
        self.assertEqual(r['name'], 'MIGTEST-Admin')
        self.assertEqual(r['enforcements']['two_factor_required'], True)
        self.assertEqual(r['managed_nodes'][0]['cascade'], True)


class BuildRolePivotTests(unittest.TestCase):
    """Regression: Commander stores managed_nodes / role_privileges /
    role_enforcements / role_users / role_teams as top-level flat tables
    on `params.enterprise`, not on each role dict. build_role_entities
    must pivot them — otherwise admin privileges + new_user flags get
    silently lost in migration."""

    def _ent(self):
        return {
            'enterprise_name': 'Acme',
            'nodes': [
                {'node_id': 1, 'data': {'displayname': 'Acme'}, 'parent_id': None},
                {'node_id': 2, 'data': {'displayname': 'MIGRATION-TEST-NODE'},
                 'parent_id': 1},
            ],
            'teams': [
                {'team_uid': 'uid-t1', 'name': 'MIGTEST-Team',
                 'node_id': 2, 'restrict_edit': False,
                 'restrict_view': False, 'restrict_sharing': False},
            ],
            'users': [
                # Enterprise user 777 — used by the role_users pivot
                # below to validate email resolution.
                {'enterprise_user_id': 777,
                 'username': 'admin@acme.example',
                 'node_id': 2, 'status': 'active'},
            ],
            'roles': [
                {'role_id': 500, 'node_id': 2, 'new_user_inherit': False,
                 'data': {'displayname': 'MIGTEST-Role-Admin'}},
                {'role_id': 501, 'node_id': 2, 'new_user_inherit': True,
                 'data': {'displayname': 'MIGTEST-Role-Default'}},
            ],
            'managed_nodes': [
                {'role_id': 500, 'managed_node_id': 2,
                 'cascade_node_management': True},
            ],
            'role_privileges': [
                {'role_id': 500, 'managed_node_id': 2, 'privilege': 'manage_user'},
                {'role_id': 500, 'managed_node_id': 2, 'privilege': 'manage_roles'},
            ],
            'role_enforcements': [
                {'role_id': 500,
                 'enforcements': {'two_factor_required': True}},
            ],
            'role_users': [
                {'role_id': 500, 'enterprise_user_id': 777},
            ],
            'role_teams': [
                {'role_id': 500, 'team_uid': 'uid-t1'},
            ],
        }

    def test_managed_nodes_privileges_pivoted_from_flat_tables(self):
        ent = self._ent()
        descendants = _compute_descendants(ent, 'MIGRATION-TEST-NODE')
        path_map = _build_node_path_map(ent)
        out = build_role_entities(ent, descendants, path_map, prefix='MIGTEST-')
        by_name = {r['name']: r for r in out}

        admin = by_name['MIGTEST-Role-Admin']
        self.assertEqual(len(admin['managed_nodes']), 1)
        mn = admin['managed_nodes'][0]
        self.assertEqual(mn['node_name'], 'MIGRATION-TEST-NODE')
        self.assertTrue(mn['cascade'])
        self.assertEqual(sorted(mn['privileges']),
                          ['manage_roles', 'manage_user'])
        self.assertTrue(admin['enforcements']['two_factor_required'])
        # role['users'] now carries dicts {'username': email} — raw ids
        # broke downstream structure.plan_role_user_assignments which
        # expects the dict shape (see 2026-04-20 full-tenant run fix).
        self.assertEqual(admin['users'],
                          [{'username': 'admin@acme.example'}])
        self.assertEqual(admin['teams'], ['MIGTEST-Team'])

    def test_role_users_orphan_user_id_dropped_with_warning(self):
        """If role_users references a user_id not present in ent['users']
        (deleted user with lingering join-row), drop + warn rather than
        letting an int leak through and crash downstream."""
        ent = self._ent()
        # Keep user 777 mapped, add a bogus 999 reference.
        ent['role_users'].append({'role_id': 500, 'enterprise_user_id': 999})
        descendants = _compute_descendants(ent, 'MIGRATION-TEST-NODE')
        path_map = _build_node_path_map(ent)
        with self.assertLogs(level='WARNING') as captured:
            out = build_role_entities(ent, descendants, path_map,
                                       prefix='MIGTEST-')
        self.assertIn('999', '\n'.join(captured.output))
        admin = next(r for r in out if r['name'] == 'MIGTEST-Role-Admin')
        # Only the resolvable 777 landed — 999 got dropped.
        self.assertEqual(admin['users'],
                          [{'username': 'admin@acme.example'}])

    def test_new_user_inherit_captured(self):
        ent = self._ent()
        descendants = _compute_descendants(ent, 'MIGRATION-TEST-NODE')
        path_map = _build_node_path_map(ent)
        out = build_role_entities(ent, descendants, path_map, prefix='MIGTEST-')
        by_name = {r['name']: r for r in out}
        self.assertTrue(by_name['MIGTEST-Role-Default']['new_user'])
        self.assertFalse(by_name['MIGTEST-Role-Admin']['new_user'])


class BuildUserEntitiesTests(unittest.TestCase):
    def test_self_alias_stripped(self):
        ent = _enterprise_fixture()
        path_map = _build_node_path_map(ent)
        out = build_user_entities(ent, None, path_map, prefix='')
        alice = next(u for u in out if u['email'] == 'alice@x')
        self.assertEqual(alice['aliases'], ['alt@x'])
        self.assertTrue(alice['2fa_enabled'])
        self.assertEqual(alice['teams'], ['MIGTEST-Team'])

    def test_scoped_includes_users_on_subtree_only(self):
        ent = _enterprise_fixture()
        descendants = _compute_descendants(ent, 'MIGRATION-TEST-NODE')
        path_map = _build_node_path_map(ent)
        out = build_user_entities(ent, descendants, path_map, prefix='')
        emails = {u['email'] for u in out}
        # alice@x is on node 2 (scoped), bob@x is on node 99 (not scoped)
        self.assertEqual(emails, {'alice@x'})


class BuildRecordTypesTests(unittest.TestCase):
    """Bug 40 — fetch enterprise/user record types via the proto API and
    translate them into the file-shape Commander's LoadRecordTypeCommand
    expects ($ref → $type, $id → record_type_name)."""

    @staticmethod
    def _stub(entries):
        """Fake `communicator` returning [(rti_id, content_str), ...]."""
        return lambda: list(entries)

    def test_translates_id_and_ref_keys(self):
        entries = [
            (1, json.dumps({
                '$id': 'pamMachine',
                'description': 'PAM target',
                'fields': [
                    {'$ref': 'login'},
                    {'$ref': 'password', 'label': 'rotated', 'required': True},
                ],
            })),
        ]
        out = build_record_types(None, communicator=self._stub(entries))
        self.assertEqual(len(out), 1)
        rt = out[0]
        self.assertEqual(rt['record_type_name'], 'pamMachine')
        self.assertEqual(rt['description'], 'PAM target')
        self.assertEqual(rt['fields'][0], {'$type': 'login'})
        self.assertEqual(
            rt['fields'][1],
            {'$type': 'password', 'label': 'rotated', 'required': True},
        )

    def test_communicator_failure_returns_empty(self):
        def boom():
            raise RuntimeError('proto unavailable')
        out = build_record_types(None, communicator=boom)
        self.assertEqual(out, [])

    def test_skips_entries_without_id(self):
        entries = [
            (1, json.dumps({'description': 'no-id'})),
            (2, json.dumps({'$id': 'good', 'fields': []})),
        ]
        out = build_record_types(None, communicator=self._stub(entries))
        self.assertEqual([rt['record_type_name'] for rt in out], ['good'])

    def test_skips_invalid_json_entries(self):
        entries = [
            (1, 'not-json'),
            (2, json.dumps({'$id': 'good', 'fields': []})),
        ]
        out = build_record_types(None, communicator=self._stub(entries))
        self.assertEqual([rt['record_type_name'] for rt in out], ['good'])


class RecordTypeIdToNameTests(unittest.TestCase):
    """Task #17 / Bug 60 — at SOURCE inventory capture, build the
    id_to_name table that lets us translate `restrict_record_types`
    enforcement values from tenant-local IDs to portable names.
    """

    def test_communicator_returns_id_to_name(self):
        out = _source_record_type_id_to_name(
            None,
            communicator=lambda: {1: 'login', 315: 'pamMachine'})
        self.assertEqual(out, {1: 'login', 315: 'pamMachine'})

    def test_communicator_failure_returns_empty(self):
        def boom():
            raise RuntimeError('proto unavailable')
        out = _source_record_type_id_to_name(None, communicator=boom)
        self.assertEqual(out, {})


class TranslateRecordTypesEnforcementTests(unittest.TestCase):
    """The translation primitive: JSON `{"std":[],"ent":[]}` value → CSV
    of names using a supplied id_to_name. Idempotent passthrough on
    already-translated strings keeps the call safe in mixed pipelines."""

    def test_translates_std_and_ent_ids(self):
        id_to_name = {1: 'login', 2: 'sshKeys', 315: 'pamMachine'}
        value = json.dumps({'std': [1, 2], 'ent': [315]})
        out = _translate_record_types_enforcement(value, id_to_name)
        self.assertEqual(out, 'login,sshKeys,pamMachine')

    def test_dangling_id_dropped_with_warning(self):
        # Bug 66 (rehearsal-11) — source has dangling record-type IDs
        # in restrict_record_types from deleted enterprise types.
        # Filter them out + log a warning so the operator can fix
        # source. Salvages the resolvable subset rather than failing
        # the whole enforcement.
        id_to_name = {1: 'login'}
        value = json.dumps({'std': [1], 'ent': [999]})
        out = _translate_record_types_enforcement(value, id_to_name)
        self.assertEqual(out, 'login')
        self.assertNotIn('<unknown', out)

    def test_all_dangling_returns_all_keyword(self):
        # Edge case — every ID is dangling. Returns 'all' (Commander's
        # cleared-keyword) rather than empty string which the CLI
        # parser rejects.
        out = _translate_record_types_enforcement(
            json.dumps({'std': [], 'ent': [999, 998]}),
            {1: 'login'})
        self.assertEqual(out, 'all')

    def test_already_translated_is_passthrough(self):
        out = _translate_record_types_enforcement('login,sshKeys', {})
        self.assertEqual(out, 'login,sshKeys')

    def test_empty_lists_return_all_keyword(self):
        value = json.dumps({'std': [], 'ent': []})
        out = _translate_record_types_enforcement(value, {1: 'login'})
        self.assertEqual(out, 'all')

    def test_dict_input_handled_directly(self):
        out = _translate_record_types_enforcement(
            {'std': [1], 'ent': []}, {1: 'login'})
        self.assertEqual(out, 'login')


class DeprecatedEnforcementKeyRewriteTests(unittest.TestCase):
    """Bug 63 / Upstream-4 reclassified — source carries deprecated
    enforcement names with original semantics (e.g. allow_*=true).
    Target server resolves the legacy name to its canonical
    enforcementId but doesn't auto-invert the value, so the BOOLEAN
    coercion ends up null-rejected. Plugin pre-rewrites at capture
    time."""

    def test_invert_bool_handles_python_bool(self):
        self.assertIs(_invert_bool_value(True), False)
        self.assertIs(_invert_bool_value(False), True)

    def test_invert_bool_handles_string_true(self):
        self.assertEqual(_invert_bool_value('true'), 'false')
        self.assertEqual(_invert_bool_value('True'), 'false')
        self.assertEqual(_invert_bool_value('false'), 'true')

    def test_invert_bool_passthrough_unknown(self):
        # Non-boolean values pass through (defensive — the deprecation
        # map should only register value-transformers that match the
        # source value type).
        self.assertEqual(_invert_bool_value(42), 42)

    def test_remap_rewrites_deprecated_allow_to_restrict(self):
        roles = [{
            'name': 'Keeper Administrator',
            'enforcements': {
                'allow_can_edit_external_shares': 'true',
                'two_factor_required': True,
            },
        }]
        _remap_role_enforcement_values(
            roles, record_types_id_to_name={}, enforcement_types={})
        enfs = roles[0]['enforcements']
        self.assertNotIn('allow_can_edit_external_shares', enfs)
        self.assertIn('restrict_can_edit_external_shares', enfs)
        # Inverted: source allow=true → target restrict=false
        self.assertEqual(enfs['restrict_can_edit_external_shares'], 'false')
        # Untouched key
        self.assertEqual(enfs['two_factor_required'], True)

    def test_deprecated_map_includes_known_aliases(self):
        # Defensive — the deprecation map must include the
        # rehearsal-10 case that drove this fix.
        self.assertIn('allow_can_edit_external_shares',
                      _DEPRECATED_ENFORCEMENT_KEYS)


class RemapRoleEnforcementValuesTests(unittest.TestCase):
    """End-to-end wiring: walk a roles list and translate
    record_types-typed enforcement values in-place. Other enforcement
    keys are untouched. Roles without enforcements are no-ops."""

    def _roles(self, value):
        return [{
            'name': 'CLI Device Approval Role',
            'enforcements': {
                'restrict_record_types': value,
                'two_factor_required': True,
            },
        }]

    _ENFORCEMENT_TYPES = {'restrict_record_types': 'record_types'}

    def test_translates_record_types_value_in_place(self):
        roles = self._roles(json.dumps({'std': [1], 'ent': [315]}))
        _remap_role_enforcement_values(
            roles,
            record_types_id_to_name={1: 'login', 315: 'pamMachine'},
            enforcement_types=self._ENFORCEMENT_TYPES)
        self.assertEqual(
            roles[0]['enforcements']['restrict_record_types'],
            'login,pamMachine')
        # Untouched non-record-types key
        self.assertEqual(
            roles[0]['enforcements']['two_factor_required'], True)

    def test_role_without_enforcements_skipped(self):
        roles = [{'name': 'Empty', 'enforcements': {}}]
        _remap_role_enforcement_values(
            roles,
            record_types_id_to_name={1: 'login'},
            enforcement_types=self._ENFORCEMENT_TYPES)
        self.assertEqual(roles[0]['enforcements'], {})

    def test_already_translated_value_is_idempotent(self):
        roles = self._roles('login,sshKeys')
        _remap_role_enforcement_values(
            roles,
            record_types_id_to_name={1: 'login'},
            enforcement_types=self._ENFORCEMENT_TYPES)
        # Idempotent — already in NAME form, passthrough returns same string
        self.assertEqual(
            roles[0]['enforcements']['restrict_record_types'],
            'login,sshKeys')


class ComputeCountsTests(unittest.TestCase):
    def test_aggregates_nested_fields(self):
        entities = {
            'nodes': [1, 2], 'teams': [1], 'users': [1, 2],
            'shared_folders': [1],
            'records': [{'attachment_count': 3, 'direct_shares': [{}, {}]}],
            'roles': [{'enforcements': {'a': 1},
                       'managed_nodes': [{'privileges': ['p1', 'p2']}]}],
        }
        c = compute_counts(entities)
        self.assertEqual(c['nodes'], 2)
        self.assertEqual(c['attachments'], 3)
        self.assertEqual(c['direct_shares'], 2)
        self.assertEqual(c['total_privileges'], 2)


class ScrapeTeamHsfUsersTests(unittest.TestCase):
    def test_returns_email_when_marker_present(self):
        text = (
            'Team Name: MIGTEST-Team\n'
            '   Active User(s): alice@example.com      (No Shared Folders)\n'
            '   Active User(s): bob@example.com\n'
            '   Active User(s): carol@example.com   (No Shared Folders)\n'
        )
        emails = scrape_team_hsf_users(text, 'MIGTEST-Team')
        self.assertEqual(emails, ['alice@example.com', 'carol@example.com'])

    def test_no_marker_returns_empty(self):
        text = 'Team Name: X\n   Active User(s): alice@example.com\n'
        self.assertEqual(scrape_team_hsf_users(text, 'X'), [])

    def test_empty_input(self):
        self.assertEqual(scrape_team_hsf_users('', 'X'), [])
        self.assertEqual(scrape_team_hsf_users(None, 'X'), [])


class BuildUserEntitiesWithHsfTests(unittest.TestCase):
    def test_hsf_map_populates_user_entry(self):
        ent = _enterprise_fixture()
        path_map = _build_node_path_map(ent)
        hsf = {'alice@x': {'MIGTEST-Team'}}
        out = build_user_entities(ent, None, path_map, prefix='', hsf_map=hsf)
        alice = next(u for u in out if u['email'] == 'alice@x')
        self.assertEqual(alice['hide_shared_folders_teams'], ['MIGTEST-Team'])

    def test_no_hsf_map_leaves_list_empty(self):
        ent = _enterprise_fixture()
        path_map = _build_node_path_map(ent)
        out = build_user_entities(ent, None, path_map, prefix='', hsf_map=None)
        alice = next(u for u in out if u['email'] == 'alice@x')
        self.assertEqual(alice['hide_shared_folders_teams'], [])


class BuildInventoryFromParamsIntegrationTests(unittest.TestCase):
    def test_full_inventory_layout(self):
        params = FakeParams(_enterprise_fixture())
        # skip_hsf_scrape to avoid actual Commander call in this fixture test
        inv = build_inventory_from_params(params, scope_node='MIGRATION-TEST-NODE',
                                           prefix='MIGTEST-', scrape_hsf=False)
        # Structural checks
        self.assertEqual(inv['scope_node'], 'MIGRATION-TEST-NODE')
        self.assertEqual(inv['prefix_filter'], 'MIGTEST-')
        self.assertEqual(inv['source_user'], 'admin@src')
        self.assertEqual(inv['source_root'], 'My company')
        # Teams/roles/SFs named with the prefix are captured
        self.assertEqual(inv['counts']['teams'], 1)
        self.assertEqual(inv['counts']['roles'], 1)
        self.assertEqual(inv['counts']['shared_folders'], 1)
        # With prefix=MIGTEST-, nodes whose names don't start with MIGTEST- are
        # excluded (same behavior as the bash reference's keep() filter).
        self.assertEqual(inv['counts']['nodes'], 0)

    def test_scope_without_prefix_keeps_all_subtree_nodes(self):
        params = FakeParams(_enterprise_fixture())
        inv = build_inventory_from_params(params, scope_node='MIGRATION-TEST-NODE',
                                           scrape_hsf=False)
        # Both MIGRATION-TEST-NODE and Isolated-Sub are under scope
        self.assertEqual(inv['counts']['nodes'], 2)

    def test_empty_enterprise_still_produces_shape(self):
        params = FakeParams({})
        inv = build_inventory_from_params(params, scrape_hsf=False)
        self.assertEqual(inv['counts']['nodes'], 0)
        self.assertIn('entities', inv)


class _FakeFolder:
    """Minimal stand-in for keepercommander.subfolder.*FolderNode — the
    enumerator only reads .name, .type, .parent_uid, .shared_folder_uid."""
    def __init__(self, uid, name, ftype, parent_uid='', shared_folder_uid=''):
        self.uid = uid
        self.name = name
        self.type = ftype
        self.parent_uid = parent_uid
        self.shared_folder_uid = shared_folder_uid


class _FakeParamsWithFolders:
    def __init__(self, folder_cache):
        self.folder_cache = folder_cache


def _rebuilt_source_fixture():
    """Mirrors the 2026-04-20 source scaffold captured live:

      MIGRATION-TEST-NODE/                     (user_folder, top-level)
        MIGTEST-Parent-Folder/                 (user_folder)
          MIGTEST-SF-Nested                    (shared_folder)
        MIGTEST-SF-Root                        (shared_folder)
          MIGTEST-Subfolder-A                  (shared_folder_folder)
          MIGTEST-Subfolder-B                  (shared_folder_folder)
        MIGTEST-SF-With/Slash                  (shared_folder)

    Real UIDs shortened for readability but kept unique.
    """
    cache = {
        'ROOT-NODE-UID': _FakeFolder('ROOT-NODE-UID', 'MIGRATION-TEST-NODE',
                                      'user_folder', parent_uid=''),
        'PARENT-UID': _FakeFolder('PARENT-UID', 'MIGTEST-Parent-Folder',
                                   'user_folder', parent_uid='ROOT-NODE-UID'),
        'SF-NESTED-UID': _FakeFolder('SF-NESTED-UID', 'MIGTEST-SF-Nested',
                                      'shared_folder', parent_uid='PARENT-UID'),
        'SF-ROOT-UID': _FakeFolder('SF-ROOT-UID', 'MIGTEST-SF-Root',
                                    'shared_folder', parent_uid='ROOT-NODE-UID'),
        'SUB-A-UID': _FakeFolder('SUB-A-UID', 'MIGTEST-Subfolder-A',
                                  'shared_folder_folder',
                                  parent_uid='SF-ROOT-UID',
                                  shared_folder_uid='SF-ROOT-UID'),
        'SUB-B-UID': _FakeFolder('SUB-B-UID', 'MIGTEST-Subfolder-B',
                                  'shared_folder_folder',
                                  parent_uid='SF-ROOT-UID',
                                  shared_folder_uid='SF-ROOT-UID'),
        'SF-SLASH-UID': _FakeFolder('SF-SLASH-UID', 'MIGTEST-SF-With/Slash',
                                     'shared_folder', parent_uid='ROOT-NODE-UID'),
        # Noise — unrelated folders NOT under the scope.
        'OTHER-UID': _FakeFolder('OTHER-UID', 'Work', 'user_folder',
                                   parent_uid=''),
        'OTHER-SF-UID': _FakeFolder('OTHER-SF-UID', 'MIGTEST-Stray',
                                     'shared_folder', parent_uid='OTHER-UID'),
    }
    return cache


class FolderParentChainTests(unittest.TestCase):
    def test_empty_chain_at_root(self):
        cache = {'A': _FakeFolder('A', 'A', 'user_folder', parent_uid='')}
        self.assertEqual(_folder_parent_chain(cache, 'A'), [])

    def test_walks_upward(self):
        cache = _rebuilt_source_fixture()
        chain = _folder_parent_chain(cache, 'SUB-A-UID')
        self.assertEqual(chain, ['SF-ROOT-UID', 'ROOT-NODE-UID'])

    def test_missing_uid_returns_empty(self):
        self.assertEqual(_folder_parent_chain({}, 'NO-SUCH'), [])

    def test_loop_guard(self):
        """Corrupt cache where A is its own ancestor should stop at 32
        hops instead of spinning forever."""
        loop = {'A': _FakeFolder('A', 'A', 'user_folder', parent_uid='A')}
        self.assertLessEqual(len(_folder_parent_chain(loop, 'A')), 32)


class ResolveScopeVaultRootTests(unittest.TestCase):
    def test_single_match_returns_uid(self):
        params = _FakeParamsWithFolders(_rebuilt_source_fixture())
        self.assertEqual(
            resolve_scope_vault_root(params, 'MIGRATION-TEST-NODE'),
            'ROOT-NODE-UID',
        )

    def test_empty_scope_returns_empty(self):
        params = _FakeParamsWithFolders(_rebuilt_source_fixture())
        self.assertEqual(resolve_scope_vault_root(params, ''), '')

    def test_no_match_returns_empty(self):
        params = _FakeParamsWithFolders(_rebuilt_source_fixture())
        self.assertEqual(
            resolve_scope_vault_root(params, 'NoSuchFolder'), '')

    def test_nested_folder_same_name_is_not_picked(self):
        """Only TOP-LEVEL user_folders count — a nested folder happening
        to share the name shouldn't hijack scope resolution."""
        cache = {
            'TOP': _FakeFolder('TOP', 'Work', 'user_folder', parent_uid=''),
            'NESTED': _FakeFolder('NESTED', 'MIGRATION-TEST-NODE',
                                    'user_folder', parent_uid='TOP'),
        }
        self.assertEqual(
            resolve_scope_vault_root(_FakeParamsWithFolders(cache),
                                      'MIGRATION-TEST-NODE'),
            '',
        )

    def test_shared_folder_with_matching_name_is_not_picked(self):
        cache = {
            'SF': _FakeFolder('SF', 'MIGRATION-TEST-NODE',
                               'shared_folder', parent_uid=''),
        }
        self.assertEqual(
            resolve_scope_vault_root(_FakeParamsWithFolders(cache),
                                      'MIGRATION-TEST-NODE'),
            '',
        )


class BuildVaultFolderEntitiesTests(unittest.TestCase):
    def _scoped(self, prefix='MIGTEST-'):
        params = _FakeParamsWithFolders(_rebuilt_source_fixture())
        return build_vault_folder_entities(
            params, prefix=prefix,
            scope_vault_root_uid='ROOT-NODE-UID',
        )

    def test_captures_all_six_under_scope(self):
        """Regression guard for the 2026-04-20 audit — source has 6
        MIGTEST-* vault folders + subfolders under MIGRATION-TEST-NODE
        that inventory USED to capture 0 of."""
        out = self._scoped()
        names = [e['name'] for e in out]
        expected = {
            'MIGTEST-Parent-Folder',      # user_folder
            'MIGTEST-SF-Nested',           # shared_folder (nested)
            'MIGTEST-SF-Root',             # shared_folder (top)
            'MIGTEST-Subfolder-A',         # shared_folder_folder
            'MIGTEST-Subfolder-B',         # shared_folder_folder
            'MIGTEST-SF-With/Slash',       # shared_folder (odd name)
        }
        self.assertEqual(set(names), expected)

    def test_parents_emit_before_children(self):
        out = self._scoped()
        positions = {e['name']: i for i, e in enumerate(out)}
        # Parent-Folder must come before SF-Nested (nested under it).
        self.assertLess(positions['MIGTEST-Parent-Folder'],
                        positions['MIGTEST-SF-Nested'])
        # SF-Root must come before both its subfolders.
        self.assertLess(positions['MIGTEST-SF-Root'],
                        positions['MIGTEST-Subfolder-A'])
        self.assertLess(positions['MIGTEST-SF-Root'],
                        positions['MIGTEST-Subfolder-B'])

    def test_scope_excludes_out_of_tree(self):
        """MIGTEST-Stray lives under Work/ (outside scope root) — must NOT
        appear even though the name matches the prefix."""
        out = self._scoped()
        names = [e['name'] for e in out]
        self.assertNotIn('MIGTEST-Stray', names)

    def test_types_preserved(self):
        out = self._scoped()
        by_name = {e['name']: e for e in out}
        self.assertEqual(by_name['MIGTEST-Parent-Folder']['type'], 'user_folder')
        self.assertEqual(by_name['MIGTEST-SF-Root']['type'], 'shared_folder')
        self.assertEqual(by_name['MIGTEST-Subfolder-A']['type'],
                         'shared_folder_folder')

    def test_subfolder_carries_shared_folder_uid(self):
        out = self._scoped()
        sub_a = next(e for e in out if e['name'] == 'MIGTEST-Subfolder-A')
        self.assertEqual(sub_a['shared_folder_uid'], 'SF-ROOT-UID')
        # Non-subfolder entries should NOT carry a shared_folder_uid key.
        parent_folder = next(e for e in out
                              if e['name'] == 'MIGTEST-Parent-Folder')
        self.assertNotIn('shared_folder_uid', parent_folder)

    def test_parent_chain_includes_ancestors(self):
        out = self._scoped()
        nested = next(e for e in out if e['name'] == 'MIGTEST-SF-Nested')
        self.assertEqual(nested['parent_uid'], 'PARENT-UID')
        self.assertEqual(nested['parent_chain'],
                         ['PARENT-UID', 'ROOT-NODE-UID'])

    def test_no_prefix_captures_everything_under_scope(self):
        params = _FakeParamsWithFolders(_rebuilt_source_fixture())
        out = build_vault_folder_entities(
            params, prefix='', scope_vault_root_uid='ROOT-NODE-UID',
        )
        self.assertEqual(len(out), 6)  # all 6 MIGTEST-* entries

    def test_no_scope_captures_prefixed_everywhere(self):
        """Without a scope root, every prefix-matching folder anywhere in
        the cache is included — including MIGTEST-Stray under Work/."""
        params = _FakeParamsWithFolders(_rebuilt_source_fixture())
        out = build_vault_folder_entities(params, prefix='MIGTEST-',
                                           scope_vault_root_uid='')
        names = [e['name'] for e in out]
        self.assertIn('MIGTEST-Stray', names)

    def test_empty_folder_cache_returns_empty(self):
        params = _FakeParamsWithFolders({})
        self.assertEqual(
            build_vault_folder_entities(params, prefix='MIGTEST-'),
            [],
        )

    def test_params_without_folder_cache_returns_empty(self):
        class _Bare:
            pass
        self.assertEqual(
            build_vault_folder_entities(_Bare(), prefix='MIGTEST-'),
            [],
        )


class _FakeParamsWithFoldersAndRecords:
    def __init__(self, folder_cache=None, shared_folder_cache=None,
                  subfolder_record_cache=None, enterprise=None):
        self.folder_cache = folder_cache or {}
        self.shared_folder_cache = shared_folder_cache or {}
        self.subfolder_record_cache = subfolder_record_cache or {}
        self.enterprise = enterprise or {}


class BuildRecordFolderMapTests(unittest.TestCase):
    def test_root_records(self):
        params = _FakeParamsWithFoldersAndRecords(
            subfolder_record_cache={'': {'REC-A', 'REC-B'}},
        )
        m = _build_record_folder_map(params)
        self.assertEqual(m['REC-A'], ('', 'root'))
        self.assertEqual(m['REC-B'], ('', 'root'))

    def test_user_folder_record(self):
        fc = {'UF-UID': _FakeFolder('UF-UID', 'Work', 'user_folder')}
        params = _FakeParamsWithFoldersAndRecords(
            folder_cache=fc,
            subfolder_record_cache={'UF-UID': {'REC-X'}},
        )
        self.assertEqual(_build_record_folder_map(params)['REC-X'],
                          ('UF-UID', 'user_folder'))

    def test_shared_folder_top_level_record(self):
        """Record directly in a shared folder (not in a subfolder)."""
        params = _FakeParamsWithFoldersAndRecords(
            shared_folder_cache={
                'SF-UID': {
                    'name': 'MIGTEST-SF-Root',
                    'records': [{'record_uid': 'REC-SF', 'can_edit': True}],
                },
            },
        )
        self.assertEqual(_build_record_folder_map(params)['REC-SF'],
                          ('SF-UID', 'shared_folder'))

    def test_shared_folder_subfolder_record(self):
        """Record in a shared-folder-subfolder: the SF.records entry
        carries folder_uid pointing at the subfolder."""
        params = _FakeParamsWithFoldersAndRecords(
            shared_folder_cache={
                'SF-UID': {
                    'name': 'MIGTEST-SF-Root',
                    'records': [
                        {'record_uid': 'REC-IN-SUB',
                         'folder_uid': 'SUB-A-UID'},
                    ],
                },
            },
        )
        self.assertEqual(_build_record_folder_map(params)['REC-IN-SUB'],
                          ('SUB-A-UID', 'shared_folder_folder'))

    def test_first_placement_wins(self):
        """A record reachable via multiple caches should pick the first
        encountered — subfolder_record_cache wins over shared_folder_cache
        for the duplicate."""
        params = _FakeParamsWithFoldersAndRecords(
            subfolder_record_cache={'': {'DUP'}},
            shared_folder_cache={
                'SF-UID': {
                    'name': 'MIGTEST-SF',
                    'records': [{'record_uid': 'DUP'}],
                },
            },
        )
        self.assertEqual(_build_record_folder_map(params)['DUP'],
                          ('', 'root'))


class FolderNamePathTests(unittest.TestCase):
    def test_empty_uid_returns_empty(self):
        self.assertEqual(_folder_name_path({}, ''), '')

    def test_builds_root_to_leaf_path(self):
        fc = _rebuilt_source_fixture()
        self.assertEqual(
            _folder_name_path(fc, 'SUB-A-UID'),
            'MIGRATION-TEST-NODE/MIGTEST-SF-Root/MIGTEST-Subfolder-A',
        )

    def test_missing_uid_returns_empty(self):
        self.assertEqual(_folder_name_path({}, 'NO-SUCH'), '')


class BuildSharedFolderEntitiesMergeTests(unittest.TestCase):
    def test_enterprise_only_is_unchanged(self):
        ent = {'shared_folders': [
            {'shared_folder_uid': 'ENT-SF-1', 'name': 'MIGTEST-Ent',
             'users': [], 'teams': [], 'records': []},
        ]}
        out = build_shared_folder_entities(ent, 'MIGTEST-')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['source'], 'enterprise')

    def test_vault_folders_merge_with_enterprise(self):
        ent = {'shared_folders': [
            {'shared_folder_uid': 'ENT-SF-1', 'name': 'MIGTEST-Ent',
             'users': [], 'teams': [], 'records': []},
        ]}
        vault_folders = [
            {'uid': 'SF-ROOT-UID', 'name': 'MIGTEST-SF-Root',
             'type': 'shared_folder', 'parent_uid': 'ROOT-NODE-UID',
             'parent_chain': ['ROOT-NODE-UID']},
        ]
        params = _FakeParamsWithFoldersAndRecords(
            shared_folder_cache={
                'SF-ROOT-UID': {
                    'name': 'MIGTEST-SF-Root',
                    'default_can_edit': True,
                    'default_can_share': False,
                    'users': [{'username': 'a@x', 'can_edit': True,
                                'can_share': False,
                                'manage_users': False,
                                'manage_records': False}],
                    'teams': [{'name': 'MIGTEST-Team',
                                'manage_users': True,
                                'manage_records': True}],
                    'records': [{'record_uid': 'REC-X'}],
                },
            },
        )
        out = build_shared_folder_entities(
            ent, 'MIGTEST-', params=params, vault_folders=vault_folders,
        )
        self.assertEqual(len(out), 2)
        sources = {e['source'] for e in out}
        self.assertEqual(sources, {'enterprise', 'vault'})
        vault_entry = next(e for e in out if e['source'] == 'vault')
        self.assertEqual(vault_entry['uid'], 'SF-ROOT-UID')
        self.assertTrue(vault_entry['default_can_edit'])
        self.assertFalse(vault_entry['default_can_share'])
        self.assertEqual(vault_entry['parent_uid'], 'ROOT-NODE-UID')
        self.assertEqual(vault_entry['parent_chain'], ['ROOT-NODE-UID'])
        self.assertEqual(vault_entry['users'][0]['username'], 'a@x')
        self.assertEqual(vault_entry['teams'][0]['name'], 'MIGTEST-Team')
        self.assertEqual(len(vault_entry['records']), 1)

    def test_uid_collision_enterprise_wins(self):
        """If the admin has a shared folder that is ALSO on the enterprise
        SF list, enterprise's entry wins — one entry out, not two."""
        ent = {'shared_folders': [
            {'shared_folder_uid': 'SAME-UID', 'name': 'MIGTEST-X',
             'default_can_edit': True,
             'users': [], 'teams': [], 'records': []},
        ]}
        vault_folders = [
            {'uid': 'SAME-UID', 'name': 'MIGTEST-X',
             'type': 'shared_folder', 'parent_uid': '',
             'parent_chain': []},
        ]
        params = _FakeParamsWithFoldersAndRecords(
            shared_folder_cache={'SAME-UID': {'name': 'MIGTEST-X'}},
        )
        out = build_shared_folder_entities(
            ent, 'MIGTEST-', params=params, vault_folders=vault_folders,
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['source'], 'enterprise')
        self.assertTrue(out[0]['default_can_edit'])

    def test_vault_folder_missing_from_sf_cache_still_emits_skeleton(self):
        """Admin access revoked — folder_cache has the SF but
        shared_folder_cache doesn't. Should emit a minimal entry so the
        hierarchy is preserved and downstream code can skip destructive
        work cleanly."""
        vault_folders = [
            {'uid': 'ORPHAN-UID', 'name': 'MIGTEST-Orphan',
             'type': 'shared_folder', 'parent_uid': '',
             'parent_chain': []},
        ]
        params = _FakeParamsWithFoldersAndRecords(shared_folder_cache={})
        out = build_shared_folder_entities(
            {}, 'MIGTEST-', params=params, vault_folders=vault_folders,
        )
        self.assertEqual(len(out), 1)
        entry = out[0]
        self.assertEqual(entry['source'], 'vault')
        self.assertEqual(entry['uid'], 'ORPHAN-UID')
        self.assertEqual(entry['name'], 'MIGTEST-Orphan')
        self.assertEqual(entry['users'], [])
        self.assertEqual(entry['teams'], [])
        self.assertEqual(entry['records'], [])

    def test_prefix_filter_applies_to_vault_sfs(self):
        vault_folders = [
            {'uid': 'A', 'name': 'MIGTEST-A', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': 'B', 'name': 'Work', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
        ]
        params = _FakeParamsWithFoldersAndRecords(
            shared_folder_cache={
                'A': {'name': 'MIGTEST-A'},
                'B': {'name': 'Work'},
            },
        )
        out = build_shared_folder_entities(
            {}, 'MIGTEST-', params=params, vault_folders=vault_folders,
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['name'], 'MIGTEST-A')

    def test_non_shared_folder_vault_entries_skipped(self):
        """Only shared_folder type merges; user_folder + shared_folder_folder
        live in vault_folders but are structural, not SFs themselves."""
        vault_folders = [
            {'uid': 'UF', 'name': 'MIGTEST-Parent', 'type': 'user_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': 'SUB', 'name': 'MIGTEST-Sub',
             'type': 'shared_folder_folder',
             'parent_uid': '', 'parent_chain': [],
             'shared_folder_uid': 'SF-1'},
        ]
        params = _FakeParamsWithFoldersAndRecords()
        out = build_shared_folder_entities(
            {}, 'MIGTEST-', params=params, vault_folders=vault_folders,
        )
        self.assertEqual(out, [])

    def test_sf_records_strip_crypto_material(self):
        """Regression guard for the 2026-04-20 full-tenant run: plan
        FAILED with 'Object of type bytes is not JSON serializable' when
        admin-owned SFs carried record_key_unencrypted byte blobs. The
        merge must strip any field not on the safe allowlist — record
        keys, raw blobs, SDK-internal state all stay out of inventory."""
        vault_folders = [
            {'uid': 'SF-UID', 'name': 'MIGTEST-SF',
             'type': 'shared_folder', 'parent_uid': '',
             'parent_chain': []},
        ]
        params = _FakeParamsWithFoldersAndRecords(
            shared_folder_cache={
                'SF-UID': {
                    'name': 'MIGTEST-SF',
                    'records': [
                        {
                            'record_uid': 'REC-A',
                            'can_edit': True,
                            'can_share': False,
                            'folder_uid': 'SUB-UID',
                            # Crypto material — MUST be stripped.
                            'record_key_unencrypted': b'\xa1\x7b\x16\x9e',
                            # SDK internal state.
                            'revision': 12345,
                            'data': b'encrypted blob',
                        },
                    ],
                },
            },
        )
        out = build_shared_folder_entities(
            {}, 'MIGTEST-', params=params, vault_folders=vault_folders,
        )
        self.assertEqual(len(out), 1)
        recs = out[0]['records']
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r['record_uid'], 'REC-A')
        self.assertTrue(r['can_edit'])
        self.assertFalse(r['can_share'])
        self.assertEqual(r['folder_uid'], 'SUB-UID')
        # Crypto/raw blobs stripped.
        self.assertNotIn('record_key_unencrypted', r)
        self.assertNotIn('revision', r)
        self.assertNotIn('data', r)
        # Serializable end-to-end.
        json.dumps(out)

    def test_sf_records_drop_entries_without_uid(self):
        """Anything that doesn't carry a record_uid (malformed SF
        membership) gets dropped silently — we can't migrate a pointer
        we can't name."""
        vault_folders = [
            {'uid': 'SF-UID', 'name': 'MIGTEST-SF',
             'type': 'shared_folder', 'parent_uid': '', 'parent_chain': []},
        ]
        params = _FakeParamsWithFoldersAndRecords(
            shared_folder_cache={
                'SF-UID': {
                    'name': 'MIGTEST-SF',
                    'records': [
                        {'can_edit': True},            # no record_uid
                        {'record_uid': ''},            # empty record_uid
                        {'record_uid': 'REC-OK'},      # keeper
                    ],
                },
            },
        )
        out = build_shared_folder_entities(
            {}, 'MIGTEST-', params=params, vault_folders=vault_folders,
        )
        recs = out[0]['records']
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]['record_uid'], 'REC-OK')

    def test_no_params_preserves_legacy_behavior(self):
        """Callers that omit params+vault_folders get enterprise-only."""
        ent = {'shared_folders': [
            {'shared_folder_uid': 'E1', 'name': 'MIGTEST-Ent',
             'users': [], 'teams': [], 'records': []},
        ]}
        out = build_shared_folder_entities(ent, 'MIGTEST-')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['source'], 'enterprise')


class WriteInventoryTests(unittest.TestCase):
    def test_writes_json_and_sha256(self):
        tmp = tempfile.mkdtemp()
        try:
            out = os.path.join(tmp, 'inv.json')
            inv = build_inventory_from_params(FakeParams(_enterprise_fixture()),
                                               scrape_hsf=False)
            checksum = write_inventory(inv, out)
            self.assertEqual(len(checksum), 64)
            self.assertTrue(os.path.exists(out + '.sha256'))
            with open(out) as f:
                data = json.load(f)
            self.assertEqual(data['source_root'], 'My company')
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
