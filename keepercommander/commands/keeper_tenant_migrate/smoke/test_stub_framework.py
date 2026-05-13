"""Coverage for the stub framework itself.

Targets every public surface of `_stub.runtime`:
    StubCommander install + teardown
    parser_dests reflection
    StubAssertionError on unknown kwargs
    extra_strict_drift rejection path
    state mutators (node/team/role/user create + delete)
    seed_record helper
    register_unknown_kwarg / get_last_unknown_kwarg
"""

import unittest

from keepercommander.commands.enterprise import (
    EnterpriseNodeCommand, EnterpriseRoleCommand,
    EnterpriseTeamCommand, EnterpriseUserCommand,
)

from keepercommander.commands.keeper_tenant_migrate.smoke._stub import (
    StubAssertionError, StubCommander, build_smoke_params,
    register_unknown_kwarg,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import (
    _add_node, _delete_node, _delete_role, _delete_team, _delete_user,
    _fake_get_record, _find_node_id, _names, _parser_dests,
    get_last_unknown_kwarg, seed_record, writeable_run_dir,
)


class StubParserDestsTests(unittest.TestCase):
    """parser_dests resolves real argparse destinations for the SDK."""

    def test_enterprise_node_dests_present(self):
        d = _parser_dests(EnterpriseNodeCommand)
        # Pin the dests commander_clients depends on.
        for required in ('node', 'add', 'parent', 'force', 'delete',
                         'toggle_isolated'):
            self.assertIn(required, d, f'expected {required} in dests: {d}')

    def test_classes_with_no_parser_return_empty(self):
        class _Bare:
            pass

        self.assertEqual(_parser_dests(_Bare), set())


class BuildSmokeParamsTests(unittest.TestCase):
    """Smoke params expose the shape the plugin reads from KeeperParams."""

    def test_default_shape(self):
        p = build_smoke_params()
        self.assertEqual(p.enterprise['enterprise_name'], 'SmokeCo')
        # Two seed nodes: root + MIGRATION-TEST-NODE
        self.assertEqual(len(p.enterprise['nodes']), 2)
        # One admin + one pre-existing MIGTEST user.
        self.assertEqual(len(p.enterprise['users']), 2)
        self.assertEqual(p.record_cache, {})

    def test_custom_scope_and_prefix(self):
        p = build_smoke_params(scope_node='ANOTHER-NODE', prefix='AAA-')
        nodes = p.enterprise['nodes']
        self.assertEqual(nodes[1]['data']['displayname'], 'ANOTHER-NODE')
        # Pre-existing user uses the lowercase prefix.
        self.assertTrue(any('aaa-existing' in u['username']
                            for u in p.enterprise['users']))


class StubCommanderInstallTests(unittest.TestCase):
    """The stub patches Commander commands and accepts known kwargs."""

    def test_known_kwargs_accepted(self):
        params = build_smoke_params()
        with StubCommander() as stub:
            EnterpriseNodeCommand().execute(params, node=['child-1'],
                                             add=True, parent='SmokeCo',
                                             force=True)
            self.assertIn('EnterpriseNodeCommand', stub.recorder.names())
            # State-mutator should have folded the new node into params.
            names = [(n.get('data') or {}).get('displayname')
                     for n in params.enterprise['nodes']]
            self.assertIn('child-1', names)

    def test_unknown_kwarg_raises(self):
        params = build_smoke_params()
        with StubCommander():
            with self.assertRaises(StubAssertionError) as ctx:
                EnterpriseNodeCommand().execute(params,
                                                  node=['bad'], add=True,
                                                  not_a_real_kwarg=True)
            self.assertIn('not_a_real_kwarg', str(ctx.exception))

    def test_extra_strict_drift_path(self):
        params = build_smoke_params()
        # Drift force=True even though it's a real dest — simulates SDK
        # removing the kwarg in a future release.
        with StubCommander(extra_strict_drift={
                EnterpriseNodeCommand: {'force'}}) as stub:
            stub.register_drift(EnterpriseNodeCommand, 'force')   # idempotent
            with self.assertRaises(StubAssertionError) as ctx:
                EnterpriseNodeCommand().execute(params, node=['x'],
                                                 add=True, force=True)
            self.assertIn('force', str(ctx.exception))

    def test_recorder_captures_calls(self):
        params = build_smoke_params()
        with StubCommander() as stub:
            EnterpriseTeamCommand().execute(
                params, team=['MIGTEST-T1'], add=True, force=True,
                node='MIGRATION-TEST-NODE',
                restrict_share='on', restrict_edit='off', restrict_view='off')
            self.assertEqual(stub.recorder.names(),
                              ['EnterpriseTeamCommand'])
            kw = stub.recorder.kwargs_for('EnterpriseTeamCommand')[0]
            self.assertEqual(kw['team'], ['MIGTEST-T1'])
            stub.recorder.reset()
            self.assertEqual(stub.recorder.calls, [])


class StateMutatorTests(unittest.TestCase):
    """Each mutator folds kwargs into params.enterprise consistently."""

    def test_node_add_then_delete(self):
        p = build_smoke_params()
        with StubCommander():
            EnterpriseNodeCommand().execute(p, node=['Created-N'], add=True,
                                             parent='MIGRATION-TEST-NODE',
                                             force=True)
            names = [(n.get('data') or {}).get('displayname')
                     for n in p.enterprise['nodes']]
            self.assertIn('Created-N', names)
            EnterpriseNodeCommand().execute(p, node=['Created-N'],
                                             delete=True, force=True)
            names = [(n.get('data') or {}).get('displayname')
                     for n in p.enterprise['nodes']]
            self.assertNotIn('Created-N', names)

    def test_team_create_with_restrict_kwargs(self):
        p = build_smoke_params()
        with StubCommander():
            EnterpriseTeamCommand().execute(
                p, team=['T1'], add=True, force=True,
                node='MIGRATION-TEST-NODE',
                restrict_share='on', restrict_edit='off', restrict_view='off')
        team = p.enterprise['teams'][0]
        self.assertEqual(team['name'], 'T1')
        self.assertEqual(team['restrict_sharing'], 'on')   # bug-2 key

    def test_role_create_default_new_user(self):
        p = build_smoke_params()
        with StubCommander():
            EnterpriseRoleCommand().execute(p, role=['R1'], add=True,
                                              force=True,
                                              node='MIGRATION-TEST-NODE',
                                              new_user='on')
        role = p.enterprise['roles'][0]
        self.assertTrue(role['new_user_inherit'])          # bug-3 key

    def test_user_invite_then_lock_then_delete(self):
        p = build_smoke_params()
        email = 'migtest-bob@smokeco.example'
        with StubCommander():
            EnterpriseUserCommand().execute(p, email=[email], invite=True,
                                              displayname='Bob',
                                              node='MIGRATION-TEST-NODE',
                                              force=True)
            self.assertTrue(any(u['username'] == email
                                 for u in p.enterprise['users']))
            EnterpriseUserCommand().execute(p, email=[email], lock=True,
                                              force=True)
            user = next(u for u in p.enterprise['users']
                         if u['username'] == email)
            self.assertEqual(user['status'], 'locked')
            EnterpriseUserCommand().execute(p, email=[email], delete=True,
                                              force=True)
            self.assertFalse(any(u['username'] == email
                                  for u in p.enterprise['users']))

    def test_team_add_user_queues(self):
        p = build_smoke_params()
        with StubCommander():
            EnterpriseTeamCommand().execute(
                p, team=['Q-Team'], add_user=['migtest-q@smokeco.example'],
                force=True)
        self.assertEqual(p.enterprise['queued_team_users'][0]['team_name'],
                          'Q-Team')


class HelpersTests(unittest.TestCase):
    def test_names_handles_str_list_none(self):
        self.assertEqual(_names({'k': 'v'}, 'k'), ['v'])
        self.assertEqual(_names({'k': ['a', 'b']}, 'k'), ['a', 'b'])
        self.assertEqual(_names({}, 'k'), [])
        self.assertEqual(_names({'k': None}, 'k'), [])

    def test_find_node_id_with_unknown_returns_none(self):
        ent = {'nodes': [{'node_id': 7,
                          'data': {'displayname': 'Known'}}]}
        self.assertEqual(_find_node_id(ent, 'Known'), 7)
        self.assertIsNone(_find_node_id(ent, 'Unknown'))
        self.assertIsNone(_find_node_id(ent, ''))

    def test_seed_record_round_trip(self):
        p = build_smoke_params()
        seed_record(p, uid='UID-1', title='MIGTEST-X')
        self.assertIn('UID-1', p.record_cache)
        # data_unencrypted must be parseable back to a dict with the title.
        import json
        decoded = json.loads(p.record_cache['UID-1']['data_unencrypted'])
        self.assertEqual(decoded['title'], 'MIGTEST-X')
        self.assertEqual(decoded['type'], 'login')

    def test_seed_record_with_folders(self):
        p = build_smoke_params()
        seed_record(p, uid='UID-2', title='MIGTEST-Y',
                    folders=['Folder-A'])
        self.assertEqual(p.subfolder_record_cache['UID-2'], ['Folder-A'])

    def test_writeable_run_dir(self):
        d = writeable_run_dir('hello')
        import os
        try:
            self.assertTrue(os.path.isdir(d))
            self.assertIn('kcmd-smoke-hello-', d)
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def test_register_and_read_last_unknown(self):
        register_unknown_kwarg('Foo', {'a'}, {'b', 'c'})
        last = get_last_unknown_kwarg()
        self.assertEqual(last[0], 'Foo')
        self.assertEqual(last[1], {'a'})
        self.assertEqual(last[2], {'b', 'c'})


class MutatorDispatchTests(unittest.TestCase):
    """Hit the _default_mutator delete/add_user dispatch branches."""

    def test_team_delete_via_dispatch(self):
        p = build_smoke_params()
        p.enterprise['teams'].append({'name': 'X', 'node_id': 2})
        with StubCommander():
            EnterpriseTeamCommand().execute(p, team=['X'], delete=True,
                                              force=True)
        self.assertEqual(
            [t['name'] for t in p.enterprise['teams']], [])

    def test_role_delete_via_dispatch(self):
        p = build_smoke_params()
        p.enterprise['roles'].append({'role_id': 9,
                                       'data': {'displayname': 'R-X'}})
        with StubCommander():
            EnterpriseRoleCommand().execute(p, role=['R-X'], delete=True,
                                              force=True)
        self.assertEqual(p.enterprise['roles'], [])

    def test_role_add_with_no_names_is_safe(self):
        # Pass empty role list — exercises the `if not emails / names`
        # guard inside the mutators.
        p = build_smoke_params()
        # invite_user with empty email list runs no mutation.
        with StubCommander():
            EnterpriseUserCommand().execute(p, email=[], invite=True,
                                              displayname='', node='SmokeCo',
                                              force=True)
        # Pre-seeded users: 2 (admin + existing). No delta.
        self.assertEqual(len(p.enterprise['users']), 2)


class FakeGetRecordEdgeTests(unittest.TestCase):
    """Cover the rare branches in _fake_get_record."""

    def test_missing_uid_returns_none(self):
        p = build_smoke_params()
        self.assertIsNone(_fake_get_record(p, 'NO-SUCH-UID'))

    def test_corrupt_data_falls_back_to_empty_title(self):
        p = build_smoke_params()
        p.record_cache['UID-X'] = {
            'data_unencrypted': b'this is not json',
            'shares': {},
        }
        rec = _fake_get_record(p, 'UID-X')
        # Decode error → title falls back to ''.
        self.assertEqual(rec.title, '')

    def test_top_level_title_takes_precedence(self):
        p = build_smoke_params()
        p.record_cache['UID-T'] = {'title': 'Direct-Title',
                                    'data_unencrypted': b'{}',
                                    'shares': {}}
        rec = _fake_get_record(p, 'UID-T')
        self.assertEqual(rec.title, 'Direct-Title')


class MutatorEdgeTests(unittest.TestCase):
    """Branches the smoke tests don't naturally hit."""

    def test_add_node_implicit_parent(self):
        ent = {'nodes': [{'node_id': 1, 'data': {'displayname': 'Root'}}]}
        _add_node(ent, {'node': ['child'], 'parent': 'Unknown'})
        # parent was unknown → root used as fallback.
        self.assertEqual(ent['nodes'][1]['parent_id'], 1)

    def test_add_node_no_existing_nodes(self):
        ent = {'nodes': []}
        _add_node(ent, {'node': ['solo']})
        self.assertEqual(ent['nodes'][0]['node_id'], 1)

    def test_delete_node_with_no_target_is_noop(self):
        ent = {'nodes': [{'node_id': 1, 'data': {'displayname': 'X'}}]}
        before = list(ent['nodes'])
        _delete_node(ent, {'node': []})
        self.assertEqual(ent['nodes'], before)

    def test_delete_team_removes_match(self):
        ent = {'teams': [{'name': 'A'}, {'name': 'B'}]}
        _delete_team(ent, {'team': ['A']})
        self.assertEqual(ent['teams'], [{'name': 'B'}])

    def test_delete_role_uses_displayname_or_name_fallback(self):
        ent = {'roles': [
            {'role_id': 1, 'data': {'displayname': 'D'}},
            {'role_id': 2, 'name': 'N'},                  # no data dict
        ]}
        _delete_role(ent, {'role': ['D', 'N']})
        self.assertEqual(ent['roles'], [])

    def test_delete_role_keeps_unmatched_entries(self):
        ent = {'roles': [
            {'role_id': 1, 'data': {'displayname': 'KeepMe'}},
            {'role_id': 2, 'data': {'displayname': 'DropMe'}},
        ]}
        _delete_role(ent, {'role': ['DropMe']})
        self.assertEqual([r['data']['displayname'] for r in ent['roles']],
                          ['KeepMe'])

    def test_delete_user_case_insensitive(self):
        ent = {'users': [{'username': 'A@X.example'},
                         {'username': 'b@x.example'}]}
        _delete_user(ent, {'email': ['a@x.example']})
        self.assertEqual([u['username'] for u in ent['users']],
                          ['b@x.example'])


class StubCommanderBehaviorOverrideTests(unittest.TestCase):
    """Per-command behavior overrides let smoke tests simulate edge cases."""

    def test_behavior_runs_after_default_mutator(self):
        from keepercommander.commands.enterprise import EnterpriseNodeCommand
        observed = {}

        def behavior(params, kwargs):
            # Mutator already ran — params.enterprise has the new node.
            observed['nodes'] = len(params.enterprise['nodes'])

        params = build_smoke_params()
        with StubCommander(behaviors={EnterpriseNodeCommand: behavior}):
            EnterpriseNodeCommand().execute(
                params, node=['hooked'], add=True, parent='SmokeCo',
                force=True)
        # Two seed nodes + the new one.
        self.assertEqual(observed['nodes'], 3)

    def test_parser_dests_via_install_table(self):
        from keepercommander.commands.enterprise import EnterpriseTeamCommand
        with StubCommander() as stub:
            d = stub.parser_dests(EnterpriseTeamCommand)
            self.assertIn('team', d)
            # Unknown class returns an empty set.
            self.assertEqual(stub.parser_dests(int), set())


class ParserDestsErrorPathTests(unittest.TestCase):
    """Exercise the failure-mode path inside _parser_dests."""

    def test_class_with_failing_get_parser_returns_empty(self):
        class _Bad:
            def get_parser(self):
                raise RuntimeError('boom')

        self.assertEqual(_parser_dests(_Bad), set())

    def test_class_with_non_argparse_parser_returns_empty(self):
        class _Bad:
            def get_parser(self):
                return object()

        self.assertEqual(_parser_dests(_Bad), set())


if __name__ == '__main__':
    unittest.main()
