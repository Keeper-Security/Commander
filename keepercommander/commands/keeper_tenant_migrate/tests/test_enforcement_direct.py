import unittest

from keepercommander.commands.keeper_tenant_migrate.enforcement_direct import (
    _build_request,
    _existing_enforcement,
    is_cli_unsupported,
    partition_enforcements,
    resolve_role_id,
    set_enforcement,
    set_role_enforcements_direct,
)


class _FakeParams:
    def __init__(self, enterprise=None):
        self.enterprise = enterprise or {}


def _ent_with_role(role_id=42, name='MIGTEST-Admin', enforcements=None):
    ent = {
        'roles': [
            {'role_id': role_id, 'data': {'displayname': name}},
        ],
    }
    if enforcements is not None:
        ent['role_enforcements'] = [{
            'role_id': role_id, 'enforcements': enforcements,
        }]
    return ent


class IsCliUnsupportedTests(unittest.TestCase):
    def test_known_boolean_is_supported(self):
        # require_two_factor is a 'boolean' — supported by CLI
        self.assertFalse(is_cli_unsupported('require_two_factor'))

    def test_unknown_key_is_unsupported(self):
        self.assertTrue(is_cli_unsupported('some_brand_new_enforcement_xyz'))


class ResolveRoleIdTests(unittest.TestCase):
    def test_by_displayname_case_insensitive(self):
        params = _FakeParams(_ent_with_role())
        self.assertEqual(resolve_role_id(params, 'migtest-admin'), 42)

    def test_by_numeric_id(self):
        params = _FakeParams(_ent_with_role())
        self.assertEqual(resolve_role_id(params, '42'), 42)

    def test_not_found_returns_none(self):
        params = _FakeParams(_ent_with_role())
        self.assertIsNone(resolve_role_id(params, 'Nonexistent'))


class BuildRequestTests(unittest.TestCase):
    def test_add_for_new_simple_value(self):
        rq = _build_request(42, 'some_key', 'val', existing=None)
        self.assertEqual(rq['command'], 'role_enforcement_add')
        self.assertEqual(rq['value'], 'val')

    def test_update_when_existing(self):
        rq = _build_request(42, 'some_key', 'val', existing='old')
        self.assertEqual(rq['command'], 'role_enforcement_update')

    def test_true_boolean_marshals_value_as_python_bool(self):
        """Bug 48 (v1.5.5): match Commander's BULK path
        (`enterprise.py:2799-2817`) which sends Python bool `True`,
        not string `'true'`. The v1.5.3 fix sent string and live
        rehearsal-7 still rejected with `value=null` for
        ALLOW_CAN_EDIT_EXTERNAL_SHARES — the SDK serializes Python
        bools to JSON `true`/`false`, which is what valueType=BOOLEAN
        expects on the wire."""
        rq = _build_request(42, 'flag', True, existing=None)
        self.assertEqual(rq['command'], 'role_enforcement_add')
        self.assertEqual(rq['value'], True)
        self.assertIsInstance(rq['value'], bool)

    def test_true_boolean_uses_update_when_existing(self):
        """Bug 48: same value contract on update path."""
        rq = _build_request(42, 'flag', True, existing='already')
        self.assertEqual(rq['command'], 'role_enforcement_update')
        self.assertEqual(rq['value'], True)
        self.assertIsInstance(rq['value'], bool)

    def test_false_boolean_uses_remove(self):
        rq = _build_request(42, 'flag', False, existing='on')
        self.assertEqual(rq['command'], 'role_enforcement_remove')

    def test_dict_value_json_encoded(self):
        rq = _build_request(42, 'cfg', {'k': 1}, existing=None)
        self.assertEqual(rq['value'], '{"k": 1}')

    def test_list_value_json_encoded(self):
        rq = _build_request(42, 'ips', [{'ip': '10.0.0.0/8'}], existing=None)
        self.assertIn('"ip"', rq['value'])


class ExistingEnforcementTests(unittest.TestCase):
    def test_returns_current_value(self):
        params = _FakeParams(_ent_with_role(enforcements={'k': 'v'}))
        self.assertEqual(_existing_enforcement(params, 42, 'k'), 'v')

    def test_returns_none_for_missing_role(self):
        params = _FakeParams()
        self.assertIsNone(_existing_enforcement(params, 42, 'k'))


class SetEnforcementTests(unittest.TestCase):
    def test_success_path(self):
        calls = []

        def fake_communicate(params, rq):
            calls.append(rq)
            return {'result': 'success'}

        params = _FakeParams(_ent_with_role())
        ok, msg = set_enforcement(params, 42, 'k', 'v',
                                   communicator=fake_communicate)
        self.assertTrue(ok)
        self.assertEqual(msg, 'OK')
        self.assertEqual(calls[0]['role_id'], 42)

    def test_server_failure_reports_message(self):
        def fake_communicate(params, rq):
            return {'result': 'fail', 'message': 'bad value'}

        ok, msg = set_enforcement(_FakeParams(_ent_with_role()), 42, 'k', 'v',
                                   communicator=fake_communicate)
        self.assertFalse(ok)
        self.assertEqual(msg, 'bad value')

    def test_exception_wrapped(self):
        def fake_communicate(params, rq):
            raise RuntimeError('network dead')

        ok, msg = set_enforcement(_FakeParams(_ent_with_role()), 42, 'k', 'v',
                                   communicator=fake_communicate)
        self.assertFalse(ok)
        self.assertIn('network dead', msg)


class SetRoleEnforcementsDirectTests(unittest.TestCase):
    def test_batch_apply_all(self):
        called = []

        def fake_communicate(params, rq):
            called.append(rq['enforcement'])
            return {'result': 'success'}

        params = _FakeParams(_ent_with_role())
        results = set_role_enforcements_direct(
            params, 'MIGTEST-Admin',
            {'k1': 'v1', 'k2': [{'a': 1}]},
            communicator=fake_communicate,
        )
        self.assertEqual(set(results.keys()), {'k1', 'k2'})
        for (ok, _msg) in results.values():
            self.assertTrue(ok)
        self.assertEqual(sorted(called), ['k1', 'k2'])

    def test_unknown_role_fails_all_entries(self):
        results = set_role_enforcements_direct(
            _FakeParams(_ent_with_role()), 'Ghost',
            {'k1': 'v'},
        )
        ok, msg = results['k1']
        self.assertFalse(ok)
        self.assertIn('not found', msg)


class PartitionEnforcementsTests(unittest.TestCase):
    def test_splits_cli_vs_direct(self):
        # require_two_factor is 'boolean' (CLI-supported).
        # an unknown key should go to direct-API bucket.
        enfs = {
            'require_two_factor': True,
            'brand_new_unknown_key': 'x',
        }
        cli, direct = partition_enforcements(enfs)
        self.assertIn('require_two_factor', cli)
        self.assertIn('brand_new_unknown_key', direct)


if __name__ == '__main__':
    unittest.main()
