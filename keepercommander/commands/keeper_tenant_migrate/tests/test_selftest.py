import unittest

from keepercommander.commands.keeper_tenant_migrate.selftest import (
    _check_commander_imports,
    _check_enterprise_loaded,
    _check_live_inventory,
    _check_parser_dests,
    _check_record_read,
    _check_session,
    _check_target_state_projection,
    run,
)


class _FakeParams:
    def __init__(self, user='admin@src', enterprise=None, record_cache=None):
        self.user = user
        self.enterprise = enterprise if enterprise is not None else {}
        self.record_cache = record_cache or {}
        self.server = 'https://keepersecurity.eu'


class IndividualCheckTests(unittest.TestCase):
    def test_session_fails_when_user_empty(self):
        self.assertEqual(_check_session(_FakeParams(user='')).status, 'FAIL')

    def test_session_passes_with_user(self):
        self.assertEqual(_check_session(_FakeParams(user='a@x')).status, 'PASS')

    def test_enterprise_loaded_fails_on_empty(self):
        self.assertEqual(_check_enterprise_loaded(_FakeParams()).status, 'FAIL')

    def test_enterprise_loaded_passes_with_data(self):
        params = _FakeParams(enterprise={'enterprise_name': 'Keeperdemo',
                                          'nodes': [{}, {}]})
        self.assertEqual(_check_enterprise_loaded(params).status, 'PASS')

    def test_commander_imports_pass(self):
        self.assertEqual(_check_commander_imports().status, 'PASS')

    def test_parser_dests_pass(self):
        self.assertEqual(_check_parser_dests().status, 'PASS')

    def test_live_inventory_skips_on_empty_tenant(self):
        params = _FakeParams(enterprise={'enterprise_name': 'Empty'})
        self.assertEqual(_check_live_inventory(params).status, 'SKIP')

    def test_live_inventory_passes_with_entities(self):
        params = _FakeParams(enterprise={
            'enterprise_name': 'X',
            'nodes': [{'node_id': 1, 'data': {'displayname': 'X'}}],
        })
        self.assertEqual(_check_live_inventory(params).status, 'PASS')

    def test_target_state_projection_skips_empty(self):
        self.assertEqual(_check_target_state_projection(_FakeParams()).status, 'SKIP')

    def test_record_read_skips_empty_cache(self):
        self.assertEqual(_check_record_read(_FakeParams()).status, 'SKIP')


class RunIntegrationTests(unittest.TestCase):
    def test_empty_tenant_is_mostly_skip_no_fail(self):
        params = _FakeParams(enterprise={'enterprise_name': 'Empty'})
        results, fails = run(params)
        self.assertEqual(fails, 0)
        statuses = [r.status for r in results]
        self.assertIn('PASS', statuses)  # session + commander_imports + parser_dests pass
        self.assertIn('SKIP', statuses)

    def test_unlogged_session_has_failures(self):
        params = _FakeParams(user='')
        results, fails = run(params)
        self.assertGreater(fails, 0)


class CheckReprTests(unittest.TestCase):
    def test_repr_includes_status_name_detail(self):
        from keepercommander.commands.keeper_tenant_migrate.selftest import Check
        r = repr(Check('session.user', 'PASS', 'jlima@example'))
        self.assertIn('PASS', r)
        self.assertIn('session.user', r)
        self.assertIn('jlima@example', r)
        self.assertNotIn('object at 0x', r)


class CheckParserDestsFailureTests(unittest.TestCase):
    def test_parser_dest_gap_returns_fail(self):
        """When an expected dest is missing on a parser, return FAIL with the gap."""
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import selftest

        # Build a fake parser whose `_actions` are missing the dests the
        # selftest expects. We monkeypatch ONE of the imported command
        # classes' get_parser() to return this stub parser so the FAIL
        # path exercises the missing-dests aggregation.
        class _Action:
            def __init__(self, dest):
                self.dest = dest

        class _Parser:
            def __init__(self):
                self._actions = [_Action('different')]

        class _StubCmd:
            def get_parser(self):
                return _Parser()

        # The real module imports inside `_check_parser_dests` — we patch
        # at the import site: keepercommander.commands.enterprise.EnterpriseNodeCommand
        with patch('keepercommander.commands.enterprise.EnterpriseNodeCommand',
                   _StubCmd):
            result = selftest._check_parser_dests()
        self.assertEqual(result.status, 'FAIL')
        # Detail string lists the missing dests for the swapped-in class.
        self.assertIn('add', result.detail)
        self.assertIn('node', result.detail)


class LiveInventoryExceptionTests(unittest.TestCase):
    def test_exception_inside_inventory_returns_fail(self):
        """When build_inventory_from_params raises, return FAIL with repr."""
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import selftest
        with patch('keepercommander.commands.keeper_tenant_migrate.live_inventory.'
                    'build_inventory_from_params',
                    side_effect=RuntimeError('boom')):
            result = selftest._check_live_inventory(_FakeParams(
                enterprise={'enterprise_name': 'X'}))
        self.assertEqual(result.status, 'FAIL')
        self.assertIn('boom', result.detail)


class TargetStateProjectionTests(unittest.TestCase):
    def test_pass_when_state_has_data(self):
        """A non-empty enterprise structure triggers PASS with counts."""
        params = _FakeParams(enterprise={
            'enterprise_name': 'X',
            'nodes': [{'node_id': 1, 'data': {'displayname': 'X'}}],
            'teams': [{'team_uid': 't', 'name': 'T1', 'node_id': 1}],
        })
        result = _check_target_state_projection(params)
        self.assertEqual(result.status, 'PASS')
        self.assertIn('nodes=', result.detail)

    def test_exception_returns_fail(self):
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import selftest
        with patch('keepercommander.commands.keeper_tenant_migrate.commands.'
                    '_params_enterprise_to_target_state',
                    side_effect=RuntimeError('proj-explode')):
            result = selftest._check_target_state_projection(_FakeParams())
        self.assertEqual(result.status, 'FAIL')
        self.assertIn('proj-explode', result.detail)


class RecordReadTests(unittest.TestCase):
    def test_pass_when_share_client_returns_record(self):
        """Populated record_cache → exercises CommanderShareClient path."""
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import selftest

        class _StubShareClient:
            def __init__(self, *a, **kw):
                pass

            def get_record_json(self, uid):
                return {'title': 'Sample', 'type': 'login'}

        params = _FakeParams(record_cache={'uid-1': object()})
        with patch.object(selftest, '_check_record_read',
                            wraps=selftest._check_record_read):
            with patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.'
                        'CommanderShareClient', _StubShareClient):
                result = selftest._check_record_read(params)
        self.assertEqual(result.status, 'PASS')
        self.assertIn('Sample', result.detail)

    def test_fail_when_share_client_returns_none(self):
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import selftest

        class _NoneShareClient:
            def __init__(self, *a, **kw):
                pass

            def get_record_json(self, uid):
                return None

        params = _FakeParams(record_cache={'uid-1': object()})
        with patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.'
                    'CommanderShareClient', _NoneShareClient):
            result = selftest._check_record_read(params)
        self.assertEqual(result.status, 'FAIL')

    def test_exception_returns_fail(self):
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import selftest

        class _BoomShareClient:
            def __init__(self, *a, **kw):
                raise RuntimeError('client-init-blew-up')

        params = _FakeParams(record_cache={'uid-1': object()})
        with patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.'
                    'CommanderShareClient', _BoomShareClient):
            result = selftest._check_record_read(params)
        self.assertEqual(result.status, 'FAIL')
        self.assertIn('client-init-blew-up', result.detail)


class RunUncaughtExceptionTests(unittest.TestCase):
    def test_uncaught_exception_recorded_as_fail(self):
        """A check function that raises (rather than returning a Check)
        must still produce a FAIL result with `uncaught:` prefix."""
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import selftest

        # Replace the FIRST entry of CHECKS with a function that raises.
        boom_checks = [('booming', lambda _p: (_ for _ in ()).throw(
            RuntimeError('uncaught-go-boom')))]
        with patch.object(selftest, 'CHECKS', boom_checks):
            results, fails = selftest.run(_FakeParams())
        self.assertEqual(fails, 1)
        self.assertEqual(results[0].status, 'FAIL')
        self.assertIn('uncaught', results[0].detail)


if __name__ == '__main__':
    unittest.main()
