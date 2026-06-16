import datetime
import time
import types
import unittest

from keepercommander.mcp import capabilities as caps_module
from keepercommander.mcp import config as config_module
from keepercommander.mcp import guardrails
from keepercommander.mcp import server as server_module
from keepercommander.mcp import tools as tools_module
from keepercommander.mcp.config import CapabilityGrant, MCPClient, MCPConfig, hash_token
from keepercommander.mcp.guardrails import MCPAccessError


def _client(token='tok', name='agent', expiration=None, revoked=False, grants=None):
    return MCPClient(
        client_id='cid-' + name,
        name=name,
        token_hash=hash_token(token),
        created=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        expiration=expiration,
        revoked=revoked,
        grants=grants,
    )


class TestTokenValidation(unittest.TestCase):
    def test_valid_token_matches(self):
        cfg = MCPConfig(enabled=True, clients=[_client('secret-token')])
        self.assertIsNotNone(cfg.validate_token('secret-token'))

    def test_wrong_token_rejected(self):
        cfg = MCPConfig(enabled=True, clients=[_client('secret-token')])
        self.assertIsNone(cfg.validate_token('nope'))
        self.assertIsNone(cfg.validate_token(''))

    def test_revoked_token_rejected(self):
        cfg = MCPConfig(enabled=True, clients=[_client('t', revoked=True)])
        self.assertIsNone(cfg.validate_token('t'))

    def test_expired_token_rejected(self):
        past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat()
        cfg = MCPConfig(enabled=True, clients=[_client('t', expiration=past)])
        self.assertIsNone(cfg.validate_token('t'))

    def test_future_expiration_accepted(self):
        future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
        cfg = MCPConfig(enabled=True, clients=[_client('t', expiration=future)])
        self.assertIsNotNone(cfg.validate_token('t'))


class TestCapabilityGating(unittest.TestCase):
    def test_only_enabled_capabilities_effective(self):
        cfg = MCPConfig(
            enabled=True,
            capabilities={
                'read_secret': CapabilityGrant(enabled=True),
                'pam_rotate': CapabilityGrant(enabled=False),
            },
            clients=[_client()],
        )
        eff = cfg.effective_capabilities(cfg.clients[0])
        self.assertIn('read_secret', eff)
        self.assertNotIn('pam_rotate', eff)

    def test_per_client_grant_subset(self):
        cfg = MCPConfig(
            enabled=True,
            capabilities={
                'read_secret': CapabilityGrant(enabled=True),
                'search_records': CapabilityGrant(enabled=True),
            },
            clients=[_client(grants=['read_secret'])],
        )
        eff = cfg.effective_capabilities(cfg.clients[0])
        self.assertEqual({'read_secret'}, set(eff.keys()))


class TestRoundTrip(unittest.TestCase):
    def test_json_round_trip(self):
        cfg = MCPConfig(
            enabled=True,
            capabilities={'read_secret': CapabilityGrant(enabled=True, scope={'folders': ['f1']})},
            clients=[_client('t', grants=['read_secret'])],
        )
        restored = MCPConfig.from_json(cfg.to_json())
        self.assertTrue(restored.enabled)
        self.assertTrue(restored.capabilities['read_secret'].enabled)
        self.assertEqual(['f1'], restored.capabilities['read_secret'].scope['folders'])
        self.assertEqual('read_secret', restored.clients[0].grants[0])


def _fake_params(record_to_folder):
    """Build a minimal params with folder/record caches for scope tests.

    record_to_folder: dict mapping folder_uid -> set(record_uids). Folder hierarchy is flat.
    """
    params = types.SimpleNamespace()
    params.subfolder_record_cache = {k: set(v) for k, v in record_to_folder.items()}
    # Flat folder cache (no nesting): each folder has no subfolders.
    params.folder_cache = {fuid: types.SimpleNamespace(uid=fuid, subfolders=[]) for fuid in record_to_folder}
    params.record_cache = {}
    return params


class TestScopeEnforcement(unittest.TestCase):
    def test_unscoped_allows_all(self):
        params = _fake_params({'fA': {'r1'}})
        grant = CapabilityGrant(enabled=True)  # empty scope
        self.assertTrue(guardrails.record_in_scope(params, grant, 'anything'))

    def test_record_inside_allowed_folder(self):
        params = _fake_params({'fA': {'r1', 'r2'}, 'fB': {'r3'}})
        grant = CapabilityGrant(enabled=True, scope={'folders': ['fA']})
        self.assertTrue(guardrails.record_in_scope(params, grant, 'r1'))
        self.assertFalse(guardrails.record_in_scope(params, grant, 'r3'))

    def test_record_allowlist(self):
        params = _fake_params({'fA': {'r1'}})
        grant = CapabilityGrant(enabled=True, scope={'records': ['r9']})
        self.assertTrue(guardrails.record_in_scope(params, grant, 'r9'))
        self.assertFalse(guardrails.record_in_scope(params, grant, 'r1'))

    def test_nested_folder_descendant(self):
        params = types.SimpleNamespace()
        params.subfolder_record_cache = {'child': {'r1'}}
        params.folder_cache = {
            'parent': types.SimpleNamespace(uid='parent', subfolders=['child']),
            'child': types.SimpleNamespace(uid='child', subfolders=[]),
        }
        params.record_cache = {}
        grant = CapabilityGrant(enabled=True, scope={'folders': ['parent']})
        self.assertTrue(guardrails.record_in_scope(params, grant, 'r1'))

    def test_assert_raises_outside_scope(self):
        params = _fake_params({'fA': {'r1'}})
        grant = CapabilityGrant(enabled=True, scope={'folders': ['fA']})
        with self.assertRaises(MCPAccessError):
            guardrails.assert_record_in_scope(params, grant, 'r_other')


class TestSelfProtection(unittest.TestCase):
    def test_config_record_blocked(self):
        cfg = MCPConfig(enabled=True, config_record_uid='CFG')
        with self.assertRaises(MCPAccessError):
            guardrails.assert_not_config_record(cfg, 'CFG')

    def test_other_record_allowed(self):
        cfg = MCPConfig(enabled=True, config_record_uid='CFG')
        guardrails.assert_not_config_record(cfg, 'OTHER')  # no raise


class TestPamActionAvailability(unittest.TestCase):
    """exec/query target planned "pam action" verbs and must degrade cleanly until present."""

    def setUp(self):
        self._orig = tools_module._pam_action_verbs

    def tearDown(self):
        tools_module._pam_action_verbs = self._orig

    def test_exec_unavailable_until_verb_registered(self):
        tools_module._pam_action_verbs = lambda params: {'rotate'}
        grant = config_module.CapabilityGrant(enabled=True)
        with self.assertRaises(MCPAccessError):
            tools_module.pam_exec_command(None, MCPConfig(), grant, {'record_uid': 'u', 'command': 'ls'})

    def test_query_unavailable_until_verb_registered(self):
        tools_module._pam_action_verbs = lambda params: {'rotate'}
        grant = config_module.CapabilityGrant(enabled=True)
        with self.assertRaises(MCPAccessError):
            tools_module.pam_db_query(None, MCPConfig(), grant, {'record_uid': 'u', 'query': 'select 1'})

    def test_exec_blocks_config_record_before_availability(self):
        # Self-protection must trip even if the verb were available.
        tools_module._pam_action_verbs = lambda params: {'exec'}
        cfg = MCPConfig(config_record_uid='CFG')
        grant = config_module.CapabilityGrant(enabled=True)
        with self.assertRaises(MCPAccessError):
            tools_module.pam_exec_command(None, cfg, grant, {'record_uid': 'CFG', 'command': 'ls'})


class TestServerCall(unittest.TestCase):
    def setUp(self):
        # Register a temporary capability backed by a recording handler.
        self.calls = []

        def handler(params, config, grant, args):
            self.calls.append(args)
            return {'ok': True, 'echo': args}

        self.cap = caps_module.Capability(
            name='test_tool', title='Test', description='test', tool_name='test_tool',
            input_schema={'type': 'object', 'properties': {}}, handler=handler)
        caps_module.CAPABILITIES['test_tool'] = self.cap
        # Silence audit file writes.
        self._orig_audit = server_module.audit.record_tool_call
        server_module.audit.record_tool_call = lambda *a, **k: None

    def tearDown(self):
        caps_module.CAPABILITIES.pop('test_tool', None)
        server_module.audit.record_tool_call = self._orig_audit

    def _server(self, config):
        # Bypass vault loading by stubbing config load.
        srv = server_module.CommanderMCPServer.__new__(server_module.CommanderMCPServer)
        srv.params = None
        srv._token = 'tok'
        srv._refresh_ttl = 9999
        srv._last_refresh = time.monotonic()  # within TTL: _reload short-circuits, no vault read
        srv.config = config
        srv.client = config.validate_token('tok')
        return srv

    def test_allowed_call_dispatches(self):
        cfg = MCPConfig(enabled=True,
                        capabilities={'test_tool': CapabilityGrant(enabled=True)},
                        clients=[_client('tok')])
        srv = self._server(cfg)
        result = srv.call('test_tool', {'x': 1})
        self.assertEqual({'ok': True, 'echo': {'x': 1}}, result)

    def test_disabled_capability_denied(self):
        cfg = MCPConfig(enabled=True,
                        capabilities={'test_tool': CapabilityGrant(enabled=False)},
                        clients=[_client('tok')])
        srv = self._server(cfg)
        with self.assertRaises(MCPAccessError):
            srv.call('test_tool', {})

    def test_revoked_client_denied(self):
        cfg = MCPConfig(enabled=True,
                        capabilities={'test_tool': CapabilityGrant(enabled=True)},
                        clients=[_client('tok', revoked=True)])
        srv = self._server(cfg)
        with self.assertRaises(MCPAccessError):
            srv.call('test_tool', {})

    def test_master_disabled_denied(self):
        cfg = MCPConfig(enabled=False,
                        capabilities={'test_tool': CapabilityGrant(enabled=True)},
                        clients=[_client('tok')])
        srv = self._server(cfg)
        with self.assertRaises(MCPAccessError):
            srv.call('test_tool', {})


if __name__ == '__main__':
    unittest.main()
