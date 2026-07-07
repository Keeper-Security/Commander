"""Comprehensive test suite for the Keeper Commander MCP server.

Covers every MCP tool and capability without a live/production account:

  * capability registry integrity (every capability wired to a real handler + schema)
  * read handlers exercised against a real in-memory vault (data_vault.get_synced_params)
  * mutating vault/KSM/PAM handlers verified by the exact Commander command they build
    (Commander execution is intercepted, so no network/gateway is required)
  * pam action exec/query run end-to-end through the registered stub commands
  * server-level tool dispatch + capability gating + client revocation/expiry
  * MCP config vault-record persistence round-trip (writes mocked)

The only "real service" seams are mocked here; see the module docstring in
test_mcp.py for the pure-unit coverage of config/guardrails/server internals.
"""

import datetime
import unittest
from unittest import mock

# data_vault builds a fully in-memory, synced KeeperParams (no network).
from data_vault import get_synced_params

# Importing cli once populates the global command registry, which the PAM
# availability guard (tools._pam_action_verbs) reads.
from keepercommander import cli  # noqa: F401
from keepercommander import vault_extensions
from keepercommander.mcp import capabilities as caps_module
from keepercommander.mcp import config as config_module
from keepercommander.mcp import tools as tools_module
from keepercommander.mcp.config import CapabilityGrant, MCPClient, MCPConfig, hash_token
from keepercommander.mcp.guardrails import MCPAccessError


def _grant(**kw):
    return CapabilityGrant(enabled=True, **kw)


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


class CommandCapture:
    """Context manager that intercepts tools.run_cli_command and records the command.

    Returns itself; ``.commands`` holds every command string issued, ``.last`` the most
    recent. The canned return value simulates Commander's textual output.
    """

    def __init__(self, return_value='OK'):
        self.commands = []
        self.return_value = return_value
        self._patch = None

    def __enter__(self):
        def fake_run(params, command):
            self.commands.append(command)
            return self.return_value
        self._patch = mock.patch.object(tools_module, 'run_cli_command', side_effect=fake_run)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        return False

    @property
    def last(self):
        return self.commands[-1] if self.commands else None


class MCPToolTestBase(unittest.TestCase):
    """Shares one synced in-memory vault and resolves the seeded record/folder UIDs."""

    @classmethod
    def setUpClass(cls):
        cls.params = get_synced_params()
        # Seeded by data_vault.generate_data(): Record 1/2/3 + one shared folder.
        by_title = {r.title: r.record_uid for r in vault_extensions.find_records(cls.params, None)}
        cls.rec1 = by_title['Record 1']   # PasswordRecord in the root folder
        cls.rec2 = by_title['Record 2']   # TypedRecord in the root folder
        cls.rec3 = by_title['Record 3']   # record inside the shared folder
        # Resolve the shared folder by type (root is keyed as '' in the record cache).
        cls.shared_folder_uid = next(
            uid for uid, node in cls.params.folder_cache.items() if node.type == 'shared_folder')


# ======================================================================================
# 1. Capability registry integrity — guards against a tool being added but left unwired.
# ======================================================================================
class TestCapabilityRegistry(unittest.TestCase):
    def test_every_capability_is_fully_wired(self):
        self.assertTrue(caps_module.CAPABILITIES, 'registry must not be empty')
        for name, cap in caps_module.CAPABILITIES.items():
            self.assertEqual(name, cap.name)
            # tool_name is what the MCP client sees; keep it aligned with the registry key.
            self.assertEqual(name, cap.tool_name, f'{name}: tool_name mismatch')
            self.assertTrue(callable(cap.handler), f'{name}: handler not callable')
            self.assertTrue(cap.description, f'{name}: missing description')
            schema = cap.input_schema
            self.assertEqual(schema.get('type'), 'object', f'{name}: schema must be object')
            props = schema.get('properties', {})
            self.assertIsInstance(props, dict)
            # Every "required" field must exist in properties.
            for req in schema.get('required', []):
                self.assertIn(req, props, f'{name}: required "{req}" not in properties')

    def test_handler_names_resolve_in_tools_module(self):
        for name, cap in caps_module.CAPABILITIES.items():
            self.assertTrue(hasattr(tools_module, cap.handler.__name__),
                            f'{name}: handler {cap.handler.__name__} not found in tools module')

    def test_expected_capability_set(self):
        # Locks the intended surface so removals/additions are deliberate.
        expected = {
            'search_records', 'read_secret', 'create_record', 'update_record',
            'share_record', 'share_folder', 'ksm_manage_app',
            'pam_rotate', 'pam_launch_session', 'pam_exec_command', 'pam_db_query',
        }
        self.assertEqual(expected, set(caps_module.CAPABILITIES.keys()))

    def test_pam_capabilities_flagged_high_risk(self):
        for name in ('pam_rotate', 'pam_launch_session', 'pam_exec_command', 'pam_db_query'):
            self.assertTrue(caps_module.get_capability(name).high_risk, f'{name} should be high-risk')


# ======================================================================================
# 2. Read handlers against the real in-memory vault.
# ======================================================================================
class TestReadHandlers(MCPToolTestBase):
    def test_search_returns_all_records(self):
        res = tools_module.search_records(self.params, MCPConfig(), _grant(), {})
        self.assertEqual(3, res['count'])
        titles = {r['title'] for r in res['records']}
        self.assertEqual({'Record 1', 'Record 2', 'Record 3'}, titles)

    def test_search_respects_limit(self):
        res = tools_module.search_records(self.params, MCPConfig(), _grant(), {'limit': 1})
        self.assertEqual(1, res['count'])

    def test_search_query_filters(self):
        # Distinctive term (Record 1's login) so we exercise the query path unambiguously.
        res = tools_module.search_records(self.params, MCPConfig(), _grant(),
                                          {'query': 'user1@keepersecurity.com'})
        self.assertEqual({'Record 1'}, {r['title'] for r in res['records']})

    def test_search_omits_config_record(self):
        cfg = MCPConfig(config_record_uid=self.rec2)
        res = tools_module.search_records(self.params, cfg, _grant(), {})
        uids = {r['uid'] for r in res['records']}
        self.assertNotIn(self.rec2, uids)
        self.assertEqual(2, res['count'])

    def test_search_scope_limits_to_folder(self):
        # Scope to the shared folder -> only Record 3 is visible.
        grant = _grant(scope={'folders': [self.shared_folder_uid]})
        res = tools_module.search_records(self.params, MCPConfig(), grant, {})
        self.assertEqual({'Record 3'}, {r['title'] for r in res['records']})

    def test_read_secret_by_title(self):
        res = tools_module.read_secret(self.params, MCPConfig(), _grant(), {'record': 'Record 1'})
        self.assertEqual(self.rec1, res['uid'])
        self.assertIn('(login)', res['fields'])
        self.assertIn('(password)', res['fields'])

    def test_read_secret_by_uid(self):
        res = tools_module.read_secret(self.params, MCPConfig(), _grant(), {'record': self.rec1})
        self.assertEqual('Record 1', res['title'])

    def test_read_secret_field_filter(self):
        res = tools_module.read_secret(self.params, MCPConfig(), _grant(),
                                       {'record': self.rec1, 'field': 'password'})
        self.assertTrue(all('password' in k.lower() for k in res['fields']))
        self.assertTrue(res['fields'])

    def test_read_secret_not_found(self):
        with self.assertRaises(MCPAccessError):
            tools_module.read_secret(self.params, MCPConfig(), _grant(), {'record': 'nope-xyz'})

    def test_read_secret_out_of_scope_denied(self):
        grant = _grant(scope={'folders': [self.shared_folder_uid]})  # rec1 is in root, not here
        with self.assertRaises(MCPAccessError):
            tools_module.read_secret(self.params, MCPConfig(), grant, {'record': self.rec1})

    def test_read_secret_config_record_denied(self):
        cfg = MCPConfig(config_record_uid=self.rec1)
        with self.assertRaises(MCPAccessError):
            tools_module.read_secret(self.params, cfg, _grant(), {'record': self.rec1})


# ======================================================================================
# 3. Vault mutation handlers — verify the exact Commander command that gets built.
# ======================================================================================
class TestVaultMutationHandlers(MCPToolTestBase):
    def test_create_record_minimal(self):
        with CommandCapture() as cap:
            tools_module.create_record(self.params, MCPConfig(), _grant(), {'title': 'New Login'})
        self.assertIn('record-add', cap.last)
        self.assertIn('New Login', cap.last)
        self.assertIn('--record-type=login', cap.last)

    def test_create_record_with_folder_type_notes_fields(self):
        grant = _grant(scope={'folders': [self.shared_folder_uid]})
        args = {
            'title': 'API Key', 'record_type': 'login', 'folder': self.shared_folder_uid,
            'notes': 'created by agent', 'fields': ['login=svc@x.com', 'password=s3cret'],
        }
        with CommandCapture() as cap:
            tools_module.create_record(self.params, MCPConfig(), grant, args)
        cmd = cap.last
        self.assertIn('--folder', cmd)
        self.assertIn(self.shared_folder_uid, cmd)
        self.assertIn('login=svc@x.com', cmd)
        self.assertIn('password=s3cret', cmd)

    def test_create_record_requires_title(self):
        with self.assertRaises(MCPAccessError):
            tools_module.create_record(self.params, MCPConfig(), _grant(), {})

    def test_create_record_folder_out_of_scope_denied(self):
        grant = _grant(scope={'folders': ['some-other-folder']})
        with self.assertRaises(MCPAccessError):
            tools_module.create_record(self.params, MCPConfig(), grant,
                                       {'title': 'x', 'folder': self.shared_folder_uid})

    def test_update_record_builds_command(self):
        with CommandCapture() as cap:
            tools_module.update_record(self.params, MCPConfig(), _grant(),
                                       {'record': self.rec1, 'notes': 'updated'})
        self.assertIn('record-update', cap.last)
        self.assertIn(self.rec1, cap.last)

    def test_update_record_not_found(self):
        with self.assertRaises(MCPAccessError):
            tools_module.update_record(self.params, MCPConfig(), _grant(), {'record': 'nope-xyz'})

    def test_update_record_config_record_denied(self):
        cfg = MCPConfig(config_record_uid=self.rec1)
        with self.assertRaises(MCPAccessError):
            tools_module.update_record(self.params, cfg, _grant(), {'record': self.rec1})

    def test_share_record_grant(self):
        with CommandCapture() as cap:
            tools_module.share_record(self.params, MCPConfig(), _grant(),
                                      {'record': self.rec1, 'email': 'peer@x.com', 'can_edit': True})
        cmd = cap.last
        self.assertIn('share-record', cmd)
        self.assertIn('peer@x.com', cmd)
        self.assertIn('--can-edit', cmd)

    def test_share_record_one_time(self):
        with CommandCapture() as cap:
            tools_module.share_record(self.params, MCPConfig(), _grant(),
                                      {'record': self.rec1, 'one_time': True, 'expire': '1d'})
        cmd = cap.last
        self.assertIn('one-time-share', cmd)
        self.assertIn('1d', cmd)

    def test_share_record_grant_requires_email(self):
        with self.assertRaises(MCPAccessError):
            tools_module.share_record(self.params, MCPConfig(), _grant(), {'record': self.rec1})

    def test_share_record_config_record_denied(self):
        cfg = MCPConfig(config_record_uid=self.rec1)
        with self.assertRaises(MCPAccessError):
            tools_module.share_record(self.params, cfg, _grant(),
                                      {'record': self.rec1, 'email': 'peer@x.com'})

    def test_share_folder_builds_command(self):
        with CommandCapture() as cap:
            tools_module.share_folder(self.params, MCPConfig(), _grant(),
                                      {'folder': self.shared_folder_uid, 'email': 'peer@x.com'})
        cmd = cap.last
        self.assertIn('share-folder', cmd)
        self.assertIn(self.shared_folder_uid, cmd)
        self.assertIn('peer@x.com', cmd)

    def test_share_folder_requires_folder(self):
        with self.assertRaises(MCPAccessError):
            tools_module.share_folder(self.params, MCPConfig(), _grant(), {})


# ======================================================================================
# 4. KSM handler — action routing.
# ======================================================================================
class TestKsmHandler(MCPToolTestBase):
    def test_app_create(self):
        with CommandCapture() as cap:
            tools_module.ksm_manage_app(self.params, MCPConfig(), _grant(),
                                        {'action': 'app-create', 'name': 'MyApp'})
        self.assertIn('secrets-manager app create', cap.last)
        self.assertIn('MyApp', cap.last)

    def test_client_add(self):
        with CommandCapture() as cap:
            tools_module.ksm_manage_app(self.params, MCPConfig(), _grant(),
                                        {'action': 'client-add', 'app': 'MyApp'})
        self.assertIn('secrets-manager client add', cap.last)
        self.assertIn('--app', cap.last)

    def test_share(self):
        with CommandCapture() as cap:
            tools_module.ksm_manage_app(self.params, MCPConfig(), _grant(),
                                        {'action': 'share', 'app': 'MyApp', 'secret': self.rec1})
        self.assertIn('secrets-manager share add', cap.last)
        self.assertIn(self.rec1, cap.last)

    def test_unknown_action(self):
        with self.assertRaises(MCPAccessError):
            tools_module.ksm_manage_app(self.params, MCPConfig(), _grant(), {'action': 'bogus'})

    def test_missing_required_args(self):
        with self.assertRaises(MCPAccessError):
            tools_module.ksm_manage_app(self.params, MCPConfig(), _grant(), {'action': 'app-create'})
        with self.assertRaises(MCPAccessError):
            tools_module.ksm_manage_app(self.params, MCPConfig(), _grant(),
                                        {'action': 'share', 'app': 'MyApp'})


# ======================================================================================
# 5. PAM command construction (rotate, launch) — verified by built command.
# ======================================================================================
class TestPamCommandBuilding(MCPToolTestBase):
    def test_rotate_basic(self):
        with CommandCapture() as cap:
            tools_module.pam_rotate(self.params, MCPConfig(), _grant(), {'record_uid': 'PAMREC'})
        self.assertIn('pam action rotate', cap.last)
        self.assertIn('PAMREC', cap.last)
        self.assertNotIn('--dry-run', cap.last)

    def test_rotate_dry_run_from_arg(self):
        with CommandCapture() as cap:
            tools_module.pam_rotate(self.params, MCPConfig(), _grant(),
                                    {'record_uid': 'PAMREC', 'dry_run': True})
        self.assertIn('--dry-run', cap.last)

    def test_rotate_dry_run_forced_by_guardrail(self):
        grant = _grant(guardrails={'dry_run_only': True})
        with CommandCapture() as cap:
            tools_module.pam_rotate(self.params, MCPConfig(), grant, {'record_uid': 'PAMREC'})
        self.assertIn('--dry-run', cap.last)

    def test_rotate_requires_record(self):
        with self.assertRaises(MCPAccessError):
            tools_module.pam_rotate(self.params, MCPConfig(), _grant(), {})

    def test_rotate_config_record_denied(self):
        cfg = MCPConfig(config_record_uid='PAMREC')
        with self.assertRaises(MCPAccessError):
            tools_module.pam_rotate(self.params, cfg, _grant(), {'record_uid': 'PAMREC'})

    def test_launch_session_basic(self):
        with CommandCapture() as cap:
            tools_module.pam_launch_session(self.params, MCPConfig(), _grant(), {'record_uid': 'PAMREC'})
        self.assertIn('pam tunnel start', cap.last)
        self.assertIn('PAMREC', cap.last)

    def test_launch_session_with_workflow(self):
        with CommandCapture() as cap:
            tools_module.pam_launch_session(self.params, MCPConfig(), _grant(),
                                            {'record_uid': 'PAMREC', 'reason': 'debugging',
                                             'ticket': 'JIRA-1'})
        self.assertIn('--reason', cap.last)
        self.assertIn('--ticket', cap.last)

    def test_launch_session_host_allowlist(self):
        grant = _grant(guardrails={'host_allowlist': ['allowed.host']})
        with CommandCapture():
            # allowed host proceeds
            tools_module.pam_launch_session(self.params, MCPConfig(), grant,
                                            {'record_uid': 'PAMREC', 'host': 'allowed.host'})
            # disallowed host is denied
            with self.assertRaises(MCPAccessError):
                tools_module.pam_launch_session(self.params, MCPConfig(), grant,
                                                {'record_uid': 'PAMREC', 'host': 'evil.host'})


# ======================================================================================
# 6. PAM exec/query end-to-end through the registered stub commands.
# ======================================================================================
class TestPamActionEndToEnd(MCPToolTestBase):
    def test_exec_returns_synthetic_result(self):
        res = tools_module.pam_exec_command(self.params, MCPConfig(), _grant(),
                                            {'record_uid': 'M1', 'command': 'whoami'})
        self.assertEqual('success', res['status'])
        self.assertEqual(0, res['exit_code'])
        self.assertIn('whoami', res['stdout'])

    def test_query_returns_synthetic_rows(self):
        res = tools_module.pam_db_query(self.params, MCPConfig(), _grant(),
                                        {'record_uid': 'DB1', 'query': 'select 1'})
        self.assertEqual('success', res['status'])
        self.assertEqual(res['rows'], [[1, 'alpha'], [2, 'beta']])
        self.assertEqual(2, res['row_count'])

    def test_exec_requires_args(self):
        with self.assertRaises(MCPAccessError):
            tools_module.pam_exec_command(self.params, MCPConfig(), _grant(), {'record_uid': 'M1'})

    def test_query_requires_args(self):
        with self.assertRaises(MCPAccessError):
            tools_module.pam_db_query(self.params, MCPConfig(), _grant(), {'record_uid': 'DB1'})

    def test_exec_host_allowlist(self):
        grant = _grant(guardrails={'host_allowlist': ['ok.host']})
        with self.assertRaises(MCPAccessError):
            tools_module.pam_exec_command(self.params, MCPConfig(), grant,
                                          {'record_uid': 'M1', 'command': 'id', 'host': 'bad.host'})

    def test_exec_config_record_denied(self):
        cfg = MCPConfig(config_record_uid='M1')
        with self.assertRaises(MCPAccessError):
            tools_module.pam_exec_command(self.params, cfg, _grant(),
                                          {'record_uid': 'M1', 'command': 'id'})

    def test_availability_guard_when_verb_missing(self):
        # Simulate a Commander build without the "pam action query" verb.
        with mock.patch.object(tools_module, '_pam_action_verbs', return_value={'rotate'}):
            with self.assertRaises(MCPAccessError):
                tools_module.pam_db_query(self.params, MCPConfig(), _grant(),
                                          {'record_uid': 'DB1', 'query': 'select 1'})


# ======================================================================================
# 7. Server-level dispatch + capability gating across the full tool set.
# ======================================================================================
class TestServerDispatch(unittest.TestCase):
    def setUp(self):
        from keepercommander.mcp import server as server_module
        self.server_module = server_module
        # Silence audit disk writes.
        self._audit = mock.patch.object(server_module.audit, 'record_tool_call').start()

    def tearDown(self):
        mock.patch.stopall()

    def _make_server(self, config):
        import time
        srv = self.server_module.CommanderMCPServer.__new__(self.server_module.CommanderMCPServer)
        srv.params = None
        srv._token = 'tok'
        srv._refresh_ttl = 9999
        srv._last_refresh = time.monotonic()  # inside TTL -> no vault reload
        srv.config = config
        srv.client = config.validate_token('tok')
        return srv

    def test_list_tool_specs_reflects_enabled_and_grants(self):
        cfg = MCPConfig(enabled=True,
                        capabilities={'read_secret': _grant(), 'search_records': _grant(),
                                      'pam_rotate': CapabilityGrant(enabled=False)},
                        clients=[_client('tok', grants=['read_secret'])])
        srv = self._make_server(cfg)
        names = {c.tool_name for c in srv.list_tool_specs()}
        self.assertEqual({'read_secret'}, names)  # search enabled but not granted; pam off

    def test_call_routes_to_handler(self):
        called = {}

        def fake_handler(params, config, grant, args):
            called['args'] = args
            return {'ok': True}

        with mock.patch.object(caps_module.get_capability('read_secret'), 'handler', fake_handler):
            cfg = MCPConfig(enabled=True, capabilities={'read_secret': _grant()},
                            clients=[_client('tok')])
            srv = self._make_server(cfg)
            out = srv.call('read_secret', {'record': 'x'})
        self.assertEqual({'ok': True}, out)
        self.assertEqual({'record': 'x'}, called['args'])
        self.assertTrue(self._audit.called)

    def test_disabled_capability_denied(self):
        cfg = MCPConfig(enabled=True, capabilities={'read_secret': CapabilityGrant(enabled=False)},
                        clients=[_client('tok')])
        srv = self._make_server(cfg)
        with self.assertRaises(MCPAccessError):
            srv.call('read_secret', {})

    def test_ungranted_capability_denied(self):
        cfg = MCPConfig(enabled=True,
                        capabilities={'read_secret': _grant(), 'create_record': _grant()},
                        clients=[_client('tok', grants=['read_secret'])])
        srv = self._make_server(cfg)
        with self.assertRaises(MCPAccessError):
            srv.call('create_record', {'title': 'x'})

    def test_revoked_client_denied(self):
        cfg = MCPConfig(enabled=True, capabilities={'read_secret': _grant()},
                        clients=[_client('tok', revoked=True)])
        srv = self._make_server(cfg)
        with self.assertRaises(MCPAccessError):
            srv.call('read_secret', {})

    def test_master_disabled_denied(self):
        cfg = MCPConfig(enabled=False, capabilities={'read_secret': _grant()},
                        clients=[_client('tok')])
        srv = self._make_server(cfg)
        with self.assertRaises(MCPAccessError):
            srv.call('read_secret', {})

    def test_unknown_tool_denied(self):
        cfg = MCPConfig(enabled=True, capabilities={'read_secret': _grant()},
                        clients=[_client('tok')])
        srv = self._make_server(cfg)
        with self.assertRaises(MCPAccessError):
            srv.call('does_not_exist', {})


# ======================================================================================
# 8. MCP config vault-record persistence round-trip (writes mocked, no network).
# ======================================================================================
class TestConfigPersistence(MCPToolTestBase):
    def test_save_then_load_round_trip(self):
        params = get_synced_params()  # isolated copy so we can mutate the cache
        cfg = MCPConfig(
            enabled=True,
            capabilities={'read_secret': _grant(scope={'folders': ['f1']})},
            clients=[_client('tok', name='Agent A', grants=['read_secret'])],
        )

        # Intercept the record write; apply it to the in-memory cache so load can read it.
        def fake_add(p, record, *a, **k):
            from keepercommander import vault
            import json as _json
            data = {'type': record.type_name, 'title': record.title,
                    'fields': [{'type': f.type, 'label': f.label, 'value': f.value} for f in record.fields],
                    'custom': [{'type': f.type, 'label': f.label, 'value': f.value} for f in record.custom]}
            p.record_cache[record.record_uid] = {
                'record_uid': record.record_uid,
                'version': 3,
                'revision': 1,
                'record_key_unencrypted': record.record_key,
                'data_unencrypted': _json.dumps(data),
            }

        with mock.patch.object(config_module.record_management, 'add_record_to_folder', side_effect=fake_add), \
                mock.patch.object(config_module.record_management, 'update_record'), \
                mock.patch('keepercommander.api.sync_down'):
            uid = config_module.save_config(params, cfg)

        self.assertTrue(uid)
        # Now load it back from the (mock-populated) cache.
        loaded = config_module.load_config(params)
        self.assertTrue(loaded.enabled)
        self.assertEqual(uid, loaded.config_record_uid)
        self.assertIn('read_secret', loaded.capabilities)
        self.assertEqual(['f1'], loaded.capabilities['read_secret'].scope['folders'])
        self.assertEqual(1, len(loaded.clients))
        self.assertEqual('Agent A', loaded.clients[0].name)
        self.assertEqual(['read_secret'], loaded.clients[0].grants)

    def test_load_returns_default_when_no_record(self):
        params = get_synced_params()
        cfg = config_module.load_config(params)
        self.assertFalse(cfg.enabled)
        self.assertIsNone(cfg.config_record_uid)
        self.assertEqual([], cfg.clients)


if __name__ == '__main__':
    unittest.main()
