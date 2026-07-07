"""Opt-in LIVE integration tests for the MCP tools against a real Keeper session.

These tests talk to a real vault using the machine's persistent Commander login. They
are SKIPPED by default and only run when ``KEEPER_MCP_LIVE=1`` is set, so they never
run in CI or by accident.

Safety model — only self-contained / reversible operations run live:
  * Read tools (search_records, read_secret) run against real data; secret VALUES are
    never printed, only structure is asserted.
  * A create -> read -> update -> delete lifecycle uses a uniquely named throwaway
    record and always deletes it (even on failure).
  * pam action exec/query hit the registered stub commands (synthetic data), so they
    are safe regardless of the vault.

Deliberately NOT run live (outward-facing / real infrastructure / irreversible):
  * share_record / share_folder to other users, ksm_manage_app (creates real apps),
    pam_rotate / pam_launch_session against real PAM resources.
  These are covered by command-construction tests in test_mcp_tools.py.

Run with:
    KEEPER_MCP_LIVE=1 python -m pytest unit-tests/test_mcp_live.py -v -s
"""

import logging
import os
import unittest
import uuid

from keepercommander.mcp import config as config_module
from keepercommander.mcp import tools as tools_module
from keepercommander.mcp.config import CapabilityGrant, MCPConfig

LIVE = os.environ.get('KEEPER_MCP_LIVE') == '1'
_params = None
_login_error = None


def setUpModule():
    """Bootstrap the persistent Commander session once for the whole module."""
    global _params, _login_error
    if not LIVE:
        return
    try:
        logging.getLogger().setLevel(logging.ERROR)
        # Importing cli populates the command registry (needed by pam action verbs).
        from keepercommander import cli  # noqa: F401
        from keepercommander import api
        from keepercommander.__main__ import get_params_from_config
        p = get_params_from_config()
        api.login(p)
        if not p.session_token:
            _login_error = 'No active persistent session (login produced no session token).'
            return
        api.sync_down(p)
        _params = p
    except Exception as e:  # pragma: no cover - environment dependent
        _login_error = f'{type(e).__name__}: {e}'


@unittest.skipUnless(LIVE, 'set KEEPER_MCP_LIVE=1 to run live integration tests')
class LiveMCPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _params is None:
            raise unittest.SkipTest(_login_error or 'persistent session unavailable')
        cls.params = _params
        # Enabled config, all-capabilities, unscoped. No config record exists in the
        # vault, so load_config() returns a default and self-protection is inert here.
        cls.config = MCPConfig(enabled=True)

    def _grant(self, **kw):
        return CapabilityGrant(enabled=True, **kw)


class TestLiveRead(LiveMCPTest):
    def test_search_returns_records(self):
        res = tools_module.search_records(self.params, self.config, self._grant(), {'limit': 5})
        self.assertGreater(res['count'], 0)
        self.assertLessEqual(res['count'], 5)
        for r in res['records']:
            self.assertIn('uid', r)
            self.assertIn('title', r)
            self.assertIn('type', r)
        print(f"\n[live] search returned {res['count']} record(s); "
              f"first title: {res['records'][0]['title']!r}")

    def test_read_secret_structure(self):
        found = tools_module.search_records(self.params, self.config, self._grant(), {'limit': 1})
        self.assertTrue(found['records'], 'vault has at least one record')
        uid = found['records'][0]['uid']
        res = tools_module.read_secret(self.params, self.config, self._grant(), {'record': uid})
        self.assertEqual(uid, res['uid'])
        self.assertIn('fields', res)
        self.assertIsInstance(res['fields'], dict)
        # Do not print secret values — only the field names.
        print(f"\n[live] read_secret on {uid}: field names = {sorted(res['fields'].keys())}")


class TestLiveRecordLifecycle(LiveMCPTest):
    """create -> read -> update -> delete, fully self-contained with guaranteed cleanup."""

    def setUp(self):
        self.title = f'zz-mcp-live-{uuid.uuid4().hex[:12]}'
        self.created_uid = None

    def tearDown(self):
        # Always remove the throwaway record, even if an assertion failed mid-test.
        if self.created_uid:
            try:
                from keepercommander import api
                api.delete_record(self.params, self.created_uid)
                print(f"\n[live] cleaned up record {self.created_uid}")
            except Exception as e:  # pragma: no cover
                print(f"\n[live] WARNING: cleanup failed for {self.created_uid}: {e}")

    def _find_uid_by_title(self, title):
        from keepercommander import vault_extensions
        for rec in vault_extensions.find_records(self.params, title):
            if rec.title == title:
                return rec.record_uid
        return None

    def test_create_read_update_delete(self):
        from keepercommander import api

        # CREATE (login + notes only; no password value, to avoid the passphrase policy)
        tools_module.create_record(self.params, self.config, self._grant(), {
            'title': self.title,
            'record_type': 'login',
            'fields': ['login=agent@example.com'],
            'notes': 'created by MCP live integration test',
        })
        api.sync_down(self.params)
        self.created_uid = self._find_uid_by_title(self.title)
        self.assertIsNotNone(self.created_uid, 'created record should be found by title')
        print(f"\n[live] created record {self.created_uid} ({self.title})")

        # READ
        read = tools_module.read_secret(self.params, self.config, self._grant(),
                                        {'record': self.created_uid})
        self.assertEqual(self.title, read['title'])
        # The login field round-trips (field key is like "(login).login").
        self.assertIn('agent@example.com', list(read['fields'].values()))

        # UPDATE
        tools_module.update_record(self.params, self.config, self._grant(),
                                   {'record': self.created_uid, 'notes': 'updated by MCP live test'})
        api.sync_down(self.params)

        # DELETE (explicit; tearDown also guards)
        api.delete_record(self.params, self.created_uid)
        deleted_uid = self.created_uid
        self.created_uid = None  # already cleaned up
        self.assertIsNone(self._find_uid_by_title(self.title), 'record should be gone after delete')
        print(f"\n[live] deleted record {deleted_uid}")

    def test_command_failure_is_surfaced(self):
        """A blocked record-add must return a diagnostic, not a silent empty success.

        Commander's passphrase policy rejects a password with fewer than 5 words. The
        MCP handler should surface that reason (captured from logs/stderr) so the agent
        is not left guessing.
        """
        from keepercommander import api

        result = tools_module.create_record(self.params, self.config, self._grant(), {
            'title': self.title,
            'record_type': 'login',
            'fields': ['password=too-few-words'],  # 3 words -> violates policy
        })
        text = str(result.get('result', '')).lower()
        self.assertTrue(text, 'a blocked command must return a non-empty diagnostic')
        self.assertIn('word', text, f'diagnostic should mention the passphrase policy; got: {text!r}')

        # It should NOT have created a record; guard cleanup just in case it did.
        api.sync_down(self.params)
        self.created_uid = self._find_uid_by_title(self.title)
        self.assertIsNone(self.created_uid, 'blocked create should not persist a record')
        print(f"\n[live] blocked create surfaced: {text[:80]!r}")


class TestLivePamStubs(LiveMCPTest):
    """exec/query run through the real registered stub commands (synthetic data)."""

    def test_pam_exec_stub(self):
        res = tools_module.pam_exec_command(self.params, self.config, self._grant(),
                                            {'record_uid': 'LIVE-STUB', 'command': 'hostname'})
        self.assertEqual('success', res['status'])
        self.assertIn('hostname', res['stdout'])
        print(f"\n[live] pam exec stub -> exit {res['exit_code']}")

    def test_pam_query_stub(self):
        res = tools_module.pam_db_query(self.params, self.config, self._grant(),
                                        {'record_uid': 'LIVE-STUB', 'query': 'select 1'})
        self.assertEqual('success', res['status'])
        self.assertEqual(2, res['row_count'])
        print(f"\n[live] pam query stub -> {res['row_count']} row(s)")


if __name__ == '__main__':
    unittest.main()
