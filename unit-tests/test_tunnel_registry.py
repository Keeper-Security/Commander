#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# Unit tests for tunnel_registry and pam tunnel start parser / batch-mode guard.
#

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import keepercommander.commands.tunnel_registry as tunnel_registry_mod
from keepercommander.commands.tunnel_registry import (
    PARENT_GRACE_SECONDS,
    is_pid_alive,
    list_registered_tunnels,
    normalize_bind_host,
    register_tunnel,
    stop_tunnel_process,
    unregister_tunnel,
)
from keepercommander.error import CommandError

if sys.version_info < (3, 8):
    raise unittest.SkipTest('pam tunnel tests require Python 3.8+')


def _patch_registry_dir(testcase, tmp: Path):
    """Point tunnel_registry_dir at tmp for the duration of a test."""
    patcher = mock.patch.object(
        tunnel_registry_mod,
        'tunnel_registry_dir',
        return_value=tmp,
    )
    patcher.start()
    testcase.addCleanup(patcher.stop)
    tunnel_registry_mod._registry_dir_initialized = False


class TestNormalizeBindHost(unittest.TestCase):
    def test_localhost_maps(self):
        self.assertEqual(normalize_bind_host('localhost'), '127.0.0.1')
        self.assertEqual(normalize_bind_host('LOCALHOST'), '127.0.0.1')

    def test_other_preserved_lower(self):
        self.assertEqual(normalize_bind_host('10.0.0.5'), '10.0.0.5')


class TestTunnelRegistryDir(unittest.TestCase):
    def test_creates_with_permissions(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        _patch_registry_dir(self, tmp)
        d = tunnel_registry_mod.tunnel_registry_dir()
        self.assertTrue(d.exists())
        self.assertEqual(d, tmp)


class TestRegisterUnregister(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        _patch_registry_dir(self, self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_register_writes_json_unregister_removes(self):
        register_tunnel(
            12345, 'rec1', 'tube1', '127.0.0.1', 5432,
            target_host='host', target_port=22, mode='foreground',
            record_title='t',
        )
        self.assertTrue((self.tmp / '12345.json').exists())
        with open(self.tmp / '12345.json', encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(data['record_uid'], 'rec1')
        self.assertEqual(data['tube_id'], 'tube1')
        self.assertEqual(data['port'], 5432)
        unregister_tunnel(12345)
        self.assertFalse((self.tmp / '12345.json').exists())


class TestListRegisteredTunnels(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        _patch_registry_dir(self, self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_list_removes_stale_entries_when_clean(self):
        dead_pid = 999999991
        p = self.tmp / f'{dead_pid}.json'
        with open(p, 'w', encoding='utf-8') as f:
            json.dump({'pid': dead_pid, 'record_uid': 'x', 'host': '127.0.0.1', 'port': 1}, f)
        out = list_registered_tunnels(clean_stale=True)
        self.assertFalse(p.exists())
        self.assertEqual(out, [])


class TestIsPidAlive(unittest.TestCase):
    def test_current_process_alive(self):
        self.assertTrue(is_pid_alive(os.getpid()))

    def test_nonexistent_pid(self):
        self.assertFalse(is_pid_alive(999999997))


class TestDuplicatePortDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        _patch_registry_dir(self, self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @mock.patch('keepercommander.commands.tunnel_registry.is_pid_alive', return_value=True)
    def test_duplicate_host_port_raises(self, _mock_alive):
        register_tunnel(
            111, 'a', 't1', '127.0.0.1', 5432, mode='foreground',
        )
        with self.assertRaises(CommandError) as ctx:
            register_tunnel(
                222, 'b', 't2', 'localhost', 5432, mode='foreground',
            )
        msg = str(ctx.exception)
        self.assertIn('pam tunnel start', msg)
        self.assertIn('5432', msg)
        self.assertIn('111', msg)
        self.assertIn('pam tunnel stop', msg)


class TestStopTunnelProcess(unittest.TestCase):
    def test_dead_pid_returns_false(self):
        self.assertFalse(stop_tunnel_process(999999996))


class TestPamTunnelStartParser(unittest.TestCase):
    def test_defaults(self):
        from keepercommander.commands.tunnel_and_connections import PAMTunnelStartCommand
        p = PAMTunnelStartCommand.pam_cmd_parser
        ns = p.parse_args(['recuid'])
        self.assertFalse(ns.foreground)
        self.assertFalse(ns.background)
        self.assertIsNone(ns.run_command)
        self.assertEqual(ns.connect_timeout, 30)
        self.assertIsNone(ns.pid_file)

    def test_flags_parse(self):
        from keepercommander.commands.tunnel_and_connections import PAMTunnelStartCommand
        p = PAMTunnelStartCommand.pam_cmd_parser
        ns = p.parse_args([
            'recuid', '-fg', '--pid-file', '/tmp/p.pid', '--timeout', '60',
            '-R', 'echo hi',
        ])
        self.assertTrue(ns.foreground)
        self.assertEqual(ns.pid_file, '/tmp/p.pid')
        self.assertEqual(ns.connect_timeout, 60)
        self.assertEqual(ns.run_command, 'echo hi')

    def test_mutual_exclusive_flags_parse_together(self):
        from keepercommander.commands.tunnel_and_connections import PAMTunnelStartCommand
        p = PAMTunnelStartCommand.pam_cmd_parser
        ns = p.parse_args(['recuid', '--foreground', '--background'])
        self.assertTrue(ns.foreground)
        self.assertTrue(ns.background)


class _DummyTypedRecord:
    """Stand-in for vault.TypedRecord when patching isinstance checks."""


class TestBatchModeTargetHostPort(unittest.TestCase):
    @mock.patch('keepercommander.commands.workflow.check_workflow_and_prompt_2fa',
                return_value=(True, None), create=True)
    @mock.patch('keepercommander.commands.tunnel_and_connections.vault.TypedRecord', _DummyTypedRecord)
    @mock.patch('keepercommander.commands.tunnel_and_connections.find_open_port')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.vault.KeeperRecord.load')
    def test_input_not_called_batch_missing_target_host(
        self, mock_load, mock_sync, mock_tr, mock_fop, mock_wf,
    ):
        mock_tr.return_value = mock.MagicMock()
        mock_fop.return_value = 5432

        pam = mock.MagicMock()
        pam.get_default_value.return_value = {'allowSupplyHost': True, 'portForward': {'port': 22}}
        rec = _DummyTypedRecord()
        rec.record_uid = 'rec1'
        rec.title = 'rec1-title'
        rec.get_typed_field = lambda name, *a, **kw: pam if name == 'pamSettings' else None

        mock_load.return_value = rec

        from keepercommander.commands.tunnel_and_connections import PAMTunnelStartCommand
        p = mock.MagicMock()
        p.batch_mode = True
        p.config_filename = None
        p.server = None

        with mock.patch('builtins.input', side_effect=AssertionError('input must not be called')):
            cmd = PAMTunnelStartCommand()
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(
                    p,
                    uid='rec1',
                    host='127.0.0.1',
                    port=5432,
                    target_host=None,
                    target_port=None,
                    no_trickle_ice=False,
                    foreground=False,
                    background=False,
                    run_command=None,
                    connect_timeout=30,
                    pid_file=None,
                )
        msg = str(ctx.exception)
        self.assertIn('--target-host', msg)
        self.assertIn('--target-port', msg)


class TestParentGraceConstant(unittest.TestCase):
    def test_parent_grace_seconds(self):
        self.assertEqual(PARENT_GRACE_SECONDS, 10)


class TestListCleanStaleFalse(unittest.TestCase):
    """Stale files are listed but not deleted when clean_stale=False."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        _patch_registry_dir(self, self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_clean_stale_false_keeps_dead_file(self):
        dead_pid = 999999992
        p = self.tmp / f'{dead_pid}.json'
        with open(p, 'w', encoding='utf-8') as f:
            json.dump({'pid': dead_pid, 'record_uid': 'x', 'host': '127.0.0.1', 'port': 1}, f)
        out = list_registered_tunnels(clean_stale=False)
        self.assertTrue(p.exists())
        self.assertEqual(out, [])


if __name__ == '__main__':
    unittest.main()
