import unittest
from unittest import mock

from keepercommander.auth import desktop_bridge


class _Notice:
    reason = 'vault_session_socket_closed'


class _Monitor:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


class _BridgeClient:
    instance = None

    def __init__(self):
        type(self).instance = self
        self.callback = None
        self.config = None
        self.monitor = _Monitor()

    def start_vault_lifecycle_monitor(self, config, callback):
        self.config = config
        self.callback = callback
        return self.monitor


class _BridgeModule:
    BridgeClient = _BridgeClient


class _Params:
    def __init__(self):
        self.desktop_lifecycle_monitor = None
        self.via_desktop_session_terminated = False
        self.clear_calls = 0

    def clear_session(self):
        self.clear_calls += 1
        monitor = self.desktop_lifecycle_monitor
        self.desktop_lifecycle_monitor = None
        if monitor is not None:
            monitor.stop()


class DesktopLifecycleMonitorTestCase(unittest.TestCase):
    @mock.patch.object(desktop_bridge, '_suspend_desktop_pam_state')
    @mock.patch.object(desktop_bridge, '_close_desktop_lifecycle_tunnels')
    def test_terminal_notice_revokes_session_without_stopping_its_reader(self, close_tunnels, suspend_state):
        params = _Params()
        config = object()

        monitor = desktop_bridge._start_vault_lifecycle_monitor(params, _BridgeModule, config)
        _BridgeClient.instance.callback(_Notice())

        self.assertIs(_BridgeClient.instance.config, config)
        self.assertIsNone(params.desktop_lifecycle_monitor)
        self.assertTrue(params.via_desktop_session_terminated)
        self.assertEqual(params.clear_calls, 1)
        self.assertFalse(monitor.stopped)
        close_tunnels.assert_called_once_with(params)
        suspend_state.assert_called_once_with(params)
