"""
Unit tests for _print_proxy_ready_banner, the KeeperDB/KeeperRDP/KeeperSSH
Proxy "ready" banner printed from TunnelSignalHandler's WebRTC 'connected'
callback (not immediately after start_rust_tunnel returns -- see the
function's docstring for why: a proxy tunnel's offer can be "accepted" well
before the gateway has actually spawned the proxy and authenticated against
the real target, and that can still fail afterward).
"""

import logging
import unittest

from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (
    TunnelSession,
    _print_proxy_ready_banner,
)


def _make_session(proxy_kind, proxy_db_type=None, host='127.0.0.1', port=49152):
    return TunnelSession(
        tube_id='tube-1', conversation_id='conv-1', gateway_uid='gw-1', symmetric_key=b'key',
        host=host, port=port, proxy_kind=proxy_kind, proxy_db_type=proxy_db_type,
    )


class TestPrintProxyReadyBanner(unittest.TestCase):
    def test_ssh_banner_mentions_listen_and_connect_string(self):
        session = _make_session('ssh')
        with self.assertLogs(level='INFO') as captured:
            _print_proxy_ready_banner(session)
        combined = '\n'.join(captured.output)
        self.assertIn('KeeperSSH Proxy ready', combined)
        self.assertIn('127.0.0.1:49152', combined)
        self.assertIn('ssh -p 49152', combined)

    def test_rdp_banner_mentions_mstsc(self):
        session = _make_session('rdp')
        with self.assertLogs(level='INFO') as captured:
            _print_proxy_ready_banner(session)
        combined = '\n'.join(captured.output)
        self.assertIn('KeeperRDP Proxy ready', combined)
        self.assertIn('mstsc', combined)

    def test_db_banner_mysql_specific_connect_string(self):
        session = _make_session('db', proxy_db_type='mysql')
        with self.assertLogs(level='INFO') as captured:
            _print_proxy_ready_banner(session)
        combined = '\n'.join(captured.output)
        self.assertIn('KeeperDB Proxy ready (mysql)', combined)
        self.assertIn('mysql -h 127.0.0.1 -P 49152', combined)

    def test_db_banner_falls_back_to_generic_connect_string_when_type_unknown(self):
        session = _make_session('db', proxy_db_type=None)
        with self.assertLogs(level='INFO') as captured:
            _print_proxy_ready_banner(session)
        combined = '\n'.join(captured.output)
        self.assertIn('KeeperDB Proxy ready', combined)
        self.assertNotIn('KeeperDB Proxy ready (', combined)
        self.assertIn('use your database client', combined)


if __name__ == '__main__':
    unittest.main()
