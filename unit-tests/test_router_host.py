import os
import unittest
from unittest import mock

from keepercommander import constants
from keepercommander.commands.pam import router_helper
from keepercommander.keeper_dag.connection import commander as dag_commander
from keepercommander.keeper_dag.connection import ksm as dag_ksm


class RouterHostTestBase(unittest.TestCase):
    def setUp(self):
        env = {k: v for k, v in os.environ.items() if k not in ('KROUTER_URL', 'ROUTER_HOST', 'USE_SSL')}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        constants.clear_router_hosts()
        self.addCleanup(constants.clear_router_hosts)


class TestGetRouterHost(RouterHostTestBase):
    def test_cloud_without_override(self):
        self.assertEqual(constants.get_router_host('keepersecurity.com'), 'connect.keepersecurity.com')
        self.assertEqual(constants.get_router_base('keepersecurity.com'), 'https://connect.keepersecurity.com')
        self.assertEqual(constants.get_router_host('govcloud.keepersecurity.us'), 'connect.keepersecurity.us')

    def test_ip_without_override_keeps_derived_value(self):
        self.assertEqual(constants.get_router_host('10.1.2.3'), 'connect.10.1.2.3')
        self.assertEqual(constants.get_router_host(None), 'connect.None')

    def test_bare_host(self):
        os.environ['KROUTER_URL'] = 'connect.example.test'
        self.assertEqual(constants.get_router_base('keepersecurity.com'), 'https://connect.example.test')
        self.assertEqual(constants.get_router_host('keepersecurity.com'), 'connect.example.test')

    def test_host_port(self):
        os.environ['KROUTER_URL'] = 'connect.example.test:8443'
        self.assertEqual(constants.get_router_base('x'), 'https://connect.example.test:8443')

    def test_https_url(self):
        os.environ['KROUTER_URL'] = 'https://connect.example.test:8443'
        self.assertEqual(constants.get_router_base('x'), 'https://connect.example.test:8443')

    def test_url_trailing_slash(self):
        os.environ['KROUTER_URL'] = 'https://connect.example.test/'
        self.assertEqual(constants.get_router_base('x'), 'https://connect.example.test')

    def test_url_with_path_is_rejected(self):
        os.environ['KROUTER_URL'] = 'https://connect.example.test/prefix'
        with self.assertRaises(ValueError):
            constants.get_router_base('x')

    def test_invalid_scheme(self):
        for value in ('http://connect.example.test', 'ws://connect.example.test', 'ftp://h', 'https://'):
            os.environ['KROUTER_URL'] = value
            with self.assertRaises(ValueError, msg=value):
                constants.get_router_base('x')

    def test_insecure_base_only_without_override(self):
        self.assertEqual(constants.get_router_base('keepersecurity.com', secure=False),
                         'http://connect.keepersecurity.com')

    def test_config_override_per_server(self):
        constants.load_router_hosts({'router_hosts': {'10.1.2.3': 'https://connect.smk.test'}})
        self.assertEqual(constants.get_router_base('10.1.2.3'), 'https://connect.smk.test')
        self.assertEqual(constants.get_router_base('https://10.1.2.3'), 'https://connect.smk.test')
        self.assertEqual(constants.get_router_host('keepersecurity.com'), 'connect.keepersecurity.com')

    def test_env_wins_over_config(self):
        constants.load_router_hosts({'router_hosts': {'a.test': 'cfg.test'}})
        os.environ['KROUTER_URL'] = 'env.test'
        self.assertEqual(constants.get_router_host('a.test'), 'env.test')

    def test_invalid_config_entry_is_ignored(self):
        constants.load_router_hosts({'router_hosts': {'a.test': 'http://bad.test', 'b.test': 5}})
        self.assertEqual(constants.get_router_host('a.test'), 'connect.a.test')
        constants.load_router_hosts({'router_hosts': 'nope'})


class TestCallers(RouterHostTestBase):
    @staticmethod
    def _params(server_base='https://keepersecurity.com'):
        params = mock.Mock()
        params.rest_context.server_base = server_base
        return params

    def test_router_helper_url_and_ws(self):
        os.environ['KROUTER_URL'] = 'connect.example.test:8443'
        self.assertEqual(router_helper.get_router_url(self._params()), 'https://connect.example.test:8443')
        self.assertEqual(router_helper.get_router_ws_url(self._params()), 'wss://connect.example.test:8443')

    def test_router_helper_cloud(self):
        self.assertEqual(router_helper.get_router_url(self._params()), 'https://connect.keepersecurity.com')

    def test_router_helper_calls_constants(self):
        with mock.patch.object(constants, 'get_router_base', return_value='https://z.test') as m:
            self.assertEqual(router_helper.get_router_url(self._params()), 'https://z.test')
        m.assert_called_once()

    def _dag(self, is_ws):
        conn = object.__new__(dag_commander.Connection)
        conn.params = mock.Mock()
        conn.params.config = {'server': 'keepersecurity.com'}
        conn.is_ws = is_ws
        return conn

    def test_dag_commander_url(self):
        self.assertEqual(self._dag(False).dag_server_url, 'https://connect.keepersecurity.com')
        self.assertEqual(self._dag(True).dag_server_url, 'wss://connect.keepersecurity.com')
        os.environ['KROUTER_URL'] = 'https://connect.example.test'
        self.assertEqual(self._dag(False).dag_server_url, 'https://connect.example.test')
        self.assertEqual(self._dag(True).dag_server_url, 'wss://connect.example.test')
        os.environ['KROUTER_URL'] = 'connect.example.test:8443'
        self.assertEqual(self._dag(True).dag_server_url, 'wss://connect.example.test:8443')

    def test_dag_commander_rejects_http_override(self):
        os.environ['KROUTER_URL'] = 'http://connect.example.test'
        with self.assertRaises(ValueError):
            self._dag(False).dag_server_url

    def _ksm(self):
        conn = object.__new__(dag_ksm.Connection)
        conn.__dict__['hostname_value'] = 'keepersecurity.com'
        return conn

    def test_dag_ksm_url(self):
        with mock.patch.object(dag_ksm.Connection, 'hostname', new_callable=mock.PropertyMock,
                               return_value='keepersecurity.com'):
            conn = self._ksm()
            self.assertEqual(conn.http_router_url_from_ksm_config_or_env(), 'https://connect.keepersecurity.com')
            os.environ['KROUTER_URL'] = 'connect.news.test'
            # a host that contains "ws" must not be changed
            self.assertEqual(conn.http_router_url_from_ksm_config_or_env(), 'https://connect.news.test')
            self.assertEqual(conn.ws_router_url_from_ksm_config(is_ws=True), 'wss://connect.news.test')

    def test_api_router_call_uses_helper(self):
        from keepercommander import api
        params = self._params('https://10.1.2.3')
        params.session_token = 'dG9rZW4'
        response = mock.Mock(status_code=200, content=b'')
        with mock.patch.object(api.rest_api, 'encrypt_with_keeper_key', return_value=b'k'), \
                mock.patch.object(api.crypto, 'encrypt_aes_v2', return_value=b'e'), \
                mock.patch.object(api.requests, 'post', return_value=response) as post, \
                mock.patch.object(api.crypto, 'decrypt_aes_v2', return_value=b''):
            constants.load_router_hosts({'router_hosts': {'10.1.2.3': 'connect.smk.test'}})
            try:
                api.execute_router_rest(params, 'ep', None)
            except Exception:
                pass
        self.assertEqual(post.call_args[0][0], 'https://connect.smk.test/api/user/ep')

    def test_tunnel_diagnose_uses_helper(self):
        from keepercommander.commands import tunnel_and_connections as tc
        self.assertIs(tc.get_router_host, constants.get_router_host)


if __name__ == '__main__':
    unittest.main()
