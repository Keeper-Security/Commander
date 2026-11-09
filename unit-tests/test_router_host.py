import os
import unittest
from unittest import mock

from keepercommander import constants, error, rest_api
from keepercommander.commands.pam import router_helper
from keepercommander.keeper_dag.connection import commander as dag_commander
from keepercommander.keeper_dag.connection import ksm as dag_ksm

CLOUD = 'keepersecurity.com'

# KROUTER_URL shapes that the code before BOX-661 (origin/master ba6c3a94) accepted. Each row holds the output
# of that code, measured with the same calls:
# (router_helper.get_router_url, router_helper.get_router_ws_url, dag Commander http, dag Commander ws,
#  dag KSM http). A trailing "/" is stripped now. The other differences are noted in the test.
OLD_SHAPES = {
    'http://localhost:8080': ('http://localhost:8080', 'ws://localhost:8080', 'http://localhost:8080',
                              'http://localhost:8080', 'http://localhost:8080'),
    'https://r.test': ('https://r.test', 'wss://r.test', 'https://r.test', 'https://r.test', 'https://r.test'),
    'ws://r.test:8080': ('ws://r.test:8080', 'ws://r.test:8080', 'ws://r.test:8080', 'ws://r.test:8080',
                         'http://r.test:8080'),
    'wss://r.test': ('wss://r.test', 'wss://r.test', 'wss://r.test', 'wss://r.test', 'https://r.test'),
    'https://r.test/': ('https://r.test/', 'wss://r.test/', 'https://r.test/', 'https://r.test/',
                        'https://r.test/'),
    'https://r.test/pfx': ('https://r.test/pfx', 'wss://r.test/pfx', 'https://r.test/pfx', 'https://r.test/pfx',
                           'https://r.test/pfx'),
    'https://r.test/pfx/': ('https://r.test/pfx/', 'wss://r.test/pfx/', 'https://r.test/pfx/',
                            'https://r.test/pfx/', 'https://r.test/pfx/'),
    'wss://r.test/pfx/': ('wss://r.test/pfx/', 'wss://r.test/pfx/', 'wss://r.test/pfx/', 'wss://r.test/pfx/',
                          'https://r.test/pfx/'),
}


def _params(server_base='https://keepersecurity.com', config=None):
    params = mock.Mock()
    params.rest_context.server_base = server_base
    params.config = config if config is not None else {'server': CLOUD}
    return params


def _dag(is_ws, config=None):
    conn = object.__new__(dag_commander.Connection)
    conn.params = _params(config=config)
    conn.is_ws = is_ws
    return conn


def _ksm(config_host=CLOUD):
    conn = object.__new__(dag_ksm.Connection)
    patcher = mock.patch.object(dag_ksm.Connection, 'hostname', new_callable=mock.PropertyMock,
                                return_value=config_host)
    patcher.start()
    return conn, patcher


class RouterHostTestBase(unittest.TestCase):
    def setUp(self):
        env = {k: v for k, v in os.environ.items() if k not in ('KROUTER_URL', 'ROUTER_HOST', 'USE_SSL')}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)


class TestGetRouterHost(RouterHostTestBase):
    def test_cloud_without_override(self):
        self.assertEqual(constants.get_router_host(CLOUD), 'connect.keepersecurity.com')
        self.assertEqual(constants.get_router_base(CLOUD), 'https://connect.keepersecurity.com')
        self.assertEqual(constants.get_router_host('govcloud.keepersecurity.us'), 'connect.keepersecurity.us')

    def test_self_hosted_without_router_url_has_no_router(self):
        # Never guess connect.<host> for a self-hosted host.
        with self.assertRaises(constants.RouterHostError):
            constants.get_router_host('10.1.2.3')
        with self.assertRaises(constants.RouterHostError):
            constants.get_router_host('smk.test')

    def test_bare_host_and_port(self):
        os.environ['KROUTER_URL'] = 'connect.example.test:8443'
        self.assertEqual(constants.get_router_base(CLOUD), 'https://connect.example.test:8443')
        self.assertEqual(constants.get_router_host(CLOUD), 'connect.example.test:8443')

    def test_env_url_invalid_values(self):
        for value in ('ftp://h', 'https://', 'https://u:p@h.test', 'https://h.test?x=1', 'https://h.test:99999'):
            os.environ['KROUTER_URL'] = value
            with self.assertRaises(constants.RouterHostError, msg=value) as ctx:
                constants.get_router_base('x')
            self.assertIn('KROUTER_URL', str(ctx.exception))

    def test_error_is_command_error_and_value_error(self):
        os.environ['KROUTER_URL'] = 'ftp://h'
        with self.assertRaises(error.CommandError) as ctx:
            constants.get_router_host('x')
        self.assertIsInstance(ctx.exception, ValueError)
        self.assertEqual(str(ctx.exception), 'Invalid KROUTER_URL: "ftp://h" must use https, http, wss, or ws')

    def test_plaintext_env_scheme_warns(self):
        os.environ['KROUTER_URL'] = 'http://localhost:8080'
        with self.assertLogs(level='WARNING') as logs:
            constants.get_router_base('x')
        self.assertIn('KROUTER_URL', logs.output[0])
        os.environ['KROUTER_URL'] = 'https://localhost:8080'
        # assertNoLogs needs Python 3.10; CI also runs 3.9.
        with mock.patch.object(constants.logging, 'warning') as warning:
            constants.get_router_base('x')
        warning.assert_not_called()

    def test_config_override_per_server(self):
        config = {'router_hosts': {'10.1.2.3': 'https://connect.smk.test'}}
        self.assertEqual(constants.get_router_base('10.1.2.3', config), 'https://connect.smk.test')
        self.assertEqual(constants.get_router_base('https://10.1.2.3', config), 'https://connect.smk.test')
        self.assertEqual(constants.get_router_host(CLOUD, config), 'connect.keepersecurity.com')
        self.assertEqual(constants.get_router_host('10.1.2.3', {'router_hosts': {'10.1.2.3': 'h.test:8443'}}),
                         'h.test:8443')

    def test_env_wins_over_config(self):
        os.environ['KROUTER_URL'] = 'env.test'
        self.assertEqual(constants.get_router_host('a.test', {'router_hosts': {'a.test': 'cfg.test'}}), 'env.test')

    def test_config_is_strict(self):
        for value in ('http://bad.test', 'ws://bad.test', 'https://bad.test/pfx', 5, '', 'wss://bad.test'):
            with self.assertRaises(constants.RouterHostError, msg=str(value)) as ctx:
                constants.get_router_host('a.test', {'router_hosts': {'a.test': value}})
            self.assertIn('router_hosts[a.test]', str(ctx.exception))

    def test_invalid_config_entry_is_an_error_not_a_fallback(self):
        config = {'router_hosts': {'b.test': 'http://bad.test'}}
        with self.assertRaises(constants.RouterHostError):
            constants.get_router_host('a.test', config)
        with self.assertRaises(constants.RouterHostError):
            constants.get_router_host('a.test', {'router_hosts': 'nope'})

    def test_no_config_is_fine(self):
        self.assertEqual(constants.get_router_host(CLOUD, None), 'connect.keepersecurity.com')
        self.assertEqual(constants.get_router_host(CLOUD, {}), 'connect.keepersecurity.com')


class TestDiscoveredRouterUrl(RouterHostTestBase):
    HOST = 'smk.test'

    def _discover(self, value):
        key = rest_api.SelfManagedServerKey(7, 'k', 'test', True, value)
        patcher = mock.patch.dict(rest_api._resolved_server_keys, {self.HOST: key})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_router_url_is_used_for_self_hosted(self):
        self._discover('https://connect.smk.test:8443')
        self.assertEqual(constants.get_router_host(self.HOST), 'connect.smk.test:8443')
        self.assertEqual(constants.get_router_base(self.HOST), 'https://connect.smk.test:8443')

    def test_explicit_settings_win_over_router_url(self):
        self._discover('https://connect.smk.test')
        config = {'router_hosts': {self.HOST: 'r.test'}}
        self.assertEqual(constants.get_router_host(self.HOST, config), 'r.test')
        with mock.patch.dict(os.environ, {'KROUTER_URL': 'k.test'}):
            self.assertEqual(constants.get_router_host(self.HOST, config), 'k.test')

    def test_invalid_router_url_is_ignored(self):
        for value in ('http://r.test', 'https://r.test/path', 'https://r.test/', 'https://u:p@r.test',
                      'https://r.test?x=1', 'https://r.test#f', 'https://', 'r.test', 7):
            self._discover(value)
            self.assertIsNone(rest_api.get_discovered_router_url(self.HOST), value)
            with self.assertRaises(constants.RouterHostError):
                constants.get_router_host(self.HOST)

    def test_cloud_ignores_router_url(self):
        key = rest_api.SelfManagedServerKey(7, 'k', 'test', True, 'https://evil.test')
        with mock.patch.dict(rest_api._resolved_server_keys, {CLOUD: key}):
            self.assertEqual(constants.get_router_host(CLOUD), 'connect.keepersecurity.com')

    def test_fetch_reads_router_url(self):
        _, public_key = utils_key()
        reply = mock.Mock()
        reply.json.return_value = {'serverPublicKey': public_key, 'serverPublicKeyId': 7,
                                   'routerUrl': 'https://connect.smk.test'}
        with mock.patch('keepercommander.rest_api.requests.get', return_value=reply):
            key = rest_api._fetch_server_key_from(mock.Mock(proxies=None, certificate_check=True), 'https://smk.test/x')
        self.assertEqual(key.router_url, 'https://connect.smk.test')
        reply.json.return_value['routerUrl'] = 'http://bad.test'
        with mock.patch('keepercommander.rest_api.requests.get', return_value=reply):
            key = rest_api._fetch_server_key_from(mock.Mock(proxies=None, certificate_check=True), 'https://smk.test/x')
        self.assertIsNone(key.router_url)


def utils_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from keepercommander import utils
    k = ec.generate_private_key(ec.SECP256R1())
    return k, utils.base64_url_encode(k.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


class TestStrictHostSyntax(RouterHostTestBase):
    """The host part is an RFC 1123 DNS name, an IPv4 address, or a bracketed IPv6 literal."""
    BAD = ('not a host!!', 'a b.test', 'bad$host.test', 'a..test', '.a.test', '-a.test', 'a-.test',
           'a' * 64 + '.test', 'h.test:0', 'h.test:70000', '[::1', '[zz::1]:8443', '1.2.3.999')

    def test_invalid_hosts_name_the_source(self):
        for value in self.BAD:
            with self.subTest(value):
                with self.assertRaises(constants.RouterHostError) as ctx:
                    constants.parse_router_override(value, 'KROUTER_URL', allow_url_schemes=True)
                self.assertIn('KROUTER_URL', str(ctx.exception))

    def test_env_invalid_host_fails_before_any_request(self):
        os.environ['KROUTER_URL'] = 'not a host!!'
        with self.assertRaises(constants.RouterHostError) as ctx:
            constants.get_router_target(CLOUD)
        self.assertIn('KROUTER_URL', str(ctx.exception))

    def test_router_hosts_invalid_host(self):
        with self.assertRaises(constants.RouterHostError):
            constants.get_router_target(CLOUD, {'router_hosts': {CLOUD: 'bad host.test'}})

    def test_valid_hosts_still_accepted(self):
        for value, host in (('[::1]:8443', '[::1]:8443'), ('10.1.2.3:8443', '10.1.2.3:8443'),
                            ('Connect.Example-1.test:65535', 'connect.example-1.test:65535'),
                            ('localhost', 'localhost'), ('a' * 63 + '.test', 'a' * 63 + '.test'),
                            ('my_router', 'my_router'), ('my_router:6080', 'my_router:6080'),
                            ('xn--mnchen-3ya.de', 'xn--mnchen-3ya.de'), ('Example.COM', 'example.com'),
                            ('example.com.', 'example.com.')):
            with self.subTest(value):
                self.assertEqual(constants.parse_router_override(value, 'x').host, host)

    def test_repeated_trailing_dot_and_zero_port_url_rejected(self):
        for value in ('example.com..', 'http://h:0/path'):
            with self.subTest(value):
                with self.assertRaises(constants.RouterHostError):
                    constants.parse_router_override(value, 'KROUTER_URL', allow_url_schemes=True)


class TestLegacyKrouterUrlShapes(RouterHostTestBase):
    """Every KROUTER_URL shape that worked before still works. Each output equals the old output (OLD_SHAPES),
    except a trailing "/" (now stripped) and a scheme of the wrong family. The old code returned a ws URL
    for an HTTP call and an http URL for a WebSocket. Now the family follows the call, and the scheme the
    user gave still decides secure or plain."""

    def test_old_outputs_for_every_shape(self):
        for shape, (old_url, old_ws, old_dag_http, old_dag_ws, old_ksm) in OLD_SHAPES.items():
            os.environ['KROUTER_URL'] = shape
            http_family = shape.startswith(('http://', 'https://'))
            conn, patcher = _ksm()
            try:
                ksm_url = conn.http_router_url_from_ksm_config_or_env()
            finally:
                patcher.stop()
            with self.subTest(shape):
                self.assertEqual(router_helper.get_router_ws_url(_params()), old_ws.rstrip('/'))
                self.assertEqual(ksm_url, old_ksm.rstrip('/'))
                if http_family:
                    self.assertEqual(router_helper.get_router_url(_params()), old_url.rstrip('/'))
                    self.assertEqual(_dag(False).dag_server_url, old_dag_http.rstrip('/'))
                else:
                    self.assertEqual(_dag(True).dag_server_url, old_dag_ws.rstrip('/'))

    def test_scheme_family_follows_the_call(self):
        for shape, http_url, ws_url in (
                ('http://localhost:8080', 'http://localhost:8080', 'ws://localhost:8080'),
                ('https://r.test', 'https://r.test', 'wss://r.test'),
                ('ws://r.test:8080', 'http://r.test:8080', 'ws://r.test:8080'),
                ('wss://r.test/pfx/', 'https://r.test/pfx', 'wss://r.test/pfx')):
            os.environ['KROUTER_URL'] = shape
            with self.subTest(shape):
                self.assertEqual(router_helper.get_router_url(_params()), http_url)
                self.assertEqual(_dag(False).dag_server_url, http_url)
                self.assertEqual(_dag(True).dag_server_url, ws_url)

    def test_use_ssl_false_applies_only_without_scheme(self):
        os.environ['USE_SSL'] = 'false'
        self.assertEqual(_dag(True).dag_server_url, 'ws://connect.keepersecurity.com')
        os.environ['KROUTER_URL'] = 'https://r.test'
        self.assertEqual(_dag(True).dag_server_url, 'wss://r.test')


class TestCallers(RouterHostTestBase):
    def test_router_helper_url_and_ws(self):
        os.environ['KROUTER_URL'] = 'connect.example.test:8443'
        self.assertEqual(router_helper.get_router_url(_params()), 'https://connect.example.test:8443')
        self.assertEqual(router_helper.get_router_ws_url(_params()), 'wss://connect.example.test:8443')

    def test_router_helper_cloud(self):
        self.assertEqual(router_helper.get_router_url(_params()), 'https://connect.keepersecurity.com')
        self.assertEqual(router_helper.get_router_ws_url(_params()), 'wss://connect.keepersecurity.com')

    def test_router_helper_reads_params_config(self):
        params = _params('https://10.1.2.3', {'router_hosts': {'10.1.2.3': 'connect.smk.test'}})
        self.assertEqual(router_helper.get_router_url(params), 'https://connect.smk.test')
        bad = _params('https://10.1.2.3', {'router_hosts': {'10.1.2.3': 'http://x'}})
        with self.assertRaises(error.CommandError):
            router_helper.get_router_url(bad)

    def test_dag_commander_reads_params_config(self):
        config = {'server': '10.1.2.3', 'router_hosts': {'10.1.2.3': 'connect.smk.test:8443'}}
        self.assertEqual(_dag(True, config).dag_server_url, 'wss://connect.smk.test:8443')
        self.assertEqual(_dag(False, config).hostname, 'connect.smk.test:8443')

    def test_dag_commander_cloud(self):
        self.assertEqual(_dag(False).dag_server_url, 'https://connect.keepersecurity.com')
        self.assertEqual(_dag(True).dag_server_url, 'wss://connect.keepersecurity.com')

    def test_dag_commander_invalid_env(self):
        os.environ['KROUTER_URL'] = 'ftp://h'
        with self.assertRaises(error.CommandError):
            _dag(False).dag_server_url

    def test_router_host_env_is_normalized_and_ordered(self):
        get = dag_commander.Connection.get_router_target
        config = {'router_hosts': {'a.test': 'cfg.test'}}
        os.environ['ROUTER_HOST'] = 'HTTPS://Env.Test:8443/'
        self.assertEqual(get('a.test', config).host, 'env.test:8443')
        os.environ['KROUTER_URL'] = 'krouter.test'
        self.assertEqual(get('a.test', config).host, 'krouter.test')
        del os.environ['KROUTER_URL']
        os.environ['ROUTER_HOST'] = 'http://env.test'
        with self.assertRaises(error.CommandError) as ctx:
            get('a.test', config)
        self.assertIn('ROUTER_HOST', str(ctx.exception))
        del os.environ['ROUTER_HOST']
        self.assertEqual(get('a.test', config).host, 'cfg.test')
        self.assertEqual(get(CLOUD).host, 'connect.keepersecurity.com')

    def test_dag_ksm_url(self):
        conn, patcher = _ksm()
        self.addCleanup(patcher.stop)
        self.assertEqual(conn.http_router_url_from_ksm_config_or_env(), 'https://connect.keepersecurity.com')
        os.environ['KROUTER_URL'] = 'connect.news.test'
        # a host that contains "ws" must not be changed
        self.assertEqual(conn.http_router_url_from_ksm_config_or_env(), 'https://connect.news.test')
        self.assertEqual(conn.ws_router_url_from_ksm_config(is_ws=True), 'wss://connect.news.test')

    def _post_url(self, params):
        from keepercommander import api
        params.session_token = 'dG9rZW4'
        response = mock.Mock(status_code=200, content=b'')
        with mock.patch.object(api.rest_api, 'encrypt_with_keeper_key', return_value=b'k'), \
                mock.patch.object(api.crypto, 'encrypt_aes_v2', return_value=b'e'), \
                mock.patch.object(api.requests, 'post', return_value=response) as post, \
                mock.patch.object(api.crypto, 'decrypt_aes_v2', return_value=b''):
            try:
                api.execute_router_rest(params, 'ep', None)
            except Exception:
                pass
        return post.call_args[0][0]

    def test_api_router_call_uses_helper_and_params_config(self):
        params = _params('https://10.1.2.3', {'router_hosts': {'10.1.2.3': 'connect.smk.test'}})
        self.assertEqual(self._post_url(params), 'https://connect.smk.test/api/user/ep')
        os.environ['KROUTER_URL'] = 'http://localhost:8080/pfx/'
        self.assertEqual(self._post_url(_params()), 'http://localhost:8080/pfx/api/user/ep')

    def test_api_router_url_escape_hatch_is_unchanged(self):
        os.environ['ROUTER_URL'] = 'http://legacy.test:9000'
        os.environ['KROUTER_URL'] = 'ignored.test'
        self.assertEqual(self._post_url(_params()), 'http://legacy.test:9000/api/user/ep')

    def test_get_router_base_has_no_secure_parameter(self):
        with self.assertRaises(TypeError):
            constants.get_router_base(CLOUD, None, secure=False)


class TestDiagnose(RouterHostTestBase):
    def _run(self, router_host):
        from keepercommander.commands import tunnel_and_connections as tc
        params = mock.MagicMock()
        params.server = CLOUD
        params.config = {}
        cls = tc.PAMTunnelDiagnoseCommand
        ok = (True, 'ok', 1)
        with mock.patch.object(tc, 'get_router_host', return_value=router_host) as helper, \
                mock.patch.object(tc, 'get_relay_host', return_value='relay.example'), \
                mock.patch.object(tc, 'get_or_create_tube_registry', return_value=None), \
                mock.patch.object(tc.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('203.0.113.1', 0))]), \
                mock.patch.object(tc.socket, 'gethostbyname', return_value='203.0.113.1'), \
                mock.patch.object(cls, '_test_https', return_value=ok), \
                mock.patch.object(cls, '_test_websocket', return_value=ok) as ws, \
                mock.patch.object(cls, '_test_tcp_stun', return_value=(True, 'ok', 1, None)), \
                mock.patch.object(cls, '_test_udp_stun', return_value=(True, 'ok', 1, None)), \
                mock.patch.object(cls, '_test_turn', return_value=ok), \
                mock.patch.object(cls, '_test_udp_port', return_value=(True, 1)), \
                mock.patch('builtins.print') as printed:
            cls().execute(params)
        return helper, ws, ' '.join(str(c) for c in printed.call_args_list)

    def test_port_is_split_and_used(self):
        helper, ws, output = self._run('router.test:8443')
        self.assertEqual(helper.call_args[0][0], CLOUD)
        self.assertEqual(len(helper.call_args[0]), 2)
        self.assertEqual(ws.call_args[0][0], 'router.test')
        self.assertEqual(ws.call_args[1].get('port'), 8443)
        self.assertIn('WebSocket  router.test:8443', output)
        self.assertNotIn('8443:443', output)

    def test_default_port(self):
        _, ws, output = self._run('router.test')
        self.assertEqual(ws.call_args[1].get('port'), 443)
        self.assertIn('WebSocket  router.test:443', output)


if __name__ == '__main__':
    unittest.main()
