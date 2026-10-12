"""Tests for the server key of a self-managed Keeper deployment in rest_api.py.

Verifies:
- Keeper cloud hosts keep using the built-in SERVER_PUBLIC_KEYS, and fetch nothing
- Any other host uses, in order: a configured key, KEEPER_SERVER_PUBLIC_KEY, the key fetched from
  <host>/api/rest/server_public_key or <host>/status/api/connect, and the built-in keys only when
  none of these is available
- A key is fetched only over a verified HTTPS connection, and must match the fingerprint published with it
- A key set for one host is never used for another
- execute_rest encrypts the transmission key to the self-managed key; when the server rejects it,
  it looks for the key once more, then stops with a clear error
- The server command sets, saves and clears a key and --insecure, and refuses a mistyped region
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Add parent dir so imports work from unit-tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from keepercommander import rest_api, utils, crypto
from keepercommander.constants import resolve_server
from keepercommander.error import KeeperApiError
from keepercommander.params import RestApiContext, KeeperParams, INSECURE_SERVER_HOSTS
from keepercommander.proto import APIRequest_pb2 as proto


def make_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return private_key, utils.base64_url_encode(public_key)


def make_context(server):
    ctx = RestApiContext(server=server, locale='en_US')
    ctx.transmission_key = os.urandom(32)
    ctx.disable_qrc()
    return ctx


def make_server_key_response(public_key, key_id=7, fingerprint=None):
    rs = MagicMock()
    rs.status_code = 200
    rs.json.return_value = {'server': 'keeper.example.com', 'serverPublicKeyId': key_id,
                            'serverPublicKey': public_key,
                            'fingerprint': fingerprint or rest_api.server_key_fingerprint(public_key)}
    rs.raise_for_status.return_value = None
    return rs


def make_key_error_response():
    body = [{'key_id': -1, 'location': 'encrypted_rest_filter', 'error': 'key', 'message': 'key'}]
    rs = MagicMock()
    rs.status_code = 401
    rs.headers = {'Content-Type': 'application/json'}
    rs.json.return_value = body
    rs.content = json.dumps(body).encode()
    return rs


def make_not_found_response():
    rs = MagicMock()
    rs.status_code = 404
    rs.raise_for_status.side_effect = Exception('404 Not Found')
    return rs


def make_success_response():
    rs = MagicMock()
    rs.status_code = 200
    rs.headers = {'Content-Type': 'application/octet-stream'}
    rs.content = b''
    return rs


class SelfManagedKeyTestCase(unittest.TestCase):
    def setUp(self):
        rest_api._configured_server_keys.clear()
        rest_api._resolved_server_keys.clear()
        rest_api._server_key_errors.clear()
        INSECURE_SERVER_HOSTS.clear()
        # Other tests change the process-wide SSL settings (VERIFY_SSL, KEEPER_SSL_CERT_FILE and
        # its cache). These tests need certificate checks on unless a test turns them off.
        ssl_verify = patch('keepercommander.utils.resolve_ssl_verify',
                           side_effect=lambda certificate_check_enabled=True:
                           '/etc/ssl/cert.pem' if certificate_check_enabled else False)
        ssl_verify.start()
        self.addCleanup(ssl_verify.stop)
        env = patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('KEEPER_SERVER_PUBLIC_KEY', None)
        os.environ.pop('KEEPER_SERVER_KEY_ID', None)
        os.environ.pop('KEEPER_SERVER_PUBLIC_KEY_ID', None)
        self.private_key, self.public_key = make_key_pair()

    def tearDown(self):
        rest_api._configured_server_keys.clear()
        rest_api._resolved_server_keys.clear()
        rest_api._server_key_errors.clear()
        INSECURE_SERVER_HOSTS.clear()


class TestHosts(SelfManagedKeyTestCase):
    def test_keeper_cloud_hosts(self):
        for host in ('keepersecurity.com', 'dev.keepersecurity.com', 'keepersecurity.eu',
                     'keepersecurity.com.au', 'govcloud.keepersecurity.us', 'https://qa.keepersecurity.jp/api/rest/'):
            self.assertTrue(rest_api.is_keeper_cloud_host(host), host)

    def test_other_hosts(self):
        for host in ('localhost', 'localhost:8443', 'keeper.example.com', 'keepersecurity.com.example.com',
                     'notkeepersecurity.com'):
            self.assertFalse(rest_api.is_keeper_cloud_host(host), host)

    def test_fingerprint(self):
        # Keeper's built-in key 7, from SERVER_PUBLIC_KEYS.
        key = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
        self.assertTrue(rest_api.server_key_fingerprint(key).startswith('SHA256:'))
        self.assertNotIn('=', rest_api.server_key_fingerprint(key))

    def test_published_fingerprint_formats(self):
        import base64, hashlib
        digest = hashlib.sha256(utils.base64_url_decode(self.public_key)).digest()
        self.assertTrue(rest_api._fingerprint_matches(rest_api.server_key_fingerprint(self.public_key),
                                                      self.public_key))
        self.assertTrue(rest_api._fingerprint_matches('SHA256:' + base64.b64encode(digest).decode(),
                                                      self.public_key))
        self.assertTrue(rest_api._fingerprint_matches(':'.join(f'{b:02X}' for b in digest), self.public_key))
        other = make_key_pair()[1]
        self.assertFalse(rest_api._fingerprint_matches(rest_api.server_key_fingerprint(other), self.public_key))
        self.assertIsNone(rest_api._fingerprint_matches('something else', self.public_key))


class TestResolveServer(unittest.TestCase):
    def test_region_codes_and_keeper_hosts(self):
        self.assertEqual(resolve_server('US'), 'keepersecurity.com')
        self.assertEqual(resolve_server('eu'), 'keepersecurity.eu')
        self.assertEqual(resolve_server('US-DEV'), 'dev.keepersecurity.com')
        self.assertEqual(resolve_server('QA.KEEPERSECURITY.COM'), 'qa.keepersecurity.com')

    def test_self_managed_hosts(self):
        for host in ('vault.example.com', 'localhost', 'localhost:8080', '192.0.2.10:8443',
                     'https://keeper.example.com', '[::1]:8443'):
            self.assertEqual(resolve_server(host), host)

    def test_mistyped_region_is_not_a_server(self):
        for value in ('EUU', 'GOVDEV', 'prod', '', None):
            self.assertIsNone(resolve_server(value), value)


class TestResolve(SelfManagedKeyTestCase):
    @patch('keepercommander.rest_api.requests.get')
    def test_cloud_host_uses_built_in_keys(self, mock_get):
        ctx = make_context('keepersecurity.com')
        ctx.server_key_id = 7
        self.assertIs(rest_api.get_server_public_key(ctx), rest_api.SERVER_PUBLIC_KEYS[7])
        mock_get.assert_not_called()

    @patch('keepercommander.rest_api.requests.get')
    def test_fetches_key_from_server(self, mock_get):
        mock_get.return_value = make_server_key_response(self.public_key, 9)
        ctx = make_context('keeper.example.com')
        key = rest_api.get_server_public_key(ctx)
        self.assertEqual(crypto.unload_ec_public_key(key), utils.base64_url_decode(self.public_key))
        self.assertEqual(ctx.server_key_id, 9)
        self.assertEqual(mock_get.call_args[0][0], 'https://keeper.example.com/api/rest/server_public_key')

        # Fetched once per host
        rest_api.get_server_public_key(make_context('keeper.example.com'))
        self.assertEqual(mock_get.call_count, 1)

    @patch('keepercommander.rest_api.requests.get')
    def test_falls_back_to_the_status_service(self, mock_get):
        mock_get.side_effect = [make_not_found_response(), make_server_key_response(self.public_key)]
        ctx = make_context('keeper.example.com:8443')
        key = rest_api.get_server_public_key(ctx)
        self.assertEqual(crypto.unload_ec_public_key(key), utils.base64_url_decode(self.public_key))
        self.assertEqual([c[0][0] for c in mock_get.call_args_list],
                         ['https://keeper.example.com:8443/api/rest/server_public_key',
                          'https://keeper.example.com:8443/status/api/connect'])

    @patch('keepercommander.rest_api.requests.get')
    def test_key_that_does_not_match_its_fingerprint_is_refused(self, mock_get):
        other_fingerprint = rest_api.server_key_fingerprint(make_key_pair()[1])
        mock_get.return_value = make_server_key_response(self.public_key, fingerprint=other_fingerprint)
        ctx = make_context('keeper.example.com')
        ctx.server_key_id = 7
        self.assertIs(rest_api.get_server_public_key(ctx), rest_api.SERVER_PUBLIC_KEYS[7])
        self.assertIn('does not match', rest_api.self_managed_key_error(ctx))

    @patch('keepercommander.rest_api.requests.get')
    def test_configured_key_wins(self, mock_get):
        rest_api.set_server_public_key('keeper.example.com', 8, self.public_key)
        os.environ['KEEPER_SERVER_PUBLIC_KEY'] = make_key_pair()[1]
        ctx = make_context('keeper.example.com')
        key = rest_api.get_server_public_key(ctx)
        self.assertEqual(crypto.unload_ec_public_key(key), utils.base64_url_decode(self.public_key))
        self.assertEqual(ctx.server_key_id, 8)
        mock_get.assert_not_called()

    @patch('keepercommander.rest_api.requests.get')
    def test_environment_key(self, mock_get):
        os.environ['KEEPER_SERVER_PUBLIC_KEY'] = self.public_key
        ctx = make_context('keeper.example.com')
        key = rest_api.get_server_public_key(ctx)
        self.assertEqual(crypto.unload_ec_public_key(key), utils.base64_url_decode(self.public_key))
        self.assertEqual(ctx.server_key_id, 7)
        mock_get.assert_not_called()

    @patch('keepercommander.rest_api.requests.get')
    def test_environment_key_id(self, mock_get):
        os.environ['KEEPER_SERVER_PUBLIC_KEY'] = self.public_key
        os.environ['KEEPER_SERVER_PUBLIC_KEY_ID'] = '11'
        ctx = make_context('keeper.example.com')
        rest_api.get_server_public_key(ctx)
        self.assertEqual(ctx.server_key_id, 11)

    @patch('keepercommander.rest_api.requests.get')
    def test_key_is_per_host(self, mock_get):
        mock_get.side_effect = Exception('unreachable')
        rest_api.set_server_public_key('keeper.example.com', 7, self.public_key)
        other = make_context('other.example.com')
        other.server_key_id = 7
        self.assertIs(rest_api.get_server_public_key(other), rest_api.SERVER_PUBLIC_KEYS[7])
        cloud = make_context('keepersecurity.com')
        cloud.server_key_id = 7
        self.assertIs(rest_api.get_server_public_key(cloud), rest_api.SERVER_PUBLIC_KEYS[7])

    @patch('keepercommander.rest_api.requests.get')
    def test_fetch_failure_falls_back_to_built_in_keys(self, mock_get):
        mock_get.side_effect = Exception('connection refused')
        ctx = make_context('localhost:8080')
        ctx.server_key_id = 7
        self.assertIs(rest_api.get_server_public_key(ctx), rest_api.SERVER_PUBLIC_KEYS[7])
        self.assertIn('connection refused', rest_api.self_managed_key_error(ctx))

    @patch('keepercommander.rest_api.requests.get')
    def test_not_a_server_key(self, mock_get):
        rs = make_server_key_response(self.public_key)
        rs.json.side_effect = ValueError('not JSON')
        mock_get.return_value = rs
        ctx = make_context('keeper.example.com')
        ctx.server_key_id = 7
        self.assertIs(rest_api.get_server_public_key(ctx), rest_api.SERVER_PUBLIC_KEYS[7])

    def test_invalid_keys_are_refused(self):
        with self.assertRaises(ValueError):
            rest_api.set_server_public_key('keeper.example.com', 3, self.public_key)
        with self.assertRaises(ValueError):
            rest_api.set_server_public_key('keeper.example.com', 7, 'not-a-key')

    def test_load_server_keys(self):
        rest_api.load_server_keys({'server_keys': {
            'keeper.example.com': {'key_id': 7, 'public_key': self.public_key},
            'bad.example.com': {'key_id': 7, 'public_key': 'not-a-key'},
        }})
        self.assertIn('keeper.example.com', rest_api._configured_server_keys)
        self.assertNotIn('bad.example.com', rest_api._configured_server_keys)

    @patch('keepercommander.rest_api.requests.get')
    def test_unverified_connection_does_not_fetch(self, mock_get):
        mock_get.return_value = make_server_key_response(self.public_key)
        ctx = make_context('keeper.example.com')
        ctx.certificate_check = False
        ctx.server_key_id = 7
        self.assertIs(rest_api.get_server_public_key(ctx), rest_api.SERVER_PUBLIC_KEYS[7])
        mock_get.assert_not_called()
        self.assertIn('not verified', rest_api.self_managed_key_error(ctx))

    @patch('keepercommander.rest_api.requests.get')
    def test_plain_http_does_not_fetch(self, mock_get):
        mock_get.return_value = make_server_key_response(self.public_key)
        ctx = make_context('http://keeper.example.com')
        ctx.server_key_id = 7
        self.assertIs(rest_api.get_server_public_key(ctx), rest_api.SERVER_PUBLIC_KEYS[7])
        mock_get.assert_not_called()
        self.assertIn('plain HTTP', rest_api.self_managed_key_error(ctx))

    @patch('keepercommander.rest_api.requests.get')
    def test_key_set_by_user_over_unverified_connection_warns(self, mock_get):
        rest_api.set_server_public_key('keeper.example.com', 7, self.public_key)
        rest_api.set_server_insecure('keeper.example.com', True)
        ctx = make_context('keeper.example.com')
        with self.assertLogs(level='WARNING') as logs:
            key = rest_api.get_server_public_key(ctx)
        self.assertEqual(crypto.unload_ec_public_key(key), utils.base64_url_decode(self.public_key))
        self.assertIn('not verified', '\n'.join(logs.output))
        mock_get.assert_not_called()

    def test_insecure_is_per_host(self):
        rest_api.set_server_insecure('keeper.example.com', True)
        self.assertIs(make_context('keeper.example.com').certificate_check, False)
        self.assertIsNot(make_context('other.example.com').certificate_check, False)
        self.assertIsNot(make_context('keepersecurity.com').certificate_check, False)
        with self.assertRaises(ValueError):
            rest_api.set_server_insecure('keepersecurity.com', True)

    def test_load_insecure_from_config(self):
        rest_api.load_server_keys({'server_keys': {'keeper.example.com': {'insecure': True}}})
        self.assertTrue(rest_api.is_server_insecure('keeper.example.com'))
        self.assertNotIn('keeper.example.com', rest_api._configured_server_keys)


class TestExecuteRest(SelfManagedKeyTestCase):
    @patch('keepercommander.rest_api.requests.post')
    @patch('keepercommander.rest_api.requests.get')
    def test_transmission_key_is_encrypted_to_the_server_key(self, mock_get, mock_post):
        mock_get.return_value = make_server_key_response(self.public_key)
        mock_post.return_value = make_success_response()
        ctx = make_context('keeper.example.com')
        rest_api.execute_rest(ctx, 'authentication/register_device', proto.ApiRequestPayload())

        request = proto.ApiRequest()
        request.ParseFromString(mock_post.call_args[1]['data'])
        self.assertEqual(request.publicKeyId, 7)
        transmission_key = crypto.decrypt_ec(request.encryptedTransmissionKey, self.private_key)
        self.assertEqual(transmission_key, ctx.transmission_key)

    @patch('keepercommander.rest_api.requests.post')
    @patch('keepercommander.rest_api.requests.get')
    def test_rejected_key_stops_with_clear_error(self, mock_get, mock_post):
        mock_get.return_value = make_server_key_response(self.public_key)
        mock_post.return_value = make_key_error_response()
        ctx = make_context('keeper.example.com')
        with self.assertRaises(KeeperApiError) as cm:
            rest_api.execute_rest(ctx, 'authentication/register_device', proto.ApiRequestPayload())
        self.assertIn(rest_api.server_key_fingerprint(self.public_key), cm.exception.message)
        self.assertEqual(mock_post.call_count, 1)

    @patch('keepercommander.rest_api.requests.post')
    @patch('keepercommander.rest_api.requests.get')
    def test_no_key_found_stops_with_clear_error(self, mock_get, mock_post):
        mock_get.side_effect = Exception('404 Not Found')
        mock_post.return_value = make_key_error_response()
        ctx = make_context('keeper.example.com')
        with self.assertRaises(KeeperApiError) as cm:
            rest_api.execute_rest(ctx, 'authentication/register_device', proto.ApiRequestPayload())
        self.assertIn('--public-key', cm.exception.message)
        self.assertEqual(mock_post.call_count, 1)


    @patch('keepercommander.rest_api.requests.post')
    @patch('keepercommander.rest_api.requests.get')
    def test_failed_fetch_is_tried_again_when_the_key_is_rejected(self, mock_get, mock_post):
        mock_get.side_effect = [Exception('timed out'), Exception('timed out'),
                                make_server_key_response(self.public_key)]
        mock_post.side_effect = [make_key_error_response(), make_success_response()]
        ctx = make_context('keeper.example.com')
        rest_api.execute_rest(ctx, 'authentication/register_device', proto.ApiRequestPayload())
        self.assertEqual(mock_post.call_count, 2)
        request = proto.ApiRequest()
        request.ParseFromString(mock_post.call_args[1]['data'])
        self.assertEqual(crypto.decrypt_ec(request.encryptedTransmissionKey, self.private_key),
                         ctx.transmission_key)

    @patch('keepercommander.rest_api.requests.post')
    @patch('keepercommander.rest_api.requests.get')
    def test_changed_server_key_is_fetched_again(self, mock_get, mock_post):
        _, old_public_key = make_key_pair()
        mock_get.side_effect = [make_server_key_response(old_public_key),
                                make_server_key_response(self.public_key)]
        mock_post.side_effect = [make_key_error_response(), make_success_response()]
        ctx = make_context('keeper.example.com')
        rest_api.execute_rest(ctx, 'authentication/register_device', proto.ApiRequestPayload())
        self.assertEqual(mock_post.call_count, 2)
        request = proto.ApiRequest()
        request.ParseFromString(mock_post.call_args[1]['data'])
        self.assertEqual(crypto.decrypt_ec(request.encryptedTransmissionKey, self.private_key),
                         ctx.transmission_key)

    @patch('keepercommander.rest_api.requests.post')
    @patch('keepercommander.rest_api.requests.get')
    def test_key_set_by_user_is_not_fetched_again(self, mock_get, mock_post):
        rest_api.set_server_public_key('keeper.example.com', 7, self.public_key)
        mock_post.return_value = make_key_error_response()
        ctx = make_context('keeper.example.com')
        with self.assertRaises(KeeperApiError) as cm:
            rest_api.execute_rest(ctx, 'authentication/register_device', proto.ApiRequestPayload())
        self.assertIn('from config.json', cm.exception.message)
        mock_get.assert_not_called()
        self.assertEqual(mock_post.call_count, 1)


class TestServerCommand(SelfManagedKeyTestCase):
    def make_params(self, config_filename):
        params = KeeperParams(config_filename=config_filename, config={'user': 'a@example.com'})
        params.server = 'keeper.example.com'
        return params

    def test_set_save_and_clear_key(self):
        from keepercommander import cli
        with tempfile.TemporaryDirectory() as d:
            config_filename = os.path.join(d, 'config.json')
            with open(config_filename, 'w') as fd:
                json.dump({'user': 'a@example.com'}, fd)
            params = self.make_params(config_filename)

            cli.server_command(params, f'--key-id 7 --public-key {self.public_key}')
            with open(config_filename) as fd:
                saved = json.load(fd)
            self.assertEqual(saved['user'], 'a@example.com')
            self.assertEqual(saved['server_keys']['keeper.example.com'],
                             {'key_id': 7, 'public_key': self.public_key})
            self.assertIn('keeper.example.com', rest_api._configured_server_keys)

            cli.server_command(params, '--clear-key')
            with open(config_filename) as fd:
                saved = json.load(fd)
            self.assertNotIn('server_keys', saved)
            self.assertNotIn('keeper.example.com', rest_api._configured_server_keys)

    def test_insecure_is_saved_and_cleared(self):
        from keepercommander import cli
        with tempfile.TemporaryDirectory() as d:
            config_filename = os.path.join(d, 'config.json')
            params = self.make_params(config_filename)
            with self.assertLogs(level='WARNING') as logs:
                cli.server_command(params, '--insecure')
            self.assertIn('--public-key', '\n'.join(logs.output))
            with open(config_filename) as fd:
                self.assertEqual(json.load(fd)['server_keys'], {'keeper.example.com': {'insecure': True}})
            self.assertIs(params.rest_context.certificate_check, False)

            cli.server_command(params, f'--key-id 7 --public-key {self.public_key}')
            with open(config_filename) as fd:
                self.assertEqual(json.load(fd)['server_keys']['keeper.example.com'],
                                 {'insecure': True, 'key_id': 7, 'public_key': self.public_key})

            cli.server_command(params, '--clear-key')
            with open(config_filename) as fd:
                self.assertNotIn('server_keys', json.load(fd))
            self.assertIsNot(params.rest_context.certificate_check, False)

    def test_mistyped_region_is_refused(self):
        from keepercommander import cli
        with tempfile.TemporaryDirectory() as d:
            params = self.make_params(os.path.join(d, 'config.json'))
            with self.assertLogs(level='ERROR'):
                cli.server_command(params, 'EUU')
            self.assertEqual(params.server, 'keeper.example.com')

    def test_cloud_host_refuses_insecure(self):
        from keepercommander import cli
        with tempfile.TemporaryDirectory() as d:
            params = self.make_params(os.path.join(d, 'config.json'))
            with self.assertLogs(level='ERROR'):
                cli.server_command(params, 'EU --insecure')
            self.assertEqual(INSECURE_SERVER_HOSTS, set())

    def test_cloud_host_refuses_a_key(self):
        from keepercommander import cli
        with tempfile.TemporaryDirectory() as d:
            params = self.make_params(os.path.join(d, 'config.json'))
            with self.assertLogs(level='ERROR'):
                cli.server_command(params, f'US --key-id 7 --public-key {self.public_key}')
            self.assertEqual(rest_api._configured_server_keys, {})

    def test_logged_in_refuses_a_change(self):
        from keepercommander import cli
        with tempfile.TemporaryDirectory() as d:
            params = self.make_params(os.path.join(d, 'config.json'))
            params.session_token = 'token'
            with self.assertLogs(level='WARNING'):
                cli.server_command(params, f'--key-id 7 --public-key {self.public_key}')
            self.assertEqual(rest_api._configured_server_keys, {})


if __name__ == '__main__':
    unittest.main()
