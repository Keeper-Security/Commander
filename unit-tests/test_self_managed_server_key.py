"""Tests for the server key of a self-managed Keeper deployment in rest_api.py.

Verifies:
- Keeper cloud hosts keep using the built-in SERVER_PUBLIC_KEYS, and fetch nothing
- Any other host uses, in order: a configured key, KEEPER_SERVER_PUBLIC_KEY, the key fetched from
  <host>/status/api/connect, and the built-in keys only when none of these is available
- A key set for one host is never used for another
- execute_rest encrypts the transmission key to the self-managed key, and stops with a clear error
  instead of retrying when the server rejects it
- A key fetched without TLS verification prints a warning
- The server command sets, saves and clears a key
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
from keepercommander.error import KeeperApiError
from keepercommander.params import RestApiContext, KeeperParams
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


def make_server_key_response(public_key, key_id=7):
    rs = MagicMock()
    rs.status_code = 200
    rs.json.return_value = {'server': 'keeper.example.com', 'serverPublicKeyId': key_id,
                            'serverPublicKey': public_key, 'fingerprint': 'SHA256:x'}
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
        env = patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('KEEPER_SERVER_PUBLIC_KEY', None)
        os.environ.pop('KEEPER_SERVER_KEY_ID', None)
        self.private_key, self.public_key = make_key_pair()

    def tearDown(self):
        rest_api._configured_server_keys.clear()
        rest_api._resolved_server_keys.clear()
        rest_api._server_key_errors.clear()


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
        # The value scripts/key-fingerprint.py prints for this key.
        key = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
        self.assertTrue(rest_api.server_key_fingerprint(key).startswith('SHA256:'))
        self.assertNotIn('=', rest_api.server_key_fingerprint(key))


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
        self.assertEqual(mock_get.call_args[0][0], 'https://keeper.example.com/status/api/connect')

        # Fetched once per host
        rest_api.get_server_public_key(make_context('keeper.example.com'))
        self.assertEqual(mock_get.call_count, 1)

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
    def test_unverified_fetch_warns(self, mock_get):
        mock_get.return_value = make_server_key_response(self.public_key)
        ctx = make_context('keeper.example.com')
        ctx.certificate_check = False
        with self.assertLogs(level='WARNING') as logs:
            rest_api.get_server_public_key(ctx)
        self.assertIn('UNVERIFIED CONNECTION', '\n'.join(logs.output))
        self.assertFalse(rest_api._resolved_server_keys['keeper.example.com'].verified)

    @patch('keepercommander.rest_api.requests.get')
    def test_plain_http_fetch_warns(self, mock_get):
        mock_get.return_value = make_server_key_response(self.public_key)
        ctx = make_context('http://keeper.example.com')
        with self.assertLogs(level='WARNING') as logs:
            rest_api.get_server_public_key(ctx)
        self.assertIn('plain HTTP', '\n'.join(logs.output))
        self.assertEqual(mock_get.call_args[0][0], 'http://keeper.example.com/status/api/connect')


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
