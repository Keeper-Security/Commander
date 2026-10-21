import json
import base64
import json
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from keepercommander import crypto, rest_api, utils
from keepercommander.params import RestApiContext
from keepercommander.proto import APIRequest_pb2 as proto


def _new_server_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    point = private_key.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint)
    return private_key, utils.base64_url_encode(point)


def _response(status, body=None, content_type='application/json', content=b''):
    rs = mock.Mock()
    rs.status_code = status
    rs.headers = {'Content-Type': content_type}
    rs.json.return_value = body
    rs.content = content
    return rs


class TestServerPublicKeyFetch(unittest.TestCase):
    def setUp(self):
        self._saved_keys = dict(rest_api.SERVER_PUBLIC_KEYS)
        from keeper_secrets_manager_core.keeper_globals import keeper_public_keys
        self._ksm_keys = keeper_public_keys
        self._saved_ksm_keys = dict(keeper_public_keys)
        rest_api._server_key_fetch_attempted.clear()
        rest_api._fetched_server_public_keys.clear()
        self.context = RestApiContext(server='https://smk.example.test')
        self.context.disable_qrc()

    def tearDown(self):
        rest_api.SERVER_PUBLIC_KEYS.clear()
        rest_api.SERVER_PUBLIC_KEYS.update(self._saved_keys)
        self._ksm_keys.clear()
        self._ksm_keys.update(self._saved_ksm_keys)
        rest_api._server_key_fetch_attempted.clear()
        rest_api._fetched_server_public_keys.clear()

    def test_registers_the_published_key_in_commander_and_the_ksm_sdk(self):
        _, key_b64 = _new_server_key()
        body = {'serverPublicKeyId': 7, 'serverPublicKey': key_b64, 'fingerprint': 'SHA256:x'}
        with mock.patch('requests.get', return_value=_response(200, body)) as get:
            self.assertEqual(rest_api._fetch_server_public_key(self.context), 7)
        get.assert_called_once()
        self.assertEqual(get.call_args[0][0], 'https://smk.example.test/api/rest/server_public_key')
        self.assertTrue(get.call_args.kwargs['verify'])
        self.assertEqual(
            utils.base64_url_encode(
                crypto.unload_ec_public_key(rest_api.get_server_public_key(self.context))
            ),
            key_b64,
        )
        # A server's key must not replace Keeper's built-in key for the same ID.
        self.assertIs(rest_api.SERVER_PUBLIC_KEYS[7], self._saved_keys[7])
        self.assertEqual(self._ksm_keys['7'], self._saved_ksm_keys['7'])
        self.assertEqual(rest_api.get_fetched_server_public_key(self.context), (7, key_b64))
        cloud_context = RestApiContext(server='https://keepersecurity.com')
        self.assertIs(
            rest_api.get_server_public_key(cloud_context),
            self._saved_keys[7],
        )

    def test_a_server_without_the_endpoint_changes_nothing(self):
        before = rest_api.SERVER_PUBLIC_KEYS[7]
        for rs in (_response(404, {'error': 'not_found'}), _response(200, None, 'text/html')):
            rest_api._server_key_fetch_attempted.clear()
            rs.json.side_effect = None if rs.status_code == 404 else ValueError('not json')
            with mock.patch('requests.get', return_value=rs):
                self.assertIsNone(rest_api._fetch_server_public_key(self.context))
        self.assertIs(rest_api.SERVER_PUBLIC_KEYS[7], before)

    def test_network_errors_and_bad_keys_are_swallowed(self):
        before = rest_api.SERVER_PUBLIC_KEYS[7]
        with mock.patch('requests.get', side_effect=OSError('connection refused')):
            self.assertIsNone(rest_api._fetch_server_public_key(self.context))
        rest_api._server_key_fetch_attempted.clear()
        bad = {'serverPublicKeyId': 7, 'serverPublicKey': 'not-a-key'}
        with mock.patch('requests.get', return_value=_response(200, bad)):
            self.assertIsNone(rest_api._fetch_server_public_key(self.context))
        self.assertIs(rest_api.SERVER_PUBLIC_KEYS[7], before)

    def test_asks_each_server_once(self):
        with mock.patch('requests.get', return_value=_response(404, {})) as get:
            rest_api._fetch_server_public_key(self.context)
            rest_api._fetch_server_public_key(self.context)
        get.assert_called_once()

    def test_switching_servers_resets_the_key_id(self):
        _, key_b64 = _new_server_key()
        rest_api._register_server_public_key(
            9, key_b64, 'https://smk.example.test/api/rest/'
        )
        self.context.server_key_id = 9
        self.context.server_base = 'https://keepersecurity.com/api/rest/'
        self.assertEqual(self.context.server_key_id, 7)
        self.assertIs(
            rest_api.get_server_public_key(self.context),
            self._saved_keys[7],
        )
        self.context.server_base = 'https://smk.example.test/api/rest/'
        fetched_key = rest_api.get_server_public_key(self.context)
        self.assertEqual(self.context.server_key_id, 9)
        self.assertEqual(
            crypto.unload_ec_public_key(fetched_key),
            utils.base64_url_decode(key_b64),
        )

    def test_execute_rest_retries_with_the_fetched_key(self):
        private_key, key_b64 = _new_server_key()
        server_public = crypto.load_ec_public_key(utils.base64_url_decode(key_b64))

        def post(url, data, **kwargs):
            # Answer like a server whose own key is private_key: reject anything else with key_id -1.
            rq = proto.ApiRequest()
            rq.ParseFromString(data)
            if rq.publicKeyId != self.context.server_key_id or \
                    crypto.unload_ec_public_key(rest_api.get_server_public_key(self.context)) != \
                    crypto.unload_ec_public_key(server_public):
                return _response(401, [{'key_id': -1, 'error': 'key', 'message': 'key'}])
            transmission_key = crypto.decrypt_ec(rq.encryptedTransmissionKey, private_key)
            return _response(200, content=crypto.encrypt_aes_v2(b'ok', transmission_key),
                             content_type='application/octet-stream')

        body = {'serverPublicKeyId': 7, 'serverPublicKey': key_b64}
        with mock.patch('requests.post', side_effect=post), \
                mock.patch('requests.get', return_value=_response(200, body)) as get:
            rs = rest_api.execute_rest(self.context, 'authentication/start_login', proto.ApiRequestPayload())
        self.assertEqual(rs, b'ok')
        get.assert_called_once()

    def test_keeper_cloud_never_calls_the_endpoint(self):
        cloud_context = RestApiContext(server='https://keepersecurity.com')
        cloud_context.disable_qrc()

        def post(url, data, **kwargs):
            return _response(200, content=b'', content_type='application/octet-stream')

        with mock.patch('requests.post', side_effect=post), mock.patch('requests.get') as get:
            rest_api.execute_rest(cloud_context, 'authentication/start_login', proto.ApiRequestPayload())
        get.assert_not_called()

    def test_generated_ksm_config_carries_fetched_key_to_other_processes(self):
        from keepercommander.commands.ksm import KSMCommand
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        _, key_b64 = _new_server_key()
        params = mock.Mock()
        params.config = {'server': 'smk.example.test'}
        params.rest_context = self.context
        storage = mock.Mock()
        storage.config = {
            ConfigKeys.KEY_HOSTNAME: 'https://smk.example.test',
            ConfigKeys.KEY_CLIENT_ID: base64.b64encode(b'c' * 64).decode(),
            ConfigKeys.KEY_PRIVATE_KEY: base64.b64encode(b'private').decode(),
            ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID: '7',
            ConfigKeys.KEY_APP_KEY: base64.b64encode(b'app').decode(),
        }
        sdk_args = []

        class FakeSecretsManager:
            def __init__(self, **kwargs):
                sdk_args.append(kwargs)

            def get_secrets(self, _record_uid):
                return []

        with mock.patch.object(
                rest_api, 'get_fetched_server_public_key', return_value=(7, key_b64)), \
                mock.patch('keeper_secrets_manager_core.SecretsManager', FakeSecretsManager), \
                mock.patch('keeper_secrets_manager_core.storage.InMemoryKeyValueStorage',
                           return_value=storage):
            result = KSMCommand.init_ksm_config(
                params, 'one-time-token', 'json', include_config_dict=True
            )

        self.assertEqual(sdk_args[0]['server_public_key_id'], '7')
        self.assertEqual(sdk_args[0]['server_public_key'], key_b64)
        config = result['config_dict']
        self.assertEqual(config[ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID.value], '7')
        self.assertEqual(config[ConfigKeys.KEY_SERVER_PUBLIC_KEY.value], key_b64)
        self.assertEqual(json.loads(result['config_str']), config)


if __name__ == '__main__':
    unittest.main()
