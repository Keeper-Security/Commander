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
        self.context = RestApiContext(server='https://smk.example.test')
        self.context.disable_qrc()

    def tearDown(self):
        rest_api.SERVER_PUBLIC_KEYS.clear()
        rest_api.SERVER_PUBLIC_KEYS.update(self._saved_keys)
        self._ksm_keys.clear()
        self._ksm_keys.update(self._saved_ksm_keys)
        rest_api._server_key_fetch_attempted.clear()

    def test_registers_the_published_key_in_commander_and_the_ksm_sdk(self):
        _, key_b64 = _new_server_key()
        body = {'serverPublicKeyId': 7, 'serverPublicKey': key_b64, 'fingerprint': 'SHA256:x'}
        with mock.patch('requests.get', return_value=_response(200, body)) as get:
            self.assertEqual(rest_api._fetch_server_public_key(self.context), 7)
        get.assert_called_once()
        self.assertEqual(get.call_args[0][0], 'https://smk.example.test/api/rest/server_public_key')
        self.assertEqual(utils.base64_url_encode(crypto.unload_ec_public_key(rest_api.SERVER_PUBLIC_KEYS[7])), key_b64)
        self.assertEqual(self._ksm_keys['7'], key_b64)

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

    def test_execute_rest_retries_with_the_fetched_key(self):
        private_key, key_b64 = _new_server_key()
        server_public = crypto.load_ec_public_key(utils.base64_url_decode(key_b64))

        def post(url, data, **kwargs):
            # Answer like a server whose own key is private_key: reject anything else with key_id -1.
            rq = proto.ApiRequest()
            rq.ParseFromString(data)
            if rest_api.SERVER_PUBLIC_KEYS.get(rq.publicKeyId) is None or \
                    crypto.unload_ec_public_key(rest_api.SERVER_PUBLIC_KEYS[rq.publicKeyId]) != \
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
        def post(url, data, **kwargs):
            return _response(200, content=b'', content_type='application/octet-stream')

        with mock.patch('requests.post', side_effect=post), mock.patch('requests.get') as get:
            rest_api.execute_rest(self.context, 'authentication/start_login', proto.ApiRequestPayload())
        get.assert_not_called()


if __name__ == '__main__':
    unittest.main()
