import os
import tempfile
import unittest

from keepercommander import utils
from keepercommander.params import KeeperParams


def _reset_ssl_cert_cache():
    utils._cached_ssl_cert_file = utils._SSL_CERT_UNSET


class TestSslVerify(unittest.TestCase):
    def setUp(self):
        self._saved_env = {
            'VERIFY_SSL': os.environ.get('VERIFY_SSL'),
            'KEEPER_SSL_CERT_FILE': os.environ.get('KEEPER_SSL_CERT_FILE'),
        }
        _reset_ssl_cert_cache()
        # PAM DAG tests set VERIFY_SSL=false without always restoring it.
        os.environ['VERIFY_SSL'] = 'TRUE'
        os.environ.pop('KEEPER_SSL_CERT_FILE', None)

    def tearDown(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        _reset_ssl_cert_cache()

    def test_keeper_ssl_cert_file_none_disables_http_verify(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = 'none'
        params = KeeperParams()
        self.assertFalse(params.ssl_verify)

    def test_verify_ssl_false_legacy_fallback(self):
        os.environ['VERIFY_SSL'] = 'FALSE'
        self.assertFalse(utils.resolve_ssl_verify())

    def test_config_certificate_check_false_disables_verify(self):
        params = KeeperParams()
        params.rest_context.certificate_check = False
        self.assertFalse(params.ssl_verify)

    def test_keeper_ssl_cert_file_custom_path_via_ssl_verify(self):
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as cert_file:
            cert_file.write(b'fake-ca')
            cert_path = cert_file.name
        try:
            os.environ['KEEPER_SSL_CERT_FILE'] = cert_path
            params = KeeperParams()
            self.assertEqual(params.ssl_verify, cert_path)
        finally:
            os.unlink(cert_path)


if __name__ == '__main__':
    unittest.main()
