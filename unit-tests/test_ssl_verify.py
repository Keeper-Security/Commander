import os
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


if __name__ == '__main__':
    unittest.main()
