"""
Round-trip unit tests for RDP `security` mode and cert-ignore fields across the
three connection types that carry them: RDP (security + ignoreCert), Kubernetes
(ignoreCert), and RBI/HTTP (ignoreInitialSslCert).

Each test loads a `pam project import` YAML/JSON-shaped connection dict via
`ConnectionSettings*.load()` and re-serializes it via `to_record_dict()`, asserting
the on-record JSON keys match what Web Vault / Commander expect
(field-data-pam-settings.ts): `security`, `ignoreCert`, `ignoreInitialSslCert`.
"""

import unittest

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_import.base import (
        ConnectionSettingsRDP, ConnectionSettingsKubernetes, ConnectionSettingsHTTP, RDPSecurity,
    )
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import pam_import.base: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestRDPSecurityRoundTrip(unittest.TestCase):
    def test_security_and_ignore_cert_round_trip(self):
        for mode in ('any', 'nla', 'tls', 'vmconnect', 'rdp'):
            with self.subTest(mode=mode):
                obj = ConnectionSettingsRDP.load({
                    'protocol': 'rdp',
                    'port': '3389',
                    'security': mode,
                    'ignore_server_cert': True,
                })
                self.assertEqual(obj.security, RDPSecurity.map(mode))
                self.assertTrue(obj.ignoreCert)
                record_dict = obj.to_record_dict()
                self.assertEqual(record_dict['security'], mode)
                self.assertEqual(record_dict['ignoreCert'], True)

    def test_ignore_cert_false_round_trip(self):
        obj = ConnectionSettingsRDP.load({'protocol': 'rdp', 'ignore_server_cert': False})
        self.assertFalse(obj.ignoreCert)
        record_dict = obj.to_record_dict()
        self.assertEqual(record_dict['ignoreCert'], False)

    def test_security_absent_not_written(self):
        obj = ConnectionSettingsRDP.load({'protocol': 'rdp'})
        self.assertIsNone(obj.security)
        record_dict = obj.to_record_dict()
        self.assertNotIn('security', record_dict)
        self.assertNotIn('ignoreCert', record_dict)

    def test_invalid_security_mode_maps_to_none(self):
        obj = ConnectionSettingsRDP.load({'protocol': 'rdp', 'security': 'bogus'})
        self.assertIsNone(obj.security)
        record_dict = obj.to_record_dict()
        self.assertNotIn('security', record_dict)


@unittest.skipIf(skip_tests, skip_reason)
class TestKubernetesIgnoreCertRoundTrip(unittest.TestCase):
    def test_ignore_cert_round_trip(self):
        obj = ConnectionSettingsKubernetes.load({
            'protocol': 'kubernetes',
            'ignore_server_cert': True,
            'ca_certificate': 'ca-data',
            'client_certificate': 'client-cert-data',
            'client_key': 'client-key-data',
            'namespace': 'prod',
        })
        self.assertTrue(obj.ignoreCert)
        record_dict = obj.to_record_dict()
        self.assertEqual(record_dict['ignoreCert'], True)
        self.assertEqual(record_dict['caCert'], 'ca-data')
        self.assertEqual(record_dict['clientCert'], 'client-cert-data')
        self.assertEqual(record_dict['clientKey'], 'client-key-data')
        self.assertEqual(record_dict['namespace'], 'prod')

    def test_ignore_cert_false_round_trip(self):
        obj = ConnectionSettingsKubernetes.load({'protocol': 'kubernetes', 'ignore_server_cert': False})
        self.assertFalse(obj.ignoreCert)
        record_dict = obj.to_record_dict()
        self.assertEqual(record_dict['ignoreCert'], False)

    def test_ignore_cert_absent_not_written(self):
        obj = ConnectionSettingsKubernetes.load({'protocol': 'kubernetes'})
        self.assertIsNone(obj.ignoreCert)
        record_dict = obj.to_record_dict()
        self.assertNotIn('ignoreCert', record_dict)

    def test_no_security_field_on_kubernetes(self):
        """Kubernetes has no security-mode concept (RDP-only)."""
        self.assertFalse(hasattr(ConnectionSettingsKubernetes(), 'security'))


@unittest.skipIf(skip_tests, skip_reason)
class TestRBIIgnoreInitialSslCertRoundTrip(unittest.TestCase):
    def test_ignore_server_cert_maps_to_ignore_initial_ssl_cert(self):
        """RBI/HTTP uses the same YAML key (ignore_server_cert) as RDP/K8s, but the
        on-record field name differs: ignoreInitialSslCert, not ignoreCert."""
        obj = ConnectionSettingsHTTP.load({'protocol': 'http', 'ignore_server_cert': True})
        self.assertTrue(obj.ignoreInitialSslCert)
        record_dict = obj.to_record_dict()
        self.assertEqual(record_dict['ignoreInitialSslCert'], True)
        self.assertNotIn('ignoreCert', record_dict)

    def test_ignore_server_cert_false_round_trip(self):
        obj = ConnectionSettingsHTTP.load({'protocol': 'http', 'ignore_server_cert': False})
        self.assertFalse(obj.ignoreInitialSslCert)
        record_dict = obj.to_record_dict()
        self.assertEqual(record_dict['ignoreInitialSslCert'], False)

    def test_ignore_server_cert_absent_not_written(self):
        obj = ConnectionSettingsHTTP.load({'protocol': 'http'})
        self.assertIsNone(obj.ignoreInitialSslCert)
        record_dict = obj.to_record_dict()
        self.assertNotIn('ignoreInitialSslCert', record_dict)


if __name__ == '__main__':
    unittest.main()
