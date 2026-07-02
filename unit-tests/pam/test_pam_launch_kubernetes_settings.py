"""
Unit tests for `_extract_kubernetes_settings` in pam_launch/terminal_connection.py.

The record (and Web Vault) store Kubernetes cert fields as `ignoreCert` / `caCert` /
`clientCert` (matching `pam_import/base.py` ConnectionSettingsKubernetes and
field-data-pam-settings.ts). This extractor previously read the wrong, non-existent
keys (`ignoreServerCertificate` / `caCertificate` / `clientCertificate`), so cert-ignore
and custom CA/client certs never reached the guacd connection for Kubernetes launches.
"""

import unittest

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_launch.terminal_connection import _extract_kubernetes_settings
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import terminal_connection: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestExtractKubernetesSettings(unittest.TestCase):
    def test_reads_record_shaped_cert_fields(self):
        connection = {
            'namespace': 'prod',
            'pod': 'my-pod',
            'container': 'my-container',
            'ignoreCert': True,
            'caCert': 'ca-cert-data',
            'clientCert': 'client-cert-data',
            'clientKey': 'client-key-data',
        }
        result = _extract_kubernetes_settings(connection)
        self.assertEqual(result['ignoreServerCertificate'], True)
        self.assertEqual(result['caCertificate'], 'ca-cert-data')
        self.assertEqual(result['clientCertificate'], 'client-cert-data')
        self.assertEqual(result['clientKey'], 'client-key-data')

    def test_legacy_expanded_keys_are_ignored(self):
        """Confirms the fix: the old (wrong) key names are no longer read."""
        connection = {
            'ignoreServerCertificate': True,
            'caCertificate': 'legacy-ca',
            'clientCertificate': 'legacy-client-cert',
        }
        result = _extract_kubernetes_settings(connection)
        self.assertEqual(result['ignoreServerCertificate'], False)
        self.assertEqual(result['caCertificate'], '')
        self.assertEqual(result['clientCertificate'], '')

    def test_defaults_when_fields_absent(self):
        result = _extract_kubernetes_settings({})
        self.assertEqual(result['namespace'], 'default')
        self.assertEqual(result['pod'], '')
        self.assertEqual(result['container'], '')
        self.assertEqual(result['ignoreServerCertificate'], False)
        self.assertEqual(result['caCertificate'], '')
        self.assertEqual(result['clientCertificate'], '')
        self.assertEqual(result['clientKey'], '')


if __name__ == '__main__':
    unittest.main()
