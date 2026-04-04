"""Tests for PR #1876: --siem NDJSON export for security-audit report."""

import json
import os
import stat
import tempfile
import unittest
from unittest.mock import MagicMock

from keepercommander.commands.security_audit import SecurityAuditReportCommand
from keepercommander.error import CommandError


class TestSiemExport(unittest.TestCase):
    """Test the _export_siem static method."""

    def _make_params(self, server='https://vault.example.com'):
        params = MagicMock()
        params.server = server
        return params

    def _sample_rows(self):
        return [
            {
                'email': 'alice@example.com',
                'name': 'Alice Smith',
                'sync_pending': 0,
                'weak': 2,
                'fair': 1,
                'medium': 3,
                'strong': 10,
                'reused': 1,
                'unique': 15,
                'securityScore': 72,
                'twoFactorChannel': 'Off',
                'node': 'Root',
            },
            {
                'email': 'bob@example.com',
                'name': 'Bob Jones',
                'sync_pending': 0,
                'weak': 0,
                'fair': 0,
                'medium': 0,
                'strong': 5,
                'reused': 0,
                'unique': 5,
                'securityScore': 100,
                'twoFactorChannel': 'TOTP',
                'node': 'Root',
            },
        ]

    def _fields(self):
        return ('email', 'name', 'sync_pending', 'weak', 'fair', 'medium',
                'strong', 'reused', 'unique', 'securityScore',
                'twoFactorChannel', 'node')

    def test_ndjson_output_format(self):
        """Each line should be valid JSON."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        lines = result.strip().split('\n')
        self.assertEqual(len(lines), 2)
        for line in lines:
            event = json.loads(line)
            self.assertEqual(event['event_type'], 'keeper.security_audit')
            self.assertIn('timestamp', event)
            self.assertIn('user', event)
            self.assertIn('risk_factors', event)

    def test_empty_rows_produces_empty_string(self):
        """Empty rows should produce empty string, not a blank line."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), [], self._fields(),
            show_breachwatch=False, filename=None)
        self.assertEqual(result, '')

    def test_trailing_newline(self):
        """Non-empty output should end with exactly one newline."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        self.assertTrue(result.endswith('\n'))
        self.assertFalse(result.endswith('\n\n'))

    def test_email_masked(self):
        """Email in SIEM output should be masked."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        event = json.loads(result.strip().split('\n')[0])
        email = event['user']['email']
        self.assertNotEqual(email, 'alice@example.com')
        self.assertIn('@example.com', email)
        self.assertIn('***', email)

    def test_name_masked(self):
        """Name in SIEM output should be masked."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        event = json.loads(result.strip().split('\n')[0])
        name = event['user']['name']
        self.assertNotEqual(name, 'Alice Smith')
        self.assertIn('***', name)

    def test_risk_factors_weak_passwords(self):
        """Users with weak > 0 should have weak_passwords risk factor."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        alice = json.loads(result.strip().split('\n')[0])
        self.assertIn('weak_passwords', alice['risk_factors'])

    def test_risk_factors_reused_passwords(self):
        """Users with reused > 0 should have reused_passwords risk factor."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        alice = json.loads(result.strip().split('\n')[0])
        self.assertIn('reused_passwords', alice['risk_factors'])

    def test_risk_factors_no_2fa(self):
        """Users with 2FA off should have no_2fa risk factor."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        alice = json.loads(result.strip().split('\n')[0])
        self.assertIn('no_2fa', alice['risk_factors'])

    def test_clean_user_no_risk_factors(self):
        """Users with strong passwords and 2FA should have no risk factors."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        bob = json.loads(result.strip().split('\n')[1])
        self.assertEqual(bob['risk_factors'], [])
        self.assertEqual(bob['security_score'], 100)

    def test_security_score_included(self):
        """Security score should be in the event when not BreachWatch."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), self._sample_rows(), self._fields(),
            show_breachwatch=False, filename=None)
        event = json.loads(result.strip().split('\n')[0])
        self.assertIn('security_score', event)
        self.assertEqual(event['security_score'], 72)

    def test_breachwatch_mode(self):
        """BreachWatch mode should use at_risk for risk factors."""
        bw_fields = ('email', 'name', 'sync_pending', 'at_risk', 'passed', 'ignored')
        bw_rows = [{'email': 'user@test.com', 'name': 'User', 'sync_pending': 0,
                     'at_risk': 3, 'passed': 10, 'ignored': 1}]
        result = SecurityAuditReportCommand._export_siem(
            self._make_params(), bw_rows, bw_fields,
            show_breachwatch=True, filename=None)
        event = json.loads(result.strip())
        self.assertIn('breach_exposure', event['risk_factors'])
        self.assertNotIn('security_score', event)

    def test_file_output_permissions(self):
        """File output should have 0600 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, 'report')
            SecurityAuditReportCommand._export_siem(
                self._make_params(), self._sample_rows(), self._fields(),
                show_breachwatch=False, filename=filepath)
            actual_path = filepath + '.ndjson'
            self.assertTrue(os.path.isfile(actual_path))
            mode = os.stat(actual_path).st_mode
            self.assertEqual(stat.S_IMODE(mode), 0o600)

    def test_file_output_auto_extension(self):
        """Files without extension should get .ndjson added."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, 'report')
            SecurityAuditReportCommand._export_siem(
                self._make_params(), self._sample_rows(), self._fields(),
                show_breachwatch=False, filename=filepath)
            self.assertTrue(os.path.isfile(filepath + '.ndjson'))

    def test_file_output_keeps_existing_extension(self):
        """Files with extension should keep it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, 'report.json')
            SecurityAuditReportCommand._export_siem(
                self._make_params(), self._sample_rows(), self._fields(),
                show_breachwatch=False, filename=filepath)
            self.assertTrue(os.path.isfile(filepath))

    def test_file_content_valid_ndjson(self):
        """File output should contain valid NDJSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, 'report.ndjson')
            SecurityAuditReportCommand._export_siem(
                self._make_params(), self._sample_rows(), self._fields(),
                show_breachwatch=False, filename=filepath)
            with open(filepath) as f:
                content = f.read()
            lines = content.strip().split('\n')
            self.assertEqual(len(lines), 2)
            for line in lines:
                json.loads(line)  # must not raise

    def test_source_field_from_params(self):
        """Source field should come from params.server."""
        result = SecurityAuditReportCommand._export_siem(
            self._make_params('https://my.keeper.io'), self._sample_rows(),
            self._fields(), show_breachwatch=False, filename=None)
        event = json.loads(result.strip().split('\n')[0])
        self.assertEqual(event['source'], 'https://my.keeper.io')


class TestSiemFlagValidation(unittest.TestCase):
    """Test that incompatible flag combinations are rejected."""

    def test_siem_with_record_details_raises(self):
        """--siem and --record-details should be rejected."""
        params = MagicMock()
        params.enterprise = True
        cmd = SecurityAuditReportCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, siem=True, record_details=True)
        self.assertIn('--siem and --record-details cannot be used together', str(ctx.exception))

    def test_siem_with_format_raises(self):
        """--siem and --format should be rejected."""
        params = MagicMock()
        params.enterprise = True
        cmd = SecurityAuditReportCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(params, siem=True, format='csv')
        self.assertIn('--siem produces NDJSON output exclusively', str(ctx.exception))

    def test_siem_flag_registered(self):
        """--siem flag should be registered in the parser."""
        from keepercommander.commands.security_audit import report_parser
        actions = {a.dest: a for a in report_parser._actions}
        self.assertIn('siem', actions)
        self.assertEqual(actions['siem'].const, True)


class TestPiiMasking(unittest.TestCase):
    """Test edge cases for the PII masking function."""

    def _mask(self, field_name, value):
        """Call _mask_pii indirectly through _export_siem."""
        rows = [{field_name: value, 'sync_pending': 0, 'weak': 0, 'fair': 0,
                 'medium': 0, 'strong': 0, 'reused': 0, 'unique': 0,
                 'securityScore': 100, 'twoFactorChannel': 'TOTP', 'node': 'Root'}]
        if field_name == 'email':
            rows[0]['name'] = 'Test'
        else:
            rows[0]['email'] = 'test@test.com'
        fields = ('email', 'name', 'sync_pending', 'weak', 'fair', 'medium',
                  'strong', 'reused', 'unique', 'securityScore',
                  'twoFactorChannel', 'node')
        result = SecurityAuditReportCommand._export_siem(
            MagicMock(server='test'), rows, fields,
            show_breachwatch=False, filename=None)
        event = json.loads(result.strip())
        return event['user'][field_name]

    def test_email_single_char_local(self):
        """Single character email local part should still mask."""
        masked = self._mask('email', 'a@example.com')
        self.assertIn('***', masked)
        self.assertIn('@example.com', masked)

    def test_email_no_at_sign(self):
        """Malformed email without @ should still mask."""
        masked = self._mask('email', 'noemail')
        self.assertIn('***', masked)
        self.assertNotEqual(masked, 'noemail')

    def test_name_single_char(self):
        """Single character name should return '***'."""
        masked = self._mask('name', 'J')
        self.assertEqual(masked, '***')

    def test_empty_email_passthrough(self):
        """Empty/falsy email should pass through."""
        masked = self._mask('email', '')
        self.assertEqual(masked, '')

    def test_none_name_passthrough(self):
        """None name should pass through."""
        masked = self._mask('name', None)
        self.assertIsNone(masked)

    def test_node_not_masked(self):
        """Node (organizational path) should NOT be masked — it's not PII."""
        rows = [{'email': 'test@test.com', 'name': 'Test', 'sync_pending': 0,
                 'weak': 0, 'fair': 0, 'medium': 0, 'strong': 5, 'reused': 0,
                 'unique': 5, 'securityScore': 100, 'twoFactorChannel': 'TOTP',
                 'node': 'Engineering/TeamA'}]
        fields = ('email', 'name', 'sync_pending', 'weak', 'fair', 'medium',
                  'strong', 'reused', 'unique', 'securityScore',
                  'twoFactorChannel', 'node')
        result = SecurityAuditReportCommand._export_siem(
            MagicMock(server='test'), rows, fields,
            show_breachwatch=False, filename=None
        )
        event = json.loads(result.strip())
        self.assertEqual(event['user']['node'], 'Engineering/TeamA')

    def test_numeric_fields_not_masked(self):
        """Non-sensitive fields should not be masked."""
        rows = [{'email': 'test@test.com', 'name': 'Test', 'sync_pending': 0,
                 'weak': 5, 'fair': 0, 'medium': 0, 'strong': 0, 'reused': 0,
                 'unique': 0, 'securityScore': 50, 'twoFactorChannel': 'Off', 'node': 'Root'}]
        fields = ('email', 'name', 'sync_pending', 'weak', 'fair', 'medium',
                  'strong', 'reused', 'unique', 'securityScore',
                  'twoFactorChannel', 'node')
        result = SecurityAuditReportCommand._export_siem(
            MagicMock(server='test'), rows, fields,
            show_breachwatch=False, filename=None)
        event = json.loads(result.strip())
        self.assertEqual(event['user']['weak'], 5)
        self.assertEqual(event['user']['securityScore'], 50)


if __name__ == '__main__':
    unittest.main()
