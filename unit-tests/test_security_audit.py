from types import SimpleNamespace
from unittest import TestCase, mock

from keepercommander import security_audit


class TestSecurityAudit(TestCase):
    def setUp(self):
        self.record = SimpleNamespace(record_uid='record_uid')
        self.params = SimpleNamespace(
            enterprise_ec_key=b'enterprise-key',
            security_score_data={},
            breach_watch_security_data={},
        )

    def test_needs_security_audit_updates_missing_security_data_for_weak_password(self):
        self.params.security_score_data = {
            self.record.record_uid: {
                'data': {'password': 'weak-password', 'score': 0},
                'revision': 7,
            }
        }

        with mock.patch('keepercommander.security_audit._get_pass', return_value='weak-password'), \
                mock.patch('keepercommander.security_audit.get_security_score', return_value=0):
            self.assertTrue(security_audit.needs_security_audit(self.params, self.record))

    def test_needs_security_audit_updates_missing_security_data_for_nonzero_score(self):
        self.params.security_score_data = {
            self.record.record_uid: {
                'data': {'password': 'StrongPass123!', 'score': 100},
                'revision': 9,
            }
        }

        with mock.patch('keepercommander.security_audit._get_pass', return_value='StrongPass123!'), \
                mock.patch('keepercommander.security_audit.get_security_score', return_value=100):
            self.assertTrue(security_audit.needs_security_audit(self.params, self.record))

    def test_needs_security_audit_skips_when_no_password_and_no_security_data(self):
        with mock.patch('keepercommander.security_audit._get_pass', return_value=None), \
                mock.patch('keepercommander.security_audit.get_security_score', return_value=None):
            self.assertFalse(security_audit.needs_security_audit(self.params, self.record))

    def test_needs_security_audit_skips_when_security_data_already_exists_for_weak_password(self):
        self.params.security_score_data = {
            self.record.record_uid: {
                'data': {'password': 'weak-password', 'score': 0},
                'revision': 7,
            }
        }
        self.params.breach_watch_security_data = {
            self.record.record_uid: {'revision': 7}
        }

        with mock.patch('keepercommander.security_audit._get_pass', return_value='weak-password'), \
                mock.patch('keepercommander.security_audit.get_security_score', return_value=0):
            self.assertFalse(security_audit.needs_security_audit(self.params, self.record))

    def test_needs_security_audit_updates_when_security_data_revision_is_stale(self):
        self.params.security_score_data = {
            self.record.record_uid: {
                'data': {'password': 'StrongPass123!', 'score': 100},
                'revision': 11,
            }
        }
        self.params.breach_watch_security_data = {
            self.record.record_uid: {'revision': 7}
        }

        with mock.patch('keepercommander.security_audit._get_pass', return_value='StrongPass123!'), \
                mock.patch('keepercommander.security_audit.get_security_score', return_value=100):
            self.assertTrue(security_audit.needs_security_audit(self.params, self.record))

    def test_needs_security_audit_updates_when_password_is_removed(self):
        self.params.security_score_data = {
            self.record.record_uid: {
                'data': {'password': 'StrongPass123!', 'score': 100},
                'revision': 11,
            }
        }

        with mock.patch('keepercommander.security_audit._get_pass', return_value=None), \
                mock.patch('keepercommander.security_audit.get_security_score', return_value=None):
            self.assertTrue(security_audit.needs_security_audit(self.params, self.record))
