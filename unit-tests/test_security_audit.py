from types import SimpleNamespace
from unittest import TestCase, mock

from keepercommander import security_audit
from keepercommander.error import KeeperApiError


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


class TestUpdateSecurityAuditData(TestCase):
    def setUp(self):
        self.params = SimpleNamespace(
            enterprise_ec_key=b'enterprise-key',
            forbid_rsa=False,
            security_score_data={},
        )
        self.rec_good = SimpleNamespace(record_uid='rec_good', record_key=b'key1')
        self.rec_deleted = SimpleNamespace(record_uid='rec_deleted', record_key=b'key2')
        self.rec_good2 = SimpleNamespace(record_uid='rec_good2', record_key=b'key3')

    @mock.patch('keepercommander.security_audit._build_security_data_request')
    @mock.patch('keepercommander.api.communicate_rest')
    def test_batch_success_no_retry(self, mock_comm_rest, mock_build_rq):
        mock_build_rq.return_value = mock.MagicMock()
        records = [self.rec_good, self.rec_good2]
        result = security_audit.update_security_audit_data(self.params, records)
        self.assertEqual(result, 2)
        mock_build_rq.assert_called_once_with(self.params, records)
        mock_comm_rest.assert_called_once()

    @mock.patch('keepercommander.security_audit._build_security_data_request')
    @mock.patch('keepercommander.api.communicate_rest')
    def test_missing_security_data_retries_individually(self, mock_comm_rest, mock_build_rq):
        mock_build_rq.return_value = mock.MagicMock()
        missing_data_error = KeeperApiError('missing_security_data', 'Missing Security Data')

        call_count = [0]
        def comm_rest_side_effect(params, rq, endpoint):
            call_count[0] += 1
            if call_count[0] == 1:
                raise missing_data_error

        mock_comm_rest.side_effect = comm_rest_side_effect
        records = [self.rec_good, self.rec_deleted, self.rec_good2]
        result = security_audit.update_security_audit_data(self.params, list(records))

        self.assertEqual(result, 3)
        # 1 batch call + 3 individual retry calls
        self.assertEqual(mock_comm_rest.call_count, 4)

    @mock.patch('keepercommander.security_audit._build_security_data_request')
    @mock.patch('keepercommander.api.communicate_rest')
    def test_missing_security_data_counts_individual_failures(self, mock_comm_rest, mock_build_rq):
        mock_build_rq.return_value = mock.MagicMock()
        missing_data_error = KeeperApiError('missing_security_data', 'Missing Security Data')

        call_count = [0]
        def comm_rest_side_effect(params, rq, endpoint):
            call_count[0] += 1
            if call_count[0] == 1:
                raise missing_data_error
            if call_count[0] == 3:
                raise missing_data_error

        mock_comm_rest.side_effect = comm_rest_side_effect
        records = [self.rec_good, self.rec_deleted, self.rec_good2]
        result = security_audit.update_security_audit_data(self.params, list(records))

        # rec_deleted fails individually, so 2 out of 3 succeed
        self.assertEqual(result, 2)

    @mock.patch('keepercommander.security_audit._build_security_data_request')
    @mock.patch('keepercommander.api.communicate_rest')
    def test_non_missing_data_ka_error_fails_entire_chunk(self, mock_comm_rest, mock_build_rq):
        mock_build_rq.return_value = mock.MagicMock()
        other_error = KeeperApiError('access_denied', 'Access Denied')
        mock_comm_rest.side_effect = other_error
        records = [self.rec_good, self.rec_good2]
        result = security_audit.update_security_audit_data(self.params, list(records))

        self.assertEqual(result, 0)
        # Only the batch call, no individual retries
        mock_comm_rest.assert_called_once()

    @mock.patch('keepercommander.security_audit._build_security_data_request')
    @mock.patch('keepercommander.api.communicate_rest')
    def test_generic_exception_fails_entire_chunk(self, mock_comm_rest, mock_build_rq):
        mock_build_rq.return_value = mock.MagicMock()
        mock_comm_rest.side_effect = Exception('network error')
        records = [self.rec_good, self.rec_good2]
        result = security_audit.update_security_audit_data(self.params, list(records))

        self.assertEqual(result, 0)
        mock_comm_rest.assert_called_once()
