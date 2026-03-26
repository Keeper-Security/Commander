import os
import json
from collections import Counter
from unittest import TestCase

import pytest

from data_config import read_config_file
from keepercommander import api, cli, security_audit
from keepercommander.commands.security_audit import SecurityAuditReportCommand, SecurityAuditSyncCommand
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams
from keepercommander.utils import is_pw_fair, is_pw_strong, is_pw_weak
from keepercommander import vault


@pytest.mark.integration
class TestSecurityAuditRefresh(TestCase):
    params = None  # type: KeeperParams

    @classmethod
    def setUpClass(cls):
        cls.params = KeeperParams()
        read_config_file(cls.params, os.environ.get('KEEPER_CONFIG', '../config.json'))
        api.login(cls.params)
        api.query_enterprise(cls.params)
        api.sync_down(cls.params, record_types=True)

    @classmethod
    def tearDownClass(cls):
        try:
            if cls.params:
                cli.do_command(cls.params, 'delete-all --force')
                api.sync_down(cls.params, record_types=True)
        except Exception:
            pass

    def setUp(self):
        api.sync_down(self.params, record_types=True)
        cli.do_command(self.params, 'delete-all --force')
        api.sync_down(self.params, record_types=True)

    def add_legacy_record(self, title, password, extra_fields=''):
        command = (
            f'record-add --title="{title}" --record-type=legacy '
            f'login=security.audit@example.com password={password} url=https://example.com'
        )
        if extra_fields:
            command = f'{command} {extra_fields}'
        record_uid = cli.do_command(self.params, command)
        api.sync_down(self.params, record_types=True)
        return record_uid

    def add_typed_login_record(self, title, password):
        command = (
            f'record-add --title="{title}" --record-type=login '
            f'login=security.audit@example.com password={password} url=https://example.com'
        )
        try:
            record_uid = cli.do_command(self.params, command)
        except CommandError as err:
            if 'Record type "login" cannot be found.' in str(err):
                self.skipTest('Typed login record type is not available in this integration environment')
            raise
        api.sync_down(self.params, record_types=True)
        return record_uid

    def update_password(self, record_uid, password):
        cli.do_command(self.params, f'record-update --record={record_uid} password={password}')
        api.sync_down(self.params, record_types=True)

    def rotate_password(self, record_uid):
        cli.do_command(self.params, f'rotate -- {record_uid}')
        api.sync_down(self.params, record_types=True)

    def hard_clear_current_user_security_data(self):
        SecurityAuditSyncCommand().execute(
            self.params,
            email=[self.params.user],
            hard=True,
            force=True,
        )
        api.sync_down(self.params, record_types=True)

    def current_user_report_row(self):
        report = json.loads(SecurityAuditReportCommand().execute(self.params, save=True, format='json'))
        return next((x for x in report if x.get('email') == self.params.user), None)

    def current_user_debug_row(self):
        report = json.loads(SecurityAuditReportCommand().execute(self.params, debug=True, format='json'))
        return next((x for x in report if x.get('vault_owner') == self.params.user), None)

    def get_score_payload(self, record_uid):
        return (self.params.security_score_data.get(record_uid) or {}).get('data', {})

    def assert_record_security_state(self, record_uid, password, score, has_security_data):
        score_data = self.get_score_payload(record_uid)
        self.assertEqual(score_data.get('password'), password)
        self.assertEqual(score_data.get('score'), score)

        security_data = self.params.breach_watch_security_data.get(record_uid)
        if has_security_data:
            self.assertIsNotNone(security_data)
        else:
            self.assertIsNone(security_data)

    def assert_record_revisions_aligned(self, record_uid):
        score_revision = (self.params.security_score_data.get(record_uid) or {}).get('revision')
        security_revision = (self.params.breach_watch_security_data.get(record_uid) or {}).get('revision')
        self.assertEqual(score_revision, security_revision)

    def assert_record_has_no_password_score_data(self, record_uid):
        self.assertEqual(self.get_score_payload(record_uid), {})

    def expected_summary(self, record_uids):
        summary = {
            'weak': 0,
            'fair': 0,
            'medium': 0,
            'strong': 0,
            'reused': 0,
            'unique': 0,
            'securityScore': 25,
        }
        password_counts = Counter()
        total = 0
        for record_uid in record_uids:
            score_data = self.get_score_payload(record_uid)
            password = score_data.get('password')
            score = score_data.get('score')
            if password is None or score is None:
                continue
            total += 1
            password_counts[password] += 1
            if is_pw_strong(score):
                summary['strong'] += 1
            elif is_pw_fair(score):
                summary['fair'] += 1
            elif is_pw_weak(score):
                summary['weak'] += 1
            else:
                summary['medium'] += 1

        summary['reused'] = sum(count for count in password_counts.values() if count > 1)
        summary['unique'] = total - summary['reused']
        if total > 0:
            strong_ratio = summary['strong'] / total
            unique_ratio = summary['unique'] / total
            summary['securityScore'] = int(100 * round((strong_ratio + unique_ratio + 1) / 4, 2))
        return summary

    def assert_debug_pending(self):
        debug_row = self.current_user_debug_row()
        self.assertIsNotNone(debug_row)
        raw_old = debug_row.get('old_incremental_data') or []
        raw_curr = debug_row.get('current_incremental_data') or []
        self.assertTrue(any(item is not None for item in raw_old + raw_curr))

    def assert_admin_summary_matches_records(self, record_uids, expect_debug_pending=True):
        if expect_debug_pending:
            self.assert_debug_pending()

        row = self.current_user_report_row()
        self.assertIsNotNone(row)
        expected = self.expected_summary(record_uids)
        for key, value in expected.items():
            self.assertEqual(row.get(key), value, msg=f'{key} mismatch: {row}')
        self.assertIsNone(self.current_user_debug_row())

    def test_summary_alignment_for_add_update_reuse_and_password_removal(self):
        record_uid_1 = self.add_legacy_record('Security audit lifecycle-1', 'aa')
        self.assert_record_security_state(record_uid_1, 'aa', 0, True)
        self.assert_record_revisions_aligned(record_uid_1)
        self.assert_admin_summary_matches_records([record_uid_1])

        self.update_password(record_uid_1, 'weak-password')
        self.assert_record_security_state(record_uid_1, 'weak-password', 41, True)
        self.assert_record_revisions_aligned(record_uid_1)
        self.assert_admin_summary_matches_records([record_uid_1])

        self.update_password(record_uid_1, 'A1!bcdefgh')
        self.assert_record_security_state(record_uid_1, 'A1!bcdefgh', 61, True)
        self.assert_record_revisions_aligned(record_uid_1)
        self.assert_admin_summary_matches_records([record_uid_1])

        self.update_password(record_uid_1, 'StrongPass123!')
        self.assert_record_security_state(record_uid_1, 'StrongPass123!', 100, True)
        self.assert_record_revisions_aligned(record_uid_1)
        self.assert_admin_summary_matches_records([record_uid_1])

        record_uid_2 = self.add_legacy_record('Security audit lifecycle-2', 'StrongPass123!')
        self.assert_record_security_state(record_uid_2, 'StrongPass123!', 100, True)
        self.assert_record_revisions_aligned(record_uid_2)
        self.assert_admin_summary_matches_records([record_uid_1, record_uid_2])

        self.update_password(record_uid_1, '')
        self.assert_record_has_no_password_score_data(record_uid_1)
        self.assert_admin_summary_matches_records([record_uid_1, record_uid_2])

    def test_rotation_and_hard_clear_repair_align_admin_summary(self):
        record_uid = self.add_legacy_record('Security audit rotate/repair', 'aa', extra_fields='cmdr:plugin=noop')
        self.assert_record_security_state(record_uid, 'aa', 0, True)
        self.assert_record_revisions_aligned(record_uid)
        self.assert_admin_summary_matches_records([record_uid])

        self.rotate_password(record_uid)
        rotated_score_data = self.get_score_payload(record_uid)
        self.assertIsInstance(rotated_score_data.get('password'), str)
        self.assertTrue(rotated_score_data.get('password'))
        self.assertIn('score', rotated_score_data)
        self.assertIsNotNone(self.params.breach_watch_security_data.get(record_uid))
        self.assert_record_revisions_aligned(record_uid)
        self.assert_admin_summary_matches_records([record_uid])

        self.hard_clear_current_user_security_data()
        self.assertIsNotNone(self.get_score_payload(record_uid))
        self.assertIsNone(self.params.breach_watch_security_data.get(record_uid))

        record = vault.KeeperRecord.load(self.params, record_uid)
        self.assertTrue(security_audit.needs_security_audit(self.params, record))

        cli.do_command(self.params, f'sync-security-data {record_uid} --quiet')
        api.sync_down(self.params, record_types=True)
        self.assertIsNotNone(self.params.breach_watch_security_data.get(record_uid))
        self.assert_record_revisions_aligned(record_uid)
        self.assert_admin_summary_matches_records([record_uid])

    def test_typed_login_add_and_update_align_admin_summary(self):
        record_uid = self.add_typed_login_record('Security audit typed login', 'aa')
        self.assert_record_security_state(record_uid, 'aa', 0, True)
        self.assert_record_revisions_aligned(record_uid)
        self.assert_admin_summary_matches_records([record_uid])

        self.update_password(record_uid, 'StrongPass123!')
        self.assert_record_security_state(record_uid, 'StrongPass123!', 100, True)
        self.assert_record_revisions_aligned(record_uid)
        self.assert_admin_summary_matches_records([record_uid])
