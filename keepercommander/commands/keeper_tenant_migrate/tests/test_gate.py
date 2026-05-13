import csv
import datetime
import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.gate import (
    GateError,
    _sign,
    evaluate,
    read_checkpoint,
    write_checkpoint,
)


def _write_checks(path, rows):
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['phase', 'severity', 'message', 'detail'])
        for row in rows:
            w.writerow(row)


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.checks = os.path.join(self.tmp, 'checks.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_missing_checks_file(self):
        with self.assertRaises(GateError):
            evaluate('/does/not/exist', confirm_token='YES')

    def test_any_fail_blocks_gate(self):
        _write_checks(self.checks, [
            ['nodes', 'PASS', 'ok', ''],
            ['teams', 'FAIL', 'bad', ''],
        ])
        with self.assertRaises(GateError) as e:
            evaluate(self.checks, confirm_token='YES')
        self.assertIn('FAIL', str(e.exception))

    def test_requires_explicit_yes_token(self):
        _write_checks(self.checks, [['nodes', 'PASS', 'ok', '']])
        with self.assertRaises(GateError):
            evaluate(self.checks, confirm_token='')
        with self.assertRaises(GateError):
            evaluate(self.checks, confirm_token='y')

    def test_passes_with_no_fails_and_yes(self):
        _write_checks(self.checks, [['nodes', 'PASS', 'ok', '']])
        cp = evaluate(self.checks, confirm_token='YES')
        self.assertEqual(cp['checks_summary']['FAIL'], 0)
        self.assertIn('timestamp', cp)
        self.assertNotIn('signature', cp)  # evaluate returns unsigned

    def test_missing_reconcile_raises_if_provided(self):
        _write_checks(self.checks, [['nodes', 'PASS', 'ok', '']])
        with self.assertRaises(GateError):
            evaluate(self.checks, reconcile_md='/nonexistent/recon.md',
                     confirm_token='YES')


class CheckpointRoundtripTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cp_path = os.path.join(self.tmp, 'cp.json')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _fresh_cp(self):
        return {
            'timestamp': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'checks_path': '/x/checks.csv',
            'checks_summary': {'PASS': 5, 'FAIL': 0, 'SKIP': 0, 'WARN': 0},
            'reconcile_path': '',
        }

    def test_write_adds_signature_and_0600(self):
        written = write_checkpoint(self._fresh_cp(), self.cp_path)
        self.assertIn('signature', written)
        import stat
        mode = stat.S_IMODE(os.stat(self.cp_path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_read_accepts_fresh_valid_checkpoint(self):
        write_checkpoint(self._fresh_cp(), self.cp_path)
        read = read_checkpoint(self.cp_path)
        self.assertEqual(read['checks_path'], '/x/checks.csv')

    def test_tampered_signature_rejected(self):
        cp = self._fresh_cp()
        write_checkpoint(cp, self.cp_path)
        # Tamper with checks_path but keep signature
        with open(self.cp_path) as f:
            data = json.load(f)
        data['checks_path'] = '/evil/path'
        with open(self.cp_path, 'w') as f:
            json.dump(data, f)
        with self.assertRaises(GateError) as e:
            read_checkpoint(self.cp_path)
        self.assertIn('signature', str(e.exception))

    def test_expired_checkpoint_rejected(self):
        cp = {
            'timestamp': '2020-01-01T00:00:00Z',
            'checks_path': '', 'checks_summary': {}, 'reconcile_path': '',
        }
        write_checkpoint(cp, self.cp_path)
        with self.assertRaises(GateError) as e:
            read_checkpoint(self.cp_path, max_age_hours=72)
        self.assertIn('expired', str(e.exception))

    def test_invalid_timestamp_rejected(self):
        cp = {
            'timestamp': 'not-a-date',
            'checks_path': '', 'checks_summary': {}, 'reconcile_path': '',
        }
        write_checkpoint(cp, self.cp_path)
        with self.assertRaises(GateError):
            read_checkpoint(self.cp_path)

    def test_missing_file_rejected(self):
        with self.assertRaises(GateError):
            read_checkpoint('/nonexistent.json')

    def test_high2_future_timestamp_rejected(self):
        """HIGH-2 regression — a checkpoint claiming to be from the future
        (NTP step backwards, wrong system clock, tampered timestamp)
        previously passed the freshness check silently because
        `age.total_seconds() > max_age_hours * 3600` is False for
        negative ages. Post-fix raises GateError immediately.
        """
        import datetime
        future = (datetime.datetime.now(datetime.timezone.utc)
                  + datetime.timedelta(hours=2))
        cp = {
            'timestamp': future.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'checks_path': '', 'checks_summary': {}, 'reconcile_path': '',
        }
        write_checkpoint(cp, self.cp_path)
        with self.assertRaises(GateError) as e:
            read_checkpoint(self.cp_path)
        msg = str(e.exception).lower()
        self.assertIn('future', msg)
        # The error must surface the diagnostic causes so the operator
        # knows what to fix:
        self.assertIn('clock', msg)


class SignTests(unittest.TestCase):
    def test_sign_stable_on_repeated_calls(self):
        data = {'a': 1, 'b': [1, 2, 3]}
        self.assertEqual(_sign(data), _sign(data))

    def test_sign_ignores_signature_field_in_body(self):
        a = {'a': 1, 'signature': 'x'}
        b = {'a': 1, 'signature': 'y'}
        self.assertEqual(_sign(a), _sign(b))


if __name__ == '__main__':
    unittest.main()
