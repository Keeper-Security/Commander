"""Smoke: tenant-migrate records-export — emits one JSON per record."""

import json
import os
import shutil
import unittest

from keepercommander.commands.keeper_tenant_migrate.commands import RecordsExportCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import StubCommander, build_smoke_params
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import (
    seed_record, writeable_run_dir,
)


class RecordsExportSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('records-export')
        self.out_dir = os.path.join(self.run_dir, 'export')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_records_export_emits_json_per_matching_record(self):
        params = build_smoke_params()
        seed_record(params, uid='UID-A', title='MIGTEST-Login-A',
                    fields=[{'type': 'login', 'value': ['a@x']}])
        seed_record(params, uid='UID-B', title='MIGTEST-Login-B',
                    fields=[{'type': 'password', 'value': ['s3cret']}])
        # A non-matching record so prefix filter has something to drop.
        seed_record(params, uid='UID-C', title='Personal-Login')

        with StubCommander():
            result = RecordsExportCommand().execute(
                params, output_dir=self.out_dir, prefix='MIGTEST-',
                folder_uids=[],
            )
        # 2 of 3 records matched the MIGTEST- prefix.
        self.assertEqual(result['written'], 2)
        emitted = sorted(f for f in os.listdir(self.out_dir)
                          if f.endswith('.json') and not f.startswith('SHA'))
        self.assertEqual(emitted, ['UID-A.json', 'UID-B.json'])

        # Each emitted file is JSON with the expected shape.
        for fname in emitted:
            with open(os.path.join(self.out_dir, fname)) as f:
                rec = json.load(f)
            self.assertIn('record_uid', rec)
            self.assertIn('title', rec)
            self.assertTrue(rec['title'].startswith('MIGTEST-'))
            # Plaintext file → 0600 mode.
            mode = os.stat(os.path.join(self.out_dir, fname)).st_mode & 0o777
            self.assertEqual(mode, 0o600)

        # SHA256SUMS sidecar must exist.
        manifest = os.path.join(self.out_dir, 'SHA256SUMS.txt')
        self.assertTrue(os.path.exists(manifest))


if __name__ == '__main__':
    unittest.main()
