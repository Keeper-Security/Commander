"""Smoke: tenant-migrate records-attachments-{download,upload} end-to-end.

Two-phase attachments flow exercised against the kwarg-strict stub.

Phase 1 (download): drives RecordDownloadAttachmentCommand for each
source UID. The stub patches .execute() to a no-op, so no files are
actually staged — but the staging.json index is written and every call
flows through the kwarg-strict gate.

Phase 2 (upload): reads pre-staged files from disk and dispatches
RecordUploadAttachmentCommand per file. We pre-populate the staging
dir with byte-shaped fixtures so the uploader has real files to walk.
"""

import csv
import json
import os
import shutil
import unittest

from keepercommander.commands.record_edit import (
    RecordDownloadAttachmentCommand, RecordUploadAttachmentCommand,
)

from keepercommander.commands.keeper_tenant_migrate.commands import (
    RecordsAttachmentsDownloadCommand, RecordsAttachmentsUploadCommand,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import (
    StubAssertionError, StubCommander, build_smoke_params,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


def _write_manifest(path, pairs):
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['source_uid', 'target_uid'])
        w.writeheader()
        for src, tgt in pairs:
            w.writerow({'source_uid': src, 'target_uid': tgt})


def _write_uid_list(path, uids):
    with open(path, 'w') as f:
        for u in uids:
            f.write(u + '\n')


class RecordsAttachmentsSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('records-attachments')
        self.staging = os.path.join(self.run_dir, 'staging')
        self.uid_list = os.path.join(self.run_dir, 'source_uids.txt')
        self.manifest = os.path.join(self.run_dir, 'manifest.csv')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_download_then_upload_round_trip(self):
        # Phase 1 — download. The stub no-ops the actual SDK call, so
        # the per-uid directory stays empty. We assert the call landed
        # on RecordDownloadAttachmentCommand with the expected kwargs.
        _write_uid_list(self.uid_list, ['UID-A', 'UID-B'])
        params = build_smoke_params()
        with StubCommander() as stub:
            dl_summary = RecordsAttachmentsDownloadCommand().execute(
                params, source_uids=self.uid_list, staging_dir=self.staging,
                delay=0.0, batch_size=0,
            )
            dl_kwargs = stub.recorder.kwargs_for(
                'RecordDownloadAttachmentCommand')
            self.assertEqual(len(dl_kwargs), 2,
                              'expected one download call per UID')
            for kw in dl_kwargs:
                self.assertIn('records', kw)
                self.assertIn('out_dir', kw)
        self.assertEqual(dl_summary['total'], 2)
        self.assertEqual(dl_summary['total_files'], 0,
                          'stub does not stage real files')
        # staging.json index gets written even when no files arrive.
        self.assertTrue(os.path.exists(
            os.path.join(self.staging, 'staging.json')))

        # Phase 2 — upload. Seed two synthetic files under each
        # source_uid dir so the uploader has something to dispatch.
        for uid in ('UID-A', 'UID-B'):
            os.makedirs(os.path.join(self.staging, uid), exist_ok=True)
            with open(os.path.join(self.staging, uid, f'{uid}-1.txt'),
                       'w') as f:
                f.write(f'fixture for {uid}\n')
        # Update staging.json so the uploader's index sees the files
        # rather than falling back to a directory listing.
        with open(os.path.join(self.staging, 'staging.json'), 'w') as f:
            json.dump({'UID-A': ['UID-A-1.txt'],
                       'UID-B': ['UID-B-1.txt']}, f)

        _write_manifest(self.manifest, [('UID-A', 'TGT-A'), ('UID-B', 'TGT-B')])
        with StubCommander() as stub:
            up_summary = RecordsAttachmentsUploadCommand().execute(
                params, manifest=self.manifest, staging_dir=self.staging,
                delay=0.0, batch_size=0, run_dir=self.run_dir,
                resume=False, force_restart=False,
            )
            up_kwargs = stub.recorder.kwargs_for(
                'RecordUploadAttachmentCommand')
            self.assertEqual(len(up_kwargs), 2,
                              'expected one upload call per (uid, file) pair')
            for kw in up_kwargs:
                # `record` is the target UID (single string, not list).
                # `file` is a list per record_edit's parser.
                self.assertIn('record', kw)
                self.assertIn(kw['record'], {'TGT-A', 'TGT-B'})
                self.assertIsInstance(kw['file'], list)
                self.assertTrue(kw['file'][0].endswith('.txt'))
        self.assertEqual(up_summary['total'], 2)
        self.assertEqual(up_summary['pass'], 2,
                          'stub returns truthy from RecordUploadAttachmentCommand')
        # Audit log was written next to the manifest by the upload path.
        self.assertTrue(os.path.exists(
            os.path.join(self.run_dir, 'audit.log')))

    def test_upload_kwarg_strict_drift_is_caught(self):
        """Records-attachments-upload sends `record` + `file` through
        RecordUploadAttachmentCommand. Drift either dest and the smoke
        layer must surface a StubAssertionError."""
        os.makedirs(os.path.join(self.staging, 'UID-Z'), exist_ok=True)
        with open(os.path.join(self.staging, 'UID-Z', 'z.txt'), 'w') as f:
            f.write('z\n')
        with open(os.path.join(self.staging, 'staging.json'), 'w') as f:
            json.dump({'UID-Z': ['z.txt']}, f)
        _write_manifest(self.manifest, [('UID-Z', 'TGT-Z')])

        params = build_smoke_params()
        with StubCommander(extra_strict_drift={
                RecordUploadAttachmentCommand: {'file'}}):
            # The uploader catches non-Exception failures internally;
            # StubAssertionError extends BaseException to escape the
            # `except Exception` swallow in commander_clients._call. The
            # backoff Retry layer also extends except Exception, so the
            # assertion propagates all the way out.
            with self.assertRaises(StubAssertionError):
                RecordsAttachmentsUploadCommand().execute(
                    params, manifest=self.manifest,
                    staging_dir=self.staging,
                    delay=0.0, batch_size=0, run_dir=self.run_dir,
                    resume=False, force_restart=False,
                )


if __name__ == '__main__':
    unittest.main()
