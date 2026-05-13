import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.attachments import (
    AttachmentMigrator,
    FakeAttachmentClient,
    load_manifest,
)


class LoadManifestTests(unittest.TestCase):
    def test_reads_source_and_target_columns(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            t.write('source_uid,target_uid\n')
            t.write('src1,tgt1\n')
            t.write('src2,tgt2\n')
            path = t.name
        try:
            pairs = load_manifest(path)
        finally:
            os.unlink(path)
        self.assertEqual(pairs, [
            {'source_uid': 'src1', 'target_uid': 'tgt1'},
            {'source_uid': 'src2', 'target_uid': 'tgt2'},
        ])

    def test_skips_rows_with_missing_columns(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            t.write('source_uid,target_uid\n')
            t.write('src1,\n')
            t.write(',tgt2\n')
            t.write('src3,tgt3\n')
            path = t.name
        try:
            pairs = load_manifest(path)
        finally:
            os.unlink(path)
        self.assertEqual([p['source_uid'] for p in pairs], ['src3'])


class AttachmentMigratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_skip_when_no_attachments(self):
        client = FakeAttachmentClient(downloads={})
        migrator = AttachmentMigrator(client, self.tmp)
        summary = migrator.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['skip'], 1)
        self.assertEqual(summary['per_record'][0]['status'], 'SKIP')

    def test_pass_uploads_all_files(self):
        client = FakeAttachmentClient(downloads={
            's1': [('a.txt', b'hello'), ('b.pdf', b'world')],
        })
        migrator = AttachmentMigrator(client, self.tmp)
        summary = migrator.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['pass'], 1)
        self.assertEqual(summary['per_record'][0]['files_uploaded'], 2)
        upload_calls = [c for c in client.calls if c[0] == 'upload_attachment']
        self.assertEqual(len(upload_calls), 2)

    def test_fail_when_one_upload_fails(self):
        client = FakeAttachmentClient(
            downloads={'s1': [('ok.txt', b'x'), ('bad.bin', b'y')]},
            upload_fail_paths={'bad.bin'},
        )
        migrator = AttachmentMigrator(client, self.tmp)
        summary = migrator.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['fail'], 1)
        self.assertEqual(summary['per_record'][0]['files_uploaded'], 1)
        self.assertEqual(summary['per_record'][0]['files_failed'], 1)
        self.assertIn('bad.bin', summary['per_record'][0]['errors'][0])

    def test_runs_multiple_pairs_and_aggregates(self):
        client = FakeAttachmentClient(downloads={
            's1': [('a.txt', b'x')],
            's2': [],
            's3': [('b.txt', b'y'), ('c.txt', b'z')],
        })
        migrator = AttachmentMigrator(client, self.tmp)
        summary = migrator.run([
            {'source_uid': 's1', 'target_uid': 't1'},
            {'source_uid': 's2', 'target_uid': 't2'},
            {'source_uid': 's3', 'target_uid': 't3'},
        ])
        self.assertEqual(summary['total'], 3)
        self.assertEqual(summary['pass'], 2)
        self.assertEqual(summary['skip'], 1)


class TwoPhaseDownloadUploadTests(unittest.TestCase):
    """V12a: cross-tenant attachments without holding two sessions.

    Downloader (source session) writes staging.json + files.
    Uploader (target session) reads staging.json + uploads.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_download_writes_staging_manifest_and_files(self):
        from keepercommander.commands.keeper_tenant_migrate.attachments import AttachmentDownloader

        client = FakeAttachmentClient(downloads={
            'S1': [('a.txt', b'alpha'), ('b.txt', b'beta')],
            'S2': [],   # no attachments
            'S3': [('c.txt', b'charlie')],
        })
        downloader = AttachmentDownloader(client, self.tmp, delay=0.0,
                                            sleeper=lambda _s: None)
        summary = downloader.run(['S1', 'S2', 'S3'])

        self.assertEqual(summary['total'], 3)
        self.assertEqual(summary['total_files'], 3)
        import json
        manifest = os.path.join(self.tmp, 'staging.json')
        self.assertTrue(os.path.exists(manifest))
        with open(manifest) as f:
            idx = json.load(f)
        self.assertEqual(sorted(idx['S1']), ['a.txt', 'b.txt'])
        self.assertEqual(idx['S2'], [])
        self.assertEqual(idx['S3'], ['c.txt'])
        self.assertTrue(os.path.exists(os.path.join(self.tmp, 'S1', 'a.txt')))
        self.assertTrue(os.path.exists(os.path.join(self.tmp, 'S3', 'c.txt')))

    def test_upload_reads_staging_manifest_and_uploads(self):
        from keepercommander.commands.keeper_tenant_migrate.attachments import (
            AttachmentDownloader, AttachmentUploader,
        )

        src_client = FakeAttachmentClient(downloads={
            'S1': [('pic.png', b'png')],
            'S2': [('doc.pdf', b'pdf'), ('note.txt', b'n')],
        })
        AttachmentDownloader(src_client, self.tmp, delay=0.0,
                               sleeper=lambda _s: None).run(['S1', 'S2'])

        tgt_client = FakeAttachmentClient()
        uploader = AttachmentUploader(tgt_client, self.tmp, delay=0.0,
                                        sleeper=lambda _s: None)
        summary = uploader.run([
            {'source_uid': 'S1', 'target_uid': 'T1'},
            {'source_uid': 'S2', 'target_uid': 'T2'},
        ])

        self.assertEqual(summary['total'], 2)
        self.assertEqual(summary['pass'], 2)
        self.assertEqual(summary['fail'], 0)
        uploads = [c for c in tgt_client.calls
                    if c[0] == 'upload_attachment']
        # FakeAttachmentClient stores ('upload_attachment', (target_uid, file_path))
        filenames = {os.path.basename(c[1][1]) for c in uploads}
        self.assertEqual(filenames, {'pic.png', 'doc.pdf', 'note.txt'})

    def test_upload_without_prior_download_skips_gracefully(self):
        from keepercommander.commands.keeper_tenant_migrate.attachments import AttachmentUploader

        tgt_client = FakeAttachmentClient()
        uploader = AttachmentUploader(tgt_client, self.tmp, delay=0.0,
                                        sleeper=lambda _s: None)
        summary = uploader.run([
            {'source_uid': 'S1', 'target_uid': 'T1'},
        ])
        self.assertEqual(summary['skip'], 1)
        self.assertEqual(summary['pass'], 0)

    def test_upload_falls_back_to_listdir_when_manifest_absent(self):
        # Pre-v1.2 staging dirs lack staging.json — scan the dir.
        from keepercommander.commands.keeper_tenant_migrate.attachments import AttachmentUploader

        os.makedirs(os.path.join(self.tmp, 'S1'))
        with open(os.path.join(self.tmp, 'S1', 'legacy.txt'), 'wb') as f:
            f.write(b'ok')

        tgt_client = FakeAttachmentClient()
        uploader = AttachmentUploader(tgt_client, self.tmp, delay=0.0,
                                        sleeper=lambda _s: None)
        summary = uploader.run([
            {'source_uid': 'S1', 'target_uid': 'T1'},
        ])
        self.assertEqual(summary['pass'], 1)


class FileRefMapCaptureTests(unittest.TestCase):
    """Bug 56 / v1.6 — fileRef extension. Verify that the upload phase
    pairs source file UIDs (from list_record_file_uids) with target
    file UIDs (from upload_attachment_with_uid) and the run summary
    surfaces a flat source_file_uid → target_file_uid map for
    downstream records-references-rewrite consumption."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_upload_emits_file_uid_pairs(self):
        from keepercommander.commands.keeper_tenant_migrate.attachments import (
            AttachmentDownloader,
            AttachmentUploader,
        )
        # Source carries 2 attachments on record S1 with file UIDs
        # F-src-1 + F-src-2; target assigns F-tgt-1 + F-tgt-2.
        src_client = FakeAttachmentClient(
            downloads={'S1': [('a.txt', b'a'), ('b.txt', b'b')]},
            source_file_uids={'S1': ['F-src-1', 'F-src-2']},
        )
        tgt_client = FakeAttachmentClient(
            target_file_uids={'a.txt': 'F-tgt-1', 'b.txt': 'F-tgt-2'},
        )
        AttachmentDownloader(src_client, self.tmp, delay=0.0,
                              sleeper=lambda _s: None).run(['S1'])
        uploader = AttachmentUploader(tgt_client, self.tmp, delay=0.0,
                                       sleeper=lambda _s: None)
        summary = uploader.run([
            {'source_uid': 'S1', 'target_uid': 'T1'},
        ])
        self.assertEqual(summary['pass'], 1)
        # The flat map for downstream consumers
        self.assertEqual(
            summary['file_uid_map'],
            {'F-src-1': 'F-tgt-1', 'F-src-2': 'F-tgt-2'},
        )

    def test_upload_without_uid_capture_emits_empty_map(self):
        # Client without source_file_uids → no pairs available → map empty.
        # (back-compat path for pre-v1.6 staging dirs missing UID metadata.)
        from keepercommander.commands.keeper_tenant_migrate.attachments import (
            AttachmentDownloader,
            AttachmentUploader,
        )
        src_client = FakeAttachmentClient(
            downloads={'S1': [('a.txt', b'a')]},
            # Omit source_file_uids — simulates a source client that
            # doesn't expose list_record_file_uids (or returns empty).
        )
        AttachmentDownloader(src_client, self.tmp, delay=0.0,
                              sleeper=lambda _s: None).run(['S1'])
        tgt = FakeAttachmentClient()
        uploader = AttachmentUploader(tgt, self.tmp, delay=0.0,
                                       sleeper=lambda _s: None)
        summary = uploader.run([
            {'source_uid': 'S1', 'target_uid': 'T1'},
        ])
        self.assertEqual(summary['pass'], 1)
        self.assertEqual(summary['file_uid_map'], {})

    def test_remap_uid_refs_with_file_ref_keys(self):
        # End-to-end: references walker + remapper with FILE_REF_KEYS
        # rewrites a fileRef value via the file_uid_map.
        from keepercommander.commands.keeper_tenant_migrate.references import (
            FILE_REF_KEYS,
            remap_uid_refs,
        )
        record_value = {'fileRef': ['F-src-1', 'F-src-2']}
        new, stats = remap_uid_refs(
            record_value,
            uid_map={'F-src-1': 'F-tgt-1', 'F-src-2': 'F-tgt-2'},
            ref_keys=FILE_REF_KEYS,
        )
        self.assertEqual(new, {'fileRef': ['F-tgt-1', 'F-tgt-2']})
        self.assertEqual(stats['remapped'], 2)
        self.assertEqual(stats['unknown'], 0)


if __name__ == '__main__':
    unittest.main()
