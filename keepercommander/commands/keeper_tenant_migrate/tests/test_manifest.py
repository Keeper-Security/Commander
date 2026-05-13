import csv
import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.manifest import (
    load_source_uid_by_title,
    load_target_uid_by_title,
    pair_by_title,
    write_manifest_csv,
)


class LoadSourceUidByTitleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_reads_title_and_uid_from_each_json(self):
        for uid, title in [('uid-1', 'First'), ('uid-2', 'Second')]:
            with open(os.path.join(self.tmp, f'{uid}.json'), 'w') as f:
                json.dump({'record_uid': uid, 'title': title}, f)
        out = load_source_uid_by_title(self.tmp)
        self.assertEqual(out, {'First': ['uid-1'], 'Second': ['uid-2']})

    def test_groups_duplicate_titles(self):
        for uid, title in [('u1', 'Same'), ('u2', 'Same'), ('u3', 'Other')]:
            with open(os.path.join(self.tmp, f'{uid}.json'), 'w') as f:
                json.dump({'record_uid': uid, 'title': title}, f)
        out = load_source_uid_by_title(self.tmp)
        self.assertEqual(sorted(out['Same']), ['u1', 'u2'])

    def test_missing_dir_returns_empty(self):
        self.assertEqual(load_source_uid_by_title('/nonexistent'), {})

    def test_falls_back_to_filename_when_record_uid_missing(self):
        with open(os.path.join(self.tmp, 'bare.json'), 'w') as f:
            json.dump({'title': 'X'}, f)
        out = load_source_uid_by_title(self.tmp)
        self.assertEqual(out, {'X': ['bare']})


class LoadTargetUidByTitleTests(unittest.TestCase):
    def test_collects_titles_from_record_cache(self):
        class FakeRec:
            def __init__(self, title):
                self.title = title
        records = {'t1': FakeRec('First'), 't2': FakeRec('First'), 't3': FakeRec('Second')}
        out = load_target_uid_by_title(
            record_cache=records,
            get_record=lambda uid: records.get(uid),
        )
        self.assertEqual(sorted(out['First']), ['t1', 't2'])
        self.assertEqual(out['Second'], ['t3'])

    def test_empty_cache_returns_empty(self):
        self.assertEqual(
            load_target_uid_by_title({}, lambda _u: None),
            {},
        )


class PairByTitleTests(unittest.TestCase):
    def test_clean_one_to_one_pairing(self):
        src = {'A': ['u1'], 'B': ['u2']}
        tgt = {'A': ['t1'], 'B': ['t2']}
        pairs, ambig, src_only, tgt_only = pair_by_title(src, tgt)
        self.assertEqual(len(pairs), 2)
        self.assertEqual(ambig, [])
        self.assertEqual(src_only, [])
        self.assertEqual(tgt_only, [])

    def test_source_only_listed(self):
        src = {'A': ['u1'], 'MissingOnTarget': ['u2']}
        tgt = {'A': ['t1']}
        _, _, src_only, _ = pair_by_title(src, tgt)
        self.assertEqual(src_only, ['MissingOnTarget'])

    def test_target_only_listed(self):
        src = {'A': ['u1']}
        tgt = {'A': ['t1'], 'OnlyOnTarget': ['t2']}
        _, _, _, tgt_only = pair_by_title(src, tgt)
        self.assertEqual(tgt_only, ['OnlyOnTarget'])

    def test_ambiguous_flagged_by_default(self):
        src = {'Dup': ['u1', 'u2']}
        tgt = {'Dup': ['t1', 't2']}
        pairs, ambig, _, _ = pair_by_title(src, tgt)
        self.assertEqual(pairs, [])
        self.assertEqual(len(ambig), 1)
        self.assertEqual(ambig[0]['title'], 'Dup')

    def test_allow_ambiguous_pairs_positionally(self):
        src = {'Dup': ['u1', 'u2', 'u3']}
        tgt = {'Dup': ['t1', 't2']}
        pairs, ambig, _, _ = pair_by_title(src, tgt, allow_ambiguous=True)
        # 2 positional pairs + ambig record for the orphan
        self.assertEqual(len(pairs), 2)
        self.assertEqual(pairs[0], {'source_uid': 'u1', 'target_uid': 't1', 'title': 'Dup'})
        self.assertEqual(pairs[1], {'source_uid': 'u2', 'target_uid': 't2', 'title': 'Dup'})
        self.assertEqual(len(ambig), 1)


class WriteManifestCsvTests(unittest.TestCase):
    def test_emits_header_and_rows(self):
        pairs = [
            {'source_uid': 'u1', 'target_uid': 't1', 'title': 'A'},
            {'source_uid': 'u2', 'target_uid': 't2', 'title': 'B'},
        ]
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as t:
            path = t.name
        try:
            write_manifest_csv(pairs, path)
            with open(path, newline='') as f:
                rows = list(csv.DictReader(f))
        finally:
            os.unlink(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['source_uid'], 'u1')
        self.assertEqual(rows[0]['target_uid'], 't1')

    def test_sha256_sidecar_emitted_for_scenario_02(self):
        """Closes red-team Scenario 02 structurally — manifest.csv has
        a sha256 sidecar emitted at write-time, so any consumer
        (declarative SDK import path, or operator running
        `sha256sum -c`) can detect manifest.csv tamper from the
        moment manifest.csv exists, without waiting for `verify` to
        generate the run-dir SHA256SUMS.txt later.
        """
        import hashlib
        import stat
        pairs = [{'source_uid': 'u1', 'target_uid': 't1', 'title': 'A'}]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'manifest.csv')
            write_manifest_csv(pairs, path)

            sidecar = path + '.sha256'
            self.assertTrue(os.path.exists(sidecar),
                            'sha256 sidecar missing — Scenario 02 regression')

            # Sidecar permissions: 0600 (matches other sensitive files
            # in the run-dir).
            mode = stat.S_IMODE(os.stat(sidecar).st_mode)
            self.assertEqual(mode, 0o600)

            # Sidecar format: GNU coreutils '<hex>  <filename>' with
            # filename as basename (so `sha256sum -c` works from cwd).
            with open(sidecar) as f:
                line = f.read().strip()
            digest_field, _, fname_field = line.partition('  ')
            self.assertEqual(fname_field, 'manifest.csv')
            self.assertEqual(len(digest_field), 64)

            # Digest matches actual file content.
            with open(path, 'rb') as f:
                expected = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(digest_field, expected,
                             'sidecar digest does not match manifest.csv')

    def test_sha256_sidecar_detects_tamper(self):
        """Scenario 02 — write manifest.csv + sidecar, then tamper with
        manifest.csv. A re-hash of the file must NOT match the sidecar.
        This is the actual integrity check a downstream consumer runs."""
        import hashlib
        pairs = [{'source_uid': 'u1', 'target_uid': 't1', 'title': 'A'}]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'manifest.csv')
            write_manifest_csv(pairs, path)
            sidecar = path + '.sha256'

            with open(sidecar) as f:
                stored_digest = f.read().split()[0]

            # Tamper: append a row swapping target_uid (the Scenario 02
            # attack vector exactly).
            with open(path, 'a') as f:
                f.write('u1,attacker_target_uid,A\n')

            with open(path, 'rb') as f:
                live_digest = hashlib.sha256(f.read()).hexdigest()

            self.assertNotEqual(stored_digest, live_digest,
                                'tampered manifest.csv must not match the '
                                'sidecar — Scenario 02 detection invariant')


if __name__ == '__main__':
    unittest.main()
