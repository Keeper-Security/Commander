"""Bug 33 (v1.5.1) — driver tests using a fake reference client."""

import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.references_rewrite import (
    LoadedRecord,
    ReferencesRewriter,
    build_uid_map,
    load_manifest_pairs,
)


class _FakeClient:
    """In-memory fake — keeps a {target_uid: LoadedRecord} dict and
    records every persist call. Failures are injected by adding the
    UID to load_fail_uids or persist_fail_uids."""

    def __init__(self, records):
        self._records = records
        self.persisted = []
        self.load_fail_uids = set()
        self.persist_fail_uids = set()

    def load_field_values(self, uid):
        if uid in self.load_fail_uids:
            return None
        return self._records.get(uid)

    def persist(self, uid, loaded):
        if uid in self.persist_fail_uids:
            return False
        self.persisted.append(uid)
        return True


def _rec(uid, fields=None, custom=None, record_type='pamMachine'):
    return LoadedRecord(record_uid=uid, record_type=record_type,
                        fields=fields or [], custom=custom or [])


class LoadManifestPairsTests(unittest.TestCase):
    def test_reads_unambiguous_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'm.csv')
            with open(path, 'w') as f:
                f.write('source_uid,target_uid,title\n')
                f.write('s1,t1,Rec1\n')
                f.write('s2,t2,Rec2\n')
            pairs = load_manifest_pairs(path)
        self.assertEqual([p['source_uid'] for p in pairs], ['s1', 's2'])
        self.assertEqual([p['target_uid'] for p in pairs], ['t1', 't2'])

    def test_skips_rows_with_missing_uid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'm.csv')
            with open(path, 'w') as f:
                f.write('source_uid,target_uid,title\n')
                f.write('s1,,no-target\n')
                f.write(',t2,no-source\n')
                f.write('s3,t3,ok\n')
            pairs = load_manifest_pairs(path)
        self.assertEqual([p['source_uid'] for p in pairs], ['s3'])


class BuildUidMapTests(unittest.TestCase):
    def test_round_trip(self):
        m = build_uid_map([{'source_uid': 'a', 'target_uid': 'A'},
                           {'source_uid': 'b', 'target_uid': 'B'}])
        self.assertEqual(m, {'a': 'A', 'b': 'B'})

    def test_skips_identity_and_blanks(self):
        m = build_uid_map([{'source_uid': '', 'target_uid': 'A'},
                           {'source_uid': 'b', 'target_uid': ''},
                           {'source_uid': 'c', 'target_uid': 'C'}])
        self.assertEqual(m, {'c': 'C'})


class ReferencesRewriterTests(unittest.TestCase):
    def test_pam_credentials_uid_remapped(self):
        record = _rec('t1', fields=[
            {'type': 'pamRemoteBrowserSettings', 'label': '',
             'value': [{'connection': {'httpCredentialsUid': 'src-creds'}}]},
        ])
        client = _FakeClient({'t1': record})
        result = ReferencesRewriter(client).run([
            {'source_uid': 'src-anchor', 'target_uid': 't1'},
            {'source_uid': 'src-creds', 'target_uid': 'tgt-creds'},
        ])
        self.assertEqual(result['records_inspected'], 2)
        self.assertEqual(result['records_with_refs'], 1)
        self.assertEqual(result['records_rewritten'], 1)
        self.assertEqual(result['refs_remapped'], 1)
        self.assertEqual(client.persisted, ['t1'])
        # Side-effect — the field's value list is mutated to the new UID.
        self.assertEqual(
            record.fields[0]['value'][0]['connection']['httpCredentialsUid'],
            'tgt-creds')

    def test_no_refs_means_no_persist(self):
        record = _rec('t1', fields=[
            {'type': 'login', 'label': '', 'value': ['user@x']},
        ])
        client = _FakeClient({'t1': record})
        result = ReferencesRewriter(client).run([
            {'source_uid': 's1', 'target_uid': 't1'},
        ])
        self.assertEqual(result['records_with_refs'], 0)
        self.assertEqual(client.persisted, [])

    def test_idempotent_when_already_rewritten(self):
        # First pass rewrote src→tgt; second run sees only target UIDs.
        record = _rec('t1', fields=[
            {'type': 'pamSettings', 'label': '',
             'value': [{'connection': {'httpCredentialsUid': 'tgt-creds'}}]},
        ])
        client = _FakeClient({'t1': record})
        result = ReferencesRewriter(client).run([
            {'source_uid': 'src-creds', 'target_uid': 'tgt-creds'},
            {'source_uid': 'src-anchor', 'target_uid': 't1'},
        ])
        # tgt-creds is in the value list; the map has src-creds → tgt-creds.
        # tgt-creds is NOT a source UID in the map → unknown, no rewrite.
        self.assertEqual(result['records_rewritten'], 0)
        self.assertEqual(result['refs_remapped'], 0)
        self.assertEqual(result['refs_unknown'], 1)
        self.assertEqual(client.persisted, [])

    def test_unknown_uid_left_in_place(self):
        record = _rec('t1', fields=[
            {'type': 'pamSettings', 'label': '',
             'value': [{'connection': {'httpCredentialsUid': 'unknown-src'}}]},
        ])
        client = _FakeClient({'t1': record})
        result = ReferencesRewriter(client).run([
            {'source_uid': 'src-anchor', 'target_uid': 't1'},
            {'source_uid': 's2', 'target_uid': 't2'},
        ])
        self.assertEqual(result['refs_unknown'], 1)
        self.assertEqual(client.persisted, [])
        # Untouched.
        self.assertEqual(
            record.fields[0]['value'][0]['connection']['httpCredentialsUid'],
            'unknown-src')

    def test_record_ref_list_partial_remap(self):
        record = _rec('t1', fields=[
            {'type': 'recordRef', 'label': '',
             'value': [{'recordRef': ['a', 'b', 'unknown']}]},
        ])
        client = _FakeClient({'t1': record})
        result = ReferencesRewriter(client).run([
            {'source_uid': 't1', 'target_uid': 't1'},
            {'source_uid': 'a', 'target_uid': 'A'},
            {'source_uid': 'b', 'target_uid': 'B'},
        ])
        self.assertEqual(result['refs_remapped'], 2)
        self.assertEqual(result['refs_unknown'], 1)
        self.assertEqual(record.fields[0]['value'][0]['recordRef'],
                         ['A', 'B', 'unknown'])

    def test_load_failure_counted(self):
        client = _FakeClient({})
        client.load_fail_uids.add('t1')
        result = ReferencesRewriter(client).run([
            {'source_uid': 's1', 'target_uid': 't1'},
        ])
        self.assertEqual(result['load_failures'], 1)
        self.assertEqual(result['failed_uids'], ['t1'])
        self.assertEqual(result['records_rewritten'], 0)

    def test_persist_failure_counted_and_listed(self):
        record_t1 = _rec('t1', fields=[
            {'type': 'pamSettings', 'label': '',
             'value': [{'connection': {'httpCredentialsUid': 'src-creds'}}]},
        ])
        # tgt-creds is also a real target record (no embedded refs of its
        # own), so the rewriter inspects it without a load failure.
        record_creds = _rec('tgt-creds', fields=[
            {'type': 'login', 'label': '', 'value': ['cred-user']},
        ])
        client = _FakeClient({'t1': record_t1, 'tgt-creds': record_creds})
        client.persist_fail_uids.add('t1')
        result = ReferencesRewriter(client).run([
            {'source_uid': 'src-creds', 'target_uid': 'tgt-creds'},
            {'source_uid': 's1', 'target_uid': 't1'},
        ])
        self.assertEqual(result['persist_failures'], 1)
        self.assertEqual(result['load_failures'], 0)
        self.assertEqual(result['failed_uids'], ['t1'])
        self.assertEqual(result['rewritten_uids'], [])

    def test_empty_manifest_short_circuits(self):
        client = _FakeClient({})
        result = ReferencesRewriter(client).run([])
        self.assertEqual(result['records_inspected'], 0)
        self.assertEqual(client.persisted, [])

    def test_custom_fields_walked_alongside_fields(self):
        record = _rec('t1',
                       fields=[],
                       custom=[
                           {'type': 'recordRef', 'label': 'linked',
                            'value': [{'recordRef': ['src1']}]},
                       ])
        client = _FakeClient({'t1': record})
        result = ReferencesRewriter(client).run([
            {'source_uid': 'src1', 'target_uid': 'tgt1'},
            {'source_uid': 'anchor', 'target_uid': 't1'},
        ])
        self.assertEqual(result['records_rewritten'], 1)
        self.assertEqual(record.custom[0]['value'][0]['recordRef'], ['tgt1'])

    def test_non_list_field_value_skipped(self):
        # Defensive — older fixtures may have scalars where Commander
        # expects a list. Don't crash, just skip.
        record = _rec('t1', fields=[
            {'type': 'pamSettings', 'label': '',
             'value': 'unexpected-scalar'},
        ])
        client = _FakeClient({'t1': record})
        result = ReferencesRewriter(client).run([
            {'source_uid': 's1', 'target_uid': 't1'},
        ])
        self.assertEqual(result['records_with_refs'], 0)
        self.assertEqual(client.persisted, [])


if __name__ == '__main__':
    unittest.main()
