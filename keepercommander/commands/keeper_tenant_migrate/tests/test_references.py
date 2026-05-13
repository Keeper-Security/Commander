"""Bug 33 (v1.5.0) — pure-data tests for the references walker + remapper."""

import unittest

from keepercommander.commands.keeper_tenant_migrate.references import (
    RECORD_REF_KEYS,
    needs_rewrite,
    remap_uid_refs,
    walk_uid_refs,
)


class RefKeysRegistryTests(unittest.TestCase):
    """Contract tests for the REF_KEYS registry shape."""

    def test_registry_is_a_set_of_str(self):
        self.assertIsInstance(RECORD_REF_KEYS, set)
        for k in RECORD_REF_KEYS:
            self.assertIsInstance(k, str)
            self.assertTrue(k)

    def test_well_known_keys_present(self):
        # Sentinel — these keys are observed in real EU-source tenants.
        # Removing one would silently regress Bug 33's customer fix.
        for sentinel in ('httpCredentialsUid', 'recordRef', 'pamUserUid',
                         'pamConfigurationUid', 'targetRecord'):
            self.assertIn(sentinel, RECORD_REF_KEYS)

    def test_fileref_intentionally_excluded(self):
        # File-UID remapping is filed for v1.6 — staging manifest doesn't
        # carry target file UIDs yet. If this test fails because someone
        # added 'fileRef', they also need to extend the staging manifest.
        self.assertNotIn('fileRef', RECORD_REF_KEYS)


class WalkUidRefsTests(unittest.TestCase):
    def test_top_level_record_ref_string(self):
        v = {'httpCredentialsUid': 'src1'}
        self.assertEqual(list(walk_uid_refs(v)),
                         [('httpCredentialsUid', 'src1')])

    def test_nested_pam_settings_shape(self):
        # Real-world: pamRemoteBrowserSettings.connection.httpCredentialsUid
        v = {
            'connection': {
                'httpCredentialsUid': 'src-creds',
                'host': 'box.internal',
            },
            'unrelated': 'data',
        }
        refs = list(walk_uid_refs(v))
        self.assertEqual(refs, [('httpCredentialsUid', 'src-creds')])

    def test_record_ref_list_yields_each_uid(self):
        v = {'recordRef': ['a', 'b', 'c']}
        self.assertEqual(set(walk_uid_refs(v)),
                         {('recordRef', 'a'), ('recordRef', 'b'),
                          ('recordRef', 'c')})

    def test_skips_empty_string_uids(self):
        # Operator-edited fields sometimes carry empty strings.
        v = {'httpCredentialsUid': ''}
        self.assertEqual(list(walk_uid_refs(v)), [])

    def test_skips_non_string_in_ref_key(self):
        # Defensive: malformed records with int/None under a ref key.
        v = {'httpCredentialsUid': 42}
        self.assertEqual(list(walk_uid_refs(v)), [])

    def test_recurses_into_lists_of_dicts(self):
        # script.value[] is typically [{step1}, {step2}, ...] each with refs.
        v = [
            {'recordRef': ['x', 'y']},
            {'connection': {'httpCredentialsUid': 'z'}},
        ]
        self.assertEqual(set(walk_uid_refs(v)),
                         {('recordRef', 'x'), ('recordRef', 'y'),
                          ('httpCredentialsUid', 'z')})

    def test_unknown_keys_ignored(self):
        v = {'someOtherUid': 'looks-like-a-uid-but-isnt-known'}
        self.assertEqual(list(walk_uid_refs(v)), [])

    def test_handles_mixed_types_in_recordref_list(self):
        v = {'recordRef': ['valid', None, 42, 'also-valid', '']}
        self.assertEqual(list(walk_uid_refs(v)),
                         [('recordRef', 'valid'), ('recordRef', 'also-valid')])

    def test_cycle_safe(self):
        a = {'connection': {}}
        a['connection']['child'] = a  # self-cycle
        a['connection']['httpCredentialsUid'] = 'src1'
        # Without cycle protection this would recurse infinitely.
        refs = list(walk_uid_refs(a))
        self.assertEqual(refs, [('httpCredentialsUid', 'src1')])

    def test_custom_ref_keys_argument(self):
        v = {'fileRef': 'f1', 'httpCredentialsUid': 'r1'}
        # Pass an explicit set — fileRef now in scope, recordRef out.
        self.assertEqual(list(walk_uid_refs(v, {'fileRef'})),
                         [('fileRef', 'f1')])


class RemapUidRefsTests(unittest.TestCase):
    def test_replaces_known_uid_and_counts_it(self):
        v = {'connection': {'httpCredentialsUid': 'src1'}}
        out, stats = remap_uid_refs(v, {'src1': 'tgt1'})
        self.assertEqual(out, {'connection': {'httpCredentialsUid': 'tgt1'}})
        self.assertEqual(stats['remapped'], 1)
        self.assertEqual(stats['unknown'], 0)
        self.assertEqual(stats['empty'], 0)

    def test_leaves_unknown_uid_in_place(self):
        v = {'httpCredentialsUid': 'src1'}
        out, stats = remap_uid_refs(v, {'other': 'tgt'})
        self.assertEqual(out, {'httpCredentialsUid': 'src1'})
        self.assertEqual(stats['unknown'], 1)
        self.assertEqual(stats['remapped'], 0)

    def test_identity_remap_does_not_count(self):
        # Map exists but src→src — record doesn't actually need writing.
        v = {'httpCredentialsUid': 'src1'}
        out, stats = remap_uid_refs(v, {'src1': 'src1'})
        self.assertEqual(out, v)
        self.assertEqual(stats['remapped'], 0)

    def test_remaps_each_item_in_recordref_list(self):
        v = {'recordRef': ['a', 'b', 'c']}
        out, stats = remap_uid_refs(v, {'a': 'A', 'c': 'C'})
        self.assertEqual(out, {'recordRef': ['A', 'b', 'C']})
        self.assertEqual(stats['remapped'], 2)
        self.assertEqual(stats['unknown'], 1)

    def test_does_not_mutate_input(self):
        v = {'connection': {'httpCredentialsUid': 'src1'}}
        snapshot = {'connection': {'httpCredentialsUid': 'src1'}}
        remap_uid_refs(v, {'src1': 'tgt1'})
        self.assertEqual(v, snapshot)

    def test_passes_through_non_dict_non_list(self):
        # Defensive — operator can pass a primitive into the remapper.
        for primitive in ('plain', 42, None, True, 3.14):
            out, stats = remap_uid_refs(primitive, {'a': 'b'})
            self.assertEqual(out, primitive)
            self.assertEqual(stats['remapped'], 0)

    def test_empty_uid_counted_in_empty_bucket(self):
        v = {'httpCredentialsUid': ''}
        out, stats = remap_uid_refs(v, {'src': 'tgt'})
        self.assertEqual(out, {'httpCredentialsUid': ''})
        self.assertEqual(stats['empty'], 1)
        self.assertEqual(stats['unknown'], 0)

    def test_real_world_pam_remote_browser_settings(self):
        # Shape lifted from EU source 2026-04-28 audit.
        rec = {
            'pamRemoteBrowserSettings': {
                'connection': {
                    'httpCredentialsUid': 'src-creds',
                    'host': 'box.internal',
                    'port': 443,
                },
                'allowedUrls': ['https://*.example.com'],
            },
        }
        out, stats = remap_uid_refs(rec, {'src-creds': 'tgt-creds'})
        self.assertEqual(
            out['pamRemoteBrowserSettings']['connection']['httpCredentialsUid'],
            'tgt-creds')
        # Non-ref siblings preserved untouched.
        self.assertEqual(
            out['pamRemoteBrowserSettings']['connection']['host'],
            'box.internal')
        self.assertEqual(stats['remapped'], 1)


class NeedsRewriteTests(unittest.TestCase):
    def test_true_when_remappable_ref_present(self):
        v = {'httpCredentialsUid': 'src1'}
        self.assertTrue(needs_rewrite(v, {'src1': 'tgt1'}))

    def test_false_when_all_refs_unknown(self):
        v = {'httpCredentialsUid': 'src1'}
        self.assertFalse(needs_rewrite(v, {}))

    def test_false_when_remap_is_identity(self):
        v = {'httpCredentialsUid': 'src1'}
        self.assertFalse(needs_rewrite(v, {'src1': 'src1'}))

    def test_short_circuits_on_first_mismatch(self):
        v = {'recordRef': ['a', 'b', 'c'] + ['x'] * 1000}
        # Even with a thousand more refs, hitting one mismatch is enough.
        self.assertTrue(needs_rewrite(v, {'a': 'A'}))


if __name__ == '__main__':
    unittest.main()
