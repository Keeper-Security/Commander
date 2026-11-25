"""NSF records whose local data is older than the server's (found with resend_test/probe_nsf_read.py --write, QA 2026-11-19)."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from keepercommander.commands.pam_import import nsf_helpers as nh


def params(nsf=None, nsf_data=None, classic=None):
    return SimpleNamespace(nested_share_records=nsf or {}, nested_share_record_data=nsf_data or {},
                           record_cache=classic or {}, revision=5, sync_down_token=b'tok')


class TestStaleNsfRecords(unittest.TestCase):
    def test_a_classic_record_is_never_stale(self):
        self.assertEqual(nh.stale_nsf_records(params(classic={'A': {'revision': 1}}), ['A']), [])

    def test_the_classic_copy_older_than_the_nsf_revision_is_stale(self):
        # the QA case after an incremental sync: nsf 6274004, classic copy 6273968
        p = params(nsf={'A': {'revision': 6274004}}, classic={'A': {'revision': 6273968}})
        self.assertEqual(nh.stale_nsf_records(p, ['A']), ['A'])

    def test_equal_revisions_are_fresh(self):
        p = params(nsf={'A': {'revision': 7}}, classic={'A': {'revision': 7}})
        self.assertEqual(nh.stale_nsf_records(p, ['A']), [])

    def test_no_classic_copy_and_no_nsf_data_is_stale_with_data_is_fresh(self):
        self.assertEqual(nh.stale_nsf_records(params(nsf={'A': {'revision': 7}}), ['A']), ['A'])
        p = params(nsf={'A': {'revision': 7}}, nsf_data={'A': {'data_json': {'title': 't'}}})
        self.assertEqual(nh.stale_nsf_records(p, ['A']), [])

    def test_refresh_makes_a_full_sync_only_when_something_is_stale(self):
        stale = params(nsf={'A': {'revision': 9}}, classic={'A': {'revision': 3}})
        with patch.object(nh, 'sync_down_preserving_nsf_keys') as sync:
            self.assertEqual(nh.refresh_stale_nsf_records(stale, ['A']), 1)
            sync.assert_called_once()
            self.assertEqual((stale.revision, stale.sync_down_token), (0, b''))      # = `sync-down -f`
        fresh = params(nsf={'A': {'revision': 3}}, classic={'A': {'revision': 3}})
        with patch.object(nh, 'sync_down_preserving_nsf_keys') as sync:
            self.assertEqual(nh.refresh_stale_nsf_records(fresh, ['A']), 0)
            sync.assert_not_called()
            self.assertEqual((fresh.revision, fresh.sync_down_token), (5, b'tok'))


if __name__ == '__main__':
    unittest.main()
