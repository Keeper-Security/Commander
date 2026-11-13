#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from keepercommander.commands.pam_import import ksm_scope
from keepercommander.commands.pam_import.ksm_scope import (
    AppShares, SOURCE_DIRECT, SOURCE_FOLDER, STATUS_SHARED, STATUS_UNCONFIRMED, STATUS_UNSHARED, collect_ksm_scope,
)
from keepercommander.commands.pam_import.record_matcher import MODE_UPDATE, RecordIndex, match_record

REC = {  # uid -> (uid, title, type, login), what get_record_summary returns
    'p1rec1': ('p1rec1', 'p1rec1', 'pamMachine', ''),
    'p1rec2': ('p1rec2', 'p1rec2', 'pamMachine', ''),
    'c1rec1': ('c1rec1', 'c1rec1', 'pamUser', 'bob'),
    'g1rec1': ('g1rec1', 'g1rec1', 'pamUser', 'amy'),
    'shfrec': ('shfrec', 'shfrec', 'pamMachine', ''),
    'subrec': ('subrec', 'subrec', 'pamUser', 'sue'),
    'direct1': ('direct1', 'direct1', 'pamMachine', ''),
}


def _node(uid, name, parent='', subfolders=()):
    return SimpleNamespace(uid=uid, name=name, parent_uid=parent, subfolders=list(subfolders))


def _params():
    p = MagicMock()
    p.shared_folder_cache = {}
    p.folder_cache = {}
    p.nested_share_folders = {}
    p.nested_share_records = {}
    p.subfolder_record_cache = {}
    p.nested_share_folder_records = {}
    return p


def _nsf(params, uid, name, parent='', key=True):
    params.nested_share_folders[uid] = {'name': name, 'parent_uid': parent or None}
    if key:
        params.nested_share_folders[uid]['folder_key_unencrypted'] = b'k' * 32


def _collect(params, shares, **kw):
    with patch.object(ksm_scope, 'get_record_summary', side_effect=lambda p, uid: REC.get(uid)):
        return collect_ksm_scope(params, 'app1', shares=shares, **kw)


def _nsf_tree():
    """P (root) -> C -> G1; every folder holds one readable record."""
    p = _params()
    _nsf(p, 'P', 'P')
    _nsf(p, 'C', 'C', 'P')
    _nsf(p, 'G1', 'G1', 'C')
    p.nested_share_folder_records = {'P': ['p1rec1', 'p1rec2'], 'C': ['c1rec1'], 'G1': ['g1rec1']}
    return p


class TestNsfScope(unittest.TestCase):

    def test_only_parent_shared_child_and_grandchild_are_unshared(self):
        scope = _collect(_nsf_tree(), AppShares(folder_uids=['P']))
        self.assertEqual({u: f.status for u, f in scope.folders.items()},
                         {'P': STATUS_SHARED, 'C': STATUS_UNSHARED, 'G1': STATUS_UNSHARED})
        self.assertEqual(scope.folders['G1'].nearest_shared_ancestor, 'P')
        self.assertTrue(scope.records['p1rec1'].shared)
        self.assertFalse(scope.records['c1rec1'].shared)
        self.assertFalse(scope.records['g1rec1'].shared)

    def test_parent_and_child_shared_grandchild_still_unshared(self):
        scope = _collect(_nsf_tree(), AppShares(folder_uids=['P', 'C']))
        self.assertEqual(scope.folders['C'].status, STATUS_SHARED)
        self.assertEqual(scope.folders['G1'].status, STATUS_UNSHARED)
        self.assertEqual(scope.folders['G1'].nearest_shared_ancestor, 'C')
        self.assertTrue(scope.records['c1rec1'].shared)
        self.assertFalse(scope.records['g1rec1'].shared)

    def test_warning_names_folder_closest_shared_ancestor_and_count(self):
        scope = _collect(_nsf_tree(), AppShares(folder_uids=['P', 'C']))
        self.assertEqual(scope.nsf_warnings(),
                         ['WARNING: NSF "G1" (child of "C", the closest NSF shared to the KSM app) is not shared '
                          'to the KSM app - its 1 record(s) are ignored'])
        self.assertIn('the Gateway cannot see its 1 record(s)', scope.nsf_warnings(ignored=False)[0])

    def test_unreadable_nsf_folder_is_reported_not_counted_as_empty(self):
        p = _nsf_tree()
        p.nested_share_folders['C'].pop('folder_key_unencrypted')
        scope = _collect(p, AppShares(folder_uids=['P', 'C']))
        self.assertEqual(scope.unreadable_folders, ['C'])
        self.assertNotIn('c1rec1', scope.records)
        self.assertNotIn(scope.folders['C'], scope.empty_folders())
        self.assertTrue(any('cannot be read' in x for x in scope.nsf_warnings()))

    def test_empty_folder_is_listed(self):
        p = _nsf_tree()
        p.nested_share_folder_records['C'] = []
        scope = _collect(p, AppShares(folder_uids=['P', 'C']))
        self.assertEqual([f.uid for f in scope.empty_folders()], ['C'])

    def test_fallback_root_is_unconfirmed_and_visible_to_extend_only(self):
        p = _nsf_tree()
        roots = [{'uid': 'P', 'source': 'nested_share_folder'}]
        scope = _collect(p, AppShares(folder_uids=[]), folder_roots=roots)
        self.assertEqual(scope.folders['P'].status, STATUS_UNCONFIRMED)
        self.assertFalse(scope.records['p1rec1'].shared)
        self.assertTrue(any('not confirmed shared' in x for x in scope.nsf_warnings()))
        index = RecordIndex(scope.match_records())
        # update has no fallback: the record is not in scope
        self.assertEqual(match_record(index, ident='"x"', title='p1rec1', mode=MODE_UPDATE).code, 'outside_scope')

    def test_roots_given_by_the_caller_count_unresolved_shares(self):
        p = _nsf_tree()
        roots = [{'uid': 'P', 'source': 'nested'}]
        scope = _collect(p, AppShares(folder_uids=['P', 'GONE1', 'GONE2']), folder_roots=roots)
        self.assertEqual(scope.unresolved_shares, 2)
        self.assertIn('WARNING: 2 KSM app share(s) are not visible to this user - the comparison is incomplete',
                      scope.nsf_warnings())

    def test_resolvable_share_that_is_not_a_given_root_is_not_unresolved(self):
        p = _nsf_tree()
        roots = [{'uid': 'P', 'source': 'nested'}]
        scope = _collect(p, AppShares(folder_uids=['P', 'C']), folder_roots=roots)
        self.assertEqual(scope.unresolved_shares, 0)
        self.assertEqual(scope.folders['C'].status, STATUS_SHARED)

    def test_unresolved_shares_from_the_app_shares(self):
        scope = _collect(_nsf_tree(), AppShares(folder_uids=['P', 'NOT-IN-CACHE']))
        self.assertEqual(scope.unresolved_shares, 1)


class TestClassicScope(unittest.TestCase):

    def _classic(self):
        p = _params()
        p.shared_folder_cache['SHF'] = {}
        p.folder_cache['SHF'] = _node('SHF', 'shf_test', subfolders=['SUB', 'EMPTY'])
        p.folder_cache['SUB'] = _node('SUB', 'sub', parent='SHF', subfolders=['SUB2'])
        p.folder_cache['SUB2'] = _node('SUB2', 'deep', parent='SUB')
        p.folder_cache['EMPTY'] = _node('EMPTY', 'empty', parent='SHF')
        p.subfolder_record_cache = {'SHF': ['shfrec'], 'SUB2': ['subrec'], 'EMPTY': []}
        return p

    def test_shf_is_recursive_and_all_subfolders_are_shared(self):
        scope = _collect(self._classic(), AppShares(folder_uids=['SHF']))
        self.assertEqual(set(scope.folders), {'SHF', 'SUB', 'SUB2', 'EMPTY'})
        self.assertTrue(all(f.status == STATUS_SHARED for f in scope.folders.values()))
        self.assertEqual(scope.folders['SUB2'].path, 'shf_test/sub/deep')
        self.assertEqual(scope.folders['SUB2'].kind, 'shff')
        self.assertTrue(scope.records['subrec'].shared)
        # SUB holds only a subfolder, EMPTY holds nothing: both are empty folders
        self.assertEqual(sorted(f.uid for f in scope.empty_folders()), ['EMPTY', 'SUB'])

    def test_record_in_shf_and_shared_directly_is_one_record_with_two_sources(self):
        p = self._classic()
        scope = _collect(p, AppShares(folder_uids=['SHF'], record_uids=['shfrec', 'shfrec']))
        self.assertEqual(sum(1 for r in scope.records.values() if r.uid == 'shfrec'), 1)
        self.assertEqual(scope.records['shfrec'].sources, [SOURCE_FOLDER, SOURCE_DIRECT])
        index = RecordIndex(scope.match_records())
        # the KSM API returned it twice; the matcher must not report "Multiple matches"
        self.assertEqual(match_record(index, ident='"x"', title='shfrec', mode=MODE_UPDATE).uid, 'shfrec')


class TestDirectShares(unittest.TestCase):

    def test_direct_record_has_no_folder_and_is_shared(self):
        scope = _collect(_params(), AppShares(record_uids=['direct1']))
        rec = scope.records['direct1']
        self.assertEqual((rec.folder_uids, rec.sources, rec.shared), ([], [SOURCE_DIRECT], True))

    def test_direct_nsf_record_is_tagged_and_skipped(self):
        p = _params()
        p.nested_share_records['direct1'] = {'version': 3}
        scope = _collect(p, AppShares(record_uids=['direct1']))
        self.assertNotIn('direct1', scope.records)
        self.assertEqual(scope.skipped_direct_nsf, ['direct1'])
        self.assertTrue(any('direct share(s) of an NSF record skipped' in x for x in scope.nsf_warnings()))

    def test_unreadable_direct_share_is_reported(self):
        scope = _collect(_params(), AppShares(record_uids=['no-such-record']))
        self.assertEqual(scope.unreadable_direct, ['no-such-record'])
        self.assertTrue(any('could not be read' in x for x in scope.nsf_warnings()))


class TestDescribeLocation(unittest.TestCase):

    def test_names_the_full_path_and_the_closest_shared_ancestor(self):
        p = _nsf_tree()
        scope = _collect(p, AppShares(folder_uids=['P']))
        self.assertEqual(scope.describe_location('g1rec1'),
                         'folder "P/C/G1" (closest shared folder on the path: "P")')

    def test_no_shared_folder_on_the_path(self):
        p = _nsf_tree()
        scope = _collect(p, AppShares(folder_uids=[]))
        text = scope.describe_location('g1rec1')
        self.assertIn('folder "P/C/G1"', text)
        self.assertIn('no folder on this path is shared to the KSM app', text)

    def test_record_in_no_folder(self):
        scope = _collect(_params(), AppShares())
        self.assertEqual(scope.describe_location('nowhere'), 'the vault (no folder found)')

    def test_update_gives_outside_scope_error_with_the_location(self):
        scope = _collect(_nsf_tree(), AppShares(folder_uids=['P', 'C']))
        index = RecordIndex(scope.match_records())
        r = match_record(index, ident='"g1rec1"', title='g1rec1', mode=MODE_UPDATE,
                         describe_location=scope.describe_location)
        self.assertEqual(r.code, 'outside_scope')
        self.assertIn('folder "P/C/G1" (closest shared folder on the path: "C")', r.message)


class TestReadAppShares(unittest.TestCase):

    def test_splits_folder_and_record_shares(self):
        from keepercommander import utils
        from keepercommander.proto import APIRequest_pb2
        folder_bytes, record_bytes = b'\x01' * 16, b'\x02' * 16
        folder = SimpleNamespace(secretUid=folder_bytes, shareType=APIRequest_pb2.SHARE_TYPE_FOLDER)
        record = SimpleNamespace(secretUid=record_bytes, shareType=APIRequest_pb2.SHARE_TYPE_RECORD)
        info = SimpleNamespace(shares=[folder, record])
        with patch('keepercommander.commands.ksm.KSMCommand.get_app_info', return_value=[info]):
            shares = ksm_scope.read_app_shares(_params(), 'app1')
        self.assertEqual((shares.folder_uids, shares.record_uids, shares.ok),
                         ([utils.base64_url_encode(folder_bytes)], [utils.base64_url_encode(record_bytes)], True))

    def test_failure_is_reported_not_raised(self):
        with patch('keepercommander.commands.ksm.KSMCommand.get_app_info', side_effect=RuntimeError('boom')):
            shares = ksm_scope.read_app_shares(_params(), 'app1')
        self.assertFalse(shares.ok)


if __name__ == '__main__':
    unittest.main()
