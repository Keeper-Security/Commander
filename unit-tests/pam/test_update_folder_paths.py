"""`folder_path` of `pam project update` must mean the same folder as in `pam project extend`.

update resolves a JSON ``folder_path`` through ``{f.path: f.uid}`` of the KSM scope (``ksm_scope``); extend through
``path_to_folder_uid`` built from ``nsf_helpers.build_folder_tree`` + ``extend._collect_path_to_uid_from_tree``. They are
two implementations, so this builds the SAME fake vault, runs both, and compares the maps.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))

from keepercommander.commands.pam_import import ksm_scope  # noqa: E402
from keepercommander.commands.pam_import.extend import _collect_path_to_uid_from_tree  # noqa: E402
from keepercommander.commands.pam_import.ksm_scope import AppShares, collect_ksm_scope  # noqa: E402
from keepercommander.commands.pam_import.nsf_helpers import build_folder_tree  # noqa: E402

import test_ksm_scope as tk  # noqa: E402  (its fake-vault helpers)


def classic_params():
    """Shared folder SF1 "Gateway Project" -> "Users" -> "Admins", and -> "Resources"."""
    p = tk._params()
    p.shared_folder_cache = {'SF1': {'name_unencrypted': 'Gateway Project'}}
    p.folder_cache = {
        'SF1': tk._node('SF1', 'Gateway Project', '', ['S1', 'S3']),
        'S1': tk._node('S1', 'Users', 'SF1', ['S2']),
        'S2': tk._node('S2', 'Admins', 'S1'),
        'S3': tk._node('S3', 'Resources', 'SF1'),
    }
    return p


def nsf_params():
    """NSF P "Proj" -> "Users" -> "Deep"; every folder has a name."""
    p = tk._params()
    tk._nsf(p, 'P', 'Proj')
    tk._nsf(p, 'C', 'Users', 'P')
    tk._nsf(p, 'G1', 'Deep', 'C')
    return p


def extend_map(params, roots):
    """What extend puts in ``project['folders']['path_to_folder_uid']`` for the KSM app's folders *roots*
    (``get_ksm_app_folders`` dicts: uid + name), the way ``extend.py`` fills it."""
    path_to_uid = {}
    for root in roots:
        path_to_uid[root['name']] = root['uid']
        _collect_path_to_uid_from_tree(root['name'], build_folder_tree(params, root['uid']), path_to_uid,
                                       only_existing=False)
    return path_to_uid


def update_map(params, roots, share_uids):
    """What `update` hands to the matcher as ``path_to_folder_uid`` (update.py)."""
    with patch.object(ksm_scope, 'get_record_summary', return_value=None):
        scope = collect_ksm_scope(params, 'app1', shares=AppShares(folder_uids=share_uids),
                                  folder_roots=[{'uid': r['uid'], 'source': r.get('source', 'classic')} for r in roots])
    return {f.path: f.uid for f in scope.folders.values() if f.path}


class TestFolderPathsMatchExtend(unittest.TestCase):
    def test_classic_shared_folder_and_subfolders(self):
        roots = [{'uid': 'SF1', 'name': 'Gateway Project', 'source': 'classic'}]
        params = classic_params()
        mine, theirs = update_map(params, roots, ['SF1']), extend_map(params, roots)
        self.assertEqual(mine, theirs)
        self.assertEqual(mine, {'Gateway Project': 'SF1', 'Gateway Project/Users': 'S1',
                                'Gateway Project/Users/Admins': 'S2', 'Gateway Project/Resources': 'S3'})

    def test_nested_share_folder_and_children(self):
        roots = [{'uid': 'P', 'name': 'Proj', 'source': 'nested'}]
        params = nsf_params()
        mine, theirs = update_map(params, roots, ['P']), extend_map(params, roots)
        self.assertEqual(mine, theirs)
        self.assertEqual(mine, {'Proj': 'P', 'Proj/Users': 'C', 'Proj/Users/Deep': 'G1'})

    def test_an_nsf_child_that_is_not_shared_to_the_app_is_still_a_path_for_both(self):
        roots = [{'uid': 'P', 'name': 'Proj', 'source': 'nested'}]
        params = nsf_params()
        self.assertEqual(update_map(params, roots, ['P']), extend_map(params, roots))     # C, G1 are not shared

    def test_a_folder_name_with_a_slash_gives_the_same_unescaped_key(self):
        """Both join names with "/" and look the JSON string up as it is (no "//" unescaping on either side)."""
        roots = [{'uid': 'SF1', 'name': 'Gateway Project', 'source': 'classic'}]
        params = classic_params()
        params.folder_cache['S3'].name = 'a/b'
        mine, theirs = update_map(params, roots, ['SF1']), extend_map(params, roots)
        self.assertEqual(mine, theirs)
        self.assertEqual(mine['Gateway Project/a/b'], 'S3')

    def test_two_sibling_folders_with_one_name_resolve_to_the_same_one_in_both(self):
        """The LAST one wins in both (the other is unreachable by path). update's matcher then fails safe for a record in
        the hidden folder ("found in folder X, the JSON says Y"). Known small difference, not asserted: update, keyed by
        folder uid, still lists the hidden folder's own subfolders; extend's name-keyed tree drops them. Another
        degenerate difference: a classic folder with an EMPTY name is "<uid>" in update and "" in extend."""
        roots = [{'uid': 'SF1', 'name': 'Gateway Project', 'source': 'classic'}]
        params = classic_params()
        params.folder_cache['SF1'].subfolders = ['S1', 'S3', 'S4']
        params.folder_cache['S4'] = tk._node('S4', 'Users', 'SF1')
        self.assertEqual(update_map(params, roots, ['SF1'])['Gateway Project/Users'], 'S4')
        self.assertEqual(extend_map(params, roots)['Gateway Project/Users'], 'S4')

    def test_several_roots(self):
        roots = [{'uid': 'SF1', 'name': 'Gateway Project', 'source': 'classic'},
                 {'uid': 'P', 'name': 'Proj', 'source': 'nested'}]
        params = classic_params()
        params.nested_share_folders = nsf_params().nested_share_folders
        self.assertEqual(update_map(params, roots, ['SF1', 'P']), extend_map(params, roots))


if __name__ == '__main__':
    unittest.main()
