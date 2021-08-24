#!/usr/bin/env python3

"""Test keepercommander.subfolder."""

# import sys
from unittest import TestCase
from unittest.mock import Mock

# sys.path.insert(0, '.')

import keepercommander.subfolder as subfolder

# from data_vault import get_synced_params


def BFN(*, type, uid, parent_uid, name, subfolders):
    """Build a mock BaseFolderNode."""
    result = Mock()
    result.type = type
    result.uid = uid
    result.parent_uid = parent_uid
    result.name = name
    result.subfolders = subfolders
    return result


def folder_cache():
    """Build a two-node folder_cache.  Return it and the root uid."""
    cd_tests_uid = 'b' * 22
    cd_tests_bfn = BFN(type='user_folder', uid=cd_tests_uid, parent_uid=None, name='cd-tests', subfolders=[])
    root_uid = 'a' * 22
    root_bfn = BFN(type='/', uid=None, parent_uid=None, name='My Vault', subfolders=[cd_tests_uid])
    dict_ = {
        root_uid: root_bfn,
        cd_tests_uid: cd_tests_bfn,
    }
    return dict_, root_bfn, cd_tests_bfn


class TestSubfolder(TestCase):
    """Tests for subfolders."""

    def setUp(self):
        """Set up self.params, self.root_bfn and self.cd_tests_bfn."""
        self.params = Mock()
        (self.params.folder_cache, self.root_bfn, self.cd_tests_bfn) = folder_cache()
        self.params.current_folder = ''
        self.params.root_folder = self.root_bfn

    def test_a_try_resolve_path(self):
        """Try an a try_resolve_path, where a does not preexist."""
        folder, final = subfolder.try_resolve_path(self.params, 'a')
        assert folder is self.root_bfn
        assert final == 'a'

    def test_slash_a_try_resolve_path(self):
        """Try a /a try_resolve_path, where /a does not preexist."""
        folder, final = subfolder.try_resolve_path(self.params, '/a')
        assert folder is self.root_bfn
        assert final == 'a'

    def test_slash_a_b_try_resolve_path(self):
        """Try a /a/b try_resolve_path, where neither /a/b nor /a preexist."""
        folder, final = subfolder.try_resolve_path(self.params, '/a/b')
        assert folder is self.root_bfn
        assert final == 'a/b'

    def test_slash_cd_tests_a_try_resolve_path(self):
        """Try a /cd-tests/a try_resolve_path, where /cd-tests preexists, but /cd-tests/b does not."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests/a')
        assert folder is self.cd_tests_bfn
        assert final == 'a'

    def test_slash_cd_tests_try_resolve_path(self):
        """Try a /cd-tests try_resolve_path, where /cd-tests preexists."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests')
        assert folder is self.cd_tests_bfn
        assert final == ''

    def test_a_slash_slash_b_try_resolve_path(self):
        """Try an a//b try_resolve_path, where neither a/b nor a preexist."""
        folder, final = subfolder.try_resolve_path(self.params, 'a//b')
        assert folder is self.root_bfn
        assert final == 'a//b'

    def test_slash_slash_a_try_resolve_path(self):
        """Try a //a try_resolve_path, where /a does not preexist.  Note that we want to create '/a', not 'a' in /."""
        folder, final = subfolder.try_resolve_path(self.params, '//a')
        assert folder is self.root_bfn
        assert final == '/a'

    def test_slash_slash_a_slash_slash_b_try_resolve_path(self):
        """
        Try a //a//b try_resolve_path, where neither /a/b nor /a preexist.

        Note that we want to create '/a/b', not 'a' in / and b in that.
        """
        folder, final = subfolder.try_resolve_path(self.params, '//a//b')
        assert folder is self.root_bfn
        assert final == '/a/b'

    def test_cd_tests_dot_dot_try_resolve_path(self):
        """Try a /cd-tests/.. try_resolve_path, where /cd-tests preexists."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests/..')
        assert folder is self.root_bfn
        assert final == ''

    def test_cd_tests_dot_try_resolve_path(self):
        """Try a /cd-test/. try_resolve_path, where /cd-tests preexists."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests/.')
        assert folder is self.cd_tests_bfn
        assert final == ''

    def test_slash_dot_dot_try_resolve_path(self):
        """Try a /.. try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/..')
        assert folder is self.root_bfn
        assert final == ''

    def test_slash_dot_try_resolve_path(self):
        """Try a /.. try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/.')
        assert folder is self.root_bfn
        assert final == '.'

    def test_slash_cd_tests_space_try_resolve_path(self):
        """Try a '/cd-tests ' try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests ')
        assert folder is self.cd_tests_bfn
        assert final == ''

    def test_slash_space_cd_tests_try_resolve_path(self):
        """Try a '/ cd-tests' try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/ cd-tests')
        assert folder is self.cd_tests_bfn
        assert final == ''


if __name__ == '__main__':
    ts = TestSubfolder()
    if hasattr(ts, 'setUp'):
        ts.setUp()
    ts.test_cd_test_a_try_resolve_path()
    if hasattr(ts, 'tearDown'):
        ts.tearDown()
