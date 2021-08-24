#!/usr/bin/env python3

"""Test keepercommander.subfolder."""

from unittest import TestCase
from unittest.mock import Mock

import keepercommander.subfolder as subfolder


def BFN(*, type, uid, parent_uid, name, subfolders):
    """Build a mock BaseFolderNode."""
    result = Mock(name=name)
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
    root_bfn = BFN(type='/', uid=None, parent_uid=None, name='root', subfolders=[cd_tests_uid])
    dict_ = {
        root_uid: root_bfn,
        cd_tests_uid: cd_tests_bfn,
    }
    return dict_, root_bfn, cd_tests_bfn


def create_fake_params():
    """Create a fake params instance for testing."""
    params = Mock()
    (params.folder_cache, root_bfn, cd_tests_bfn) = folder_cache()
    params.current_folder = ''
    params.root_folder = root_bfn

    return params, root_bfn, cd_tests_bfn


class TestSubfolderTryResolvePath(TestCase):
    """Tests for subfolders.try_resolve_path."""

    def setUp(self):
        """Set up self.params, self.root_bfn and self.cd_tests_bfn."""
        (self.params, self.root_bfn, self.cd_tests_bfn) = create_fake_params()

    def test_a(self):
        """Try an a try_resolve_path, where a does not preexist."""
        folder, final = subfolder.try_resolve_path(self.params, 'a')
        assert folder is self.root_bfn
        assert final == 'a'

    def test_slash_a(self):
        """Try a /a try_resolve_path, where /a does not preexist."""
        folder, final = subfolder.try_resolve_path(self.params, '/a')
        assert folder is self.root_bfn
        assert final == 'a'

    def test_slash_a_b(self):
        """Try a /a/b try_resolve_path, where neither /a/b nor /a preexist."""
        folder, final = subfolder.try_resolve_path(self.params, '/a/b')
        assert folder is self.root_bfn
        assert final == 'a/b'

    def test_slash_cd_tests_a(self):
        """Try a /cd-tests/a try_resolve_path, where /cd-tests preexists, but /cd-tests/b does not."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests/a')
        assert folder is self.cd_tests_bfn
        assert final == 'a'

    def test_slash_cd_tests(self):
        """Try a /cd-tests try_resolve_path, where /cd-tests preexists."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests')
        assert folder is self.cd_tests_bfn
        assert final == ''

    def test_a_slash_slash_b(self):
        """Try an a//b try_resolve_path, where neither a/b nor a preexist."""
        folder, final = subfolder.try_resolve_path(self.params, 'a//b')
        assert folder is self.root_bfn
        assert final == 'a/b'

    def test_slash_slash_a(self):
        """Try a //a try_resolve_path, where /a does not preexist.  Note that we want to create '/a', not 'a' in /."""
        folder, final = subfolder.try_resolve_path(self.params, '//a')
        assert folder is self.root_bfn
        assert final == '/a'

    def test_slash_slash_a_slash_slash_b(self):
        """
        Try a //a//b try_resolve_path, where neither /a/b nor /a preexist.

        Note that we want to create '/a/b', not 'a' in / and b in that.
        """
        folder, final = subfolder.try_resolve_path(self.params, '//a//b')
        assert folder is self.root_bfn
        assert final == '/a/b'

    def test_cd_tests_dot_dot(self):
        """Try a /cd-tests/.. try_resolve_path, where /cd-tests preexists."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests/..')
        assert folder is self.root_bfn
        assert final == ''

    def test_cd_tests_dot(self):
        """Try a /cd-test/. try_resolve_path, where /cd-tests preexists."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests/.')
        assert folder is self.cd_tests_bfn
        assert final == ''

    def test_slash_dot_dot(self):
        """Try a /.. try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/..')
        assert folder is self.root_bfn
        assert final == ''

    def test_slash_dot(self):
        """Try a /.. try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/.')
        assert folder is self.root_bfn
        assert final == '.'

    def test_slash_cd_tests_space(self):
        """Try a '/cd-tests ' try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/cd-tests ')
        assert folder is self.cd_tests_bfn
        assert final == ''

    def test_slash_space_cd_tests(self):
        """Try a '/ cd-tests' try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/ cd-tests')
        assert folder is self.cd_tests_bfn
        assert final == ''

    def test_slash_space_cd_tests_space(self):
        """Try a '/ cd-tests ' try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/ cd-tests ')
        assert folder is self.cd_tests_bfn
        assert final == ''

    def test_slash_space_slash_a(self):
        """Try a '/ /a' try_resolve_path."""
        folder, final = subfolder.try_resolve_path(self.params, '/ /a')
        assert folder is self.root_bfn
        assert final == '/a'


class TestSubfolderHandleInitialSlash(TestCase):
    """Tests for subfolders.handle_initial_slash."""

    def setUp(self):
        """Set up self.params, self.root_bfn and self.cd_tests_bfn."""
        (self.params, self.root_bfn, self.cd_tests_bfn) = create_fake_params()

    def test_slash(self):
        """Feed [''] to handle_initial_slash."""
        list_ = ['']
        folder = subfolder.handle_initial_slash(self.params, self.cd_tests_bfn, list_)
        assert folder is self.root_bfn
        assert list_ == []

    def test_slash_a(self):
        """Feed ['', 'a'] to handle_initial_slash."""
        list_ = ['', 'a']
        folder = subfolder.handle_initial_slash(self.params, self.cd_tests_bfn, list_)
        assert folder is self.root_bfn
        assert list_ == ['a']

    def test_slash_slash(self):
        """Feed ['', ''] to handle_initial_slash and see what it does."""
        list_ = ['', '']
        folder = subfolder.handle_initial_slash(self.params, self.cd_tests_bfn, list_)
        assert folder is self.cd_tests_bfn
        assert list_ == ['/']

    def test_slash_slash_a(self):
        """Feed ['', '', 'a'] to handle_initial_slash and see what it does."""
        list_ = ['', '', 'a']
        folder = subfolder.handle_initial_slash(self.params, self.cd_tests_bfn, list_)
        assert folder is self.cd_tests_bfn
        assert list_ == ['/a']


class TestSubfolderHandleSubsequentSlashSlash(TestCase):
    """Tests for subfolders.handle_initial_slash."""

    def test_a_slash_slash_b_slash_c(self):
        """Test a//b/c ."""
        list_ = ['a', '', 'b', 'c']
        result = subfolder.handle_subsequent_slash_slash(list_)
        assert result == ['a/b', 'c']

    def test_a_slash_slash_slash_b_slash_c(self):
        """Test a///b/c ."""
        list_ = ['a', '', '', 'b', 'c']
        result = subfolder.handle_subsequent_slash_slash(list_)
        assert result == ['a/', 'b', 'c']

    def test_a_slash_slash_b_slash_c_d(self):
        """Test a//b/c/d ."""
        list_ = ['a', '', 'b', 'c', 'd']
        result = subfolder.handle_subsequent_slash_slash(list_)
        assert result == ['a/b', 'c', 'd']

    def test_a_slash_slash_b_slash_c_d_e(self):
        """Test a//b/c/d/e ."""
        list_ = ['a', '', 'b', 'c', 'd', 'e']
        result = subfolder.handle_subsequent_slash_slash(list_)
        assert result == ['a/b', 'c', 'd', 'e']

    def test_a_b_c_d_e(self):
        """Test a/b/c/d/e ."""
        list_ = ['a', 'b', 'c', 'd', 'e']
        result = subfolder.handle_subsequent_slash_slash(list_)
        assert result == ['a', 'b', 'c', 'd', 'e']


if __name__ == '__main__':
    instance = TestSubfolderTryResolvePath()
    if hasattr(instance, 'setUp'):
        instance.setUp()
    instance.test_a_slash_slash_b()
    if hasattr(instance, 'tearDown'):
        instance.tearDown()
