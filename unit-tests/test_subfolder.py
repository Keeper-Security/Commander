#!/usr/bin/env python3

"""Test keepercommander.subfolder."""

from unittest.mock import Mock

import pytest

import keepercommander.subfolder as subfolder


def BFN(*, type, uid, parent_uid, name, subfolders):
    """Build a mock BaseFolderNode."""
    result = Mock(name=name)
    result.type = type
    result.uid = uid
    result.parent_uid = parent_uid
    result.name = name
    # A list of UID's, not folders.
    assert all(isinstance(subfolder, str) for subfolder in subfolders)
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


(global_params, global_root_bfn, global_cd_tests_bfn) = create_fake_params()

global_test_params = (
    ('a', global_root_bfn, 'a'),
    ('/a', global_root_bfn, 'a'),
    ('/a/b', global_root_bfn, 'a/b'),
    ('/cd-tests/a', global_cd_tests_bfn, 'a'),
    ('/cd-tests', global_cd_tests_bfn, ''),
    ('a//b', global_root_bfn, 'a//b'),
    ('//a', global_root_bfn, '//a'),
    ('//a//b', global_root_bfn, '//a//b'),
    ('/cd-tests/a//b//c', global_cd_tests_bfn, 'a//b//c'),
    ('/cd-tests/..', global_root_bfn, ''),
    ('/cd-tests/.', global_cd_tests_bfn, ''),
    ('/..', global_root_bfn, ''),
    ('/.', global_root_bfn, ''),
    ('/./cd-tests', global_cd_tests_bfn, ''),
    ('/./cd-tests/nonexistent', global_cd_tests_bfn, 'nonexistent'),
    ('/./cd-tests/./nonexistent', global_cd_tests_bfn, 'nonexistent'),
    # The next three were complicating tab completion, so they no longer work.
    # ('/./cd-tests/ ', global_cd_tests_bfn, ''),
    # ('/ cd-tests', global_cd_tests_bfn, ''),
    # ('/ cd-tests ', global_cd_tests_bfn, ''),

    # This is a corner case we are willing to ignore
    # ('/ /a', global_root_bfn, '//a'),
    ('/', global_root_bfn, ''),
    ('//', global_root_bfn, '//'),
)


@pytest.mark.parametrize('input_, expected_folder, expected_final', global_test_params)
def test_subfolder_try_resolve_path(input_, expected_folder, expected_final):
    """Test try_resolve_path."""
    actual_folder, actual_final = subfolder.try_resolve_path(global_params, input_)
    assert actual_folder is expected_folder
    assert actual_final == expected_final
