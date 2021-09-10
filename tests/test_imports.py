from pkgutil import walk_packages
from setuptools import find_packages, find_packages

import pytest

import keepercommander


SKIP_PKG_IMPORT = ['keepercommander.yubikey', ]
SKIP_PLUGIN_IMPORT = ['azureadpwd', 'mssql', 'mysql', 'oracle', 'postgresql', 'ssh', 'unixpasswd']
SKIP_PKG_IMPORT += [f'keepercommander.plugins.{p}' for p in SKIP_PLUGIN_IMPORT]


def pkg_import_error(pkg):
    if pkg not in SKIP_PKG_IMPORT:
        print(f"ERROR: Couldn't import {pkg}")


def get_modules():
    return [
        m.name for m in
        walk_packages(keepercommander.__path__, keepercommander.__name__ + '.', onerror=pkg_import_error)
        if m.name not in SKIP_PKG_IMPORT
    ]


@pytest.mark.quicktest
@pytest.mark.keeper_imports
@pytest.mark.parametrize('pkg_name', [p for p in find_packages() if p not in SKIP_PKG_IMPORT])
def test_keeper_import_pkg(pkg_name):
    __import__(pkg_name)


@pytest.mark.quicktest
@pytest.mark.keeper_imports
@pytest.mark.parametrize('module_name', get_modules())
def test_keeper_import_module(module_name):
    __import__(module_name)
