"""Pytest session hooks for unit-tests.

CNAPP tests import `cnapp_helper` before `keepercommander.commands.record` is loaded,
which triggers a pre-existing record <-> ksm circular import. Loading `record` first
resolves the cycle (same as production startup order).
"""
import pytest


@pytest.fixture(scope='session', autouse=True)
def _preload_commands_record_module():
    import keepercommander.commands.record  # noqa: F401
