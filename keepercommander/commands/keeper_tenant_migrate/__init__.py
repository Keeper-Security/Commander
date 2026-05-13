# Keeper Commander — tenant-migrate plugin.
# Single source of truth for the package version. Read by setup/pyproject
# (via dynamic version) and by `audit_export.to_cef` for the CEF header
# vendor/product/version triple. Bumped by hand at release-tag time.

__version__ = '1.7.7'

from .commands import register_commands, register_command_info

__all__ = ['register_commands', 'register_command_info', '__version__']
