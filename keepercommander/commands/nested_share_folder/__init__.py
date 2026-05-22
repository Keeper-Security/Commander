#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Nested Share Folder CLI Commands — public package facade.

This ``__init__.py`` is the single entry-point consumed by the command
framework (``base.py``).  It re-exports every command class and exposes
``register_commands()`` / ``register_command_info()``.

Package layout (Facade pattern)::

    nested_share_folder/
        __init__.py          ← you are here (public API)
        helpers.py           ← shared utilities, constants, error handling
        parsers.py           ← argparse definitions (Factory Method)
        folder_commands.py   ← folder management (SRP)
        record_commands.py   ← record CRUD & linking (SRP)
        sharing_commands.py  ← sharing & permissions (Strategy, Template Method)
        display_commands.py  ← read-only inspection (SRP)
"""

# Folder commands
from .folder_commands import (                           # noqa: F401
    NestedShareFolderMkdirCommand,
    NestedShareFolderUpdateCommand,
    NestedShareFolderListCommand,
    NestedShareFolderShareCommand,
    NestedShareFolderRemoveCommand,
)

# Record commands
from .record_commands import (                           # noqa: F401
    NestedShareRecordAddCommand,
    NestedShareRecordUpdateCommand,
    NestedShareRecordLnCommand,
    NestedShareRecordShortcutCommand,
    NestedShareRecordRemoveCommand,
)

# Sharing commands
from .sharing_commands import (                          # noqa: F401
    NestedShareRecordShareCommand,
    NestedShareRecordPermissionCommand,
    NestedShareRecordTransferCommand,
)

# Display commands
from .display_commands import (                          # noqa: F401
    NestedShareRecordGetDetailsCommand,
    NestedShareGetCommand,
)


def register_commands(commands):
    """Register Nested Share Folder commands with the command framework."""
    commands['nsf-mkdir']                     = NestedShareFolderMkdirCommand()
    commands['nsf-record-add']                = NestedShareRecordAddCommand()
    commands['nsf-record-update']             = NestedShareRecordUpdateCommand()
    commands['nsf-rndir']                     = NestedShareFolderUpdateCommand()
    commands['nsf-list']                      = NestedShareFolderListCommand()
    commands['nsf-share-folder']              = NestedShareFolderShareCommand()
    commands['nsf-record-details']            = NestedShareRecordGetDetailsCommand()
    commands['nsf-share-record']              = NestedShareRecordShareCommand()
    commands['nsf-record-permission']         = NestedShareRecordPermissionCommand()
    commands['nsf-transfer-record']           = NestedShareRecordTransferCommand()
    commands['nsf-ln']                        = NestedShareRecordLnCommand()
    commands['nsf-rm']                        = NestedShareRecordRemoveCommand()
    commands['nsf-rmdir']                     = NestedShareFolderRemoveCommand()
    commands['nsf-shortcut']                  = NestedShareRecordShortcutCommand()
    commands['nsf-get']                       = NestedShareGetCommand()


def register_command_info(aliases, command_info):
    """Register command help descriptions."""
    command_info['nsf-mkdir']                     = 'Create a Nested Share Folder'
    command_info['nsf-record-add']                = 'Create a Nested Share Record'
    command_info['nsf-record-update']             = 'Update a Nested Share Record'
    command_info['nsf-rndir']                     = 'Rename a Nested Share Folder'
    command_info['nsf-list']                      = 'List Nested Share folders and records'
    command_info['nsf-share-folder']              = 'Grant/update/revoke folder access'
    command_info['nsf-record-details']            = 'Get record metadata'
    command_info['nsf-share-record']              = 'Grant/update/revoke record sharing'
    command_info['nsf-record-permission']         = 'Modify sharing permissions of records in a folder'
    command_info['nsf-transfer-record']           = 'Transfer record ownership to another user'
    command_info['nsf-ln']                        = 'Link a record into a Nested Share Folder'
    command_info['nsf-rm']                        = 'Remove (delete/unlink) a Nested Share Record'
    command_info['nsf-rmdir']                     = 'Remove a Nested Share Folder and its contents'
    command_info['nsf-shortcut']                  = 'Manage Nested Share Record shortcuts'
    command_info['nsf-get']                       = 'Get details of a Nested Share Record or folder'
