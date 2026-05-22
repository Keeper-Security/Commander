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
KeeperDrive CLI Commands — public package facade.

This ``__init__.py`` is the single entry-point consumed by the command
framework (``base.py``).  It re-exports every command class and exposes
``register_commands()`` / ``register_command_info()``.

Package layout (Facade pattern)::

    keeper_drive/
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
    KeeperDriveMkdirCommand,
    KeeperDriveUpdateFolderCommand,
    KeeperDriveListCommand,
    KeeperDriveShareFolderCommand,
    KeeperDriveRemoveFolderCommand,
)

# Record commands
from .record_commands import (                           # noqa: F401
    KeeperDriveAddRecordCommand,
    KeeperDriveUpdateRecordCommand,
    KeeperDriveLnCommand,
    KeeperDriveShortcutCommand,
    KeeperDriveRemoveRecordCommand,
)

# Sharing commands
from .sharing_commands import (                          # noqa: F401
    KeeperDriveShareRecordCommand,
    KeeperDriveRecordPermissionCommand,
    KeeperDriveTransferRecordCommand,
)

# Display commands
from .display_commands import (                          # noqa: F401
    KeeperDriveGetRecordDetailsCommand,
    KeeperDriveGetCommand,
)


def register_commands(commands):
    """Register KeeperDrive commands with the command framework."""
    commands['nsf-mkdir']                     = KeeperDriveMkdirCommand()
    commands['nsf-record-add']                = KeeperDriveAddRecordCommand()
    commands['nsf-record-update']             = KeeperDriveUpdateRecordCommand()
    commands['nsf-rndir']                     = KeeperDriveUpdateFolderCommand()
    commands['nsf-list']                      = KeeperDriveListCommand()
    commands['nsf-share-folder']              = KeeperDriveShareFolderCommand()
    commands['nsf-record-details']            = KeeperDriveGetRecordDetailsCommand()
    commands['nsf-share-record']              = KeeperDriveShareRecordCommand()
    commands['nsf-record-permission']         = KeeperDriveRecordPermissionCommand()
    commands['nsf-transfer-record']           = KeeperDriveTransferRecordCommand()
    commands['nsf-ln']                        = KeeperDriveLnCommand()
    commands['nsf-rm']                        = KeeperDriveRemoveRecordCommand()
    commands['nsf-rmdir']                     = KeeperDriveRemoveFolderCommand()
    commands['nsf-shortcut']                  = KeeperDriveShortcutCommand()
    commands['nsf-get']                       = KeeperDriveGetCommand()


def register_command_info(aliases, command_info):
    """Register command help descriptions."""
    command_info['nsf-mkdir']                     = 'Create a KeeperDrive folder'
    command_info['nsf-record-add']                = 'Create a KeeperDrive record'
    command_info['nsf-record-update']             = 'Update a KeeperDrive record'
    command_info['nsf-rndir']                     = 'Rename a KeeperDrive folder'
    command_info['nsf-list']                      = 'List Keeper Drive folders and records'
    command_info['nsf-share-folder']              = 'Grant/update/revoke folder access'
    command_info['nsf-record-details']            = 'Get record metadata'
    command_info['nsf-share-record']              = 'Grant/update/revoke record sharing'
    command_info['nsf-record-permission']         = 'Modify sharing permissions of records in a folder'
    command_info['nsf-transfer-record']           = 'Transfer record ownership to another user'
    command_info['nsf-ln']                        = 'Link a record into a KeeperDrive folder'
    command_info['nsf-rm']                        = 'Remove (delete/unlink) a KeeperDrive record'
    command_info['nsf-rmdir']                     = 'Remove a KeeperDrive folder and its contents'
    command_info['nsf-shortcut']                  = 'Manage KeeperDrive record shortcuts'
    command_info['nsf-get']                       = 'Get details of a KeeperDrive record or folder'
