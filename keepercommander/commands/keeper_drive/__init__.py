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
    commands['kd-mkdir']                     = KeeperDriveMkdirCommand()
    commands['kd-record-add']                = KeeperDriveAddRecordCommand()
    commands['kd-record-update']             = KeeperDriveUpdateRecordCommand()
    commands['kd-rndir']                     = KeeperDriveUpdateFolderCommand()
    commands['kd-list']                      = KeeperDriveListCommand()
    commands['kd-share-folder']              = KeeperDriveShareFolderCommand()
    commands['kd-record-details']            = KeeperDriveGetRecordDetailsCommand()
    commands['kd-share-record']              = KeeperDriveShareRecordCommand()
    commands['kd-record-permission']         = KeeperDriveRecordPermissionCommand()
    commands['kd-transfer-record']           = KeeperDriveTransferRecordCommand()
    commands['kd-ln']                        = KeeperDriveLnCommand()
    commands['kd-rm']                        = KeeperDriveRemoveRecordCommand()
    commands['kd-rmdir']                     = KeeperDriveRemoveFolderCommand()
    commands['kd-shortcut']                  = KeeperDriveShortcutCommand()
    commands['kd-get']                       = KeeperDriveGetCommand()


def register_command_info(aliases, command_info):
    """Register command help descriptions."""
    command_info['kd-mkdir']                     = 'Create a KeeperDrive folder (v3 API)'
    command_info['kd-record-add']                = 'Create a KeeperDrive record (v3 API)'
    command_info['kd-record-update']             = 'Update a KeeperDrive record (v3 API)'
    command_info['kd-rndir']                     = 'Rename a KeeperDrive folder'
    command_info['kd-list']                      = 'List Keeper Drive folders and records'
    command_info['kd-share-folder']              = 'Grant/update/revoke folder sharing (v3 API)'
    command_info['kd-record-details']            = 'Get record metadata (title, color) (v3 API)'
    command_info['kd-share-record']              = 'Grant/update/revoke record sharing (v3 API)'
    command_info['kd-record-permission']         = 'Modify sharing permissions of records in a folder (v3 API)'
    command_info['kd-transfer-record']           = 'Transfer record ownership to another user (v3 API)'
    command_info['kd-ln']                        = 'Link a record into a KeeperDrive folder (positional)'
    command_info['kd-rm']                        = 'Remove (delete/unlink) a KeeperDrive record (v3 API)'
    command_info['kd-rmdir']                     = 'Remove a KeeperDrive folder and its contents (v3 API)'
    command_info['kd-shortcut']                  = 'Manage KeeperDrive record shortcuts (multi-folder links)'
    command_info['kd-get']                       = 'Get details of a KeeperDrive record or folder (like legacy get)'
