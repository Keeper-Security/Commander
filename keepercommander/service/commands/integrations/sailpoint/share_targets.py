#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""Validate classic vs Nested Share Folder targets for SailPoint share hooks."""

from __future__ import annotations

from typing import Optional

from .....params import KeeperParams
from .....subfolder import BaseFolderNode
from .command_parse import ParsedShare


def is_nsf_folder(params: KeeperParams, uid: str) -> bool:
    return bool(uid) and uid in getattr(params, 'nested_share_folders', {})


def is_nsf_record(params: KeeperParams, uid: str) -> bool:
    return bool(uid) and uid in getattr(params, 'nested_share_records', {})


def is_classic_record(params: KeeperParams, uid: str) -> bool:
    if not uid or is_nsf_record(params, uid):
        return False
    return uid in (params.record_cache or {})


def is_classic_shared_folder(params: KeeperParams, uid: str) -> bool:
    if not uid or is_nsf_folder(params, uid):
        return False
    if uid in (params.shared_folder_cache or {}):
        return True
    folder = (params.folder_cache or {}).get(uid)
    if not folder:
        return False
    return folder.type in (
        BaseFolderNode.SharedFolderType,
        BaseFolderNode.SharedFolderFolderType,
    )


def validate_share_targets(params: KeeperParams, share: ParsedShare) -> Optional[str]:
    """
    Ensure share command family matches target type.

    Classic share-* must not target NSF UIDs, and nsf-share-* must not target
    classic shared-folder / record UIDs.
    """
    for uid in share.targets:
        if share.is_folder and share.is_nsf:
            if is_nsf_folder(params, uid):
                continue
            if is_classic_shared_folder(params, uid):
                return (
                    f'Target "{uid}" is a classic shared folder; '
                    f'use share-folder instead of nsf-share-folder.'
                )
            return (
                f'Target "{uid}" is not a Nested Share Folder; '
                f'nsf-share-folder requires an NSF folder UID.'
            )

        if share.is_folder and not share.is_nsf:
            if is_classic_shared_folder(params, uid):
                continue
            if is_nsf_folder(params, uid):
                return (
                    f'Target "{uid}" is a Nested Share Folder; '
                    f'use nsf-share-folder instead of share-folder.'
                )
            return (
                f'Target "{uid}" is not a classic shared folder; '
                f'share-folder requires a shared-folder UID.'
            )

        if share.is_record and share.is_nsf:
            if is_nsf_record(params, uid):
                continue
            if is_classic_record(params, uid):
                return (
                    f'Target "{uid}" is a classic record; '
                    f'use share-record instead of nsf-share-record.'
                )
            if is_nsf_folder(params, uid) or is_classic_shared_folder(params, uid):
                return (
                    f'Target "{uid}" is a folder; '
                    f'nsf-share-record requires an NSF record UID.'
                )
            return (
                f'Target "{uid}" is not an NSF record; '
                f'nsf-share-record requires an NSF record UID.'
            )

        if share.is_record and not share.is_nsf:
            if is_classic_record(params, uid):
                continue
            if is_nsf_record(params, uid):
                return (
                    f'Target "{uid}" is an NSF record; '
                    f'use nsf-share-record instead of share-record.'
                )
            if is_nsf_folder(params, uid) or is_classic_shared_folder(params, uid):
                return (
                    f'Target "{uid}" is a folder; '
                    f'share-record requires a classic record UID.'
                )
            return (
                f'Target "{uid}" is not a classic record; '
                f'share-record requires a record UID.'
            )

    return None
