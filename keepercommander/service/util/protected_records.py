#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Identify Service Mode's own config records and folders so they can be hidden from commands."""

from __future__ import annotations

import contextlib
import os
from collections import UserDict
from collections.abc import MutableMapping
from typing import Dict, FrozenSet, Iterable, Optional, Set, Tuple

# Each integration's own setup pins its config record's UID here, regardless of its title. Extend when a new integration gets an always-hidden record.
_PINNED_RECORD_UID_ENVS: Dict[str, str] = {
    'COMMANDER_RECORD': '<Docker config record>',
    'TERRAFORM_RECORD': '<Terraform config record>',
    'SLACK_RECORD': '<Slack config record>',
    'TEAMS_RECORD': '<Teams config record>',
    'GCHAT_RECORD': '<GChat config record>',
    'SAILPOINT_RECORD': '<SailPoint config record>',
}

# uid-keyed caches resolve_single_record/load_pam_record fall back to when a UID isn't in record_cache.
_GUARDED_CACHE_ATTRS = ('record_cache', 'nested_share_records', 'nested_share_record_data')

# Raw + derived folder caches every folder-resolving command reads through,
# directly or via subfolder.try_resolve_path/get_folder_uids.
_GUARDED_FOLDER_CACHE_ATTRS = ('folder_cache', 'shared_folder_cache', 'subfolder_cache')

# Commander's own session (config.json) and Service Mode's own runtime (service_config.json)
# config files -- always attached under these exact, hardcoded names, never user-choosable.
_RESERVED_ATTACHMENT_NAMES = frozenset({'config.json', 'service_config.json'})


def _attachment_file_uids(record) -> list:
    """UIDs of every file attachment on record -- legacy PasswordRecord.attachments' ids, or a
    typed record's fileRef entries (each its own separate FileRecord, loadable/gettable by that UID)."""
    from ... import vault

    if isinstance(record, vault.PasswordRecord):
        return [atta.id for atta in (record.attachments or []) if atta.id]
    if isinstance(record, vault.TypedRecord):
        typed_field = record.get_typed_field('fileRef')
        if typed_field and isinstance(typed_field.value, list):
            return [uid for uid in typed_field.value if isinstance(uid, str)]
    return []


def _has_reserved_legacy_attachment(record) -> bool:
    """True if a PasswordRecord's own .attachments (no extra load -- filenames live on the attachment
    object itself) include one literally named config.json/service_config.json."""
    from ... import vault

    return isinstance(record, vault.PasswordRecord) and any(
        (atta.title or atta.name or '').lower() in _RESERVED_ATTACHMENT_NAMES
        for atta in (record.attachments or [])
    )


def _protected_titles() -> Tuple[str, ...]:
    """The literal titles of Service Mode's own config records; imported lazily to avoid a circular import through verified_command."""
    from ..config.file_handler import SERVICE_CONFIG_RECORD_TITLES
    from ..commands.terraform_app_setup import TerraformSetupConstants
    from ..commands.integrations.slack_app_setup import SlackAppSetupCommand
    from ..commands.integrations.teams_app_setup import TeamsAppSetupCommand
    from ..commands.integrations.sailpoint_app_setup import SailPointAppSetupCommand
    from ..docker.models import DockerSetupConstants, GChatConstants
    return (
        *SERVICE_CONFIG_RECORD_TITLES,
        DockerSetupConstants.DEFAULT_RECORD_NAME,
        TerraformSetupConstants.DEFAULT_RECORD_NAME,
        GChatConstants.DEFAULT_RECORD_NAME,
        SlackAppSetupCommand().get_default_record_name(),
        TeamsAppSetupCommand().get_default_record_name(),
        SailPointAppSetupCommand().get_default_record_name(),
    )


def get_protected_record_title_set() -> FrozenSet[str]:
    """Lower-cased titles of Service Mode's own config records, for literal matching."""
    return frozenset(t.lower() for t in _protected_titles())


def get_protected_record_uids(params) -> Dict[str, str]:
    """Resolve current UIDs of Service Mode's own config records ({uid: title}), matching by title plus each integration's pinned UID env var (_PINNED_RECORD_UID_ENVS); not cached, since a stale result on this security check is worse than the cost of a full-vault scan."""
    from ..commands.integrations.approvals_setup import is_valid_keeper_uid
    from ..decorators.logging import logger

    found: Dict[str, str] = {}
    for env_name, label in _PINNED_RECORD_UID_ENVS.items():
        uid = (os.environ.get(env_name) or '').strip()
        if not uid:
            continue
        if not is_valid_keeper_uid(uid):
            logger.warning(f'protected_records: {env_name} is set but not a valid record UID; falling back to title matching for it')
            continue
        found[uid] = label

    if params is None or not isinstance(getattr(params, 'record_cache', None), dict) or not params.record_cache:
        return found

    from ... import vault

    protected_titles = get_protected_record_title_set()
    # One load per record_cache entry, no more -- a FileRecord attachment target is itself an
    # entry in this same cache, so its name is picked up by this same pass rather than a second,
    # per-attachment load 
    reserved_file_uids: Set[str] = set()
    pending_attachments: Dict[str, list] = {}
    for uid in params.record_cache:
        try:
            record = vault.KeeperRecord.load(params, uid)
        except Exception as e:
            logger.debug(f'protected_records: could not load record {uid} ({type(e).__name__}); skipping')
            continue
        if not record:
            continue

        if isinstance(record, vault.FileRecord):
            if (record.title or record.name or '').lower() in _RESERVED_ATTACHMENT_NAMES:
                reserved_file_uids.add(uid)
            continue

        if record.title.lower() in protected_titles:
            found[uid] = record.title
        elif _has_reserved_legacy_attachment(record):
            found[uid] = '<record with a reserved config attachment>'

        file_uids = _attachment_file_uids(record)
        if file_uids:
            pending_attachments[uid] = file_uids

    for parent_uid, file_uids in pending_attachments.items():
        if parent_uid not in found and any(file_uid in reserved_file_uids for file_uid in file_uids):
            found[parent_uid] = '<record with a reserved config attachment>'
        if parent_uid in found:
            for file_uid in file_uids:
                found.setdefault(file_uid, '<attachment on a protected record>')

    return found


def get_protected_folder_uids(params, protected_record_uids: Dict[str, str]) -> Set[str]:
    """Folders directly containing an already-protected record, via subfolder_record_cache (folder_uid -> set of record UIDs) -- derived from record protection rather than a separate per-integration title list, so it stays correct even if a folder is renamed."""
    subfolder_record_cache = getattr(params, 'subfolder_record_cache', None)
    if params is None or not protected_record_uids or not isinstance(subfolder_record_cache, dict):
        return set()

    record_uids = protected_record_uids.keys()
    return {
        folder_uid for folder_uid, uids in subfolder_record_cache.items()
        if folder_uid and isinstance(uids, (set, frozenset)) and uids & record_uids
    }


def _sync_down_exempt_commands() -> Dict[str, str]:
    """{command name: pinned-UID env var}, derived from each integration's own class instead of duplicated literals."""
    from ..commands.integrations.gchat_app_setup import GChatAppSetupCommand
    from ..commands.integrations.slack_app_setup import SlackAppSetupCommand
    return {cmd.get_command_name(): cmd.get_record_env_key() for cmd in (SlackAppSetupCommand(), GChatAppSetupCommand())}


def resolve_sync_down_exempt_uid(command_tokens) -> Optional[str]:
    """For '{slack,gchat}-app-setup ... --sync-down ...', the one UID this dispatch may bypass Layers A/B for -- always this integration's own pinned-env UID, never derived from what the admin passes (e.g. -r/--integration-record), so a different integration's protected record can never be reached this way."""
    if not command_tokens:
        return None

    env_name = _sync_down_exempt_commands().get(command_tokens[0].lower())
    if not env_name:
        return None

    if '--sync-down' not in command_tokens[1:]:
        return None

    return (os.environ.get(env_name) or '').strip() or None


class _GuardedRecordCache(UserDict):
    """A uid-keyed cache view that can never hold the given protected UIDs; UserDict (not dict) so every mutation reliably routes through __setitem__, even C-level ones like setdefault/|=."""

    def __init__(self, source, protected_uids: Iterable[str]):
        self._protected_uids = frozenset(protected_uids)
        super().__init__({k: v for k, v in source.items() if k not in self._protected_uids})

    def __setitem__(self, key, value):
        if key in self._protected_uids:
            return
        super().__setitem__(key, value)


@contextlib.contextmanager
def hide_from_record_cache(params, protected_uids: Dict[str, str]):
    """For the with-block, guards record_cache/nested_share_records/nested_share_record_data against reintroduction (not just a one-time pop) and strips protected UIDs from subfolder_record_cache, restoring everything on exit; relies on Service Mode commands running one at a time (same assumption capture_output_and_logs already makes) and may leave record_cache stale until the next sync if one lands mid-command."""
    if params is None or not protected_uids:
        yield
        return

    protected_uid_set = frozenset(protected_uids)

    original_caches = {}
    saved_entries = {}
    for attr in _GUARDED_CACHE_ATTRS:
        source = getattr(params, attr, None)
        if not isinstance(source, MutableMapping):
            continue
        original_caches[attr] = source
        saved_entries[attr] = {uid: source[uid] for uid in protected_uid_set if uid in source}
        setattr(params, attr, _GuardedRecordCache(source, protected_uid_set))

    subfolder_cache = getattr(params, 'subfolder_record_cache', None)
    removed_from_folders: Dict[str, set] = {}
    if isinstance(subfolder_cache, dict):
        for folder_uid, uids in subfolder_cache.items():
            if not isinstance(uids, set):
                continue
            hit = uids & protected_uid_set
            if hit:
                removed_from_folders[folder_uid] = hit
                uids -= hit

    try:
        yield
    finally:
        from ..decorators.logging import logger

        for attr in original_caches:
            try:
                restored = dict(getattr(params, attr, None) or {})
                restored.update(saved_entries[attr])
                setattr(params, attr, restored)
            except Exception as e:
                logger.debug(f'hide_from_record_cache: failed to restore {attr} ({type(e).__name__}); restoring protected entries only')
                try:
                    setattr(params, attr, dict(saved_entries[attr]))
                except Exception:
                    pass

        if isinstance(subfolder_cache, dict):
            for folder_uid, hit in removed_from_folders.items():
                try:
                    uids = subfolder_cache.get(folder_uid)
                    if isinstance(uids, set):
                        uids |= hit
                except Exception as e:
                    logger.debug(f'hide_from_record_cache: failed to restore subfolder {folder_uid} ({type(e).__name__})')


@contextlib.contextmanager
def hide_from_folder_cache(params, protected_folder_uids: Set[str]):
    """For the with-block, hides protected_folder_uids from folder_cache/shared_folder_cache/subfolder_cache and
    from their parent's (or root_folder's) .subfolders list, restoring everything on exit """
    if params is None or not protected_folder_uids:
        yield
        return

    protected_uid_set = frozenset(protected_folder_uids)

    folder_cache = getattr(params, 'folder_cache', None)
    root_folder = getattr(params, 'root_folder', None)
    # {uid: (subfolders_list, original_index)} -- built up incrementally inside the try below so a
    # failure partway through setup still leaves whatever was already removed restorable in finally,
    # rather than mutating this live list before there's any guarantee finally will run at all.
    removed_from_parents: Dict[str, tuple] = {}
    original_caches = {}
    saved_entries = {}

    try:
        if isinstance(folder_cache, dict):
            for uid in protected_uid_set:
                node = folder_cache.get(uid)
                parent_uid = getattr(node, 'parent_uid', None) if node is not None else None
                parent = folder_cache.get(parent_uid) if parent_uid else root_folder
                subfolders = getattr(parent, 'subfolders', None) if parent is not None else None
                if isinstance(subfolders, list) and uid in subfolders:
                    index = subfolders.index(uid)
                    subfolders.remove(uid)
                    removed_from_parents[uid] = (subfolders, index)

        for attr in _GUARDED_FOLDER_CACHE_ATTRS:
            source = getattr(params, attr, None)
            if not isinstance(source, MutableMapping):
                continue
            original_caches[attr] = source
            saved_entries[attr] = {uid: source[uid] for uid in protected_uid_set if uid in source}
            setattr(params, attr, _GuardedRecordCache(source, protected_uid_set))

        yield
    finally:
        from ..decorators.logging import logger

        for attr in original_caches:
            try:
                restored = dict(getattr(params, attr, None) or {})
                restored.update(saved_entries[attr])
                setattr(params, attr, restored)
            except Exception as e:
                logger.debug(f'hide_from_folder_cache: failed to restore {attr} ({type(e).__name__}); restoring protected entries only')
                try:
                    setattr(params, attr, dict(saved_entries[attr]))
                except Exception:
                    pass

        for uid, (subfolders, index) in removed_from_parents.items():
            try:
                if uid not in subfolders:
                    subfolders.insert(min(index, len(subfolders)), uid)
            except Exception as e:
                logger.debug(f'hide_from_folder_cache: failed to restore subfolders entry for {uid} ({type(e).__name__})')
