#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)
#
# Idempotency helpers.
#
# A CyberArk → Keeper import must be safely re-runnable: a second run
# of the same command against the same PVWA must not create duplicate
# vault records, and any account whose CyberArk-side attributes have
# changed must be reflected on the existing Keeper record.
#
# Identity strategy
# -----------------
# CyberArk assigns every account a stable numeric id (e.g. ``17_3``).
# We embed this id as a machine-readable marker on the last line of
# the Keeper record's ``notes`` field:
#
#     [CyberArk-ID: account_id=17_3; safe=Win_Local_Admins]
#
# Notes survive the ``pam project import`` code path unchanged (unlike
# ``custom`` fields, which ``PamBaseMachineParser`` does not preserve),
# so this marker is a low-risk carrier for the identity.  Subsequent
# imports parse the marker back out to match incoming CyberArk
# accounts to existing Keeper records regardless of title / host
# changes.
#
# When the marker is missing (records imported before this feature
# shipped, or hand-created records), we fall back to a tuple match on
# ``(record_type, casefold(title))`` scoped to the target project's
# safe folders.  Titles emitted by ``AccountMapper`` are deterministic
# (``{address}-{userName}`` for machines, ``{login}@{title}`` for
# users, etc.) so the fallback catches most legacy records without
# expensive full-vault scans.

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Notes marker
# ---------------------------------------------------------------------------

# ``account_id`` values look like ``17_3`` (Privilege Cloud) or numeric
# strings (self-hosted PVWA); ``safe`` names allow spaces, dashes,
# underscores and dots.  The regex tolerates both and is anchored to
# start-of-line so it doesn't accidentally match free-form notes text
# that mentions "CyberArk-ID" in prose.
_MARKER_RE = re.compile(
    r"^\s*\[CyberArk-ID:\s*account_id=(?P<id>[^;\]\s]+)"
    r"(?:\s*;\s*safe=(?P<safe>[^\]]*))?\s*\]\s*$",
    re.MULTILINE,
)


def format_id_marker(account_id: str, safe: str = "") -> str:
    """Build the machine-readable marker line for ``notes``.

    Callers are expected to append this to the record's ``notes``
    field on its own line (preceded by a blank line if there is any
    existing content) so :func:`parse_id_marker` can find it later.
    """
    account_id = (account_id or "").strip()
    safe = (safe or "").strip()
    if not account_id:
        return ""
    if safe:
        return f"[CyberArk-ID: account_id={account_id}; safe={safe}]"
    return f"[CyberArk-ID: account_id={account_id}]"


def parse_id_marker(notes: Optional[str]) -> Optional[Tuple[str, str]]:
    """Extract ``(account_id, safe)`` from a notes blob.

    Returns ``None`` when no marker is present.  Only the last marker
    is honored if a record somehow accumulated multiple — this handles
    the (unlikely) case where an admin manually pasted an old marker
    into the notes before a re-import.
    """
    if not notes or not isinstance(notes, str):
        return None
    matches = list(_MARKER_RE.finditer(notes))
    if not matches:
        return None
    last = matches[-1]
    return (last.group("id") or "").strip(), (last.group("safe") or "").strip()


def strip_id_marker(notes: Optional[str]) -> str:
    """Return ``notes`` with any CyberArk-ID marker line(s) removed.

    Used to compute the "user-visible notes" for diffing so a marker
    line the importer appended does not by itself trigger an update
    on the next run.
    """
    if not notes:
        return ""
    stripped = _MARKER_RE.sub("", notes).rstrip()
    return stripped


def annotate_record_with_marker(record: dict, account_id: str, safe: str) -> None:
    """Append the CyberArk identity marker to ``record['notes']`` in place.

    Safe to call multiple times on the same dict — existing markers are
    replaced with the new one so re-runs don't accumulate marker
    lines.  ``record`` is mutated; nothing is returned.
    """
    marker = format_id_marker(account_id, safe)
    if not marker:
        return
    existing = record.get("notes") or ""
    body = strip_id_marker(existing)
    if body:
        record["notes"] = f"{body}\n\n{marker}"
    else:
        record["notes"] = marker


# ---------------------------------------------------------------------------
# Existing-record index
# ---------------------------------------------------------------------------


@dataclass
class ExistingRecordIndex:
    """Lookup tables for records that already live in the target project.

    Built once per import run from a walk of the project's shared
    folder tree.  Two indexes are maintained so we can honor the
    CyberArk-ID marker when it is present and fall back to a
    deterministic-title match when it is not.
    """

    # account_id -> loaded KeeperRecord
    by_account_id: Dict[str, Any] = field(default_factory=dict)

    # (record_type, casefold(title)) -> loaded KeeperRecord
    by_title: Dict[Tuple[str, str], Any] = field(default_factory=dict)

    # record_uid -> parent folder UID (so callers can decide whether a
    # matched record still lives under the expected safe folder).
    folder_by_record: Dict[str, str] = field(default_factory=dict)

    # Every folder UID under the project tree we scanned.  Callers
    # use this to restrict "already exists" matches to the target
    # project instead of the whole vault.
    scanned_folder_uids: Set[str] = field(default_factory=set)

    def lookup(self, account_id: str, record_type: str, title: str) -> Optional[Any]:
        """Find an existing Keeper record for an incoming CyberArk record.

        Preference order:

        1. Match on ``account_id`` marker (strongest — survives title changes).
        2. Fallback tuple match on ``(record_type, casefold(title))``
           limited to the scanned project folders.

        Returns ``None`` when no match is found.
        """
        if account_id:
            hit = self.by_account_id.get(account_id.strip())
            if hit is not None:
                return hit
        key = ((record_type or "").strip(), (title or "").strip().casefold())
        return self.by_title.get(key)


def build_existing_index(params, folder_uids) -> ExistingRecordIndex:
    """Scan every record under ``folder_uids`` and index it by marker + title.

    ``folder_uids`` is an iterable of the shared folders that make up
    the target project (the Config folder plus every safe shared
    folder).  We recurse into each so records placed under the
    ``Resources``/``Users`` subfolders are picked up.

    Reads are done via ``params.record_cache`` + ``KeeperRecord.load``
    so no network round-trip is needed as long as the caller has
    ``sync_down``-ed recently.
    """
    # ``idempotency.py`` lives at
    # ``keepercommander.importer.cyberark.pam.idempotency``, so four dots
    # are needed to reach the top-level ``keepercommander.vault`` module
    # (three dots would land at ``keepercommander.importer``, where no
    # ``vault`` symbol exists).
    from .... import vault  # local import: keep module import graph light

    index = ExistingRecordIndex()

    folder_uids = list(folder_uids or [])
    if not folder_uids:
        return index

    # Guard against a stale/partially initialized ``params``: both caches
    # are populated by ``api.sync_down``, but a fresh session without a
    # sync will have them as ``None`` or empty dicts. Bail early so the
    # importer falls back to always-create mode instead of crashing.
    subfolder_record_cache = getattr(params, "subfolder_record_cache", None) or {}
    folder_cache = getattr(params, "folder_cache", None) or {}
    if not folder_cache and not getattr(params, "nested_share_folders", None):
        return index

    try:
        from keepercommander.commands.pam_import.nsf_helpers import get_folder_record_uids
    except ImportError:  # pragma: no cover
        get_folder_record_uids = None

    # Recursively collect record UIDs from every subfolder.
    stack = list(folder_uids)
    visited: Set[str] = set()
    all_record_uids: Set[str] = set()
    while stack:
        fuid = stack.pop()
        if not fuid or fuid in visited:
            continue
        visited.add(fuid)
        index.scanned_folder_uids.add(fuid)
        if get_folder_record_uids is not None:
            record_uids = get_folder_record_uids(params, fuid)
        else:
            record_uids = subfolder_record_cache.get(fuid) or set()
        for ruid in record_uids:
            all_record_uids.add(ruid)
            index.folder_by_record[ruid] = fuid
        folder = folder_cache.get(fuid)
        for sub_uid in (getattr(folder, "subfolders", []) or []) if folder else []:
            stack.append(sub_uid)
        for child_uid, info in (getattr(params, "nested_share_folders", None) or {}).items():
            if (info.get("parent_uid") or None) == fuid and child_uid not in visited:
                stack.append(child_uid)

    for ruid in all_record_uids:
        try:
            from keepercommander.commands.pam_import.record_loader import load_pam_record
            rec = load_pam_record(params, ruid) or vault.KeeperRecord.load(params, ruid)
        except ImportError:  # pragma: no cover
            rec = vault.KeeperRecord.load(params, ruid)
        if rec is None:
            continue
        rtype = getattr(rec, "record_type", "") or ""
        title = getattr(rec, "title", "") or ""

        # Marker index
        marker = parse_id_marker(getattr(rec, "notes", "") or "")
        if marker and marker[0]:
            # If duplicates exist (a bug or manual copy), keep the
            # first — logging the collision so admins notice.
            if marker[0] in index.by_account_id:
                logging.debug(
                    "Duplicate CyberArk-ID marker %s on records %s and %s; "
                    "keeping the first for idempotency lookup.",
                    marker[0],
                    getattr(index.by_account_id[marker[0]], "record_uid", "?"),
                    ruid,
                )
            else:
                index.by_account_id[marker[0]] = rec

        # Title fallback index
        if rtype and title:
            key = (rtype, title.casefold())
            index.by_title.setdefault(key, rec)

    return index


# ---------------------------------------------------------------------------
# Partition decision
# ---------------------------------------------------------------------------


class IdempotencyDecision(Enum):
    CREATE = "create"          # No existing match → send through pam project import
    UPDATE = "update"          # Match exists but data differs → update in place
    UNCHANGED = "unchanged"    # Match exists and every mapped field matches → skip


@dataclass
class RecordDecision:
    """Decision for a single top-level mapped record (or nested pamUser)."""

    decision: IdempotencyDecision
    incoming: dict                        # The mapped-record dict from AccountMapper
    existing: Optional[Any] = None        # Loaded KeeperRecord when matched
    account_id: str = ""                  # Parsed from marker embedded in ``notes``
    change_fields: List[str] = field(default_factory=list)  # Diagnostic


def _extract_marker(incoming: dict) -> Tuple[str, str]:
    """Return ``(account_id, safe)`` from an incoming mapped record."""
    marker = parse_id_marker(incoming.get("notes") or "")
    if marker:
        return marker
    return "", ""


def partition_records(mapped_resources: List[dict],
                      mapped_users: List[dict],
                      existing: ExistingRecordIndex,
                      diff_fn) -> List[RecordDecision]:
    """Categorize incoming CyberArk records against the existing index.

    ``mapped_resources`` and ``mapped_users`` are the two lists
    ``AccountMapper`` populates.  Nested ``users`` under a resource
    are partitioned separately because Keeper stores them as their
    own records; the parent resource's decision is independent of its
    users' decisions.

    ``diff_fn(existing_record, incoming_dict)`` is a callable that
    returns the list of field names where the two disagree.  Passed
    in so this module stays free of Keeper record-shape knowledge —
    it lives in ``cyberark_import.py`` where the mapper's schema is
    already known.

    Nested users are yielded as separate :class:`RecordDecision`
    entries with their parent-resource dict re-flattened onto them:
    the caller uses this list to build both the filtered import
    payload and the post-import update batch.
    """
    decisions: List[RecordDecision] = []

    def _decide(incoming: dict) -> RecordDecision:
        account_id, _ = _extract_marker(incoming)
        rtype = incoming.get("type", "") or ""
        title = incoming.get("title", "") or ""
        existing_rec = existing.lookup(account_id, rtype, title)
        if existing_rec is None:
            return RecordDecision(
                decision=IdempotencyDecision.CREATE,
                incoming=incoming,
                account_id=account_id,
            )
        change_fields = diff_fn(existing_rec, incoming) or []
        if change_fields:
            return RecordDecision(
                decision=IdempotencyDecision.UPDATE,
                incoming=incoming,
                existing=existing_rec,
                account_id=account_id,
                change_fields=list(change_fields),
            )
        return RecordDecision(
            decision=IdempotencyDecision.UNCHANGED,
            incoming=incoming,
            existing=existing_rec,
            account_id=account_id,
        )

    for res in mapped_resources or []:
        decisions.append(_decide(res))
        for user in res.get("users") or []:
            decisions.append(_decide(user))

    for user in mapped_users or []:
        decisions.append(_decide(user))

    return decisions


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


@dataclass
class PartitionSummary:
    created: int = 0
    updated: int = 0
    unchanged: int = 0

    @property
    def total(self) -> int:
        return self.created + self.updated + self.unchanged

    def as_dict(self) -> Dict[str, int]:
        return {
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "total": self.total,
        }


def summarize(decisions: List[RecordDecision]) -> PartitionSummary:
    summary = PartitionSummary()
    for d in decisions:
        if d.decision is IdempotencyDecision.CREATE:
            summary.created += 1
        elif d.decision is IdempotencyDecision.UPDATE:
            summary.updated += 1
        elif d.decision is IdempotencyDecision.UNCHANGED:
            summary.unchanged += 1
    return summary
