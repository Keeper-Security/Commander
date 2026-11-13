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

"""Match records of a PAM import JSON to records that already exist in the vault.

One implementation shared by ``pam project extend`` and ``pam project update``.
It is pure (no vault, no network): the caller builds a :class:`RecordIndex` ONCE
from the records it knows (see ``ksm_scope``) and then calls :func:`match_record`
for every JSON item. Nothing here loads a record or scans a list per item, so the
cost is linear in the number of records plus the number of JSON items.

Two modes:

``MODE_EXTEND``  keeps the matching rules ``extend`` always had: ``uid`` first, then
                 ``folder_path`` + title, then title. A record that is not found is
                 ``new``. Records in folders that are not shared to the KSM app still
                 count as existing, so ``extend`` never creates a duplicate of them.
``MODE_UPDATE``  ``update`` never creates, so a record that is not found is
                 ``missing`` (a PLAN error: run ``pam project extend`` first), a record
                 that exists only in a folder that is not shared to the KSM app is an
                 error (``outside_scope``), and the optional hooks add the checks
                 that only ``update`` needs (type, configuration, write permission).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

MODE_EXTEND = 'extend'
MODE_UPDATE = 'update'

STATUS_EXISTING = 'existing'
STATUS_NEW = 'new'
STATUS_MISSING = 'missing'
STATUS_ERROR = 'error'

CODE_UID_NOT_FOUND = 'uid_not_found'
CODE_FOLDER_UNRESOLVED = 'folder_unresolved'
CODE_FOLDER_MISSING = 'folder_missing'
CODE_AMBIGUOUS = 'ambiguous'
CODE_OUTSIDE_SCOPE = 'outside_scope'
CODE_IN_OTHER_FOLDER = 'in_other_folder'
CODE_TYPE_MISMATCH = 'type_mismatch'
CODE_OTHER_CONFIG = 'other_config'
CODE_NO_PERMISSION = 'no_permission'
CODE_NOTHING_TO_MATCH = 'nothing_to_match'


def _norm(title: Optional[str]) -> str:
    return (title or '').strip()


@dataclass(frozen=True)
class MatchRecord:
    """A vault record the matcher may match a JSON item to."""
    uid: str
    title: str = ''
    record_type: str = ''
    login: str = ''
    folder_uids: Tuple[str, ...] = ()
    # True when the KSM application can see the record (shared folder or direct share).
    shared: bool = True


@dataclass
class MatchResult:
    status: str
    uid: str = ''
    code: str = ''
    message: str = ''


class RecordIndex:
    """Records indexed by uid, by title and by (folder, title); unique by record UID.

    A record reachable through several folders (or a folder and a direct share) is ONE
    record here, so it can never produce a false "multiple matches".
    """

    def __init__(self, records: Iterable[MatchRecord] = ()):
        by_uid: Dict[str, MatchRecord] = {}
        for rec in records:
            if not rec.uid:
                continue
            known = by_uid.get(rec.uid)
            if known is None:
                by_uid[rec.uid] = rec
                continue
            folders = tuple(dict.fromkeys(known.folder_uids + rec.folder_uids))
            by_uid[rec.uid] = MatchRecord(
                uid=known.uid,
                title=known.title or rec.title,
                record_type=known.record_type or rec.record_type,
                login=known.login or rec.login,
                folder_uids=folders,
                shared=known.shared or rec.shared,
            )
        self._by_uid = by_uid
        self._by_title: Dict[str, List[MatchRecord]] = {}
        self._by_folder_title: Dict[Tuple[str, str], List[MatchRecord]] = {}
        for rec in by_uid.values():
            title = _norm(rec.title)
            self._by_title.setdefault(title, []).append(rec)
            for folder_uid in dict.fromkeys(rec.folder_uids):
                self._by_folder_title.setdefault((folder_uid, title), []).append(rec)

    def __len__(self) -> int:
        return len(self._by_uid)

    def get(self, uid: str) -> Optional[MatchRecord]:
        return self._by_uid.get(uid)

    def has_uid(self, uid: str) -> bool:
        return uid in self._by_uid

    def records(self) -> List[MatchRecord]:
        return list(self._by_uid.values())

    def by_title(self, title: str) -> List[MatchRecord]:
        return list(self._by_title.get(_norm(title), ()))

    def in_folder(self, folder_uid: str, title: str) -> List[MatchRecord]:
        return list(self._by_folder_title.get((folder_uid, _norm(title)), ()))


def _outside_scope(ident: str, suffix: str, location: str) -> MatchResult:
    return MatchResult(
        STATUS_ERROR, code=CODE_OUTSIDE_SCOPE,
        message=(f'record {ident}{suffix} exists in {location}, which is not shared to the KSM app. '
                 f'Share the folder to the app; update does not change shares.'))


def match_record(index: RecordIndex, *,
                 ident: str,
                 machine_suffix: str = '',
                 uid_imported: Optional[str] = None,
                 folder_path: str = '',
                 folder_uid: str = '',
                 folder_path_is_new: bool = False,
                 title: str = '',
                 login: str = '',
                 expected_type: str = '',
                 mode: str = MODE_EXTEND,
                 config_uid: str = '',
                 config_of: Optional[Callable[[str], Optional[str]]] = None,
                 can_write: Optional[Callable[[str], Optional[bool]]] = None,
                 vault_has_uid: Optional[Callable[[str], bool]] = None,
                 describe_location: Optional[Callable[[str], str]] = None,
                 folder_label: Optional[Callable[[str], str]] = None) -> MatchResult:
    """Match ONE JSON item.

    ``uid_imported`` is the (already validated) ``uid`` from the JSON, ``folder_uid`` the
    uid ``folder_path`` resolved to (empty when it did not resolve) and
    ``folder_path_is_new`` tells that the path is valid but its folder does not exist yet.
    The hooks are optional and only used by ``update``: ``config_of(uid)`` returns the
    configuration a record belongs to (None = unknown), ``can_write(uid)`` returns False
    when the user cannot edit the record (None = unknown, treated as allowed),
    ``vault_has_uid(uid)`` finds a record that is in the vault but outside the index,
    ``describe_location(uid)`` and ``folder_label(uid)`` produce texts for the errors.
    """
    update = mode == MODE_UPDATE
    suffix = machine_suffix
    title = _norm(title)
    login = (login or '').strip()

    def visible(rec: MatchRecord) -> bool:
        return (not update) or rec.shared

    def accept(rec: MatchRecord) -> MatchResult:
        if update:
            if expected_type and rec.record_type and expected_type.lower() != rec.record_type.lower():
                return MatchResult(
                    STATUS_ERROR, code=CODE_TYPE_MISMATCH,
                    message=(f'record {ident}{suffix}: the JSON type "{expected_type}" differs from the vault '
                             f'record type "{rec.record_type}" (update never changes the type)'))
            if config_of is not None:
                cfg = config_of(rec.uid)
                if cfg and config_uid and cfg != config_uid:
                    return MatchResult(
                        STATUS_ERROR, code=CODE_OTHER_CONFIG,
                        message=f'record {ident}{suffix} belongs to configuration {cfg}, not {config_uid}')
            if can_write is not None and can_write(rec.uid) is False:
                return MatchResult(
                    STATUS_ERROR, code=CODE_NO_PERMISSION,
                    message=f'no write permission on record {ident}{suffix}')
        return MatchResult(STATUS_EXISTING, uid=rec.uid)

    def not_found() -> MatchResult:
        if update:
            return MatchResult(STATUS_MISSING, message=f'record {ident}{suffix} not found in the vault')
        return MatchResult(STATUS_NEW)

    def pick(candidates: List[MatchRecord], ambiguous_msg: str) -> Optional[MatchResult]:
        """Return a result when the candidates decide the match, else None (nothing found)."""
        shown = [c for c in candidates if visible(c)]
        if len(shown) == 1:
            return accept(shown[0])
        if len(shown) > 1:
            return MatchResult(STATUS_ERROR, code=CODE_AMBIGUOUS, message=ambiguous_msg)
        hidden = [c for c in candidates if not visible(c)]
        if hidden:
            location = describe_location(hidden[0].uid) if describe_location else 'a folder'
            return _outside_scope(ident, suffix, location)
        return None

    # 1. explicit uid
    if uid_imported:
        rec = index.get(uid_imported)
        if rec is not None:
            if visible(rec):
                return accept(rec)
            location = describe_location(rec.uid) if describe_location else 'a folder'
            return _outside_scope(ident, suffix, location)
        if update and vault_has_uid is not None and vault_has_uid(uid_imported):
            location = describe_location(uid_imported) if describe_location else 'a folder'
            return _outside_scope(ident, suffix, location)
        if update:
            return MatchResult(STATUS_MISSING, code=CODE_UID_NOT_FOUND,
                               message=f'uid "{uid_imported}" not found in the vault for record {ident}{suffix}')
        return MatchResult(STATUS_ERROR, code=CODE_UID_NOT_FOUND,
                           message=f'uid "{uid_imported}" not found in KSM app for record {ident}{suffix}')

    # 2. folder_path + title
    if folder_path:
        if not folder_uid:
            if folder_path_is_new:
                if update:
                    return MatchResult(
                        STATUS_ERROR, code=CODE_FOLDER_MISSING,
                        message=(f'folder_path "{folder_path}" does not exist for record {ident}{suffix} '
                                 f'(update never creates folders)'))
                return MatchResult(STATUS_NEW)
            return MatchResult(
                STATUS_ERROR, code=CODE_FOLDER_UNRESOLVED,
                message=f'folder_path "{folder_path}" could not be resolved for record {ident}{suffix}')
        if not title and not login:
            if update:
                return MatchResult(STATUS_MISSING, code=CODE_NOTHING_TO_MATCH,
                                   message=f'record {ident}{suffix} has no title or login to match')
            return MatchResult(STATUS_NEW)
        decided = pick(index.in_folder(folder_uid, title),
                       f'Multiple matches for record {ident} in folder "{folder_path}"; '
                       f'add folder_path to disambiguate{suffix}')
        if decided is not None:
            return decided
        if update:
            elsewhere = [c for c in index.by_title(title) if visible(c)]
            if elsewhere:
                found_in = elsewhere[0].folder_uids[0] if elsewhere[0].folder_uids else ''
                label = folder_label(found_in) if (folder_label and found_in) else (found_in or 'another folder')
                return MatchResult(
                    STATUS_ERROR, code=CODE_IN_OTHER_FOLDER,
                    message=(f'record {ident}{suffix} found in folder "{label}", the JSON says "{folder_path}"; '
                             f'fix folder_path or move the record (update never moves records)'))
        return not_found()

    # 3. title only
    if not title and not login:
        if update:
            return MatchResult(STATUS_MISSING, code=CODE_NOTHING_TO_MATCH,
                               message=f'record {ident}{suffix} has no title or login to match')
        return MatchResult(STATUS_NEW)
    decided = pick(index.by_title(title),
                   f'Multiple matches for record {ident}; add folder_path to disambiguate{suffix}')
    if decided is not None:
        return decided
    return not_found()
